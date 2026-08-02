use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::sync::Mutex;

use super::{
    encode_channel_binding_mic_in_args, encode_channel_binding_mic_in_result, AcceptContext, ChannelBindingStatus,
    ChannelBindingVerifierArgs, ChannelBindingVerifierResult, Credential, GssIdentity, GssLimits, GssProvider,
    InitResult, IntegrityBody, PrivacyBody, Procedure, ProviderContextId, ProviderError, SequenceWindow,
    SequenceWindowError, Service, Version,
};

const GSS_S_COMPLETE: u32 = 0;
const GSS_S_CONTINUE_NEEDED: u32 = 1;
const CONTEXT_HANDLE_BYTES: usize = 32;

#[derive(Clone)]
pub struct GssContextRegistry {
    provider: Arc<dyn GssProvider>,
    inner: Arc<Mutex<Registry>>,
    limits: GssContextLimits,
}

struct Registry {
    contexts: HashMap<Vec<u8>, ContextRecord>,
    initializing: usize,
}

#[derive(Clone)]
struct ContextRecord {
    provider: AcceptContext,
    phase: ContextPhase,
    busy: bool,
    channel_id: Option<[u8; 32]>,
}

#[derive(Clone)]
enum ContextPhase {
    Pending,
    Established {
        identity: GssIdentity,
        sequence_window: SequenceWindow,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GssContextLimits {
    pub max_contexts: usize,
    pub sequence_window: usize,
    pub wire: GssLimits,
}

impl Default for GssContextLimits {
    fn default() -> Self {
        Self {
            max_contexts: 4096,
            sequence_window: 128,
            wire: GssLimits::default(),
        }
    }
}

impl GssContextRegistry {
    pub fn new(provider: Arc<dyn GssProvider>, limits: GssContextLimits) -> Result<Self, GssContextError> {
        if limits.max_contexts == 0 {
            return Err(GssContextError::Resource);
        }
        SequenceWindow::new(limits.sequence_window)?;
        Ok(Self {
            provider,
            inner: Arc::new(Mutex::new(Registry {
                contexts: HashMap::new(),
                initializing: 0,
            })),
            limits,
        })
    }

    pub fn limits(&self) -> GssContextLimits {
        self.limits
    }

    /// Returns a conservative maximum successful RPC procedure-body size
    /// whose fully protected accepted reply fits `max_record_bytes`.
    ///
    /// This is intentionally computed before dispatch so an NFS COMPOUND can
    /// refuse a mutation before executing it when its protected result would
    /// not fit the transport.
    pub async fn max_reply_body_size(
        &self,
        request: &AuthenticatedGssRequest,
        max_record_bytes: usize,
    ) -> Result<usize, GssContextError> {
        const ACCEPTED_REPLY_FIXED_BYTES: usize = 24;
        const MAX_RPC_AUTH_BYTES: usize = 400;

        let sizes = if request.service == Service::ChannelProtection {
            None
        } else {
            let result = self.provider.protection_sizes(request.provider_context).await;
            Some(
                self.finish_provider_call(&request.context_handle, request.provider_context, result)
                    .await?,
            )
        };
        let max_mic_bytes = sizes.map_or(0, |sizes| sizes.max_mic_token_bytes);
        if max_mic_bytes > MAX_RPC_AUTH_BYTES || max_mic_bytes > self.limits.wire.max_mic_bytes {
            return Err(GssContextError::Resource);
        }
        let verifier_bytes = if request.service == Service::ChannelProtection {
            0
        } else {
            xdr_padded_len(max_mic_bytes).ok_or(GssContextError::Resource)?
        };
        let body_capacity = max_record_bytes.saturating_sub(ACCEPTED_REPLY_FIXED_BYTES.saturating_add(verifier_bytes));

        match request.service {
            Service::None | Service::ChannelProtection => Ok(body_capacity),
            Service::Integrity => {
                // IntegrityBody contains opaque(sequence + body) and opaque(MIC).
                // A procedure body is XDR-aligned, making its fixed expansion
                // 12 bytes plus the padded MIC token.
                let integrity_overhead = 12usize
                    .checked_add(xdr_padded_len(max_mic_bytes).ok_or(GssContextError::Resource)?)
                    .ok_or(GssContextError::Resource)?;
                let wire_capacity = self.limits.wire.max_protected_body_bytes.saturating_sub(4);
                Ok(body_capacity.saturating_sub(integrity_overhead).min(wire_capacity))
            },
            Service::Privacy => {
                let wrap_overhead = sizes.expect("privacy protection sizes were requested").max_wrap_overhead_bytes;
                // PrivacyBody is one XDR opaque containing a provider token
                // over sequence + body. Three bytes conservatively cover its
                // final XDR padding for any provider token length.
                let privacy_overhead = 11usize.checked_add(wrap_overhead).ok_or(GssContextError::Resource)?;
                let wire_capacity = self
                    .limits
                    .wire
                    .max_protected_body_bytes
                    .saturating_sub(4usize.saturating_add(wrap_overhead));
                Ok(body_capacity.saturating_sub(privacy_overhead).min(wire_capacity))
            },
        }
    }

    pub async fn accept_init(&self, credential: &Credential, token: Bytes) -> Result<InitResult, GssContextError> {
        match credential.procedure {
            Procedure::Init => self.accept_first(credential.version, token).await,
            Procedure::ContinueInit => self.accept_continuation(credential.version, &credential.handle, token).await,
            _ => Err(GssContextError::BadCredential),
        }
    }

    /// Produces the verifier for the final successful context-creation
    /// response. RFC 2203 protects the negotiated sequence-window value,
    /// rather than a request sequence number, for this one reply.
    pub async fn init_reply_verifier(&self, handle: &[u8], sequence_window: u32) -> Result<Bytes, GssContextError> {
        let record = self.live_record(handle).await?;
        if !matches!(record.phase, ContextPhase::Established { .. }) {
            return Err(GssContextError::ContextProblem);
        }
        let result = self
            .provider
            .get_mic(record.provider.provider_context, Bytes::copy_from_slice(&sequence_window.to_be_bytes()))
            .await;
        self.finish_provider_call(handle, record.provider.provider_context, result)
            .await
    }

    async fn accept_first(&self, version: Version, token: Bytes) -> Result<InitResult, GssContextError> {
        let (expired, reserved) = {
            let mut inner = self.inner.lock().await;
            let expired = prune_expired(&mut inner, Instant::now());
            let reserved = inner.contexts.len().saturating_add(inner.initializing) < self.limits.max_contexts;
            if reserved {
                inner.initializing += 1;
            }
            (expired, reserved)
        };
        self.delete_records(expired).await;
        if !reserved {
            return Err(GssContextError::Resource);
        }

        let outcome = self.provider.accept_security_context(None, version, token).await;
        let mut inner = self.inner.lock().await;
        inner.initializing = inner.initializing.saturating_sub(1);
        let outcome = outcome?;
        let provider_context = outcome.context.provider_context;
        let terminal_failure = !matches!(outcome.major_status, GSS_S_COMPLETE | GSS_S_CONTINUE_NEEDED);
        let result = self.finish_accept(&mut inner, None, outcome);
        drop(inner);
        if terminal_failure || result.is_err() {
            self.delete_provider_context(provider_context).await;
        }
        result
    }

    async fn accept_continuation(
        &self,
        version: Version,
        handle: &[u8],
        token: Bytes,
    ) -> Result<InitResult, GssContextError> {
        let (continuation, expired) = {
            let mut inner = self.inner.lock().await;
            let expired = inner
                .contexts
                .get(handle)
                .is_some_and(|record| record.provider.expires_at <= Instant::now());
            if expired {
                let expired = inner.contexts.remove(handle).expect("expired record was present");
                (None, Some(expired))
            } else {
                let record = inner.contexts.get_mut(handle).ok_or(GssContextError::CredentialProblem)?;
                if record.provider.version != version || !matches!(record.phase, ContextPhase::Pending) || record.busy {
                    return Err(GssContextError::BadCredential);
                }
                record.busy = true;
                (Some(record.provider.clone()), None)
            }
        };
        if let Some(expired) = expired {
            self.delete_records(vec![expired]).await;
            return Err(GssContextError::CredentialProblem);
        }
        let continuation = continuation.expect("live continuation was selected");

        let outcome = self
            .provider
            .accept_security_context(Some(continuation.clone()), version, token)
            .await;
        let mut inner = self.inner.lock().await;
        if let Some(record) = inner.contexts.get_mut(handle) {
            record.busy = false;
        }
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                let removed = remove_matching_context(&mut inner, handle, continuation.provider_context);
                drop(inner);
                if let Some(record) = removed {
                    self.delete_records(vec![record]).await;
                }
                return Err(error.into());
            },
        };
        let provider_context = outcome.context.provider_context;
        let terminal_failure = !matches!(outcome.major_status, GSS_S_COMPLETE | GSS_S_CONTINUE_NEEDED);
        let result = self.finish_accept(&mut inner, Some(handle), outcome);
        drop(inner);
        if terminal_failure || result.is_err() {
            self.delete_provider_context(provider_context).await;
        }
        result
    }

    fn finish_accept(
        &self,
        inner: &mut Registry,
        existing_handle: Option<&[u8]>,
        outcome: super::AcceptOutcome,
    ) -> Result<InitResult, GssContextError> {
        if outcome.context.expires_at <= Instant::now() {
            if let Some(handle) = existing_handle {
                inner.contexts.remove(handle);
            }
            return Err(GssContextError::Provider(ProviderError::Expired));
        }
        if let Some(handle) = existing_handle {
            let record = inner.contexts.get(handle).ok_or(GssContextError::CredentialProblem)?;
            if record.provider.version != outcome.context.version
                || record.provider.provider_context != outcome.context.provider_context
                || !matches!(record.phase, ContextPhase::Pending)
                || record.busy
            {
                inner.contexts.remove(handle);
                return Err(GssContextError::CredentialProblem);
            }
        }
        if !matches!(outcome.major_status, GSS_S_COMPLETE | GSS_S_CONTINUE_NEEDED) {
            if let Some(handle) = existing_handle {
                inner.contexts.remove(handle);
            }
            return Ok(InitResult {
                handle: Vec::new(),
                major_status: outcome.major_status,
                minor_status: outcome.minor_status,
                sequence_window: self.limits.sequence_window as u32,
                token: outcome.output_token.to_vec(),
            });
        }

        let handle = match existing_handle {
            Some(handle) => handle.to_vec(),
            None => unique_handle(inner),
        };
        let phase = if outcome.major_status == GSS_S_COMPLETE {
            let identity = outcome
                .complete_identity
                .ok_or(GssContextError::Provider(ProviderError::InvalidToken))?;
            ContextPhase::Established {
                identity,
                sequence_window: SequenceWindow::new(self.limits.sequence_window)?,
            }
        } else {
            ContextPhase::Pending
        };
        inner.contexts.insert(
            handle.clone(),
            ContextRecord {
                provider: outcome.context,
                phase,
                busy: false,
                channel_id: None,
            },
        );
        Ok(InitResult {
            handle,
            major_status: outcome.major_status,
            minor_status: outcome.minor_status,
            sequence_window: self.limits.sequence_window as u32,
            token: outcome.output_token.to_vec(),
        })
    }

    /// Verifies the RPC header MIC and consumes the credential sequence
    /// number. Replay-window mutation occurs only after MIC verification.
    pub async fn authenticate_data(
        &self,
        credential: &Credential,
        encoded_header_through_credential: Bytes,
        verifier: Bytes,
        channel_id: Option<[u8; 32]>,
    ) -> Result<AuthenticatedGssRequest, GssContextError> {
        if !matches!(credential.procedure, Procedure::Data | Procedure::Destroy) {
            return Err(GssContextError::BadCredential);
        }
        let record = self.live_record(&credential.handle).await?;
        if record.provider.version != credential.version {
            return Err(GssContextError::BadCredential);
        }
        let ContextPhase::Established { identity, .. } = &record.phase else {
            return Err(GssContextError::ContextProblem);
        };
        let provider_context = record.provider.provider_context;
        let identity = identity.clone();

        if credential.service == Service::ChannelProtection {
            if record.channel_id.is_none() || record.channel_id != channel_id || !verifier.is_empty() {
                return Err(GssContextError::BadCredential);
            }
        } else {
            let verified = self
                .provider
                .verify_mic(provider_context, encoded_header_through_credential, verifier)
                .await;
            if let Err(error) = verified {
                self.remove_if_provider_unusable(&credential.handle, provider_context, &error)
                    .await;
                return Err(GssContextError::CredentialProblem);
            }
        }

        self.accept_sequence(&credential.handle, provider_context, credential.sequence, None)
            .await?;

        Ok(AuthenticatedGssRequest {
            context_handle: credential.handle.clone(),
            provider_context,
            identity,
            sequence: credential.sequence,
            service: credential.service,
        })
    }

    /// Verifies and installs an RFC 5403 binding for one established v2
    /// context, returning the encoded RPC reply verifier.
    pub async fn bind_channel(
        &self,
        credential: &Credential,
        encoded_header_through_credential: Bytes,
        encoded_verifier: Bytes,
        binding: &ChannelBindingMaterial,
    ) -> Result<ChannelBindingOutcome, GssContextError> {
        if credential.version != Version::V2
            || credential.procedure != Procedure::BindChannel
            || credential.service != Service::None
        {
            return Err(GssContextError::BadCredential);
        }
        let arguments = ChannelBindingVerifierArgs::decode(&encoded_verifier, self.limits.wire)?;
        let record = self.live_record(&credential.handle).await?;
        if !matches!(record.phase, ContextPhase::Established { .. }) {
            return Err(GssContextError::ContextProblem);
        }
        let provider_context = record.provider.provider_context;
        if record.provider.version != Version::V2 {
            return Err(GssContextError::BadCredential);
        }

        let status = if arguments.prefix != binding.prefix {
            ChannelBindingStatus::PrefixNotSupported(vec![binding.prefix.clone()])
        } else if arguments.hash_oid != binding.hash_oid {
            ChannelBindingStatus::HashNotSupported(vec![binding.hash_oid.clone()])
        } else {
            let mut mic_input = Vec::with_capacity(
                encoded_header_through_credential
                    .len()
                    .saturating_add(binding.hash.len())
                    .saturating_add(4),
            );
            mic_input.extend_from_slice(&encoded_header_through_credential);
            mic_input.extend_from_slice(&encode_channel_binding_mic_in_args(&binding.hash)?);
            let verified = self
                .provider
                .verify_mic(provider_context, Bytes::from(mic_input), Bytes::from(arguments.mic))
                .await;
            if let Err(error) = verified {
                self.remove_if_provider_unusable(&credential.handle, provider_context, &error)
                    .await;
                return Err(GssContextError::CredentialProblem);
            }
            self.accept_sequence(&credential.handle, provider_context, credential.sequence, Some(binding.channel_id))
                .await?;
            ChannelBindingStatus::Ok
        };

        let reply_mic_input = encode_channel_binding_mic_in_result(credential.sequence, &binding.hash, &status)?;
        let result = self.provider.get_mic(provider_context, Bytes::from(reply_mic_input)).await;
        let mic = self.finish_provider_call(&credential.handle, provider_context, result).await?;
        let verifier = ChannelBindingVerifierResult {
            status: status.clone(),
            mic: mic.to_vec(),
        }
        .encode()?;
        if verifier.len() > self.limits.wire.max_channel_binding_bytes {
            return Err(GssContextError::Resource);
        }
        Ok(ChannelBindingOutcome {
            status,
            reply_verifier: Bytes::from(verifier),
        })
    }

    pub async fn destroy(&self, request: &AuthenticatedGssRequest) -> Result<(), GssContextError> {
        let removed = {
            let mut inner = self.inner.lock().await;
            remove_matching_context(&mut inner, &request.context_handle, request.provider_context)
        };
        if removed.is_none() {
            return Err(GssContextError::CredentialProblem);
        }
        match self.provider.delete_security_context(request.provider_context).await {
            Ok(()) | Err(ProviderError::UnknownContext | ProviderError::Expired) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    pub async fn unwrap_call(
        &self,
        request: &AuthenticatedGssRequest,
        encoded_body: Bytes,
    ) -> Result<Bytes, GssContextError> {
        match request.service {
            Service::None | Service::ChannelProtection => Ok(encoded_body),
            Service::Integrity => {
                let body = IntegrityBody::decode(&encoded_body, self.limits.wire)?;
                if body.embedded_sequence()? != request.sequence {
                    return Err(GssContextError::GarbageArguments);
                }
                let procedure_body = Bytes::copy_from_slice(body.procedure_body()?);
                let result = self
                    .provider
                    .verify_mic(
                        request.provider_context,
                        Bytes::copy_from_slice(&body.protected),
                        Bytes::from(body.checksum),
                    )
                    .await;
                if let Err(error) = result {
                    self.remove_if_provider_unusable(&request.context_handle, request.provider_context, &error)
                        .await;
                    return Err(GssContextError::GarbageArguments);
                }
                Ok(procedure_body)
            },
            Service::Privacy => {
                let body = PrivacyBody::decode(&encoded_body, self.limits.wire)?;
                let result = self.provider.unwrap(request.provider_context, Bytes::from(body.wrapped)).await;
                let unwrapped = match result {
                    Ok(unwrapped) => unwrapped,
                    Err(error) => {
                        self.remove_if_provider_unusable(&request.context_handle, request.provider_context, &error)
                            .await;
                        return Err(GssContextError::GarbageArguments);
                    },
                };
                split_protected_body(unwrapped, request.sequence)
            },
        }
    }

    pub async fn reply_verifier(&self, request: &AuthenticatedGssRequest) -> Result<Bytes, GssContextError> {
        if request.service == Service::ChannelProtection {
            return Ok(Bytes::new());
        }
        let result = self
            .provider
            .get_mic(request.provider_context, Bytes::copy_from_slice(&request.sequence.to_be_bytes()))
            .await;
        let verifier = self
            .finish_provider_call(&request.context_handle, request.provider_context, result)
            .await?;
        if verifier.len() > self.limits.wire.max_mic_bytes {
            return Err(GssContextError::Resource);
        }
        Ok(verifier)
    }

    pub async fn wrap_reply(&self, request: &AuthenticatedGssRequest, body: Bytes) -> Result<Bytes, GssContextError> {
        match request.service {
            Service::None | Service::ChannelProtection => Ok(body),
            Service::Integrity => {
                let protected = protected_body(request.sequence, &body);
                if protected.len() > self.limits.wire.max_protected_body_bytes {
                    return Err(GssContextError::Resource);
                }
                let result = self
                    .provider
                    .get_mic(request.provider_context, Bytes::copy_from_slice(&protected))
                    .await;
                let checksum = self
                    .finish_provider_call(&request.context_handle, request.provider_context, result)
                    .await?;
                if checksum.len() > self.limits.wire.max_mic_bytes {
                    return Err(GssContextError::Resource);
                }
                Ok(Bytes::from(
                    IntegrityBody {
                        protected,
                        checksum: checksum.to_vec(),
                    }
                    .encode()?,
                ))
            },
            Service::Privacy => {
                let protected = protected_body(request.sequence, &body);
                let result = self.provider.wrap(request.provider_context, Bytes::from(protected), true).await;
                let wrapped = self
                    .finish_provider_call(&request.context_handle, request.provider_context, result)
                    .await?;
                if wrapped.len() > self.limits.wire.max_protected_body_bytes {
                    return Err(GssContextError::Resource);
                }
                Ok(Bytes::from(
                    PrivacyBody {
                        wrapped: wrapped.to_vec(),
                    }
                    .encode()?,
                ))
            },
        }
    }

    async fn live_record(&self, handle: &[u8]) -> Result<ContextRecord, GssContextError> {
        let (record, expired) = {
            let mut inner = self.inner.lock().await;
            let expired = inner
                .contexts
                .get(handle)
                .is_some_and(|record| record.provider.expires_at <= Instant::now());
            if expired {
                (None, inner.contexts.remove(handle))
            } else {
                (inner.contexts.get(handle).cloned(), None)
            }
        };
        if let Some(expired) = expired {
            self.delete_records(vec![expired]).await;
            return Err(GssContextError::CredentialProblem);
        }
        record.ok_or(GssContextError::CredentialProblem)
    }

    async fn accept_sequence(
        &self,
        handle: &[u8],
        provider_context: ProviderContextId,
        sequence: u32,
        bind_channel_id: Option<[u8; 32]>,
    ) -> Result<(), GssContextError> {
        let mut inner = self.inner.lock().await;
        let expired = inner
            .contexts
            .get(handle)
            .is_some_and(|record| record.provider.expires_at <= Instant::now());
        if expired {
            let expired = inner.contexts.remove(handle).expect("expired record was present");
            drop(inner);
            self.delete_records(vec![expired]).await;
            return Err(GssContextError::CredentialProblem);
        }

        let record = inner.contexts.get_mut(handle).ok_or(GssContextError::CredentialProblem)?;
        if record.provider.provider_context != provider_context {
            return Err(GssContextError::CredentialProblem);
        }
        let ContextPhase::Established { sequence_window, .. } = &mut record.phase else {
            return Err(GssContextError::ContextProblem);
        };
        sequence_window.accept(sequence)?;
        if let Some(channel_id) = bind_channel_id {
            record.channel_id = Some(channel_id);
        }
        Ok(())
    }

    async fn finish_provider_call<T>(
        &self,
        handle: &[u8],
        provider_context: ProviderContextId,
        result: Result<T, ProviderError>,
    ) -> Result<T, GssContextError> {
        if let Err(error) = &result {
            self.remove_if_provider_unusable(handle, provider_context, error).await;
        }
        result.map_err(Into::into)
    }

    async fn remove_if_provider_unusable(
        &self,
        handle: &[u8],
        provider_context: ProviderContextId,
        error: &ProviderError,
    ) {
        if !matches!(error, ProviderError::UnknownContext | ProviderError::Expired) {
            return;
        }
        let removed = {
            let mut inner = self.inner.lock().await;
            remove_matching_context(&mut inner, handle, provider_context)
        };
        if let Some(record) = removed {
            self.delete_records(vec![record]).await;
        }
    }

    async fn delete_records(&self, records: Vec<ContextRecord>) {
        for record in records {
            self.delete_provider_context(record.provider.provider_context).await;
        }
    }

    async fn delete_provider_context(&self, provider_context: ProviderContextId) {
        let _ = self.provider.delete_security_context(provider_context).await;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedGssRequest {
    pub context_handle: Vec<u8>,
    pub provider_context: ProviderContextId,
    pub identity: GssIdentity,
    pub sequence: u32,
    pub service: Service,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelBindingMaterial {
    pub channel_id: [u8; 32],
    pub prefix: Vec<u8>,
    pub hash_oid: Vec<u8>,
    pub hash: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelBindingOutcome {
    pub status: ChannelBindingStatus,
    pub reply_verifier: Bytes,
}

#[derive(Debug, thiserror::Error)]
pub enum GssContextError {
    #[error("invalid RPCSEC_GSS credential")]
    BadCredential,
    #[error("RPCSEC_GSS credential or verifier problem")]
    CredentialProblem,
    #[error("RPCSEC_GSS context problem")]
    ContextProblem,
    #[error("RPCSEC_GSS protected arguments are invalid")]
    GarbageArguments,
    #[error("RPCSEC_GSS resource limit reached")]
    Resource,
    #[error(transparent)]
    Sequence(#[from] SequenceWindowError),
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error(transparent)]
    Decode(#[from] crate::rpc::codec::DecodeError),
    #[error(transparent)]
    Encode(#[from] crate::rpc::codec::EncodeError),
}

fn prune_expired(inner: &mut Registry, now: Instant) -> Vec<ContextRecord> {
    let mut expired = Vec::new();
    inner.contexts.retain(|_, record| {
        if record.provider.expires_at <= now {
            expired.push(record.clone());
            false
        } else {
            true
        }
    });
    expired
}

fn remove_matching_context(
    inner: &mut Registry,
    handle: &[u8],
    provider_context: ProviderContextId,
) -> Option<ContextRecord> {
    let matches = inner
        .contexts
        .get(handle)
        .is_some_and(|record| record.provider.provider_context == provider_context);
    matches.then(|| inner.contexts.remove(handle)).flatten()
}

fn unique_handle(inner: &Registry) -> Vec<u8> {
    loop {
        let mut handle = vec![0; CONTEXT_HANDLE_BYTES];
        OsRng.fill_bytes(&mut handle);
        if !inner.contexts.contains_key(&handle) {
            return handle;
        }
    }
}

fn protected_body(sequence: u32, body: &[u8]) -> Vec<u8> {
    let mut protected = Vec::with_capacity(4usize.saturating_add(body.len()));
    protected.extend_from_slice(&sequence.to_be_bytes());
    protected.extend_from_slice(body);
    protected
}

fn xdr_padded_len(len: usize) -> Option<usize> {
    len.checked_add(3).map(|value| value & !3)
}

fn split_protected_body(body: Bytes, expected_sequence: u32) -> Result<Bytes, GssContextError> {
    let sequence = body
        .get(..4)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_be_bytes)
        .ok_or(GssContextError::GarbageArguments)?;
    if sequence != expected_sequence {
        return Err(GssContextError::GarbageArguments);
    }
    Ok(body.slice(4..))
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use sha2::{Digest, Sha256};

    use super::*;

    #[derive(Default)]
    struct MockProvider {
        expire_on_verify: bool,
        unknown_on_delete: bool,
    }

    #[async_trait]
    impl GssProvider for MockProvider {
        async fn accept_security_context(
            &self,
            continuation: Option<AcceptContext>,
            version: Version,
            token: Bytes,
        ) -> Result<super::super::AcceptOutcome, ProviderError> {
            let provider_context = continuation.map_or(ProviderContextId(1), |value| value.provider_context);
            let complete = token == Bytes::from_static(b"complete");
            Ok(super::super::AcceptOutcome {
                context: AcceptContext {
                    provider_context,
                    version,
                    expires_at: Instant::now() + std::time::Duration::from_secs(60),
                },
                major_status: if complete {
                    GSS_S_COMPLETE
                } else {
                    GSS_S_CONTINUE_NEEDED
                },
                minor_status: 0,
                output_token: Bytes::from_static(b"server-token"),
                complete_identity: complete.then(|| GssIdentity {
                    principal: "nfs-client@EXAMPLE.COM".into(),
                    mechanism: vec![0x2a, 0x86, 0x48],
                }),
            })
        }

        async fn verify_mic(
            &self,
            _context: ProviderContextId,
            message: Bytes,
            mic: Bytes,
        ) -> Result<(), ProviderError> {
            if self.expire_on_verify {
                return Err(ProviderError::Expired);
            }
            (mic == Sha256::digest(&message).as_slice())
                .then_some(())
                .ok_or(ProviderError::Integrity)
        }

        async fn get_mic(&self, _context: ProviderContextId, message: Bytes) -> Result<Bytes, ProviderError> {
            Ok(Bytes::copy_from_slice(&Sha256::digest(&message)))
        }

        async fn unwrap(&self, _context: ProviderContextId, token: Bytes) -> Result<Bytes, ProviderError> {
            Ok(token)
        }

        async fn wrap(
            &self,
            _context: ProviderContextId,
            message: Bytes,
            _confidentiality: bool,
        ) -> Result<Bytes, ProviderError> {
            Ok(message)
        }

        async fn protection_sizes(
            &self,
            _context: ProviderContextId,
        ) -> Result<super::super::ProtectionSizes, ProviderError> {
            Ok(super::super::ProtectionSizes {
                max_mic_token_bytes: 32,
                max_wrap_overhead_bytes: 0,
            })
        }

        async fn delete_security_context(&self, _context: ProviderContextId) -> Result<(), ProviderError> {
            if self.unknown_on_delete {
                Err(ProviderError::UnknownContext)
            } else {
                Ok(())
            }
        }
    }

    fn credential(procedure: Procedure, handle: Vec<u8>, sequence: u32, service: Service) -> Credential {
        Credential {
            version: Version::V1,
            procedure,
            sequence,
            service,
            handle,
        }
    }

    #[tokio::test]
    async fn establishes_context_and_enforces_header_replay_window() {
        let registry = GssContextRegistry::new(Arc::new(MockProvider::default()), GssContextLimits::default()).unwrap();
        let init = registry
            .accept_init(&credential(Procedure::Init, Vec::new(), 0, Service::None), Bytes::from_static(b"complete"))
            .await
            .unwrap();
        assert_eq!(
            registry.init_reply_verifier(&init.handle, init.sequence_window).await.unwrap(),
            Bytes::copy_from_slice(&Sha256::digest(init.sequence_window.to_be_bytes()))
        );
        let header = Bytes::from_static(b"rpc header through credential");
        let mic = Bytes::copy_from_slice(&Sha256::digest(&header));
        let data_credential = credential(Procedure::Data, init.handle, 7, Service::Integrity);
        assert!(matches!(
            registry
                .authenticate_data(&data_credential, header.clone(), Bytes::from_static(b"invalid verifier"), None,)
                .await,
            Err(GssContextError::CredentialProblem)
        ));
        registry
            .authenticate_data(&data_credential, header.clone(), mic.clone(), None)
            .await
            .unwrap();
        assert!(matches!(
            registry.authenticate_data(&data_credential, header, mic, None).await,
            Err(GssContextError::Sequence(SequenceWindowError::Discard))
        ));
    }

    #[tokio::test]
    async fn integrity_and_privacy_bodies_round_trip() {
        let registry = GssContextRegistry::new(Arc::new(MockProvider::default()), GssContextLimits::default()).unwrap();
        let init = registry
            .accept_init(&credential(Procedure::Init, Vec::new(), 0, Service::None), Bytes::from_static(b"complete"))
            .await
            .unwrap();
        for (sequence, service) in [(1, Service::Integrity), (2, Service::Privacy)] {
            let request = AuthenticatedGssRequest {
                context_handle: init.handle.clone(),
                provider_context: ProviderContextId(1),
                identity: GssIdentity {
                    principal: "client".into(),
                    mechanism: Vec::new(),
                },
                sequence,
                service,
            };
            let protected = registry.wrap_reply(&request, Bytes::from_static(b"compound")).await.unwrap();
            assert_eq!(registry.unwrap_call(&request, protected).await.unwrap(), Bytes::from_static(b"compound"));
        }
    }

    #[tokio::test]
    async fn protected_reply_budget_accounts_for_verifier_and_service_wrapping() {
        let registry = GssContextRegistry::new(Arc::new(MockProvider::default()), GssContextLimits::default()).unwrap();
        let init = registry
            .accept_init(&credential(Procedure::Init, Vec::new(), 0, Service::None), Bytes::from_static(b"complete"))
            .await
            .unwrap();
        let request = |service| AuthenticatedGssRequest {
            context_handle: init.handle.clone(),
            provider_context: ProviderContextId(1),
            identity: GssIdentity {
                principal: "client".into(),
                mechanism: Vec::new(),
            },
            sequence: 1,
            service,
        };

        assert_eq!(registry.max_reply_body_size(&request(Service::None), 1024).await.unwrap(), 968);
        assert_eq!(registry.max_reply_body_size(&request(Service::Integrity), 1024).await.unwrap(), 924);
        assert_eq!(registry.max_reply_body_size(&request(Service::Privacy), 1024).await.unwrap(), 957);
        assert_eq!(
            registry
                .max_reply_body_size(&request(Service::ChannelProtection), 1024)
                .await
                .unwrap(),
            1000
        );
    }

    #[tokio::test]
    async fn v2_channel_binding_is_scoped_to_the_observed_channel() {
        let registry = GssContextRegistry::new(Arc::new(MockProvider::default()), GssContextLimits::default()).unwrap();
        let init_credential = Credential {
            version: Version::V2,
            procedure: Procedure::Init,
            sequence: 0,
            service: Service::None,
            handle: Vec::new(),
        };
        let init = registry
            .accept_init(&init_credential, Bytes::from_static(b"complete"))
            .await
            .unwrap();
        let binding = ChannelBindingMaterial {
            channel_id: [3; 32],
            prefix: b"tls-exporter".to_vec(),
            hash_oid: vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
            hash: vec![4; 32],
        };
        let header = Bytes::from_static(b"rpc header through bind credential");
        let mut mic_input = header.to_vec();
        mic_input.extend_from_slice(&encode_channel_binding_mic_in_args(&binding.hash).unwrap());
        let verifier = ChannelBindingVerifierArgs {
            prefix: binding.prefix.clone(),
            hash_oid: binding.hash_oid.clone(),
            mic: Sha256::digest(&mic_input).to_vec(),
        }
        .encode()
        .unwrap();
        let bind_credential = Credential {
            version: Version::V2,
            procedure: Procedure::BindChannel,
            sequence: 5,
            service: Service::None,
            handle: init.handle.clone(),
        };
        let outcome = registry
            .bind_channel(&bind_credential, header, Bytes::from(verifier), &binding)
            .await
            .unwrap();
        assert_eq!(outcome.status, ChannelBindingStatus::Ok);

        let data_credential = Credential {
            version: Version::V2,
            procedure: Procedure::Data,
            sequence: 6,
            service: Service::ChannelProtection,
            handle: init.handle,
        };
        assert!(registry
            .authenticate_data(&data_credential, Bytes::new(), Bytes::new(), Some(binding.channel_id),)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn expired_context_at_the_bound_is_reaped_and_replaced_with_a_fresh_window() {
        let limits = GssContextLimits {
            max_contexts: 1,
            sequence_window: 4,
            ..GssContextLimits::default()
        };
        let registry = GssContextRegistry::new(Arc::new(MockProvider::default()), limits).unwrap();
        let first = registry
            .accept_init(&credential(Procedure::Init, Vec::new(), 0, Service::None), Bytes::from_static(b"complete"))
            .await
            .unwrap();
        {
            let mut inner = registry.inner.lock().await;
            inner.contexts.get_mut(&first.handle).unwrap().provider.expires_at = Instant::now();
        }

        let second = registry
            .accept_init(&credential(Procedure::Init, Vec::new(), 0, Service::None), Bytes::from_static(b"complete"))
            .await
            .expect("expired context releases the only slot");
        assert_ne!(first.handle, second.handle);
        assert_eq!(registry.inner.lock().await.contexts.len(), 1);
        assert!(matches!(
            registry.init_reply_verifier(&first.handle, first.sequence_window).await,
            Err(GssContextError::CredentialProblem)
        ));

        let header = Bytes::from_static(b"replacement request");
        let mic = Bytes::copy_from_slice(&Sha256::digest(&header));
        let request = credential(Procedure::Data, second.handle, 3, Service::Integrity);
        registry
            .authenticate_data(&request, header.clone(), mic.clone(), None)
            .await
            .expect("replacement context has an unused replay window");
        assert!(matches!(
            registry.authenticate_data(&request, header, mic, None).await,
            Err(GssContextError::Sequence(SequenceWindowError::Discard))
        ));
    }

    #[tokio::test]
    async fn provider_reported_expiry_releases_registry_capacity() {
        let limits = GssContextLimits {
            max_contexts: 1,
            ..GssContextLimits::default()
        };
        let registry = GssContextRegistry::new(
            Arc::new(MockProvider {
                expire_on_verify: true,
                unknown_on_delete: false,
            }),
            limits,
        )
        .unwrap();
        let first = registry
            .accept_init(&credential(Procedure::Init, Vec::new(), 0, Service::None), Bytes::from_static(b"complete"))
            .await
            .unwrap();
        let header = Bytes::from_static(b"expired request");
        let request = credential(Procedure::Data, first.handle, 1, Service::Integrity);
        assert!(matches!(
            registry
                .authenticate_data(&request, header.clone(), Bytes::copy_from_slice(&Sha256::digest(&header)), None,)
                .await,
            Err(GssContextError::CredentialProblem)
        ));

        registry
            .accept_init(&credential(Procedure::Init, Vec::new(), 0, Service::None), Bytes::from_static(b"complete"))
            .await
            .expect("provider expiry releases the only registry slot");
    }

    #[tokio::test]
    async fn destroy_releases_capacity_and_discards_the_old_sequence_window() {
        let limits = GssContextLimits {
            max_contexts: 1,
            sequence_window: 4,
            ..GssContextLimits::default()
        };
        let registry = GssContextRegistry::new(
            Arc::new(MockProvider {
                expire_on_verify: false,
                unknown_on_delete: true,
            }),
            limits,
        )
        .unwrap();
        let first = registry
            .accept_init(&credential(Procedure::Init, Vec::new(), 0, Service::None), Bytes::from_static(b"complete"))
            .await
            .unwrap();
        let header = Bytes::from_static(b"destroy request");
        let mic = Bytes::copy_from_slice(&Sha256::digest(&header));
        let destroy_credential = credential(Procedure::Destroy, first.handle.clone(), 2, Service::Integrity);
        let authenticated = registry
            .authenticate_data(&destroy_credential, header, mic, None)
            .await
            .unwrap();
        registry
            .destroy(&authenticated)
            .await
            .expect("an already-absent provider context is a successful destroy");
        assert!(registry.inner.lock().await.contexts.is_empty());

        let second = registry
            .accept_init(&credential(Procedure::Init, Vec::new(), 0, Service::None), Bytes::from_static(b"complete"))
            .await
            .expect("destroy releases the only registry slot");
        let header = Bytes::from_static(b"new context reuses sequence");
        let mic = Bytes::copy_from_slice(&Sha256::digest(&header));
        registry
            .authenticate_data(&credential(Procedure::Data, second.handle, 2, Service::Integrity), header, mic, None)
            .await
            .expect("the replacement context has a fresh replay window");
    }
}
