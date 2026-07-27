//! Bounded NFSv4.0 callback RPC client.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::Mutex as AsyncMutex;

use super::codec::DecodeLimits;
use super::types::{
    Bitmap, CallbackArgOp, CallbackCompoundArgs, CallbackCompoundRes, CallbackGetAttrArgs, CallbackRecallArgs,
    CallbackResOp, FileAttributes, NfsFileHandle, NfsResult, NfsStatus, StateId, CALLBACK_COMPOUND_PROCEDURE,
    CALLBACK_NULL_PROCEDURE, CALLBACK_VERSION, RPCSEC_GSS,
};
use crate::rpc::auth::{AUTH_NONE, AUTH_SYS, MAX_GROUPS, MAX_MACHINE_NAME};
use crate::rpc::codec::{DecodeError, Decoder, EncodeError, Encoder};
use crate::rpc::gss::{
    Credential as GssCredential, GssInitiatorProvider, GssLimits, InitArgs, InitResult, InitiateContext, IntegrityBody,
    PrivacyBody, Procedure as GssProcedure, ProviderContextId, ProviderError, Service as GssService,
    Version as GssVersion, MAX_SEQUENCE_NUMBER,
};
use crate::server::{CallbackConnector, CallbackError, CallbackTarget};
use crate::vfs::{GssService as PrincipalGssService, GssVersion as PrincipalGssVersion, Principal};

const RPC_CALL: u32 = 0;
const RPC_REPLY: u32 = 1;
const RPC_VERSION: u32 = 2;
const MSG_ACCEPTED: u32 = 0;
const MSG_DENIED: u32 = 1;
const ACCEPT_SUCCESS: u32 = 0;
const ACCEPT_PROGRAM_MISMATCH: u32 = 2;
const REJECT_RPC_MISMATCH: u32 = 0;
const REJECT_AUTH_ERROR: u32 = 1;

static NEXT_XID: AtomicU32 = AtomicU32::new(1);
const MAX_CALLBACK_ATTEMPT: Duration = Duration::from_secs(5);
const MAX_RPC_AUTH_BYTES: usize = 400;
const MAX_GSS_TARGET_NAME_BYTES: usize = 4 * 1024;
const KERBEROS_V5_MECHANISM_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

#[async_trait]
pub trait CallbackClock: Send + Sync + 'static {
    fn now(&self) -> Duration;
    async fn sleep(&self, duration: Duration);
}

#[derive(Debug)]
pub struct SystemCallbackClock {
    origin: Instant,
}

impl Default for SystemCallbackClock {
    fn default() -> Self {
        Self { origin: Instant::now() }
    }
}

#[async_trait]
impl CallbackClock for SystemCallbackClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }

    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthSysCredential {
    pub stamp: u32,
    pub machine_name: Vec<u8>,
    pub uid: u32,
    pub gid: u32,
    pub supplementary_gids: Vec<u32>,
}

#[derive(Clone)]
pub enum CallbackAuth {
    AuthNone,
    AuthSys(AuthSysCredential),
    /// Establishes and owns a real outbound RPCSEC_GSS context.  No encoded
    /// credential or verifier is reusable across callback RPCs.
    RpcSecGss(RpcSecGssCallbackAuth),
}

impl std::fmt::Debug for CallbackAuth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthNone => formatter.write_str("AuthNone"),
            Self::AuthSys(value) => formatter.debug_tuple("AuthSys").field(value).finish(),
            Self::RpcSecGss(value) => formatter.debug_tuple("RpcSecGss").field(value).finish(),
        }
    }
}

#[derive(Clone)]
pub struct RpcSecGssCallbackAuth {
    provider: Arc<dyn GssInitiatorProvider>,
    target_name: String,
    version: GssVersion,
    service: GssService,
}

impl std::fmt::Debug for RpcSecGssCallbackAuth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RpcSecGssCallbackAuth")
            .field("target_name", &self.target_name)
            .field("version", &self.version)
            .field("service", &self.service)
            .finish_non_exhaustive()
    }
}

impl RpcSecGssCallbackAuth {
    pub fn new(
        provider: Arc<dyn GssInitiatorProvider>,
        target_name: impl Into<String>,
        version: GssVersion,
        service: GssService,
    ) -> Result<Self, CallbackClientError> {
        let target_name = target_name.into();
        if target_name.is_empty() || target_name.as_bytes().contains(&0) {
            return Err(CallbackClientError::Gss(CallbackGssError::InvalidTargetName));
        }
        if service == GssService::ChannelProtection {
            return Err(CallbackClientError::Gss(CallbackGssError::ChannelProtectionUnavailable));
        }
        Ok(Self {
            provider,
            target_name,
            version,
            service,
        })
    }
}

impl CallbackAuth {
    fn encode_stateless(&self, max_auth_bytes: usize) -> Result<EncodedAuth, CallbackClientError> {
        match self {
            Self::AuthNone => Ok(EncodedAuth {
                credential_flavor: AUTH_NONE,
                credential: Bytes::new(),
                verifier_flavor: AUTH_NONE,
                verifier: Bytes::new(),
            }),
            Self::AuthSys(value) => {
                if value.machine_name.len() > MAX_MACHINE_NAME {
                    return Err(CallbackClientError::ResourceLimit {
                        field: "AUTH_SYS machine name",
                        actual: value.machine_name.len(),
                        limit: MAX_MACHINE_NAME,
                    });
                }
                if value.supplementary_gids.len() > MAX_GROUPS {
                    return Err(CallbackClientError::ResourceLimit {
                        field: "AUTH_SYS supplementary groups",
                        actual: value.supplementary_gids.len(),
                        limit: MAX_GROUPS,
                    });
                }
                let mut credential = Encoder::new();
                credential.write_u32(value.stamp);
                credential.write_opaque(&value.machine_name)?;
                credential.write_u32(value.uid);
                credential.write_u32(value.gid);
                credential.write_u32(
                    u32::try_from(value.supplementary_gids.len())
                        .map_err(|_| EncodeError::TooLarge(value.supplementary_gids.len()))?,
                );
                for group in &value.supplementary_gids {
                    credential.write_u32(*group);
                }
                let credential = Bytes::from(credential.into_bytes());
                check_auth_limit("AUTH_SYS credential", credential.len(), max_auth_bytes)?;
                Ok(EncodedAuth {
                    credential_flavor: AUTH_SYS,
                    credential,
                    verifier_flavor: AUTH_NONE,
                    verifier: Bytes::new(),
                })
            },
            Self::RpcSecGss(_) => Err(CallbackClientError::Gss(CallbackGssError::SessionRequired)),
        }
    }
}

/// Reconstructs the callback flavor selected by the authenticated
/// SETCLIENTID request. RPCSEC_GSS fails closed when a portable initiator is
/// absent or the request did not use the Kerberos V5 mechanism.
pub fn auth_for_setclientid_principal(
    principal: &Principal,
    gss_initiator: Option<Arc<dyn GssInitiatorProvider>>,
) -> Result<CallbackAuth, CallbackClientError> {
    match principal {
        Principal::Anonymous => Ok(CallbackAuth::AuthNone),
        Principal::AuthSys {
            uid,
            gid,
            supplementary_gids,
            machine_name,
        } => Ok(CallbackAuth::AuthSys(AuthSysCredential {
            // AUTH_SYS stamps are advisory uniqueness values, not identity.
            // The authenticated credential fields are preserved exactly.
            stamp: 0,
            machine_name: machine_name.clone(),
            uid: *uid,
            gid: *gid,
            supplementary_gids: supplementary_gids.clone(),
        })),
        Principal::Gss {
            canonical_name,
            mechanism,
            version,
            service,
        } => {
            if mechanism != KERBEROS_V5_MECHANISM_OID {
                return Err(CallbackClientError::Gss(CallbackGssError::UnsupportedMechanism));
            }
            let provider = gss_initiator.ok_or(CallbackClientError::Gss(CallbackGssError::InitiatorUnavailable))?;
            let version = match version {
                PrincipalGssVersion::V1 => GssVersion::V1,
                PrincipalGssVersion::V2 => GssVersion::V2,
            };
            let service = match service {
                PrincipalGssService::Authentication => GssService::None,
                PrincipalGssService::Integrity => GssService::Integrity,
                PrincipalGssService::Privacy => GssService::Privacy,
                PrincipalGssService::ChannelProtection => GssService::ChannelProtection,
            };
            Ok(CallbackAuth::RpcSecGss(RpcSecGssCallbackAuth::new(
                provider,
                canonical_name.clone(),
                version,
                service,
            )?))
        },
    }
}

struct EncodedAuth {
    credential_flavor: u32,
    credential: Bytes,
    verifier_flavor: u32,
    verifier: Bytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallbackClientConfig {
    pub attempt_timeout: Duration,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub max_rpc_reply_bytes: usize,
    pub max_auth_bytes: usize,
    pub max_gss_init_steps: usize,
    pub gss_limits: GssLimits,
    pub decode_limits: DecodeLimits,
}

impl Default for CallbackClientConfig {
    fn default() -> Self {
        Self {
            attempt_timeout: Duration::from_secs(5),
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(1),
            max_rpc_reply_bytes: 1024 * 1024,
            max_auth_bytes: 400,
            max_gss_init_steps: 8,
            gss_limits: GssLimits::default(),
            decode_limits: DecodeLimits::default(),
        }
    }
}

impl CallbackClientConfig {
    fn validate(self) -> Result<Self, CallbackClientError> {
        if self.attempt_timeout.is_zero()
            || self.attempt_timeout > MAX_CALLBACK_ATTEMPT
            || self.initial_backoff.is_zero()
            || self.max_backoff < self.initial_backoff
            || self.max_rpc_reply_bytes < 24
            || self.max_auth_bytes == 0
            || self.max_auth_bytes > MAX_RPC_AUTH_BYTES
            || self.max_gss_init_steps == 0
            || self.gss_limits.max_handle_bytes == 0
            || self.gss_limits.max_token_bytes == 0
            || self.gss_limits.max_mic_bytes == 0
            || self.gss_limits.max_protected_body_bytes == 0
        {
            return Err(CallbackClientError::InvalidConfiguration);
        }
        Ok(self)
    }
}

#[derive(Clone)]
pub struct CallbackRpcClient {
    connector: Arc<dyn CallbackConnector>,
    target: CallbackTarget,
    program: u32,
    callback_identifier: u32,
    auth: CallbackAuth,
    config: CallbackClientConfig,
    clock: Arc<dyn CallbackClock>,
    xid: Arc<AtomicU32>,
    gss_session: Option<Arc<AsyncMutex<Option<EstablishedGssSession>>>>,
}

#[derive(Clone, Debug)]
struct EstablishedGssSession {
    provider_context: InitiateContext,
    handle: Vec<u8>,
    sequence_window: u32,
    next_sequence: u32,
}

impl std::fmt::Debug for CallbackRpcClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CallbackRpcClient")
            .field("target", &self.target)
            .field("program", &self.program)
            .field("callback_identifier", &self.callback_identifier)
            .field("auth", &self.auth)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl CallbackRpcClient {
    pub fn new(
        connector: Arc<dyn CallbackConnector>,
        target: CallbackTarget,
        program: u32,
        callback_identifier: u32,
        auth: CallbackAuth,
        config: CallbackClientConfig,
        clock: Arc<dyn CallbackClock>,
    ) -> Result<Self, CallbackClientError> {
        if !matches!(target.network_id.as_str(), "tcp" | "tcp6")
            || target.universal_address.is_empty()
            || target.universal_address.as_bytes().contains(&0)
            || program == 0
        {
            return Err(CallbackClientError::InvalidTarget);
        }
        let config = config.validate()?;
        if matches!(auth, CallbackAuth::AuthNone | CallbackAuth::AuthSys(_)) {
            auth.encode_stateless(config.max_auth_bytes)?;
        }
        if let CallbackAuth::RpcSecGss(gss) = &auth {
            if gss.target_name.len() > MAX_GSS_TARGET_NAME_BYTES {
                return Err(CallbackClientError::ResourceLimit {
                    field: "RPCSEC_GSS target name",
                    actual: gss.target_name.len(),
                    limit: MAX_GSS_TARGET_NAME_BYTES,
                });
            }
        }
        let gss_session = matches!(auth, CallbackAuth::RpcSecGss(_)).then(|| Arc::new(AsyncMutex::new(None)));
        Ok(Self {
            connector,
            target,
            program,
            callback_identifier,
            auth,
            config,
            clock,
            xid: Arc::new(AtomicU32::new(next_global_xid())),
            gss_session,
        })
    }

    pub fn with_system_clock(
        connector: Arc<dyn CallbackConnector>,
        target: CallbackTarget,
        program: u32,
        callback_identifier: u32,
        auth: CallbackAuth,
        config: CallbackClientConfig,
    ) -> Result<Self, CallbackClientError> {
        Self::new(
            connector,
            target,
            program,
            callback_identifier,
            auth,
            config,
            Arc::new(SystemCallbackClock::default()),
        )
    }

    pub fn now(&self) -> Duration {
        self.clock.now()
    }

    pub fn deadline_after(&self, duration: Duration) -> Duration {
        self.now().saturating_add(duration)
    }

    pub fn attempt_timeout(&self) -> Duration {
        self.config.attempt_timeout
    }

    /// Sends a protected RPCSEC_GSS DESTROY call and removes the local
    /// mechanism context. Stateless callback authentication has no session.
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn destroy_gss_session(&self) -> Result<(), CallbackClientError> {
        if !matches!(self.auth, CallbackAuth::RpcSecGss(_)) {
            return Ok(());
        }
        let client = self.clone();
        let mut task = tokio::spawn(async move { client.gss_destroy_serialized().await });
        tokio::time::timeout(self.config.attempt_timeout, &mut task)
            .await
            .map_err(|_| CallbackClientError::Transport(CallbackError::Timeout))?
            .map_err(|error| CallbackClientError::Gss(CallbackGssError::Task(error.to_string())))?
    }

    /// Performs one bounded CB_NULL call.
    pub async fn probe_once(&self) -> Result<(), CallbackClientError> {
        let body = self
            .invoke_once(CALLBACK_NULL_PROCEDURE, Bytes::new(), self.config.attempt_timeout, None)
            .await?;
        if !body.is_empty() {
            return Err(CallbackClientError::UnexpectedReply("CB_NULL returned a body"));
        }
        Ok(())
    }

    /// Retries CB_NULL with bounded exponential backoff until `lease_expiry`.
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn probe_until(&self, lease_expiry: Duration) -> Result<(), CallbackClientError> {
        self.request_until(CALLBACK_NULL_PROCEDURE, Bytes::new(), lease_expiry, |body| {
            if body.is_empty() {
                Ok(())
            } else {
                Err(CallbackClientError::UnexpectedReply("CB_NULL returned a body"))
            }
        })
        .await
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn compound_once(
        &self,
        operations: Vec<CallbackArgOp>,
    ) -> Result<CallbackCompoundRes, CallbackClientError> {
        let arguments = self.compound_arguments(operations);
        let body = self
            .invoke_once(
                CALLBACK_COMPOUND_PROCEDURE,
                Bytes::from(arguments.encode()?),
                self.config.attempt_timeout,
                None,
            )
            .await?;
        self.decode_compound_reply(&arguments, &body)
    }

    #[allow(dead_code)]
    pub async fn compound_until(
        &self,
        operations: Vec<CallbackArgOp>,
        lease_expiry: Duration,
    ) -> Result<CallbackCompoundRes, CallbackClientError> {
        let arguments = self.compound_arguments(operations);
        let body = Bytes::from(arguments.encode()?);
        self.request_until(CALLBACK_COMPOUND_PROCEDURE, body, lease_expiry, |body| {
            self.decode_compound_reply(&arguments, body)
        })
        .await
    }

    pub async fn getattr_until(
        &self,
        file_handle: NfsFileHandle,
        requested_attributes: Bitmap,
        lease_expiry: Duration,
    ) -> Result<FileAttributes, CallbackClientError> {
        let arguments = self.compound_arguments(vec![CallbackArgOp::GetAttr(CallbackGetAttrArgs {
            file_handle,
            requested_attributes,
        })]);
        let body = Bytes::from(arguments.encode()?);
        self.request_until(CALLBACK_COMPOUND_PROCEDURE, body, lease_expiry, |body| {
            let response = self.decode_compound_reply(&arguments, body)?;
            match response.operations.as_slice() {
                [CallbackResOp::GetAttr(NfsResult::Ok(attributes))] if response.status == NfsStatus::Ok => {
                    Ok(attributes.clone())
                },
                [CallbackResOp::GetAttr(NfsResult::Err(status))] => Err(CallbackClientError::Nfs(*status)),
                _ => Err(CallbackClientError::UnexpectedReply("CB_GETATTR result shape does not match request")),
            }
        })
        .await
    }

    pub async fn recall_until(
        &self,
        state_id: StateId,
        truncate: bool,
        file_handle: NfsFileHandle,
        lease_expiry: Duration,
    ) -> Result<(), CallbackClientError> {
        let arguments = self.compound_arguments(vec![CallbackArgOp::Recall(CallbackRecallArgs {
            state_id,
            truncate,
            file_handle,
        })]);
        let body = Bytes::from(arguments.encode()?);
        self.request_until(CALLBACK_COMPOUND_PROCEDURE, body, lease_expiry, |body| {
            let response = self.decode_compound_reply(&arguments, body)?;
            match response.operations.as_slice() {
                [CallbackResOp::Recall(NfsStatus::Ok)] if response.status == NfsStatus::Ok => Ok(()),
                [CallbackResOp::Recall(status)] => Err(CallbackClientError::Nfs(*status)),
                _ => Err(CallbackClientError::UnexpectedReply("CB_RECALL result shape does not match request")),
            }
        })
        .await
    }

    fn compound_arguments(&self, operations: Vec<CallbackArgOp>) -> CallbackCompoundArgs {
        CallbackCompoundArgs {
            tag: b"nfsembed-callback".to_vec(),
            minor_version: 0,
            callback_identifier: self.callback_identifier,
            operations,
        }
    }

    async fn request_until<T>(
        &self,
        procedure: u32,
        body: Bytes,
        lease_expiry: Duration,
        parse: impl Fn(&[u8]) -> Result<T, CallbackClientError>,
    ) -> Result<T, CallbackClientError> {
        // Stateless RPC retries retain an XID for duplicate-request-cache
        // semantics.  RPCSEC_GSS retries require a fresh sequence number (and
        // therefore a fresh call and XID), because a verified replay may be
        // discarded without a response.
        let fixed_xid = (!matches!(self.auth, CallbackAuth::RpcSecGss(_))).then(|| self.allocate_xid());
        let mut backoff = self.config.initial_backoff;
        loop {
            let now = self.clock.now();
            if now >= lease_expiry {
                return Err(CallbackClientError::LeaseExpired {
                    last: Box::new(CallbackClientError::DeadlineReached),
                });
            }
            let attempt_timeout = self.config.attempt_timeout.min(lease_expiry.saturating_sub(now));
            let attempt = match self.invoke_once(procedure, body.clone(), attempt_timeout, fixed_xid).await {
                Ok(body) => parse(&body),
                Err(error) => Err(error),
            };
            match attempt {
                Ok(value) => return Ok(value),
                Err(error) => {
                    let now = self.clock.now();
                    if now >= lease_expiry {
                        return Err(CallbackClientError::LeaseExpired { last: Box::new(error) });
                    }
                    let remaining = lease_expiry.saturating_sub(now);
                    let sleep_for = backoff.min(remaining);
                    self.clock.sleep(sleep_for).await;
                    if sleep_for == remaining {
                        return Err(CallbackClientError::LeaseExpired { last: Box::new(error) });
                    }
                    backoff = backoff.saturating_mul(2).min(self.config.max_backoff);
                },
            }
        }
    }

    async fn send_once(&self, call: Bytes) -> Result<Bytes, CallbackClientError> {
        self.send_once_with_timeout(call, self.config.attempt_timeout).await
    }

    async fn send_once_with_timeout(
        &self,
        call: Bytes,
        timeout_duration: Duration,
    ) -> Result<Bytes, CallbackClientError> {
        let attempt = async {
            let transport = self.connector.connect(&self.target).await?;
            transport.call(call, timeout_duration).await
        };
        let reply = tokio::time::timeout(timeout_duration, attempt)
            .await
            .map_err(|_| CallbackClientError::Transport(CallbackError::Timeout))??;
        if reply.len() > self.config.max_rpc_reply_bytes {
            return Err(CallbackClientError::ResourceLimit {
                field: "callback RPC reply",
                actual: reply.len(),
                limit: self.config.max_rpc_reply_bytes,
            });
        }
        Ok(reply)
    }

    async fn invoke_once(
        &self,
        procedure: u32,
        body: Bytes,
        timeout_duration: Duration,
        fixed_xid: Option<u32>,
    ) -> Result<Bytes, CallbackClientError> {
        match &self.auth {
            CallbackAuth::RpcSecGss(_) => {
                let client = self.clone();
                let mut task = tokio::spawn(async move { client.gss_invoke_serialized(procedure, body).await });
                tokio::time::timeout(timeout_duration, &mut task)
                    .await
                    .map_err(|_| CallbackClientError::Transport(CallbackError::Timeout))?
                    .map_err(|error| CallbackClientError::Gss(CallbackGssError::Task(error.to_string())))?
            },
            CallbackAuth::AuthNone | CallbackAuth::AuthSys(_) => {
                let xid = fixed_xid.unwrap_or_else(|| self.allocate_xid());
                let call = self.encode_stateless_rpc_call(xid, procedure, &body)?;
                let reply = self.send_once_with_timeout(call, timeout_duration).await?;
                self.stateless_accepted_body(xid, reply)
            },
        }
    }

    fn encode_stateless_rpc_call(&self, xid: u32, procedure: u32, body: &[u8]) -> Result<Bytes, CallbackClientError> {
        let auth = self.auth.encode_stateless(self.config.max_auth_bytes)?;
        let mut encoder = Encoder::with_capacity(64usize.saturating_add(body.len()));
        encoder.write_u32(xid);
        encoder.write_u32(RPC_CALL);
        encoder.write_u32(RPC_VERSION);
        encoder.write_u32(self.program);
        encoder.write_u32(CALLBACK_VERSION);
        encoder.write_u32(procedure);
        encoder.write_u32(auth.credential_flavor);
        encoder.write_opaque(&auth.credential)?;
        encoder.write_u32(auth.verifier_flavor);
        encoder.write_opaque(&auth.verifier)?;
        encoder.write_fixed(body);
        Ok(Bytes::from(encoder.into_bytes()))
    }

    fn stateless_accepted_body(&self, expected_xid: u32, reply: Bytes) -> Result<Bytes, CallbackClientError> {
        let envelope = self.decode_rpc_reply(expected_xid, reply)?;
        if envelope.verifier_flavor != AUTH_NONE || !envelope.verifier.is_empty() {
            return Err(CallbackClientError::UnexpectedReply("callback RPC verifier flavor is invalid"));
        }
        envelope.success_body()
    }

    fn decode_rpc_reply(&self, expected_xid: u32, reply: Bytes) -> Result<RpcReplyEnvelope, CallbackClientError> {
        let mut decoder = Decoder::new(&reply);
        let xid = decoder.read_u32()?;
        if xid != expected_xid {
            return Err(CallbackClientError::XidMismatch {
                expected: expected_xid,
                actual: xid,
            });
        }
        if decoder.read_u32()? != RPC_REPLY {
            return Err(CallbackClientError::UnexpectedReply("RPC response is not a reply"));
        }
        match decoder.read_u32()? {
            MSG_ACCEPTED => {
                let verifier_flavor = decoder.read_u32()?;
                let verifier = decoder.read_opaque("callback RPC verifier", self.config.max_auth_bytes)?;
                let accept_status = decoder.read_u32()?;
                let version = if accept_status == ACCEPT_PROGRAM_MISMATCH {
                    Some((decoder.read_u32()?, decoder.read_u32()?))
                } else {
                    None
                };
                if accept_status != ACCEPT_SUCCESS {
                    decoder.finish()?;
                    return Ok(RpcReplyEnvelope {
                        verifier_flavor,
                        verifier,
                        accept_status,
                        version,
                        body: Bytes::new(),
                    });
                }
                let body_offset = decoder.position();
                Ok(RpcReplyEnvelope {
                    verifier_flavor,
                    verifier,
                    accept_status,
                    version,
                    body: reply.slice(body_offset..),
                })
            },
            MSG_DENIED => {
                let reject_status = decoder.read_u32()?;
                let detail = match reject_status {
                    REJECT_RPC_MISMATCH => {
                        let low = decoder.read_u32()?;
                        let high = decoder.read_u32()?;
                        format!("RPC version mismatch ({low}..={high})")
                    },
                    REJECT_AUTH_ERROR => format!("RPC authentication error {}", decoder.read_u32()?),
                    value => format!("unknown RPC rejection {value}"),
                };
                decoder.finish()?;
                Err(CallbackClientError::RpcDenied(detail))
            },
            _ => Err(CallbackClientError::UnexpectedReply("unknown RPC reply status")),
        }
    }

    async fn gss_invoke_serialized(&self, procedure: u32, body: Bytes) -> Result<Bytes, CallbackClientError> {
        let CallbackAuth::RpcSecGss(auth) = &self.auth else {
            return Err(CallbackClientError::Gss(CallbackGssError::SessionRequired));
        };
        let state = self
            .gss_session
            .as_ref()
            .ok_or(CallbackClientError::Gss(CallbackGssError::SessionRequired))?;
        let mut state = state.lock().await;
        if state
            .as_ref()
            .is_some_and(|session| Instant::now() >= session.provider_context.expires_at)
        {
            if let Some(expired) = state.take() {
                let _ = auth
                    .provider
                    .delete_security_context(expired.provider_context.provider_context)
                    .await;
            }
        }
        if state.is_none() {
            *state = Some(self.establish_gss_session(auth).await?);
        }
        let result = self
            .gss_data_call(
                auth,
                state.as_mut().expect("GSS callback session was established"),
                GssProcedure::Data,
                procedure,
                body,
            )
            .await;
        if matches!(
            result,
            Err(CallbackClientError::Gss(CallbackGssError::Provider(
                ProviderError::Expired | ProviderError::UnknownContext
            )))
        ) {
            *state = None;
        }
        result
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn gss_destroy_serialized(&self) -> Result<(), CallbackClientError> {
        let CallbackAuth::RpcSecGss(auth) = &self.auth else {
            return Ok(());
        };
        let state = self
            .gss_session
            .as_ref()
            .ok_or(CallbackClientError::Gss(CallbackGssError::SessionRequired))?;
        let mut state = state.lock().await;
        let Some(session) = state.as_mut() else {
            return Ok(());
        };
        if Instant::now() >= session.provider_context.expires_at {
            let expired = state.take().expect("expired GSS callback session exists");
            let _ = auth
                .provider
                .delete_security_context(expired.provider_context.provider_context)
                .await;
            return Ok(());
        }
        self.gss_data_call(auth, session, GssProcedure::Destroy, CALLBACK_NULL_PROCEDURE, Bytes::new())
            .await?;
        let destroyed = state.take().expect("destroyed GSS callback session exists");
        match auth
            .provider
            .delete_security_context(destroyed.provider_context.provider_context)
            .await
        {
            Ok(()) | Err(ProviderError::UnknownContext | ProviderError::Expired) => Ok(()),
            Err(error) => Err(CallbackClientError::Gss(CallbackGssError::Provider(error))),
        }
    }

    async fn establish_gss_session(
        &self,
        auth: &RpcSecGssCallbackAuth,
    ) -> Result<EstablishedGssSession, CallbackClientError> {
        let mut provider_context = None;
        let result = self.establish_gss_session_inner(auth, &mut provider_context).await;
        if result.is_err() {
            if let Some(provider_context) = provider_context {
                let _ = auth.provider.delete_security_context(provider_context).await;
            }
        }
        result
    }

    async fn establish_gss_session_inner(
        &self,
        auth: &RpcSecGssCallbackAuth,
        provider_context: &mut Option<ProviderContextId>,
    ) -> Result<EstablishedGssSession, CallbackClientError> {
        let mut continuation = None;
        let mut input_token = Bytes::new();
        let mut handle: Option<Vec<u8>> = None;
        let mut pending_final: Option<PendingGssInitFinal> = None;

        for step in 0..self.config.max_gss_init_steps {
            let outcome = auth
                .provider
                .initiate_security_context(continuation.take(), auth.version, &auth.target_name, input_token)
                .await
                .map_err(CallbackGssError::Provider)?;
            *provider_context = Some(outcome.context.provider_context);
            check_gss_limit(
                "RPCSEC_GSS initiator token",
                outcome.output_token.len(),
                self.config.gss_limits.max_token_bytes,
            )?;

            if let Some(final_reply) = pending_final.take() {
                if !outcome.complete || !outcome.output_token.is_empty() {
                    let _ = auth.provider.delete_security_context(outcome.context.provider_context).await;
                    return Err(CallbackClientError::Gss(CallbackGssError::InvalidEstablishmentReply));
                }
                self.verify_init_reply(auth, &outcome.context, &final_reply).await?;
                return Ok(EstablishedGssSession {
                    provider_context: outcome.context,
                    handle: final_reply.handle,
                    sequence_window: final_reply.sequence_window,
                    next_sequence: 1,
                });
            }

            if outcome.output_token.is_empty() {
                let _ = auth.provider.delete_security_context(outcome.context.provider_context).await;
                return Err(CallbackClientError::Gss(CallbackGssError::InvalidEstablishmentReply));
            }

            let gss_procedure = if step == 0 {
                GssProcedure::Init
            } else {
                GssProcedure::ContinueInit
            };
            let credential = GssCredential {
                version: auth.version,
                procedure: gss_procedure,
                sequence: 0,
                service: GssService::None,
                handle: handle.clone().unwrap_or_default(),
            };
            let init_body = InitArgs {
                token: outcome.output_token.to_vec(),
            }
            .encode()?;
            let xid = self.allocate_xid();
            let call =
                self.encode_gss_rpc_call(xid, CALLBACK_NULL_PROCEDURE, &credential, AUTH_NONE, &[], &init_body)?;
            let reply = self.send_once(call).await?;
            let envelope = self.decode_rpc_reply(xid, reply)?;
            let reply_body = envelope.success_body()?;
            let result = InitResult::decode(&reply_body, self.config.gss_limits)?;
            if result.handle.is_empty() || result.sequence_window == 0 {
                return Err(CallbackClientError::Gss(CallbackGssError::InvalidEstablishmentReply));
            }
            check_gss_limit("RPCSEC_GSS context handle", result.handle.len(), self.config.gss_limits.max_handle_bytes)?;
            if let Some(existing) = &handle {
                if *existing != result.handle {
                    return Err(CallbackClientError::Gss(CallbackGssError::InvalidEstablishmentReply));
                }
            } else {
                handle = Some(result.handle.clone());
            }
            let server_complete = match result.major_status {
                0 => true,
                1 => false,
                major => {
                    return Err(CallbackClientError::Gss(CallbackGssError::MechanismStatus {
                        major,
                        minor: result.minor_status,
                    }));
                },
            };
            if server_complete {
                let final_reply = PendingGssInitFinal {
                    handle: result.handle,
                    sequence_window: result.sequence_window,
                    verifier_flavor: envelope.verifier_flavor,
                    verifier: envelope.verifier,
                };
                if outcome.complete {
                    if !result.token.is_empty() {
                        return Err(CallbackClientError::Gss(CallbackGssError::InvalidEstablishmentReply));
                    }
                    self.verify_init_reply(auth, &outcome.context, &final_reply).await?;
                    return Ok(EstablishedGssSession {
                        provider_context: outcome.context,
                        handle: final_reply.handle,
                        sequence_window: final_reply.sequence_window,
                        next_sequence: 1,
                    });
                }
                if result.token.is_empty() {
                    return Err(CallbackClientError::Gss(CallbackGssError::InvalidEstablishmentReply));
                }
                pending_final = Some(final_reply);
            } else if outcome.complete
                || result.token.is_empty()
                || envelope.verifier_flavor != AUTH_NONE
                || !envelope.verifier.is_empty()
            {
                return Err(CallbackClientError::Gss(CallbackGssError::InvalidEstablishmentReply));
            }
            continuation = Some(outcome.context);
            input_token = Bytes::from(result.token);
        }
        Err(CallbackClientError::Gss(CallbackGssError::EstablishmentStepLimit))
    }

    async fn verify_init_reply(
        &self,
        auth: &RpcSecGssCallbackAuth,
        context: &InitiateContext,
        reply: &PendingGssInitFinal,
    ) -> Result<(), CallbackClientError> {
        if reply.verifier_flavor != RPCSEC_GSS {
            return Err(CallbackClientError::Gss(CallbackGssError::InvalidEstablishmentReply));
        }
        check_gss_limit("RPCSEC_GSS init reply MIC", reply.verifier.len(), self.config.gss_limits.max_mic_bytes)?;
        auth.provider
            .verify_mic(
                context.provider_context,
                Bytes::copy_from_slice(&reply.sequence_window.to_be_bytes()),
                Bytes::copy_from_slice(&reply.verifier),
            )
            .await
            .map_err(CallbackGssError::Provider)?;
        Ok(())
    }

    async fn gss_data_call(
        &self,
        auth: &RpcSecGssCallbackAuth,
        session: &mut EstablishedGssSession,
        gss_procedure: GssProcedure,
        procedure: u32,
        body: Bytes,
    ) -> Result<Bytes, CallbackClientError> {
        if session.sequence_window == 0 || session.next_sequence >= MAX_SEQUENCE_NUMBER {
            return Err(CallbackClientError::Gss(CallbackGssError::SequenceExhausted));
        }
        let sequence = session.next_sequence;
        session.next_sequence += 1;
        let credential = GssCredential {
            version: auth.version,
            procedure: gss_procedure,
            sequence,
            service: auth.service,
            handle: session.handle.clone(),
        };
        let xid = self.allocate_xid();
        let encoded_credential = credential.encode()?;
        check_auth_limit("RPCSEC_GSS credential", encoded_credential.len(), self.config.max_auth_bytes)?;
        let header = self.encode_rpc_header_through_credential(xid, procedure, RPCSEC_GSS, &encoded_credential)?;
        let request_mic = auth
            .provider
            .get_mic(session.provider_context.provider_context, Bytes::copy_from_slice(&header))
            .await
            .map_err(CallbackGssError::Provider)?;
        check_auth_limit("RPCSEC_GSS request MIC", request_mic.len(), self.config.max_auth_bytes)?;
        let protected = self.protect_gss_body(auth, session, sequence, body).await?;
        let call = finish_rpc_call(header, RPCSEC_GSS, &request_mic, &protected)?;
        let reply = self.send_once(call).await?;
        let envelope = self.decode_rpc_reply(xid, reply)?;
        if envelope.verifier_flavor != RPCSEC_GSS {
            return Err(CallbackClientError::Gss(CallbackGssError::InvalidReplyVerifier));
        }
        check_gss_limit("RPCSEC_GSS reply MIC", envelope.verifier.len(), self.config.gss_limits.max_mic_bytes)?;
        auth.provider
            .verify_mic(
                session.provider_context.provider_context,
                Bytes::copy_from_slice(&sequence.to_be_bytes()),
                Bytes::copy_from_slice(&envelope.verifier),
            )
            .await
            .map_err(CallbackGssError::Provider)?;
        let reply_body = envelope.success_body()?;
        self.unprotect_gss_body(auth, session, sequence, reply_body).await
    }

    async fn protect_gss_body(
        &self,
        auth: &RpcSecGssCallbackAuth,
        session: &EstablishedGssSession,
        sequence: u32,
        body: Bytes,
    ) -> Result<Bytes, CallbackClientError> {
        let body_limit = if auth.service == GssService::None {
            self.config.gss_limits.max_protected_body_bytes
        } else {
            self.config.gss_limits.max_protected_body_bytes.saturating_sub(4)
        };
        check_gss_limit("RPCSEC_GSS call body", body.len(), body_limit)?;
        let protected = protected_body(sequence, &body);
        match auth.service {
            GssService::None => Ok(body),
            GssService::Integrity => {
                check_gss_limit(
                    "RPCSEC_GSS protected call body",
                    protected.len(),
                    self.config.gss_limits.max_protected_body_bytes,
                )?;
                let checksum = auth
                    .provider
                    .get_mic(session.provider_context.provider_context, Bytes::copy_from_slice(&protected))
                    .await
                    .map_err(CallbackGssError::Provider)?;
                check_gss_limit("RPCSEC_GSS integrity MIC", checksum.len(), self.config.gss_limits.max_mic_bytes)?;
                Ok(Bytes::from(
                    IntegrityBody {
                        protected,
                        checksum: checksum.to_vec(),
                    }
                    .encode()?,
                ))
            },
            GssService::Privacy => {
                let wrapped = auth
                    .provider
                    .wrap(session.provider_context.provider_context, Bytes::from(protected), true)
                    .await
                    .map_err(CallbackGssError::Provider)?;
                check_gss_limit(
                    "RPCSEC_GSS privacy token",
                    wrapped.len(),
                    self.config.gss_limits.max_protected_body_bytes,
                )?;
                Ok(Bytes::from(
                    PrivacyBody {
                        wrapped: wrapped.to_vec(),
                    }
                    .encode()?,
                ))
            },
            GssService::ChannelProtection => {
                Err(CallbackClientError::Gss(CallbackGssError::ChannelProtectionUnavailable))
            },
        }
    }

    async fn unprotect_gss_body(
        &self,
        auth: &RpcSecGssCallbackAuth,
        session: &EstablishedGssSession,
        sequence: u32,
        body: Bytes,
    ) -> Result<Bytes, CallbackClientError> {
        match auth.service {
            GssService::None => Ok(body),
            GssService::Integrity => {
                let body = IntegrityBody::decode(&body, self.config.gss_limits)?;
                if body.embedded_sequence()? != sequence {
                    return Err(CallbackClientError::Gss(CallbackGssError::ReplySequenceMismatch));
                }
                let procedure_body = Bytes::copy_from_slice(body.procedure_body()?);
                auth.provider
                    .verify_mic(
                        session.provider_context.provider_context,
                        Bytes::copy_from_slice(&body.protected),
                        Bytes::from(body.checksum),
                    )
                    .await
                    .map_err(CallbackGssError::Provider)?;
                Ok(procedure_body)
            },
            GssService::Privacy => {
                let body = PrivacyBody::decode(&body, self.config.gss_limits)?;
                let clear = auth
                    .provider
                    .unwrap(session.provider_context.provider_context, Bytes::from(body.wrapped))
                    .await
                    .map_err(CallbackGssError::Provider)?;
                split_protected_body(clear, sequence)
            },
            GssService::ChannelProtection => {
                Err(CallbackClientError::Gss(CallbackGssError::ChannelProtectionUnavailable))
            },
        }
    }

    fn encode_gss_rpc_call(
        &self,
        xid: u32,
        procedure: u32,
        credential: &GssCredential,
        verifier_flavor: u32,
        verifier: &[u8],
        body: &[u8],
    ) -> Result<Bytes, CallbackClientError> {
        let credential = credential.encode()?;
        check_auth_limit("RPCSEC_GSS credential", credential.len(), self.config.max_auth_bytes)?;
        let header = self.encode_rpc_header_through_credential(xid, procedure, RPCSEC_GSS, &credential)?;
        finish_rpc_call(header, verifier_flavor, verifier, body)
    }

    fn encode_rpc_header_through_credential(
        &self,
        xid: u32,
        procedure: u32,
        credential_flavor: u32,
        credential: &[u8],
    ) -> Result<Vec<u8>, CallbackClientError> {
        let mut encoder = Encoder::with_capacity(48usize.saturating_add(credential.len()));
        encoder.write_u32(xid);
        encoder.write_u32(RPC_CALL);
        encoder.write_u32(RPC_VERSION);
        encoder.write_u32(self.program);
        encoder.write_u32(CALLBACK_VERSION);
        encoder.write_u32(procedure);
        encoder.write_u32(credential_flavor);
        encoder.write_opaque(credential)?;
        Ok(encoder.into_bytes())
    }

    fn decode_compound_reply(
        &self,
        arguments: &CallbackCompoundArgs,
        body: &[u8],
    ) -> Result<CallbackCompoundRes, CallbackClientError> {
        let response = CallbackCompoundRes::decode(body, self.config.decode_limits)?;
        if response.tag != arguments.tag
            || response.operations.len() > arguments.operations.len()
            || (!arguments.operations.is_empty() && response.operations.is_empty())
            || (response.status == NfsStatus::Ok && response.operations.len() != arguments.operations.len())
        {
            return Err(CallbackClientError::UnexpectedReply(
                "callback COMPOUND tag or operation count does not match request",
            ));
        }
        for (request, result) in arguments.operations.iter().zip(&response.operations) {
            if request.opcode() != result.opnum().code() {
                return Err(CallbackClientError::UnexpectedReply(
                    "callback COMPOUND result opcode does not match request",
                ));
            }
        }
        let expected_status = response.operations.last().map_or(NfsStatus::Ok, CallbackResOp::status);
        if response.status != expected_status {
            return Err(CallbackClientError::UnexpectedReply("callback COMPOUND top-level status is inconsistent"));
        }
        Ok(response)
    }

    fn allocate_xid(&self) -> u32 {
        let xid = self.xid.fetch_add(1, Ordering::Relaxed);
        if xid == 0 {
            self.xid.fetch_add(1, Ordering::Relaxed)
        } else {
            xid
        }
    }
}

fn next_global_xid() -> u32 {
    let xid = NEXT_XID.fetch_add(1024, Ordering::Relaxed);
    if xid == 0 {
        NEXT_XID.fetch_add(1024, Ordering::Relaxed)
    } else {
        xid
    }
}

fn check_auth_limit(field: &'static str, actual: usize, limit: usize) -> Result<(), CallbackClientError> {
    if actual > limit {
        Err(CallbackClientError::ResourceLimit { field, actual, limit })
    } else {
        Ok(())
    }
}

fn check_gss_limit(field: &'static str, actual: usize, limit: usize) -> Result<(), CallbackClientError> {
    check_auth_limit(field, actual, limit)
}

fn finish_rpc_call(
    header_through_credential: Vec<u8>,
    verifier_flavor: u32,
    verifier: &[u8],
    body: &[u8],
) -> Result<Bytes, CallbackClientError> {
    let mut encoder = Encoder::with_capacity(
        header_through_credential
            .len()
            .saturating_add(8)
            .saturating_add(verifier.len())
            .saturating_add(body.len()),
    );
    encoder.write_fixed(&header_through_credential);
    encoder.write_u32(verifier_flavor);
    encoder.write_opaque(verifier)?;
    encoder.write_fixed(body);
    Ok(Bytes::from(encoder.into_bytes()))
}

fn protected_body(sequence: u32, body: &[u8]) -> Vec<u8> {
    let mut protected = Vec::with_capacity(4usize.saturating_add(body.len()));
    protected.extend_from_slice(&sequence.to_be_bytes());
    protected.extend_from_slice(body);
    protected
}

fn split_protected_body(body: Bytes, expected_sequence: u32) -> Result<Bytes, CallbackClientError> {
    if body.len() < 4 {
        return Err(CallbackClientError::Gss(CallbackGssError::ReplySequenceMismatch));
    }
    let actual = u32::from_be_bytes(
        body[..4]
            .try_into()
            .map_err(|_| CallbackClientError::Gss(CallbackGssError::ReplySequenceMismatch))?,
    );
    if actual != expected_sequence {
        return Err(CallbackClientError::Gss(CallbackGssError::ReplySequenceMismatch));
    }
    Ok(body.slice(4..))
}

struct RpcReplyEnvelope {
    verifier_flavor: u32,
    verifier: Vec<u8>,
    accept_status: u32,
    version: Option<(u32, u32)>,
    body: Bytes,
}

impl RpcReplyEnvelope {
    fn success_body(&self) -> Result<Bytes, CallbackClientError> {
        if self.accept_status == ACCEPT_SUCCESS {
            Ok(self.body.clone())
        } else {
            Err(CallbackClientError::RpcAcceptedError {
                status: self.accept_status,
                version: self.version,
            })
        }
    }
}

struct PendingGssInitFinal {
    handle: Vec<u8>,
    sequence_window: u32,
    verifier_flavor: u32,
    verifier: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CallbackGssError {
    #[error("RPCSEC_GSS callback authentication requires a session")]
    SessionRequired,
    #[error("RPCSEC_GSS callback target name is invalid")]
    InvalidTargetName,
    #[error("portable RPCSEC_GSS callback initiator credentials are unavailable")]
    InitiatorUnavailable,
    #[error("RPCSEC_GSS callback mechanism is not Kerberos V5")]
    UnsupportedMechanism,
    #[error("RPCSEC_GSS channel protection is unavailable for a plain TCP callback")]
    ChannelProtectionUnavailable,
    #[error("RPCSEC_GSS context establishment returned an invalid reply")]
    InvalidEstablishmentReply,
    #[error("RPCSEC_GSS context establishment exceeded its bounded step count")]
    EstablishmentStepLimit,
    #[error("RPCSEC_GSS context establishment failed: major={major}, minor={minor}")]
    MechanismStatus { major: u32, minor: u32 },
    #[error("RPCSEC_GSS callback sequence number space is exhausted")]
    SequenceExhausted,
    #[error("RPCSEC_GSS callback reply verifier is invalid")]
    InvalidReplyVerifier,
    #[error("RPCSEC_GSS protected callback reply has the wrong sequence number")]
    ReplySequenceMismatch,
    #[error("RPCSEC_GSS callback provider failed: {0}")]
    Provider(ProviderError),
    #[error("RPCSEC_GSS callback task failed: {0}")]
    Task(String),
}

#[derive(Debug, thiserror::Error)]
pub enum CallbackClientError {
    #[error("callback target or program is invalid")]
    InvalidTarget,
    #[error("callback client configuration is invalid")]
    InvalidConfiguration,
    #[error(transparent)]
    Transport(#[from] CallbackError),
    #[error(transparent)]
    Encode(#[from] EncodeError),
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    Gss(#[from] CallbackGssError),
    #[error("callback RPC xid mismatch: expected {expected}, received {actual}")]
    XidMismatch { expected: u32, actual: u32 },
    #[error("callback RPC was accepted with failure status {status}")]
    RpcAcceptedError { status: u32, version: Option<(u32, u32)> },
    #[error("callback RPC was denied: {0}")]
    RpcDenied(String),
    #[error("callback returned NFS status {0:?}")]
    Nfs(NfsStatus),
    #[error("callback lease expired after the last failure: {last}")]
    LeaseExpired { last: Box<CallbackClientError> },
    #[error("callback lease deadline was reached")]
    DeadlineReached,
    #[error("{field} size {actual} exceeds limit {limit}")]
    ResourceLimit {
        field: &'static str,
        actual: usize,
        limit: usize,
    },
    #[error("invalid callback response: {0}")]
    UnexpectedReply(&'static str),
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, VecDeque};
    use std::future;
    use std::sync::atomic::{AtomicU64, AtomicUsize};
    use std::sync::Mutex;

    use super::*;
    use crate::server::{CallbackError, CallbackTransport};

    fn mock_mic(message: &[u8]) -> Bytes {
        let mut value = Vec::with_capacity(4usize.saturating_add(message.len()));
        value.extend_from_slice(b"mic:");
        value.extend_from_slice(message);
        Bytes::from(value)
    }

    struct MockGssInitiator {
        contexts: Mutex<HashMap<ProviderContextId, Instant>>,
        next_context: AtomicU64,
        starts: AtomicUsize,
        lifetime: Duration,
    }

    impl MockGssInitiator {
        fn new(lifetime: Duration) -> Self {
            Self {
                contexts: Mutex::new(HashMap::new()),
                next_context: AtomicU64::new(1),
                starts: AtomicUsize::new(0),
                lifetime,
            }
        }

        fn check_context(&self, context: ProviderContextId) -> Result<(), ProviderError> {
            let contexts = self.contexts.lock().unwrap();
            let expiry = contexts.get(&context).ok_or(ProviderError::UnknownContext)?;
            if Instant::now() >= *expiry {
                Err(ProviderError::Expired)
            } else {
                Ok(())
            }
        }
    }

    #[async_trait]
    impl GssInitiatorProvider for MockGssInitiator {
        async fn initiate_security_context(
            &self,
            continuation: Option<InitiateContext>,
            version: GssVersion,
            target_name: &str,
            input_token: Bytes,
        ) -> Result<crate::rpc::gss::InitiateOutcome, ProviderError> {
            assert_eq!(target_name, "nfs/client.example.test@EXAMPLE.TEST");
            match continuation {
                None => {
                    assert!(input_token.is_empty());
                    self.starts.fetch_add(1, Ordering::SeqCst);
                    let context = ProviderContextId(self.next_context.fetch_add(1, Ordering::SeqCst));
                    let expires_at = Instant::now() + self.lifetime;
                    self.contexts.lock().unwrap().insert(context, expires_at);
                    Ok(crate::rpc::gss::InitiateOutcome {
                        context: InitiateContext {
                            provider_context: context,
                            version,
                            target_name: target_name.to_owned(),
                            expires_at,
                        },
                        output_token: Bytes::from_static(b"client-init"),
                        complete: false,
                    })
                },
                Some(context) => {
                    self.check_context(context.provider_context)?;
                    if context.version != version || context.target_name != target_name {
                        return Err(ProviderError::InvalidToken);
                    }
                    match input_token.as_ref() {
                        b"server-continue" => Ok(crate::rpc::gss::InitiateOutcome {
                            context,
                            output_token: Bytes::from_static(b"client-continue"),
                            complete: false,
                        }),
                        b"server-final" => Ok(crate::rpc::gss::InitiateOutcome {
                            context,
                            output_token: Bytes::new(),
                            complete: true,
                        }),
                        _ => Err(ProviderError::InvalidToken),
                    }
                },
            }
        }

        async fn verify_mic(
            &self,
            context: ProviderContextId,
            message: Bytes,
            mic: Bytes,
        ) -> Result<(), ProviderError> {
            self.check_context(context)?;
            if mock_mic(&message) == mic {
                Ok(())
            } else {
                Err(ProviderError::Integrity)
            }
        }

        async fn get_mic(&self, context: ProviderContextId, message: Bytes) -> Result<Bytes, ProviderError> {
            self.check_context(context)?;
            Ok(mock_mic(&message))
        }

        async fn unwrap(&self, context: ProviderContextId, token: Bytes) -> Result<Bytes, ProviderError> {
            self.check_context(context)?;
            token
                .strip_prefix(b"sealed:")
                .map(Bytes::copy_from_slice)
                .ok_or(ProviderError::Privacy)
        }

        async fn wrap(
            &self,
            context: ProviderContextId,
            message: Bytes,
            confidentiality: bool,
        ) -> Result<Bytes, ProviderError> {
            self.check_context(context)?;
            assert!(confidentiality);
            let mut sealed = Vec::with_capacity(7usize.saturating_add(message.len()));
            sealed.extend_from_slice(b"sealed:");
            sealed.extend_from_slice(&message);
            Ok(Bytes::from(sealed))
        }

        async fn delete_security_context(&self, context: ProviderContextId) -> Result<(), ProviderError> {
            self.contexts
                .lock()
                .unwrap()
                .remove(&context)
                .map(|_| ())
                .ok_or(ProviderError::UnknownContext)
        }
    }

    #[derive(Default)]
    struct ManualClock {
        nanoseconds: AtomicU64,
        sleeps: Mutex<Vec<Duration>>,
    }

    impl ManualClock {
        fn advance(&self, duration: Duration) {
            self.nanoseconds
                .fetch_add(duration.as_nanos().min(u128::from(u64::MAX)) as u64, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl CallbackClock for ManualClock {
        fn now(&self) -> Duration {
            Duration::from_nanos(self.nanoseconds.load(Ordering::SeqCst))
        }

        async fn sleep(&self, duration: Duration) {
            self.sleeps.lock().unwrap().push(duration);
            self.advance(duration);
            tokio::task::yield_now().await;
        }
    }

    type Handler = Box<dyn FnMut(Bytes, Duration) -> Result<Bytes, CallbackError> + Send>;

    struct MockTransport {
        handler: Mutex<Handler>,
    }

    #[async_trait]
    impl CallbackTransport for MockTransport {
        async fn call(&self, call: Bytes, timeout: Duration) -> Result<Bytes, CallbackError> {
            (self.handler.lock().unwrap())(call, timeout)
        }
    }

    struct HangingTransport;

    #[async_trait]
    impl CallbackTransport for HangingTransport {
        async fn call(&self, _call: Bytes, _timeout: Duration) -> Result<Bytes, CallbackError> {
            future::pending().await
        }
    }

    struct MockConnector {
        transport: Arc<dyn CallbackTransport>,
        connects: AtomicUsize,
    }

    #[async_trait]
    impl CallbackConnector for MockConnector {
        async fn connect(&self, _target: &CallbackTarget) -> Result<Arc<dyn CallbackTransport>, CallbackError> {
            self.connects.fetch_add(1, Ordering::SeqCst);
            Ok(self.transport.clone())
        }
    }

    fn target() -> CallbackTarget {
        CallbackTarget {
            network_id: "tcp".into(),
            universal_address: "127.0.0.1.8.1".into(),
        }
    }

    fn accepted_reply(xid: u32, body: &[u8]) -> Bytes {
        accepted_reply_with_verifier(xid, AUTH_NONE, &[], body)
    }

    fn accepted_reply_with_verifier(xid: u32, verifier_flavor: u32, verifier: &[u8], body: &[u8]) -> Bytes {
        let mut reply = Encoder::new();
        reply.write_u32(xid);
        reply.write_u32(RPC_REPLY);
        reply.write_u32(MSG_ACCEPTED);
        reply.write_u32(verifier_flavor);
        reply.write_opaque(verifier).unwrap();
        reply.write_u32(ACCEPT_SUCCESS);
        reply.write_fixed(body);
        Bytes::from(reply.into_bytes())
    }

    fn decode_call(call: &[u8]) -> (u32, u32, u32, Vec<u8>, u32, Vec<u8>, Vec<u8>) {
        let mut decoder = Decoder::new(call);
        let xid = decoder.read_u32().unwrap();
        assert_eq!(decoder.read_u32().unwrap(), RPC_CALL);
        assert_eq!(decoder.read_u32().unwrap(), RPC_VERSION);
        assert_eq!(decoder.read_u32().unwrap(), 0x4000_0100);
        assert_eq!(decoder.read_u32().unwrap(), CALLBACK_VERSION);
        let procedure = decoder.read_u32().unwrap();
        let credential_flavor = decoder.read_u32().unwrap();
        let credential = decoder.read_opaque("credential", 400).unwrap();
        let verifier_flavor = decoder.read_u32().unwrap();
        let verifier = decoder.read_opaque("verifier", 400).unwrap();
        let body = call[decoder.position()..].to_vec();
        (xid, procedure, credential_flavor, credential, verifier_flavor, verifier, body)
    }

    struct DecodedGssCall {
        xid: u32,
        procedure: u32,
        header_through_credential: Vec<u8>,
        credential: GssCredential,
        verifier_flavor: u32,
        verifier: Vec<u8>,
        body: Vec<u8>,
    }

    fn decode_gss_call(call: &[u8]) -> DecodedGssCall {
        let mut decoder = Decoder::new(call);
        let xid = decoder.read_u32().unwrap();
        assert_eq!(decoder.read_u32().unwrap(), RPC_CALL);
        assert_eq!(decoder.read_u32().unwrap(), RPC_VERSION);
        assert_eq!(decoder.read_u32().unwrap(), 0x4000_0100);
        assert_eq!(decoder.read_u32().unwrap(), CALLBACK_VERSION);
        let procedure = decoder.read_u32().unwrap();
        assert_eq!(decoder.read_u32().unwrap(), RPCSEC_GSS);
        let credential = decoder.read_opaque("credential", 400).unwrap();
        let header_through_credential = call[..decoder.position()].to_vec();
        let verifier_flavor = decoder.read_u32().unwrap();
        let verifier = decoder.read_opaque("verifier", 400).unwrap();
        let body = call[decoder.position()..].to_vec();
        DecodedGssCall {
            xid,
            procedure,
            header_through_credential,
            credential: GssCredential::decode(&credential, GssLimits::default()).unwrap(),
            verifier_flavor,
            verifier,
            body,
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MockGssReplyMode {
        Normal,
        ContinueInit,
        TamperDataVerifier,
        ReplayFirstDataReply,
    }

    fn gss_server_transport(
        version: GssVersion,
        service: GssService,
        mode: MockGssReplyMode,
        sequences: Arc<Mutex<Vec<u32>>>,
    ) -> Arc<dyn CallbackTransport> {
        let mut established = false;
        let mut first_data_reply: Option<Bytes> = None;
        Arc::new(MockTransport {
            handler: Mutex::new(Box::new(move |call, _| {
                let call = decode_gss_call(&call);
                assert_eq!(call.procedure, CALLBACK_NULL_PROCEDURE);
                assert_eq!(call.credential.version, version);
                match call.credential.procedure {
                    GssProcedure::Init => {
                        assert_eq!(call.credential.sequence, 0);
                        assert_eq!(call.credential.service, GssService::None);
                        assert!(call.credential.handle.is_empty());
                        assert_eq!(call.verifier_flavor, AUTH_NONE);
                        assert!(call.verifier.is_empty());
                        let args = InitArgs::decode(&call.body, GssLimits::default()).unwrap();
                        assert_eq!(args.token, b"client-init");
                        let continue_init = mode == MockGssReplyMode::ContinueInit;
                        established = !continue_init;
                        let result = InitResult {
                            handle: vec![0xaa, 0xbb],
                            major_status: u32::from(continue_init),
                            minor_status: 0,
                            sequence_window: 16,
                            token: if continue_init {
                                b"server-continue".to_vec()
                            } else {
                                b"server-final".to_vec()
                            },
                        }
                        .encode()
                        .unwrap();
                        if continue_init {
                            Ok(accepted_reply(call.xid, &result))
                        } else {
                            Ok(accepted_reply_with_verifier(
                                call.xid,
                                RPCSEC_GSS,
                                &mock_mic(&16u32.to_be_bytes()),
                                &result,
                            ))
                        }
                    },
                    GssProcedure::ContinueInit => {
                        assert_eq!(mode, MockGssReplyMode::ContinueInit);
                        assert!(!established);
                        assert_eq!(call.credential.sequence, 0);
                        assert_eq!(call.credential.service, GssService::None);
                        assert_eq!(call.credential.handle, [0xaa, 0xbb]);
                        assert_eq!(call.verifier_flavor, AUTH_NONE);
                        assert!(call.verifier.is_empty());
                        let args = InitArgs::decode(&call.body, GssLimits::default()).unwrap();
                        assert_eq!(args.token, b"client-continue");
                        established = true;
                        let result = InitResult {
                            handle: vec![0xaa, 0xbb],
                            major_status: 0,
                            minor_status: 0,
                            sequence_window: 16,
                            token: b"server-final".to_vec(),
                        }
                        .encode()
                        .unwrap();
                        Ok(accepted_reply_with_verifier(call.xid, RPCSEC_GSS, &mock_mic(&16u32.to_be_bytes()), &result))
                    },
                    GssProcedure::Data | GssProcedure::Destroy => {
                        assert!(established);
                        assert_eq!(call.credential.service, service);
                        assert_eq!(call.credential.handle, [0xaa, 0xbb]);
                        assert_eq!(call.verifier_flavor, RPCSEC_GSS);
                        assert_eq!(call.verifier, mock_mic(&call.header_through_credential));
                        sequences.lock().unwrap().push(call.credential.sequence);

                        let clear = match service {
                            GssService::None => Bytes::from(call.body),
                            GssService::Integrity => {
                                let protected = IntegrityBody::decode(&call.body, GssLimits::default()).unwrap();
                                assert_eq!(protected.embedded_sequence().unwrap(), call.credential.sequence);
                                assert_eq!(protected.checksum, mock_mic(&protected.protected));
                                Bytes::copy_from_slice(protected.procedure_body().unwrap())
                            },
                            GssService::Privacy => {
                                let protected = PrivacyBody::decode(&call.body, GssLimits::default()).unwrap();
                                let clear = protected.wrapped.strip_prefix(b"sealed:").unwrap();
                                assert_eq!(
                                    u32::from_be_bytes(clear[..4].try_into().unwrap()),
                                    call.credential.sequence
                                );
                                Bytes::copy_from_slice(&clear[4..])
                            },
                            GssService::ChannelProtection => unreachable!(),
                        };
                        assert!(clear.is_empty());

                        let reply_clear = Bytes::new();
                        let reply_body = match service {
                            GssService::None => reply_clear,
                            GssService::Integrity => {
                                let protected = protected_body(call.credential.sequence, &reply_clear);
                                Bytes::from(
                                    IntegrityBody {
                                        checksum: mock_mic(&protected).to_vec(),
                                        protected,
                                    }
                                    .encode()
                                    .unwrap(),
                                )
                            },
                            GssService::Privacy => {
                                let protected = protected_body(call.credential.sequence, &reply_clear);
                                let mut wrapped = b"sealed:".to_vec();
                                wrapped.extend_from_slice(&protected);
                                Bytes::from(PrivacyBody { wrapped }.encode().unwrap())
                            },
                            GssService::ChannelProtection => unreachable!(),
                        };
                        let mut verifier = mock_mic(&call.credential.sequence.to_be_bytes()).to_vec();
                        if mode == MockGssReplyMode::TamperDataVerifier {
                            *verifier.last_mut().unwrap() ^= 1;
                        }
                        let reply = accepted_reply_with_verifier(call.xid, RPCSEC_GSS, &verifier, &reply_body);
                        if mode == MockGssReplyMode::ReplayFirstDataReply {
                            if let Some(first) = &first_data_reply {
                                return Ok(first.clone());
                            }
                            first_data_reply = Some(reply.clone());
                        }
                        Ok(reply)
                    },
                    other => panic!("unexpected mock RPCSEC_GSS procedure {other:?}"),
                }
            })),
        })
    }

    fn gss_auth(provider: Arc<dyn GssInitiatorProvider>, version: GssVersion, service: GssService) -> CallbackAuth {
        auth_for_setclientid_principal(
            &Principal::Gss {
                canonical_name: "nfs/client.example.test@EXAMPLE.TEST".to_owned(),
                mechanism: KERBEROS_V5_MECHANISM_OID.to_vec(),
                version: match version {
                    GssVersion::V1 => PrincipalGssVersion::V1,
                    GssVersion::V2 => PrincipalGssVersion::V2,
                },
                service: match service {
                    GssService::None => PrincipalGssService::Authentication,
                    GssService::Integrity => PrincipalGssService::Integrity,
                    GssService::Privacy => PrincipalGssService::Privacy,
                    GssService::ChannelProtection => PrincipalGssService::ChannelProtection,
                },
            },
            Some(provider),
        )
        .unwrap()
    }

    fn client(
        transport: Arc<dyn CallbackTransport>,
        auth: CallbackAuth,
        clock: Arc<dyn CallbackClock>,
        config: CallbackClientConfig,
    ) -> CallbackRpcClient {
        CallbackRpcClient::new(
            Arc::new(MockConnector {
                transport,
                connects: AtomicUsize::new(0),
            }),
            target(),
            0x4000_0100,
            7,
            auth,
            config,
            clock,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn cb_null_encodes_caller_selected_auth_sys_and_checks_reply() {
        let seen_timeout = Arc::new(Mutex::new(None));
        let seen_timeout_clone = seen_timeout.clone();
        let transport = Arc::new(MockTransport {
            handler: Mutex::new(Box::new(move |call, timeout| {
                *seen_timeout_clone.lock().unwrap() = Some(timeout);
                let (xid, procedure, flavor, credential, verifier_flavor, verifier, body) = decode_call(&call);
                assert_eq!(procedure, CALLBACK_NULL_PROCEDURE);
                assert_eq!(flavor, AUTH_SYS);
                assert_eq!(verifier_flavor, AUTH_NONE);
                assert!(verifier.is_empty());
                assert!(body.is_empty());
                let principal = crate::rpc::auth::decode_principal(flavor, &credential).unwrap();
                assert!(matches!(
                    principal,
                    crate::vfs::Principal::AuthSys {
                        uid: 1000,
                        gid: 100,
                        ..
                    }
                ));
                Ok(accepted_reply(xid, &[]))
            })),
        });
        let config = CallbackClientConfig {
            attempt_timeout: Duration::from_millis(50),
            ..CallbackClientConfig::default()
        };
        let callback = client(
            transport,
            CallbackAuth::AuthSys(AuthSysCredential {
                stamp: 9,
                machine_name: b"server".to_vec(),
                uid: 1000,
                gid: 100,
                supplementary_gids: vec![10, 20],
            }),
            Arc::new(ManualClock::default()),
            config,
        );
        callback.probe_once().await.unwrap();
        assert_eq!(*seen_timeout.lock().unwrap(), Some(Duration::from_millis(50)));
    }

    #[tokio::test]
    async fn cb_null_establishes_v2_gss_and_generates_fresh_integrity_credentials() {
        let provider = Arc::new(MockGssInitiator::new(Duration::from_secs(60)));
        let sequences = Arc::new(Mutex::new(Vec::new()));
        let transport =
            gss_server_transport(GssVersion::V2, GssService::Integrity, MockGssReplyMode::Normal, sequences.clone());
        let callback = client(
            transport,
            gss_auth(provider.clone(), GssVersion::V2, GssService::Integrity),
            Arc::new(ManualClock::default()),
            CallbackClientConfig::default(),
        );
        callback.probe_once().await.unwrap();
        callback.probe_once().await.unwrap();
        assert_eq!(provider.starts.load(Ordering::SeqCst), 1);
        assert_eq!(sequences.lock().unwrap().as_slice(), &[1, 2]);
    }

    #[test]
    fn setclientid_gss_mapping_fails_closed_without_matching_initiator_security() {
        let provider: Arc<dyn GssInitiatorProvider> = Arc::new(MockGssInitiator::new(Duration::from_secs(60)));
        let principal = Principal::Gss {
            canonical_name: "nfs/client.example.test@EXAMPLE.TEST".to_owned(),
            mechanism: KERBEROS_V5_MECHANISM_OID.to_vec(),
            version: PrincipalGssVersion::V2,
            service: PrincipalGssService::Integrity,
        };
        assert!(matches!(
            auth_for_setclientid_principal(&principal, None),
            Err(CallbackClientError::Gss(CallbackGssError::InitiatorUnavailable))
        ));
        let unsupported = Principal::Gss {
            canonical_name: "nfs/client.example.test@EXAMPLE.TEST".to_owned(),
            mechanism: vec![1, 2, 3],
            version: PrincipalGssVersion::V2,
            service: PrincipalGssService::Integrity,
        };
        assert!(matches!(
            auth_for_setclientid_principal(&unsupported, Some(provider)),
            Err(CallbackClientError::Gss(CallbackGssError::UnsupportedMechanism))
        ));
    }

    #[tokio::test]
    async fn callback_gss_v1_privacy_wraps_arguments_and_results() {
        let provider = Arc::new(MockGssInitiator::new(Duration::from_secs(60)));
        let sequences = Arc::new(Mutex::new(Vec::new()));
        let transport = gss_server_transport(
            GssVersion::V1,
            GssService::Privacy,
            MockGssReplyMode::ContinueInit,
            sequences.clone(),
        );
        let callback = client(
            transport,
            gss_auth(provider, GssVersion::V1, GssService::Privacy),
            Arc::new(ManualClock::default()),
            CallbackClientConfig::default(),
        );
        callback.probe_once().await.unwrap();
        assert_eq!(sequences.lock().unwrap().as_slice(), &[1]);
    }

    #[tokio::test]
    async fn callback_gss_rejects_a_tampered_reply_mic() {
        let provider = Arc::new(MockGssInitiator::new(Duration::from_secs(60)));
        let sequences = Arc::new(Mutex::new(Vec::new()));
        let transport =
            gss_server_transport(GssVersion::V2, GssService::None, MockGssReplyMode::TamperDataVerifier, sequences);
        let callback = client(
            transport,
            gss_auth(provider, GssVersion::V2, GssService::None),
            Arc::new(ManualClock::default()),
            CallbackClientConfig::default(),
        );
        assert!(matches!(
            callback.probe_once().await,
            Err(CallbackClientError::Gss(CallbackGssError::Provider(ProviderError::Integrity)))
        ));
    }

    #[tokio::test]
    async fn callback_gss_rejects_an_outbound_body_above_the_protection_bound() {
        let provider = Arc::new(MockGssInitiator::new(Duration::from_secs(60)));
        let sequences = Arc::new(Mutex::new(Vec::new()));
        let transport =
            gss_server_transport(GssVersion::V2, GssService::Privacy, MockGssReplyMode::Normal, sequences.clone());
        let mut config = CallbackClientConfig::default();
        config.gss_limits.max_protected_body_bytes = 4;
        let callback = client(
            transport,
            gss_auth(provider, GssVersion::V2, GssService::Privacy),
            Arc::new(ManualClock::default()),
            config,
        );
        assert!(matches!(
            callback.compound_once(Vec::new()).await,
            Err(CallbackClientError::ResourceLimit {
                field: "RPCSEC_GSS call body",
                ..
            })
        ));
        assert!(sequences.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn callback_gss_rejects_a_replayed_data_reply() {
        let provider = Arc::new(MockGssInitiator::new(Duration::from_secs(60)));
        let sequences = Arc::new(Mutex::new(Vec::new()));
        let transport = gss_server_transport(
            GssVersion::V2,
            GssService::Integrity,
            MockGssReplyMode::ReplayFirstDataReply,
            sequences.clone(),
        );
        let callback = client(
            transport,
            gss_auth(provider, GssVersion::V2, GssService::Integrity),
            Arc::new(ManualClock::default()),
            CallbackClientConfig::default(),
        );
        callback.probe_once().await.unwrap();
        assert!(matches!(callback.probe_once().await, Err(CallbackClientError::XidMismatch { .. })));
        assert_eq!(sequences.lock().unwrap().as_slice(), &[1, 2]);
    }

    #[tokio::test]
    async fn callback_gss_reestablishes_after_context_expiry() {
        let provider = Arc::new(MockGssInitiator::new(Duration::from_millis(10)));
        let sequences = Arc::new(Mutex::new(Vec::new()));
        let transport =
            gss_server_transport(GssVersion::V2, GssService::None, MockGssReplyMode::Normal, sequences.clone());
        let callback = client(
            transport,
            gss_auth(provider.clone(), GssVersion::V2, GssService::None),
            Arc::new(ManualClock::default()),
            CallbackClientConfig::default(),
        );
        callback.probe_once().await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        callback.probe_once().await.unwrap();
        assert_eq!(provider.starts.load(Ordering::SeqCst), 2);
        assert_eq!(sequences.lock().unwrap().as_slice(), &[1, 1]);
    }

    #[tokio::test]
    async fn callback_gss_destroy_is_protected_and_forces_a_new_context() {
        let provider = Arc::new(MockGssInitiator::new(Duration::from_secs(60)));
        let sequences = Arc::new(Mutex::new(Vec::new()));
        let transport =
            gss_server_transport(GssVersion::V2, GssService::Integrity, MockGssReplyMode::Normal, sequences.clone());
        let callback = client(
            transport,
            gss_auth(provider.clone(), GssVersion::V2, GssService::Integrity),
            Arc::new(ManualClock::default()),
            CallbackClientConfig::default(),
        );
        callback.probe_once().await.unwrap();
        callback.destroy_gss_session().await.unwrap();
        callback.probe_once().await.unwrap();
        assert_eq!(provider.starts.load(Ordering::SeqCst), 2);
        assert_eq!(sequences.lock().unwrap().as_slice(), &[1, 2, 1]);
    }

    #[tokio::test]
    async fn cb_recall_compound_round_trips_exact_operation() {
        let expected_state = StateId {
            sequence_id: 4,
            other: [5; 12],
        };
        let transport = Arc::new(MockTransport {
            handler: Mutex::new(Box::new(move |call, _| {
                let (xid, procedure, _, _, _, _, body) = decode_call(&call);
                assert_eq!(procedure, CALLBACK_COMPOUND_PROCEDURE);
                let request = CallbackCompoundArgs::decode(&body, DecodeLimits::default()).unwrap();
                assert_eq!(request.callback_identifier, 7);
                assert_eq!(
                    request.operations,
                    vec![CallbackArgOp::Recall(CallbackRecallArgs {
                        state_id: expected_state,
                        truncate: true,
                        file_handle: NfsFileHandle(vec![1, 2, 3]),
                    })]
                );
                let response =
                    CallbackCompoundRes::from_operations(request.tag, vec![CallbackResOp::Recall(NfsStatus::Ok)])
                        .encode()
                        .unwrap();
                Ok(accepted_reply(xid, &response))
            })),
        });
        let clock = Arc::new(ManualClock::default());
        let callback = client(transport, CallbackAuth::AuthNone, clock.clone(), CallbackClientConfig::default());
        callback
            .recall_until(
                expected_state,
                true,
                NfsFileHandle(vec![1, 2, 3]),
                clock.now().saturating_add(Duration::from_secs(30)),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn cb_getattr_decodes_bounded_attribute_result() {
        let transport = Arc::new(MockTransport {
            handler: Mutex::new(Box::new(move |call, _| {
                let (xid, procedure, _, _, _, _, body) = decode_call(&call);
                assert_eq!(procedure, CALLBACK_COMPOUND_PROCEDURE);
                let request = CallbackCompoundArgs::decode(&body, DecodeLimits::default()).unwrap();
                assert!(matches!(
                    request.operations.as_slice(),
                    [CallbackArgOp::GetAttr(CallbackGetAttrArgs {
                        file_handle,
                        requested_attributes
                    })] if file_handle.as_bytes() == [9, 8] && requested_attributes.as_slice() == [0x10]
                ));
                let response = CallbackCompoundRes::from_operations(
                    request.tag,
                    vec![CallbackResOp::GetAttr(NfsResult::Ok(FileAttributes {
                        mask: vec![0x10],
                        values: 99u64.to_be_bytes().to_vec(),
                    }))],
                )
                .encode()
                .unwrap();
                Ok(accepted_reply(xid, &response))
            })),
        });
        let clock = Arc::new(ManualClock::default());
        let callback = client(transport, CallbackAuth::AuthNone, clock.clone(), CallbackClientConfig::default());
        assert_eq!(
            callback
                .getattr_until(
                    NfsFileHandle(vec![9, 8]),
                    vec![0x10],
                    clock.now().saturating_add(Duration::from_secs(1)),
                )
                .await
                .unwrap(),
            FileAttributes {
                mask: vec![0x10],
                values: 99u64.to_be_bytes().to_vec(),
            }
        );
    }

    #[tokio::test]
    async fn retry_backoff_reuses_xid_until_success_before_lease_expiry() {
        let clock = Arc::new(ManualClock::default());
        let outcomes = Arc::new(Mutex::new(VecDeque::from([
            Err(CallbackError::Unavailable("one".into())),
            Err(CallbackError::Unavailable("two".into())),
        ])));
        let outcomes_clone = outcomes.clone();
        let observed_xids = Arc::new(Mutex::new(Vec::new()));
        let observed_xids_clone = observed_xids.clone();
        let transport = Arc::new(MockTransport {
            handler: Mutex::new(Box::new(move |call, _| {
                let (xid, _, _, _, _, _, _) = decode_call(&call);
                observed_xids_clone.lock().unwrap().push(xid);
                outcomes_clone
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or_else(|| Ok(accepted_reply(xid, &[])))
            })),
        });
        let config = CallbackClientConfig {
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(40),
            ..CallbackClientConfig::default()
        };
        let callback = client(transport, CallbackAuth::AuthNone, clock.clone(), config);
        callback.probe_until(Duration::from_millis(100)).await.unwrap();
        assert_eq!(clock.sleeps.lock().unwrap().as_slice(), &[Duration::from_millis(10), Duration::from_millis(20)]);
        let xids = observed_xids.lock().unwrap();
        assert_eq!(xids.len(), 3);
        assert!(xids.iter().all(|xid| *xid == xids[0]));
    }

    #[tokio::test]
    async fn outer_timeout_bounds_a_transport_that_ignores_timeout_argument() {
        let callback = client(
            Arc::new(HangingTransport),
            CallbackAuth::AuthNone,
            Arc::new(ManualClock::default()),
            CallbackClientConfig {
                attempt_timeout: Duration::from_millis(10),
                ..CallbackClientConfig::default()
            },
        );
        assert!(matches!(callback.probe_once().await, Err(CallbackClientError::Transport(CallbackError::Timeout))));
    }

    #[tokio::test]
    async fn oversized_reply_is_rejected_before_xdr_decode() {
        let transport = Arc::new(MockTransport {
            handler: Mutex::new(Box::new(|_, _| Ok(Bytes::from(vec![0; 129])))),
        });
        let callback = client(
            transport,
            CallbackAuth::AuthNone,
            Arc::new(ManualClock::default()),
            CallbackClientConfig {
                max_rpc_reply_bytes: 128,
                ..CallbackClientConfig::default()
            },
        );
        assert!(matches!(
            callback.probe_once().await,
            Err(CallbackClientError::ResourceLimit {
                field: "callback RPC reply",
                actual: 129,
                limit: 128
            })
        ));
    }
}
