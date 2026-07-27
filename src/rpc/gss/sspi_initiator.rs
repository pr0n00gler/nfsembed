//! Portable Kerberos initiator used by NFSv4 callback RPCSEC_GSS sessions.
//!
//! `sspi` 0.21.3 can acquire outbound credentials from a
//! [`sspi::KeytabIdentity`].  This adapter selects the same bounded AES keytab
//! entry as the acceptor and drives the SSPI generator with a Tokio-based KDC
//! client, avoiding host GSS libraries and blocking network calls.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use picky_krb::crypto::aes::AesSize;
use picky_krb::crypto::CipherSuite;
use picky_krb::gss_api::WrapToken;
use rand::rngs::OsRng;
use rand::RngCore;
use sspi::generator::{GeneratorState, NetworkRequest};
use sspi::network_client::NetworkProtocol;
use sspi::{
    BufferType, ClientRequestFlags, CredentialUse, Credentials, DataRepresentation, Error as SspiError, ErrorKind,
    Kerberos, KerberosConfig, KeytabIdentity, SecurityBuffer, SecurityStatus, Sspi, SspiImpl, Username,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream, UdpSocket};
use tokio::sync::Mutex;

use super::sspi::{
    aes_size, generate_integrity_wrap, generate_mic, map_sspi_error, read_keytab_path, seal_message, select_keytab_key,
    unwrap_message, verify_mic, SspiGssProviderConfigError, SspiGssProviderLimits, SspiKeytabSource,
};
use super::{GssInitiatorProvider, InitiateContext, InitiateOutcome, ProviderContextId, ProviderError, Version};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SspiGssInitiatorLimits {
    pub provider: SspiGssProviderLimits,
    pub kdc_attempt_timeout: Duration,
    pub max_kdc_request_bytes: usize,
    pub max_kdc_reply_bytes: usize,
}

impl Default for SspiGssInitiatorLimits {
    fn default() -> Self {
        Self {
            provider: SspiGssProviderLimits::default(),
            kdc_attempt_timeout: Duration::from_secs(5),
            max_kdc_request_bytes: 1024 * 1024,
            max_kdc_reply_bytes: 1024 * 1024,
        }
    }
}

impl SspiGssInitiatorLimits {
    fn validate(self) -> Result<Self, SspiGssInitiatorConfigError> {
        self.provider.validate().map_err(SspiGssInitiatorConfigError::Keytab)?;
        if self.kdc_attempt_timeout.is_zero() || self.kdc_attempt_timeout > Duration::from_secs(5) {
            return Err(SspiGssInitiatorConfigError::InvalidLimits);
        }
        if self.max_kdc_request_bytes < 4
            || self.max_kdc_request_bytes > self.provider.max_output_token_bytes
            || self.max_kdc_reply_bytes < 4
            || self.max_kdc_reply_bytes > self.provider.max_output_token_bytes
        {
            return Err(SspiGssInitiatorConfigError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SspiGssInitiatorConfig {
    pub service_principal: String,
    pub keytab: SspiKeytabSource,
    pub limits: SspiGssInitiatorLimits,
}

impl fmt::Debug for SspiGssInitiatorConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SspiGssInitiatorConfig")
            .field("service_principal", &self.service_principal)
            .field("keytab", &self.keytab)
            .field("limits", &self.limits)
            .finish()
    }
}

impl SspiGssInitiatorConfig {
    pub fn from_keytab_path(service_principal: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            service_principal: service_principal.into(),
            keytab: SspiKeytabSource::Path(path.into()),
            limits: SspiGssInitiatorLimits::default(),
        }
    }

    pub fn from_keytab_bytes(service_principal: impl Into<String>, keytab: impl Into<Bytes>) -> Self {
        Self {
            service_principal: service_principal.into(),
            keytab: SspiKeytabSource::Bytes(keytab.into()),
            limits: SspiGssInitiatorLimits::default(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SspiGssInitiatorConfigError {
    #[error("SSPI GSS initiator limits are invalid")]
    InvalidLimits,
    #[error(transparent)]
    Keytab(#[from] SspiGssProviderConfigError),
    #[error("configured Kerberos service principal cannot be represented as an SSPI username")]
    InvalidUsername,
    #[error("configured keytab encryption type is not supported for outbound Kerberos")]
    UnsupportedEncryptionType,
    #[error("unable to configure portable SSPI Kerberos initiator: {0}")]
    Sspi(String),
}

pub struct SspiGssInitiator {
    service_principal: String,
    credential: Credentials,
    kerberos_config: KerberosConfig,
    limits: SspiGssInitiatorLimits,
    contexts: Mutex<HashMap<ProviderContextId, ContextSlot>>,
}

impl fmt::Debug for SspiGssInitiator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SspiGssInitiator")
            .field("service_principal", &self.service_principal)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct ContextSlot {
    context: Arc<Mutex<InitiatorContext>>,
    expires_at: Instant,
}

struct InitiatorContext {
    kerberos: Kerberos,
    credentials_handle: <Kerberos as SspiImpl>::CredentialsHandle,
    version: Version,
    target_name: String,
    sspi_target_name: String,
    phase: InitiatorPhase,
    steps: usize,
    expires_at: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InitiatorPhase {
    New,
    Pending,
    Established,
}

impl SspiGssInitiator {
    pub async fn new(config: SspiGssInitiatorConfig) -> Result<Self, SspiGssInitiatorConfigError> {
        let limits = config.limits.validate()?;
        let keytab = match config.keytab {
            SspiKeytabSource::Path(path) => read_keytab_path(path, limits.provider.max_keytab_bytes)
                .await
                .map_err(SspiGssInitiatorConfigError::Keytab)?,
            SspiKeytabSource::Bytes(bytes) => {
                if bytes.len() > limits.provider.max_keytab_bytes {
                    return Err(SspiGssInitiatorConfigError::Keytab(SspiGssProviderConfigError::KeytabTooLarge));
                }
                bytes
            },
        };
        Self::from_keytab_bytes_with_limits(config.service_principal, keytab, limits)
    }

    pub fn from_keytab_bytes(
        service_principal: impl Into<String>,
        keytab: impl Into<Bytes>,
    ) -> Result<Self, SspiGssInitiatorConfigError> {
        Self::from_keytab_bytes_with_limits(service_principal.into(), keytab.into(), SspiGssInitiatorLimits::default())
    }

    pub async fn from_keytab_path(
        service_principal: impl Into<String>,
        path: impl Into<PathBuf>,
    ) -> Result<Self, SspiGssInitiatorConfigError> {
        Self::new(SspiGssInitiatorConfig::from_keytab_path(service_principal, path)).await
    }

    pub fn service_principal(&self) -> &str {
        &self.service_principal
    }

    pub fn limits(&self) -> SspiGssInitiatorLimits {
        self.limits
    }

    fn from_keytab_bytes_with_limits(
        service_principal: String,
        keytab: Bytes,
        limits: SspiGssInitiatorLimits,
    ) -> Result<Self, SspiGssInitiatorConfigError> {
        let limits = limits.validate()?;
        if keytab.len() > limits.provider.max_keytab_bytes {
            return Err(SspiGssInitiatorConfigError::Keytab(SspiGssProviderConfigError::KeytabTooLarge));
        }
        let selected = select_keytab_key(&service_principal, &keytab, limits.provider)?;
        let key_enctype = match selected.encryption_type {
            17 => CipherSuite::Aes128CtsHmacSha196,
            18 => CipherSuite::Aes256CtsHmacSha196,
            _ => return Err(SspiGssInitiatorConfigError::UnsupportedEncryptionType),
        };
        let (account_name, realm) = service_principal
            .rsplit_once('@')
            .ok_or(SspiGssInitiatorConfigError::InvalidUsername)?;
        let principal = Username::new_down_level_logon_name(account_name, realm)
            .map_err(|_| SspiGssInitiatorConfigError::InvalidUsername)?;
        let credential = Credentials::Keytab(KeytabIdentity {
            principal,
            key: selected.key,
            key_enctype,
        });
        let client_computer_name = service_principal
            .split_once('@')
            .map(|(name, _)| name)
            .and_then(|name| name.split_once('/').map(|(_, host)| host))
            .filter(|host| !host.is_empty())
            .unwrap_or("nfsembed")
            .to_owned();
        Ok(Self {
            service_principal,
            credential,
            kerberos_config: KerberosConfig {
                kdc_url: None,
                client_computer_name,
            },
            limits,
            contexts: Mutex::new(HashMap::new()),
        })
    }

    fn create_context(
        &self,
        version: Version,
        target_name: &str,
        expires_at: Instant,
    ) -> Result<InitiatorContext, ProviderError> {
        if target_name.is_empty()
            || target_name.len() > self.limits.provider.max_principal_bytes
            || target_name.as_bytes().contains(&0)
        {
            return Err(ProviderError::InvalidToken);
        }
        let sspi_target_name = match target_name.rsplit_once('@') {
            Some((name, realm)) if !name.is_empty() && !realm.is_empty() && !name.contains('@') => name,
            Some(_) => return Err(ProviderError::InvalidToken),
            None => target_name,
        };
        let mut kerberos = Kerberos::new_client_from_config(self.kerberos_config.clone()).map_err(map_sspi_error)?;
        let credential = self.credential.clone();
        let credentials_handle = kerberos
            .acquire_credentials_handle()
            .with_principal_name(&self.service_principal)
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&credential)
            .execute(&mut kerberos)
            .map_err(map_sspi_error)?
            .credentials_handle;
        Ok(InitiatorContext {
            kerberos,
            credentials_handle,
            version,
            target_name: target_name.to_owned(),
            sspi_target_name: sspi_target_name.to_owned(),
            phase: InitiatorPhase::New,
            steps: 0,
            expires_at,
        })
    }

    async fn begin(
        &self,
        version: Version,
        target_name: &str,
        input_token: Bytes,
    ) -> Result<InitiateOutcome, ProviderError> {
        if !input_token.is_empty() {
            return Err(ProviderError::InvalidToken);
        }
        let now = Instant::now();
        let expires_at = now
            .checked_add(self.limits.provider.max_context_lifetime)
            .ok_or(ProviderError::Resource)?;
        let context = Arc::new(Mutex::new(self.create_context(version, target_name, expires_at)?));
        let context_id = {
            let mut contexts = self.contexts.lock().await;
            prune_contexts(&mut contexts, now);
            if contexts.len() >= self.limits.provider.max_contexts {
                return Err(ProviderError::Resource);
            }
            let id = unique_context_id(&contexts)?;
            contexts.insert(
                id,
                ContextSlot {
                    context: Arc::clone(&context),
                    expires_at,
                },
            );
            id
        };
        let result = context.lock().await.initiate(Bytes::new(), self.limits, context_id).await;
        if result.is_err() {
            self.contexts.lock().await.remove(&context_id);
        }
        result
    }

    async fn continue_context(
        &self,
        continuation: InitiateContext,
        version: Version,
        target_name: &str,
        input_token: Bytes,
    ) -> Result<InitiateOutcome, ProviderError> {
        if continuation.version != version || continuation.target_name != target_name || input_token.is_empty() {
            return Err(ProviderError::InvalidToken);
        }
        if input_token.len() > self.limits.provider.max_init_token_bytes {
            return Err(ProviderError::Resource);
        }
        let context = self.context(continuation.provider_context).await?;
        let result = {
            let mut context = context.lock().await;
            if context.version != version || context.target_name != target_name {
                return Err(ProviderError::InvalidToken);
            }
            context.initiate(input_token, self.limits, continuation.provider_context).await
        };
        if result.is_err() {
            self.contexts.lock().await.remove(&continuation.provider_context);
        }
        result
    }

    async fn context(&self, id: ProviderContextId) -> Result<Arc<Mutex<InitiatorContext>>, ProviderError> {
        let now = Instant::now();
        let mut contexts = self.contexts.lock().await;
        if contexts.get(&id).is_some_and(|slot| now >= slot.expires_at) {
            contexts.remove(&id);
            return Err(ProviderError::Expired);
        }
        prune_contexts(&mut contexts, now);
        contexts
            .get(&id)
            .map(|slot| Arc::clone(&slot.context))
            .ok_or(ProviderError::UnknownContext)
    }

    fn validate_message(&self, value: &[u8]) -> Result<(), ProviderError> {
        if value.len() > self.limits.provider.max_message_bytes {
            Err(ProviderError::Resource)
        } else {
            Ok(())
        }
    }

    fn validate_token(&self, value: &[u8]) -> Result<(), ProviderError> {
        if value.len() > self.limits.provider.max_output_token_bytes {
            Err(ProviderError::Resource)
        } else if value.len() < WrapToken::header_len() {
            Err(ProviderError::InvalidToken)
        } else {
            Ok(())
        }
    }
}

impl InitiatorContext {
    async fn initiate(
        &mut self,
        input_token: Bytes,
        limits: SspiGssInitiatorLimits,
        context_id: ProviderContextId,
    ) -> Result<InitiateOutcome, ProviderError> {
        if Instant::now() >= self.expires_at {
            return Err(ProviderError::Expired);
        }
        if self.phase == InitiatorPhase::Established || self.steps >= limits.provider.max_continuation_steps {
            return Err(ProviderError::InvalidToken);
        }
        self.steps += 1;

        let mut input = [SecurityBuffer::new(input_token.to_vec(), BufferType::Token)];
        let mut output = [SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let result = {
            let mut builder = self
                .kerberos
                .initialize_security_context()
                .with_credentials_handle(&mut self.credentials_handle)
                .with_context_requirements(
                    ClientRequestFlags::MUTUAL_AUTH
                        | ClientRequestFlags::REPLAY_DETECT
                        | ClientRequestFlags::SEQUENCE_DETECT
                        | ClientRequestFlags::CONFIDENTIALITY
                        | ClientRequestFlags::INTEGRITY
                        | ClientRequestFlags::ALLOCATE_MEMORY,
                )
                .with_target_data_representation(DataRepresentation::Network)
                .with_target_name(&self.sspi_target_name)
                .with_input(&mut input)
                .with_output(&mut output);
            let mut operation = self
                .kerberos
                .initialize_security_context_impl(&mut builder)
                .map_err(map_sspi_error)?;
            let mut network = BoundedKdcClient {
                timeout: limits.kdc_attempt_timeout,
                max_request_bytes: limits.max_kdc_request_bytes,
                max_reply_bytes: limits.max_kdc_reply_bytes,
            };
            let mut state = operation.start();
            loop {
                match state {
                    GeneratorState::Suspended(request) => {
                        let response = network.send(&request).await;
                        state = operation.resume(response);
                    },
                    GeneratorState::Completed(result) => break result.map_err(map_sspi_error)?,
                }
            }
        };

        let complete = match result.status {
            SecurityStatus::Ok => true,
            SecurityStatus::ContinueNeeded => false,
            SecurityStatus::CompleteNeeded => {
                self.kerberos.complete_auth_token(&mut output).map_err(map_sspi_error)?;
                true
            },
            SecurityStatus::CompleteAndContinue => {
                self.kerberos.complete_auth_token(&mut output).map_err(map_sspi_error)?;
                false
            },
            status => {
                return Err(ProviderError::Mechanism {
                    major: 13 << 16,
                    minor: status as u32,
                });
            },
        };
        let output_token = Bytes::from(std::mem::take(&mut output[0].buffer));
        if output_token.len() > limits.provider.max_output_token_bytes {
            return Err(ProviderError::Resource);
        }
        if complete {
            let session_key = self.kerberos.query_context_session_key().map_err(map_sspi_error)?;
            aes_size(session_key.session_key.as_ref()).map_err(|_| ProviderError::Mechanism {
                major: 13 << 16,
                minor: ErrorKind::UnsupportedFunction as u32,
            })?;
            self.phase = InitiatorPhase::Established;
        } else {
            self.phase = InitiatorPhase::Pending;
        }
        Ok(InitiateOutcome {
            context: InitiateContext {
                provider_context: context_id,
                version: self.version,
                target_name: self.target_name.clone(),
                expires_at: self.expires_at,
            },
            output_token,
            complete,
        })
    }

    fn ensure_established(&self) -> Result<(), ProviderError> {
        if Instant::now() >= self.expires_at {
            return Err(ProviderError::Expired);
        }
        if self.phase != InitiatorPhase::Established {
            return Err(ProviderError::UnknownContext);
        }
        Ok(())
    }

    fn session_key_and_aes_size(&mut self) -> Result<(Vec<u8>, AesSize), ProviderError> {
        let session_key = self.kerberos.query_context_session_key().map_err(map_sspi_error)?;
        let key = session_key.session_key.as_ref().clone();
        let size = aes_size(&key).map_err(|_| ProviderError::Mechanism {
            major: 13 << 16,
            minor: ErrorKind::UnsupportedFunction as u32,
        })?;
        Ok((key, size))
    }

    fn next_outbound_sequence(&mut self, output_limit: usize) -> Result<u64, ProviderError> {
        let sealed = seal_message(&mut self.kerberos, &[], output_limit)?;
        WrapToken::decode(sealed.as_ref())
            .map(|token| token.seq_num)
            .map_err(|_| ProviderError::InvalidToken)
    }

    fn get_mic(&mut self, message: &[u8], output_limit: usize) -> Result<Bytes, ProviderError> {
        self.ensure_established()?;
        let (key, size) = self.session_key_and_aes_size()?;
        let sequence = self.next_outbound_sequence(output_limit)?;
        let token = generate_mic(&key, &size, sequence, message, false)?;
        if token.len() > output_limit {
            return Err(ProviderError::Resource);
        }
        Ok(Bytes::from(token))
    }

    fn verify_mic(&mut self, message: &[u8], mic: &[u8]) -> Result<(), ProviderError> {
        self.ensure_established()?;
        let (key, size) = self.session_key_and_aes_size()?;
        verify_mic(&key, &size, message, mic, true)
    }

    fn wrap(&mut self, message: &[u8], confidentiality: bool, output_limit: usize) -> Result<Bytes, ProviderError> {
        self.ensure_established()?;
        if confidentiality {
            return seal_message(&mut self.kerberos, message, output_limit);
        }
        let (key, size) = self.session_key_and_aes_size()?;
        let sequence = self.next_outbound_sequence(output_limit)?;
        let token = generate_integrity_wrap(&key, &size, sequence, message, false)?;
        if token.len() > output_limit {
            return Err(ProviderError::Resource);
        }
        Ok(Bytes::from(token))
    }

    fn unwrap(&mut self, token: &[u8], message_limit: usize) -> Result<Bytes, ProviderError> {
        self.ensure_established()?;
        unwrap_message(&mut self.kerberos, token, message_limit, true)
    }
}

#[async_trait]
impl GssInitiatorProvider for SspiGssInitiator {
    async fn initiate_security_context(
        &self,
        continuation: Option<InitiateContext>,
        version: Version,
        target_name: &str,
        input_token: Bytes,
    ) -> Result<InitiateOutcome, ProviderError> {
        match continuation {
            Some(continuation) => self.continue_context(continuation, version, target_name, input_token).await,
            None => self.begin(version, target_name, input_token).await,
        }
    }

    async fn verify_mic(&self, context: ProviderContextId, message: Bytes, mic: Bytes) -> Result<(), ProviderError> {
        self.validate_message(&message)?;
        self.validate_token(&mic)?;
        self.context(context).await?.lock().await.verify_mic(&message, &mic)
    }

    async fn get_mic(&self, context: ProviderContextId, message: Bytes) -> Result<Bytes, ProviderError> {
        self.validate_message(&message)?;
        self.context(context)
            .await?
            .lock()
            .await
            .get_mic(&message, self.limits.provider.max_output_token_bytes)
    }

    async fn unwrap(&self, context: ProviderContextId, token: Bytes) -> Result<Bytes, ProviderError> {
        self.validate_token(&token)?;
        self.context(context)
            .await?
            .lock()
            .await
            .unwrap(&token, self.limits.provider.max_message_bytes)
    }

    async fn wrap(
        &self,
        context: ProviderContextId,
        message: Bytes,
        confidentiality: bool,
    ) -> Result<Bytes, ProviderError> {
        self.validate_message(&message)?;
        self.context(context).await?.lock().await.wrap(
            &message,
            confidentiality,
            self.limits.provider.max_output_token_bytes,
        )
    }

    async fn delete_security_context(&self, context: ProviderContextId) -> Result<(), ProviderError> {
        self.contexts
            .lock()
            .await
            .remove(&context)
            .map(|_| ())
            .ok_or(ProviderError::UnknownContext)
    }
}

struct BoundedKdcClient {
    timeout: Duration,
    max_request_bytes: usize,
    max_reply_bytes: usize,
}

impl BoundedKdcClient {
    async fn send(&mut self, request: &NetworkRequest) -> sspi::Result<Vec<u8>> {
        tokio::time::timeout(self.timeout, self.send_bounded(request))
            .await
            .map_err(|_| {
                SspiError::new(ErrorKind::NoAuthenticatingAuthority, "bounded Kerberos KDC request timed out")
            })?
    }

    async fn send_bounded(&self, request: &NetworkRequest) -> sspi::Result<Vec<u8>> {
        if request.data.len() > self.max_request_bytes {
            return Err(SspiError::new(
                ErrorKind::InsufficientMemory,
                "Kerberos KDC request exceeds the configured bound",
            ));
        }
        match request.protocol {
            NetworkProtocol::Tcp => self.send_tcp(request).await,
            NetworkProtocol::Udp => self.send_udp(request).await,
            NetworkProtocol::Http | NetworkProtocol::Https => Err(SspiError::new(
                ErrorKind::UnsupportedFunction,
                "KDC proxy URLs are not available in the bounded callback initiator",
            )),
        }
    }

    async fn resolve(&self, request: &NetworkRequest) -> sspi::Result<Vec<SocketAddr>> {
        let host = request
            .url
            .host_str()
            .ok_or_else(|| SspiError::new(ErrorKind::NoAuthenticatingAuthority, "Kerberos KDC URL has no host"))?;
        let port = request.url.port().unwrap_or(88);
        let values = lookup_host((host, port)).await.map_err(|error| {
            SspiError::new(ErrorKind::NoAuthenticatingAuthority, format!("unable to resolve Kerberos KDC: {error}"))
        })?;
        let values = values.collect::<Vec<_>>();
        if values.is_empty() {
            return Err(SspiError::new(
                ErrorKind::NoAuthenticatingAuthority,
                "Kerberos KDC name resolved to no addresses",
            ));
        }
        Ok(values)
    }

    async fn send_tcp(&self, request: &NetworkRequest) -> sspi::Result<Vec<u8>> {
        let addresses = self.resolve(request).await?;
        let mut last = None;
        for address in addresses {
            match TcpStream::connect(address).await {
                Ok(mut stream) => {
                    stream.write_all(&request.data).await.map_err(kdc_io_error)?;
                    let length = stream.read_u32().await.map_err(kdc_io_error)?;
                    let length = usize::try_from(length).map_err(|_| {
                        SspiError::new(
                            ErrorKind::NoAuthenticatingAuthority,
                            "Kerberos KDC reply length is not representable",
                        )
                    })?;
                    if length > self.max_reply_bytes.saturating_sub(4) {
                        return Err(SspiError::new(
                            ErrorKind::InsufficientMemory,
                            "Kerberos KDC reply exceeds the configured bound",
                        ));
                    }
                    let mut reply = vec![0; length.saturating_add(4)];
                    reply[..4].copy_from_slice(&(length as u32).to_be_bytes());
                    stream.read_exact(&mut reply[4..]).await.map_err(kdc_io_error)?;
                    return Ok(reply);
                },
                Err(error) => last = Some(error),
            }
        }
        Err(kdc_io_error(last.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "Kerberos KDC is unavailable")
        })))
    }

    async fn send_udp(&self, request: &NetworkRequest) -> sspi::Result<Vec<u8>> {
        let addresses = self.resolve(request).await?;
        let address = addresses[0];
        let bind_address = if address.is_ipv6() {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        };
        let socket = UdpSocket::bind(bind_address).await.map_err(kdc_io_error)?;
        socket.send_to(&request.data, address).await.map_err(kdc_io_error)?;
        let maximum_payload = self.max_reply_bytes.saturating_sub(4);
        let mut reply = vec![0; maximum_payload.saturating_add(1)];
        let (length, _) = socket.recv_from(&mut reply).await.map_err(kdc_io_error)?;
        if length > maximum_payload {
            return Err(SspiError::new(
                ErrorKind::InsufficientMemory,
                "Kerberos UDP reply exceeds the configured bound",
            ));
        }
        reply.truncate(length);
        let mut framed = Vec::with_capacity(length.saturating_add(4));
        framed.extend_from_slice(
            &u32::try_from(length)
                .map_err(|_| {
                    SspiError::new(ErrorKind::InsufficientMemory, "Kerberos UDP reply length is not representable")
                })?
                .to_be_bytes(),
        );
        framed.extend_from_slice(&reply);
        Ok(framed)
    }
}

fn kdc_io_error(error: std::io::Error) -> SspiError {
    SspiError::new(ErrorKind::NoAuthenticatingAuthority, format!("Kerberos KDC transport failed: {error}"))
}

fn prune_contexts(contexts: &mut HashMap<ProviderContextId, ContextSlot>, now: Instant) {
    contexts.retain(|_, slot| now < slot.expires_at);
}

fn unique_context_id(contexts: &HashMap<ProviderContextId, ContextSlot>) -> Result<ProviderContextId, ProviderError> {
    for _ in 0..32 {
        let mut bytes = [0; 8];
        OsRng.fill_bytes(&mut bytes);
        let id = ProviderContextId(u64::from_be_bytes(bytes));
        if id.0 != 0 && !contexts.contains_key(&id) {
            return Ok(id);
        }
    }
    Err(ProviderError::Resource)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVICE_PRINCIPAL: &str = "nfs/server.example.test@EXAMPLE.TEST";

    fn aes256_keytab() -> Bytes {
        let mut record = Vec::new();
        record.extend_from_slice(&2_u16.to_be_bytes());
        push_counted(&mut record, "EXAMPLE.TEST");
        push_counted(&mut record, "nfs");
        push_counted(&mut record, "server.example.test");
        record.extend_from_slice(&2_u32.to_be_bytes());
        record.extend_from_slice(&0_u32.to_be_bytes());
        record.push(7);
        record.extend_from_slice(&18_u16.to_be_bytes());
        record.extend_from_slice(&32_u16.to_be_bytes());
        record.extend_from_slice(&[0x42; 32]);
        record.extend_from_slice(&7_u32.to_be_bytes());

        let mut keytab = 0x0502_u16.to_be_bytes().to_vec();
        keytab.extend_from_slice(&i32::try_from(record.len()).expect("test keytab record fits").to_be_bytes());
        keytab.extend_from_slice(&record);
        Bytes::from(keytab)
    }

    fn push_counted(output: &mut Vec<u8>, value: &str) {
        output.extend_from_slice(&u16::try_from(value.len()).expect("test keytab string fits").to_be_bytes());
        output.extend_from_slice(value.as_bytes());
    }

    #[test]
    fn pinned_sspi_acquires_outbound_keytab_credentials_without_host_gss() {
        let initiator = SspiGssInitiator::from_keytab_bytes(SERVICE_PRINCIPAL, aes256_keytab()).expect("valid keytab");
        let Credentials::Keytab(identity) = &initiator.credential else {
            panic!("initiator must retain keytab credentials");
        };
        assert_eq!(identity.principal.inner(), "EXAMPLE.TEST\\nfs/server.example.test");
        let context = initiator
            .create_context(
                Version::V2,
                "nfs/client.example.test@EXAMPLE.TEST",
                Instant::now() + Duration::from_secs(60),
            )
            .expect("sspi 0.21.3 accepts KeytabIdentity for outbound credentials");
        assert!(context.credentials_handle.is_some());
        assert_eq!(context.sspi_target_name, "nfs/client.example.test");
        assert_eq!(context.phase, InitiatorPhase::New);
    }

    #[test]
    fn initiator_rejects_attempt_timeouts_above_five_seconds() {
        let limits = SspiGssInitiatorLimits {
            kdc_attempt_timeout: Duration::from_secs(6),
            ..SspiGssInitiatorLimits::default()
        };
        assert!(matches!(
            SspiGssInitiator::from_keytab_bytes_with_limits(SERVICE_PRINCIPAL.to_owned(), aes256_keytab(), limits,),
            Err(SspiGssInitiatorConfigError::InvalidLimits)
        ));
    }

    #[test]
    fn initiator_rejects_unbounded_kdc_request_configuration() {
        let limits = SspiGssInitiatorLimits {
            max_kdc_request_bytes: SspiGssProviderLimits::default().max_output_token_bytes.saturating_add(1),
            ..SspiGssInitiatorLimits::default()
        };
        assert!(matches!(
            SspiGssInitiator::from_keytab_bytes_with_limits(SERVICE_PRINCIPAL.to_owned(), aes256_keytab(), limits,),
            Err(SspiGssInitiatorConfigError::InvalidLimits)
        ));
    }
}
