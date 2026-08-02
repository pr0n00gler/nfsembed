//! Pure-Rust Kerberos acceptor backed by `sspi` 0.21.3.
//!
//! This adapter deliberately uses the portable [`sspi::Kerberos`] package on
//! every platform; it never dispatches to a host GSS or Windows SSPI library.
//!
//! # `sspi` 0.21.3 API limitations
//!
//! * The crate does not parse MIT keytab files. This adapter accepts MIT keytab v2 bytes (or a path), applies strict
//!   bounds, and selects the newest AES key for the configured service principal.
//! * [`sspi::kerberos::ServerProperties`] holds one ticket-decryption key per service principal. Consequently, an
//!   acceptor cannot simultaneously try multiple kvnos or encryption types for the same principal. The adapter selects
//!   highest kvno, preferring AES-256 over AES-128 at equal kvno.
//! * Kerberos `make_signature` and `verify_signature` return `UnsupportedFunction`; the working MIC helpers are private
//!   to the crate's SPNEGO implementation. Kerberos `encrypt_message` also ignores `WRAP_NO_ENCRYPT`. The adapter
//!   therefore constructs and verifies RFC 4121 AES MIC and integrity-only Wrap tokens with the same `picky-krb`
//!   primitives already used by `sspi`. It consumes a zero-length SSPI Wrap operation first so SSPI remains
//!   authoritative for outbound sequence allocation.
//! * `query_context_session_key` exposes key bytes but not the negotiated enctype. The RFC 4121 bridge therefore
//!   supports only 16-byte and 32-byte AES session keys. A 16-byte legacy enctype cannot be distinguished from AES-128,
//!   so deployments using this adapter must configure Kerberos to negotiate AES session keys.
//! * `AcceptSecurityContextResult::expiry` is always `None` for the Kerberos acceptor, and there is no explicit
//!   delete-context method. This adapter enforces a configured maximum lifetime and deletes by dropping the portable
//!   Kerberos context.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use picky_krb::constants::key_usages::{ACCEPTOR_SEAL, ACCEPTOR_SIGN, INITIATOR_SEAL, INITIATOR_SIGN};
use picky_krb::crypto::aes::{checksum_sha_aes, AesSize, AES128_KEY_SIZE, AES256_KEY_SIZE, AES_MAC_SIZE};
use picky_krb::gss_api::{MicToken, WrapToken};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use sspi::kerberos::ServerProperties;
use sspi::{
    BufferType, CredentialUse, DataRepresentation, EncryptionFlags, Error as SspiError, ErrorKind, Kerberos,
    KerberosConfig, Secret, SecurityBuffer, SecurityBufferRef, SecurityStatus, ServerRequestFlags, Sspi, SspiImpl,
};
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;

use super::{
    AcceptContext, AcceptOutcome, GssIdentity, GssProvider, ProtectionSizes, ProviderContextId, ProviderError, Version,
};

const GSS_S_COMPLETE: u32 = 0;
const GSS_S_CONTINUE_NEEDED: u32 = 1;
const GSS_S_FAILURE: u32 = 13 << 16;
const KERBEROS_MECHANISM_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

const MIT_KEYTAB_V2: u16 = 0x0502;
const ETYPE_AES128_CTS_HMAC_SHA1_96: u16 = 17;
const ETYPE_AES256_CTS_HMAC_SHA1_96: u16 = 18;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SspiGssProviderLimits {
    pub max_contexts: usize,
    pub max_replay_entries: usize,
    pub max_init_token_bytes: usize,
    pub max_message_bytes: usize,
    pub max_output_token_bytes: usize,
    pub max_keytab_bytes: usize,
    pub max_keytab_entries: usize,
    pub max_principal_bytes: usize,
    pub max_key_bytes: usize,
    pub max_continuation_steps: usize,
    pub max_context_lifetime: Duration,
    pub max_clock_skew: Duration,
}

impl Default for SspiGssProviderLimits {
    fn default() -> Self {
        Self {
            max_contexts: 4_096,
            max_replay_entries: 8_192,
            max_init_token_bytes: 1024 * 1024,
            max_message_bytes: 16 * 1024 * 1024,
            max_output_token_bytes: 17 * 1024 * 1024,
            max_keytab_bytes: 16 * 1024 * 1024,
            max_keytab_entries: 4_096,
            max_principal_bytes: 4 * 1024,
            max_key_bytes: 1024,
            max_continuation_steps: 8,
            max_context_lifetime: Duration::from_secs(10 * 60 * 60),
            max_clock_skew: Duration::from_secs(5 * 60),
        }
    }
}

impl SspiGssProviderLimits {
    pub(super) fn validate(self) -> Result<Self, SspiGssProviderConfigError> {
        if self.max_contexts == 0
            || self.max_replay_entries < self.max_contexts
            || self.max_init_token_bytes < WrapToken::header_len()
            || self.max_message_bytes == 0
            || self.max_output_token_bytes < self.max_message_bytes
            || self.max_keytab_bytes < 2
            || self.max_keytab_entries == 0
            || self.max_principal_bytes == 0
            || self.max_key_bytes < AES256_KEY_SIZE
            || self.max_continuation_steps == 0
            || self.max_context_lifetime.is_zero()
            || self.max_clock_skew.is_zero()
        {
            return Err(SspiGssProviderConfigError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum SspiKeytabSource {
    Path(PathBuf),
    Bytes(Bytes),
}

impl fmt::Debug for SspiKeytabSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(path) => formatter.debug_tuple("Path").field(path).finish(),
            Self::Bytes(bytes) => formatter
                .debug_struct("Bytes")
                .field("len", &bytes.len())
                .finish_non_exhaustive(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SspiGssProviderConfig {
    pub service_principal: String,
    pub keytab: SspiKeytabSource,
    pub limits: SspiGssProviderLimits,
}

impl SspiGssProviderConfig {
    pub fn from_keytab_path(service_principal: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            service_principal: service_principal.into(),
            keytab: SspiKeytabSource::Path(path.into()),
            limits: SspiGssProviderLimits::default(),
        }
    }

    pub fn from_keytab_bytes(service_principal: impl Into<String>, keytab: impl Into<Bytes>) -> Self {
        Self {
            service_principal: service_principal.into(),
            keytab: SspiKeytabSource::Bytes(keytab.into()),
            limits: SspiGssProviderLimits::default(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SspiGssProviderConfigError {
    #[error("SSPI GSS provider limits are invalid")]
    InvalidLimits,
    #[error("Kerberos service principal is invalid")]
    InvalidServicePrincipal,
    #[error("Kerberos keytab exceeds the configured byte limit")]
    KeytabTooLarge,
    #[error("Kerberos keytab v{0:#06x} is unsupported; MIT keytab v2 (0x0502) is required")]
    UnsupportedKeytabVersion(u16),
    #[error("Kerberos keytab is invalid: {0}")]
    InvalidKeytab(&'static str),
    #[error("configured service principal is absent from the Kerberos keytab")]
    PrincipalNotFound,
    #[error("configured service principal has no AES-128 or AES-256 keytab entry")]
    UnsupportedEncryptionType,
    #[error("unable to read Kerberos keytab: {0}")]
    KeytabIo(#[source] std::io::Error),
    #[error("unable to configure portable SSPI Kerberos acceptor: {0}")]
    Sspi(String),
}

pub struct SspiGssProvider {
    service_principal: String,
    kerberos_config: KerberosConfig,
    server_properties: ServerProperties,
    selected_key: SelectedKeyMetadata,
    limits: SspiGssProviderLimits,
    state: Mutex<ProviderState>,
}

impl fmt::Debug for SspiGssProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SspiGssProvider")
            .field("service_principal", &self.service_principal)
            .field("selected_key", &self.selected_key)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SelectedKeyMetadata {
    kvno: u32,
    encryption_type: u16,
}

#[derive(Default)]
struct ProviderState {
    contexts: HashMap<ProviderContextId, ContextSlot>,
    replay_digests: HashSet<[u8; 32]>,
    replay_order: VecDeque<ReplayEntry>,
}

#[derive(Clone)]
struct ContextSlot {
    context: Arc<Mutex<ProviderContext>>,
    expires_at: Instant,
}

struct ReplayEntry {
    digest: [u8; 32],
    expires_at: Instant,
}

struct ProviderContext {
    kerberos: Kerberos,
    credentials_handle: <Kerberos as SspiImpl>::CredentialsHandle,
    version: Version,
    phase: ProviderPhase,
    accept_steps: usize,
    expires_at: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProviderPhase {
    New,
    Pending,
    Established,
}

impl SspiGssProvider {
    pub async fn new(config: SspiGssProviderConfig) -> Result<Self, SspiGssProviderConfigError> {
        let limits = config.limits.validate()?;
        let keytab = match config.keytab {
            SspiKeytabSource::Path(path) => read_keytab_path(path, limits.max_keytab_bytes).await?,
            SspiKeytabSource::Bytes(bytes) => {
                if bytes.len() > limits.max_keytab_bytes {
                    return Err(SspiGssProviderConfigError::KeytabTooLarge);
                }
                bytes
            },
        };
        Self::from_keytab_bytes_with_limits(config.service_principal, keytab, limits)
    }

    pub fn from_keytab_bytes(
        service_principal: impl Into<String>,
        keytab: impl Into<Bytes>,
    ) -> Result<Self, SspiGssProviderConfigError> {
        Self::from_keytab_bytes_with_limits(service_principal.into(), keytab.into(), SspiGssProviderLimits::default())
    }

    pub async fn from_keytab_path(
        service_principal: impl Into<String>,
        path: impl Into<PathBuf>,
    ) -> Result<Self, SspiGssProviderConfigError> {
        Self::new(SspiGssProviderConfig::from_keytab_path(service_principal, path)).await
    }

    pub fn service_principal(&self) -> &str {
        &self.service_principal
    }

    pub fn limits(&self) -> SspiGssProviderLimits {
        self.limits
    }

    fn from_keytab_bytes_with_limits(
        service_principal: String,
        keytab: Bytes,
        limits: SspiGssProviderLimits,
    ) -> Result<Self, SspiGssProviderConfigError> {
        let limits = limits.validate()?;
        if keytab.len() > limits.max_keytab_bytes {
            return Err(SspiGssProviderConfigError::KeytabTooLarge);
        }
        let principal = ServicePrincipal::parse(&service_principal, limits.max_principal_bytes)?;
        let entries = parse_keytab(&keytab, limits)?;
        let selected = select_service_key(entries, &principal)?;
        let selected_key = SelectedKeyMetadata {
            kvno: selected.kvno,
            encryption_type: selected.encryption_type,
        };

        let component_refs = principal.components.iter().map(String::as_str).collect::<Vec<_>>();
        let server_properties = ServerProperties::new(&component_refs, None, limits.max_clock_skew, Some(selected.key))
            .map_err(|error| SspiGssProviderConfigError::Sspi(error.to_string()))?;
        let kerberos_config = KerberosConfig {
            kdc_url: None,
            client_computer_name: principal.components.get(1).cloned().unwrap_or_else(|| "nfsserve".into()),
        };

        Ok(Self {
            service_principal,
            kerberos_config,
            server_properties,
            selected_key,
            limits,
            state: Mutex::new(ProviderState::default()),
        })
    }

    fn create_context(&self, version: Version, expires_at: Instant) -> Result<ProviderContext, ProviderError> {
        let mut kerberos =
            Kerberos::new_server_from_config(self.kerberos_config.clone(), self.server_properties.clone())
                .map_err(map_sspi_error)?;
        let credentials_handle = kerberos
            .acquire_credentials_handle()
            .with_principal_name(&self.service_principal)
            .with_credential_use(CredentialUse::Inbound)
            .execute(&mut kerberos)
            .map_err(map_sspi_error)?
            .credentials_handle;
        Ok(ProviderContext {
            kerberos,
            credentials_handle,
            version,
            phase: ProviderPhase::New,
            accept_steps: 0,
            expires_at,
        })
    }

    async fn accept_first(&self, version: Version, token: Bytes) -> Result<AcceptOutcome, ProviderError> {
        self.validate_init_token(&token)?;
        let now = Instant::now();
        let expires_at = now
            .checked_add(self.limits.max_context_lifetime)
            .ok_or(ProviderError::Resource)?;
        let replay_expires_at = now.checked_add(self.limits.max_clock_skew).ok_or(ProviderError::Resource)?;
        let digest: [u8; 32] = Sha256::digest(&token).into();
        let context = Arc::new(Mutex::new(self.create_context(version, expires_at)?));

        let context_id = {
            let mut state = self.state.lock().await;
            prune_state(&mut state, now);
            if state.contexts.len() >= self.limits.max_contexts
                || state.replay_order.len() >= self.limits.max_replay_entries
            {
                return Err(ProviderError::Resource);
            }
            if !state.replay_digests.insert(digest) {
                return Err(ProviderError::InvalidToken);
            }
            state.replay_order.push_back(ReplayEntry {
                digest,
                expires_at: replay_expires_at,
            });
            let context_id = unique_context_id(&state.contexts)?;
            state.contexts.insert(
                context_id,
                ContextSlot {
                    context: Arc::clone(&context),
                    expires_at,
                },
            );
            context_id
        };

        let result = {
            let mut context = context.lock().await;
            context.accept(token, self.limits, context_id)
        };
        if result.is_err() {
            let mut state = self.state.lock().await;
            state.contexts.remove(&context_id);
            remove_replay_digest(&mut state, digest);
        }
        result
    }

    async fn accept_continuation(
        &self,
        continuation: AcceptContext,
        version: Version,
        token: Bytes,
    ) -> Result<AcceptOutcome, ProviderError> {
        self.validate_init_token(&token)?;
        if continuation.version != version {
            return Err(ProviderError::InvalidToken);
        }
        let context = self.context(continuation.provider_context).await?;
        let result = {
            let mut context = context.lock().await;
            if context.version != version {
                return Err(ProviderError::InvalidToken);
            }
            context.accept(token, self.limits, continuation.provider_context)
        };
        if result.is_err() {
            self.state.lock().await.contexts.remove(&continuation.provider_context);
        }
        result
    }

    fn validate_init_token(&self, token: &[u8]) -> Result<(), ProviderError> {
        if token.is_empty() {
            return Err(ProviderError::InvalidToken);
        }
        if token.len() > self.limits.max_init_token_bytes {
            return Err(ProviderError::Resource);
        }
        Ok(())
    }

    fn validate_message(&self, message: &[u8]) -> Result<(), ProviderError> {
        if message.len() > self.limits.max_message_bytes {
            return Err(ProviderError::Resource);
        }
        Ok(())
    }

    fn validate_protection_token(&self, token: &[u8]) -> Result<(), ProviderError> {
        if token.len() > self.limits.max_output_token_bytes {
            return Err(ProviderError::Resource);
        }
        if token.len() < WrapToken::header_len() {
            return Err(ProviderError::InvalidToken);
        }
        Ok(())
    }

    async fn context(&self, context_id: ProviderContextId) -> Result<Arc<Mutex<ProviderContext>>, ProviderError> {
        let now = Instant::now();
        let mut state = self.state.lock().await;
        if state.contexts.get(&context_id).is_some_and(|slot| now >= slot.expires_at) {
            state.contexts.remove(&context_id);
            return Err(ProviderError::Expired);
        }
        prune_state(&mut state, now);
        state
            .contexts
            .get(&context_id)
            .map(|slot| Arc::clone(&slot.context))
            .ok_or(ProviderError::UnknownContext)
    }
}

impl ProviderContext {
    fn accept(
        &mut self,
        token: Bytes,
        limits: SspiGssProviderLimits,
        context_id: ProviderContextId,
    ) -> Result<AcceptOutcome, ProviderError> {
        if Instant::now() >= self.expires_at {
            return Err(ProviderError::Expired);
        }
        if self.phase == ProviderPhase::Established {
            return Err(ProviderError::InvalidToken);
        }
        if self.accept_steps >= limits.max_continuation_steps {
            return Err(ProviderError::Resource);
        }
        self.accept_steps += 1;

        let mut input = vec![SecurityBuffer::new(token.to_vec(), BufferType::Token)];
        let mut output = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let result = {
            let builder = self
                .kerberos
                .accept_security_context()
                .with_credentials_handle(&mut self.credentials_handle)
                .with_context_requirements(
                    ServerRequestFlags::REPLAY_DETECT
                        | ServerRequestFlags::SEQUENCE_DETECT
                        | ServerRequestFlags::CONFIDENTIALITY
                        | ServerRequestFlags::INTEGRITY
                        | ServerRequestFlags::ALLOCATE_MEMORY,
                )
                .with_target_data_representation(DataRepresentation::Network)
                .with_input(&mut input)
                .with_output(&mut output);
            let mut operation = self
                .kerberos
                .accept_security_context_impl(builder)
                .map_err(map_sspi_accept_error)?;
            operation.resolve_to_result().map_err(map_sspi_accept_error)?
        };

        let (major_status, complete) = match result.status {
            SecurityStatus::Ok => (GSS_S_COMPLETE, true),
            SecurityStatus::ContinueNeeded => (GSS_S_CONTINUE_NEEDED, false),
            SecurityStatus::CompleteNeeded => {
                self.kerberos.complete_auth_token(&mut output).map_err(map_sspi_accept_error)?;
                (GSS_S_COMPLETE, true)
            },
            SecurityStatus::CompleteAndContinue => {
                self.kerberos.complete_auth_token(&mut output).map_err(map_sspi_accept_error)?;
                (GSS_S_CONTINUE_NEEDED, false)
            },
            _ => {
                return Err(ProviderError::Mechanism {
                    major: GSS_S_FAILURE,
                    minor: result.status as u32,
                });
            },
        };
        let output_token = output
            .into_iter()
            .next()
            .map(|buffer| Bytes::from(buffer.buffer))
            .unwrap_or_default();
        if output_token.len() > limits.max_output_token_bytes {
            return Err(ProviderError::Resource);
        }

        let complete_identity = if complete {
            let session_key = self.kerberos.query_context_session_key().map_err(map_sspi_accept_error)?;
            aes_size(session_key.session_key.as_ref()).map_err(|_| ProviderError::Mechanism {
                major: GSS_S_FAILURE,
                minor: ErrorKind::UnsupportedFunction as u32,
            })?;
            let names = self.kerberos.query_context_names().map_err(map_sspi_accept_error)?;
            self.phase = ProviderPhase::Established;
            Some(GssIdentity {
                // `inner()` retains the complete UPN/down-level name. Using
                // `account_name()` here would silently discard the realm.
                principal: names.username.inner().to_owned(),
                mechanism: KERBEROS_MECHANISM_OID.to_vec(),
            })
        } else {
            self.phase = ProviderPhase::Pending;
            None
        };

        Ok(AcceptOutcome {
            context: AcceptContext {
                provider_context: context_id,
                version: self.version,
                expires_at: self.expires_at,
            },
            major_status,
            minor_status: 0,
            output_token,
            complete_identity,
        })
    }

    fn ensure_established(&self) -> Result<(), ProviderError> {
        if Instant::now() >= self.expires_at {
            return Err(ProviderError::Expired);
        }
        if self.phase != ProviderPhase::Established {
            return Err(ProviderError::UnknownContext);
        }
        Ok(())
    }

    fn session_key_and_aes_size(&mut self) -> Result<(Vec<u8>, AesSize), ProviderError> {
        let session_key = self.kerberos.query_context_session_key().map_err(map_sspi_error)?;
        let key = session_key.session_key.as_ref().clone();
        let size = aes_size(&key).map_err(|_| ProviderError::Mechanism {
            major: GSS_S_FAILURE,
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
        let (key, aes_size) = self.session_key_and_aes_size()?;
        let sequence = self.next_outbound_sequence(output_limit)?;
        let token = generate_mic(&key, &aes_size, sequence, message, true)?;
        if token.len() > output_limit {
            return Err(ProviderError::Resource);
        }
        Ok(Bytes::from(token))
    }

    fn verify_mic(&mut self, message: &[u8], mic: &[u8]) -> Result<(), ProviderError> {
        self.ensure_established()?;
        let (key, aes_size) = self.session_key_and_aes_size()?;
        verify_mic(&key, &aes_size, message, mic, false)
    }

    fn wrap(&mut self, message: &[u8], confidentiality: bool, output_limit: usize) -> Result<Bytes, ProviderError> {
        self.ensure_established()?;
        if confidentiality {
            return seal_message(&mut self.kerberos, message, output_limit);
        }
        let (key, aes_size) = self.session_key_and_aes_size()?;
        let sequence = self.next_outbound_sequence(output_limit)?;
        let token = generate_integrity_wrap(&key, &aes_size, sequence, message, true)?;
        if token.len() > output_limit {
            return Err(ProviderError::Resource);
        }
        Ok(Bytes::from(token))
    }

    fn protection_sizes(&mut self) -> Result<ProtectionSizes, ProviderError> {
        self.ensure_established()?;
        let max_mic_token_bytes = WrapToken::header_len()
            .checked_add(AES_MAC_SIZE)
            .ok_or(ProviderError::Resource)?;
        let max_wrap_overhead_bytes = usize::try_from(
            self.kerberos
                .query_context_sizes()
                .map_err(map_sspi_privacy_error)?
                .security_trailer,
        )
        .map_err(|_| ProviderError::Resource)?;
        Ok(ProtectionSizes {
            max_mic_token_bytes,
            max_wrap_overhead_bytes,
        })
    }

    fn unwrap(&mut self, token: &[u8], message_limit: usize) -> Result<Bytes, ProviderError> {
        self.ensure_established()?;
        unwrap_message(&mut self.kerberos, token, message_limit, false)
    }
}

#[async_trait]
impl GssProvider for SspiGssProvider {
    async fn accept_security_context(
        &self,
        continuation: Option<AcceptContext>,
        version: Version,
        token: Bytes,
    ) -> Result<AcceptOutcome, ProviderError> {
        match continuation {
            Some(continuation) => self.accept_continuation(continuation, version, token).await,
            None => self.accept_first(version, token).await,
        }
    }

    async fn verify_mic(&self, context: ProviderContextId, message: Bytes, mic: Bytes) -> Result<(), ProviderError> {
        self.validate_message(&message)?;
        self.validate_protection_token(&mic)?;
        self.context(context).await?.lock().await.verify_mic(&message, &mic)
    }

    async fn get_mic(&self, context: ProviderContextId, message: Bytes) -> Result<Bytes, ProviderError> {
        self.validate_message(&message)?;
        self.context(context)
            .await?
            .lock()
            .await
            .get_mic(&message, self.limits.max_output_token_bytes)
    }

    async fn unwrap(&self, context: ProviderContextId, token: Bytes) -> Result<Bytes, ProviderError> {
        self.validate_protection_token(&token)?;
        self.context(context)
            .await?
            .lock()
            .await
            .unwrap(&token, self.limits.max_message_bytes)
    }

    async fn wrap(
        &self,
        context: ProviderContextId,
        message: Bytes,
        confidentiality: bool,
    ) -> Result<Bytes, ProviderError> {
        self.validate_message(&message)?;
        self.context(context)
            .await?
            .lock()
            .await
            .wrap(&message, confidentiality, self.limits.max_output_token_bytes)
    }

    async fn protection_sizes(&self, context: ProviderContextId) -> Result<ProtectionSizes, ProviderError> {
        self.context(context).await?.lock().await.protection_sizes()
    }

    async fn delete_security_context(&self, context: ProviderContextId) -> Result<(), ProviderError> {
        self.state
            .lock()
            .await
            .contexts
            .remove(&context)
            .map(|_| ())
            .ok_or(ProviderError::UnknownContext)
    }
}

pub(super) fn seal_message(
    kerberos: &mut Kerberos,
    message: &[u8],
    output_limit: usize,
) -> Result<Bytes, ProviderError> {
    let trailer = usize::try_from(kerberos.query_context_sizes().map_err(map_sspi_privacy_error)?.security_trailer)
        .map_err(|_| ProviderError::Resource)?;
    let maximum = message.len().checked_add(trailer).ok_or(ProviderError::Resource)?;
    if maximum > output_limit {
        return Err(ProviderError::Resource);
    }

    let mut token = vec![0; trailer];
    let mut data = message.to_vec();
    let sealed = {
        let mut buffers = [
            SecurityBufferRef::token_buf(&mut token),
            SecurityBufferRef::data_buf(&mut data),
        ];
        kerberos
            .encrypt_message(EncryptionFlags::empty(), &mut buffers)
            .map_err(map_sspi_privacy_error)?;
        let mut sealed = Vec::with_capacity(buffers[0].data().len().saturating_add(buffers[1].data().len()));
        sealed.extend_from_slice(buffers[0].data());
        sealed.extend_from_slice(buffers[1].data());
        sealed
    };
    if sealed.len() > output_limit {
        return Err(ProviderError::Resource);
    }
    Ok(Bytes::from(sealed))
}

pub(super) fn unwrap_message(
    kerberos: &mut Kerberos,
    encoded: &[u8],
    message_limit: usize,
    sender_is_acceptor: bool,
) -> Result<Bytes, ProviderError> {
    let token = WrapToken::decode(encoded).map_err(|_| ProviderError::InvalidToken)?;
    if token.flags & !0x07 != 0 || (token.flags & 0x01 != 0) != sender_is_acceptor {
        return Err(ProviderError::InvalidToken);
    }

    if token.flags & 0x02 != 0 {
        let mut stream = encoded.to_vec();
        let mut empty = [];
        let cleartext = {
            let mut buffers = [
                SecurityBufferRef::stream_buf(&mut stream),
                SecurityBufferRef::data_buf(&mut empty),
            ];
            kerberos.decrypt_message(&mut buffers).map_err(map_sspi_privacy_error)?;
            Bytes::copy_from_slice(buffers[1].data())
        };
        if cleartext.len() > message_limit {
            return Err(ProviderError::Resource);
        }
        return Ok(cleartext);
    }

    if usize::from(token.ec) != AES_MAC_SIZE || token.checksum.len() < AES_MAC_SIZE {
        return Err(ProviderError::InvalidToken);
    }
    let maximum_payload = message_limit.checked_add(AES_MAC_SIZE).ok_or(ProviderError::Resource)?;
    if token.checksum.len() > maximum_payload {
        return Err(ProviderError::Resource);
    }

    // RFC 4121 section 4.2.4 carries an integrity-only token as
    // `plaintext | checksum`, then right-rotates that data by RRC.
    let mut header = token.header();
    header[4..8].fill(0);
    let mut payload = token.checksum;
    let rotation = usize::from(token.rrc) % payload.len();
    payload.rotate_left(rotation);
    let plaintext_length = payload.len() - AES_MAC_SIZE;
    let (plaintext, received_checksum) = payload.split_at(plaintext_length);

    let session_key = kerberos.query_context_session_key().map_err(map_sspi_error)?;
    let key = session_key.session_key.as_ref();
    let size = aes_size(key).map_err(|_| ProviderError::Mechanism {
        major: GSS_S_FAILURE,
        minor: ErrorKind::UnsupportedFunction as u32,
    })?;

    let mut checksum_input = Vec::with_capacity(plaintext.len().saturating_add(header.len()));
    checksum_input.extend_from_slice(plaintext);
    checksum_input.extend_from_slice(&header);
    let expected = checksum_sha_aes(
        key,
        if sender_is_acceptor {
            ACCEPTOR_SEAL
        } else {
            INITIATOR_SEAL
        },
        &checksum_input,
        &size,
    )
    .map_err(|_| ProviderError::Integrity)?;
    if !constant_time_equal(&expected, received_checksum) {
        return Err(ProviderError::Integrity);
    }
    Ok(Bytes::copy_from_slice(plaintext))
}

pub(super) fn generate_mic(
    key: &[u8],
    aes_size: &AesSize,
    sequence: u64,
    message: &[u8],
    sender_is_acceptor: bool,
) -> Result<Vec<u8>, ProviderError> {
    let mut token = if sender_is_acceptor {
        MicToken::with_acceptor_flags()
    } else {
        MicToken::with_initiator_flags()
    }
    .with_seq_number(sequence);
    let mut checksum_input = Vec::with_capacity(message.len().saturating_add(token.header().len()));
    checksum_input.extend_from_slice(message);
    checksum_input.extend_from_slice(&token.header());
    token.set_checksum(
        checksum_sha_aes(
            key,
            if sender_is_acceptor {
                ACCEPTOR_SIGN
            } else {
                INITIATOR_SIGN
            },
            &checksum_input,
            aes_size,
        )
        .map_err(|_| ProviderError::Integrity)?,
    );
    let mut encoded = Vec::with_capacity(WrapToken::header_len().saturating_add(AES_MAC_SIZE));
    token.encode(&mut encoded).map_err(|_| ProviderError::Integrity)?;
    Ok(encoded)
}

pub(super) fn verify_mic(
    key: &[u8],
    aes_size: &AesSize,
    message: &[u8],
    encoded: &[u8],
    sender_is_acceptor: bool,
) -> Result<(), ProviderError> {
    let token = MicToken::decode(encoded).map_err(|_| ProviderError::InvalidToken)?;
    if token.flags & 0x01 != u8::from(sender_is_acceptor)
        || token.flags & 0x02 != 0
        || token.checksum.len() != AES_MAC_SIZE
    {
        return Err(ProviderError::InvalidToken);
    }
    let mut checksum_input = Vec::with_capacity(message.len().saturating_add(token.header().len()));
    checksum_input.extend_from_slice(message);
    checksum_input.extend_from_slice(&token.header());
    let expected = checksum_sha_aes(
        key,
        if sender_is_acceptor {
            ACCEPTOR_SIGN
        } else {
            INITIATOR_SIGN
        },
        &checksum_input,
        aes_size,
    )
    .map_err(|_| ProviderError::Integrity)?;
    if expected != token.checksum {
        return Err(ProviderError::Integrity);
    }
    Ok(())
}

pub(super) fn generate_integrity_wrap(
    key: &[u8],
    aes_size: &AesSize,
    sequence: u64,
    message: &[u8],
    sender_is_acceptor: bool,
) -> Result<Vec<u8>, ProviderError> {
    let mut token = WrapToken::with_seq_number(sequence);
    // `query_context_session_key` exposes the acceptor subkey selected by
    // the mutual-authentication exchange. Preserve RFC 4121's
    // AcceptorSubkey flag and clear only the Sealed bit for an
    // integrity-only Wrap token.
    token.flags = 0x04 | u8::from(sender_is_acceptor);
    token.ec = 0;
    token.rrc = 0;

    let mut checksum_input = Vec::with_capacity(message.len().saturating_add(token.header().len()));
    checksum_input.extend_from_slice(message);
    checksum_input.extend_from_slice(&token.header());
    let checksum = checksum_sha_aes(
        key,
        if sender_is_acceptor {
            ACCEPTOR_SEAL
        } else {
            INITIATOR_SEAL
        },
        &checksum_input,
        aes_size,
    )
    .map_err(|_| ProviderError::Integrity)?;
    let rotation = u16::try_from(checksum.len()).map_err(|_| ProviderError::Resource)?;
    let mut payload = Vec::with_capacity(message.len().saturating_add(checksum.len()));
    payload.extend_from_slice(message);
    payload.extend_from_slice(&checksum);
    payload.rotate_right(usize::from(rotation));

    token.ec = rotation;
    token.rrc = rotation;
    token.set_checksum(payload);
    let mut encoded = Vec::with_capacity(WrapToken::header_len().saturating_add(token.checksum.len()));
    token.encode(&mut encoded).map_err(|_| ProviderError::Integrity)?;
    Ok(encoded)
}

pub(super) fn aes_size(key: &[u8]) -> Result<AesSize, ()> {
    match key.len() {
        AES128_KEY_SIZE => Ok(AesSize::Aes128),
        AES256_KEY_SIZE => Ok(AesSize::Aes256),
        _ => Err(()),
    }
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn map_sspi_accept_error(error: SspiError) -> ProviderError {
    match error.error_type {
        ErrorKind::ContextExpired => ProviderError::Expired,
        ErrorKind::InvalidToken
        | ErrorKind::IncompleteMessage
        | ErrorKind::IllegalMessage
        | ErrorKind::MessageAltered
        | ErrorKind::OutOfSequence
        | ErrorKind::TimeSkew
        | ErrorKind::WrongPrincipalName => ProviderError::InvalidToken,
        ErrorKind::InsufficientMemory | ErrorKind::BufferTooSmall => ProviderError::Resource,
        _ => map_sspi_error(error),
    }
}

pub(super) fn map_sspi_privacy_error(error: SspiError) -> ProviderError {
    match error.error_type {
        ErrorKind::ContextExpired => ProviderError::Expired,
        ErrorKind::InsufficientMemory | ErrorKind::BufferTooSmall => ProviderError::Resource,
        ErrorKind::MessageAltered
        | ErrorKind::InvalidToken
        | ErrorKind::IncompleteMessage
        | ErrorKind::IllegalMessage
        | ErrorKind::DecryptFailure
        | ErrorKind::EncryptFailure => ProviderError::Privacy,
        _ => map_sspi_error(error),
    }
}

pub(super) fn map_sspi_error(error: SspiError) -> ProviderError {
    ProviderError::Mechanism {
        major: GSS_S_FAILURE,
        minor: error.error_type as u32,
    }
}

fn prune_state(state: &mut ProviderState, now: Instant) {
    state.contexts.retain(|_, slot| slot.expires_at > now);
    while state.replay_order.front().is_some_and(|entry| entry.expires_at <= now) {
        if let Some(entry) = state.replay_order.pop_front() {
            state.replay_digests.remove(&entry.digest);
        }
    }
}

fn remove_replay_digest(state: &mut ProviderState, digest: [u8; 32]) {
    state.replay_digests.remove(&digest);
    state.replay_order.retain(|entry| entry.digest != digest);
}

fn unique_context_id(contexts: &HashMap<ProviderContextId, ContextSlot>) -> Result<ProviderContextId, ProviderError> {
    for _ in 0..128 {
        let mut bytes = [0; 8];
        OsRng.try_fill_bytes(&mut bytes).map_err(|_| ProviderError::Resource)?;
        let id = ProviderContextId(u64::from_be_bytes(bytes));
        if id.0 != 0 && !contexts.contains_key(&id) {
            return Ok(id);
        }
    }
    Err(ProviderError::Resource)
}

pub(super) async fn read_keytab_path(path: PathBuf, maximum_bytes: usize) -> Result<Bytes, SspiGssProviderConfigError> {
    let file = tokio::fs::File::open(path)
        .await
        .map_err(SspiGssProviderConfigError::KeytabIo)?;
    let read_limit = u64::try_from(maximum_bytes).unwrap_or(u64::MAX).saturating_add(1);
    let mut reader = file.take(read_limit);
    let mut keytab = Vec::with_capacity(maximum_bytes.min(64 * 1024));
    reader
        .read_to_end(&mut keytab)
        .await
        .map_err(SspiGssProviderConfigError::KeytabIo)?;
    if keytab.len() > maximum_bytes {
        return Err(SspiGssProviderConfigError::KeytabTooLarge);
    }
    Ok(Bytes::from(keytab))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ServicePrincipal {
    components: Vec<String>,
    realm: String,
}

impl ServicePrincipal {
    fn parse(value: &str, maximum_bytes: usize) -> Result<Self, SspiGssProviderConfigError> {
        if value.is_empty() || value.len() > maximum_bytes || !value.is_ascii() {
            return Err(SspiGssProviderConfigError::InvalidServicePrincipal);
        }
        let (name, realm) = value
            .rsplit_once('@')
            .ok_or(SspiGssProviderConfigError::InvalidServicePrincipal)?;
        if name.is_empty() || realm.is_empty() || name.contains('@') {
            return Err(SspiGssProviderConfigError::InvalidServicePrincipal);
        }
        let components = name.split('/').map(str::to_owned).collect::<Vec<_>>();
        if components.is_empty() || components.iter().any(String::is_empty) {
            return Err(SspiGssProviderConfigError::InvalidServicePrincipal);
        }
        Ok(Self {
            components,
            realm: realm.to_owned(),
        })
    }
}

struct KeytabEntry {
    principal: ServicePrincipal,
    kvno: u32,
    encryption_type: u16,
    key: Secret<Vec<u8>>,
}

pub(super) struct SelectedKeyMaterial {
    pub encryption_type: u16,
    pub key: Secret<Vec<u8>>,
}

pub(super) fn select_keytab_key(
    service_principal: &str,
    keytab: &[u8],
    limits: SspiGssProviderLimits,
) -> Result<SelectedKeyMaterial, SspiGssProviderConfigError> {
    let principal = ServicePrincipal::parse(service_principal, limits.max_principal_bytes)?;
    let selected = select_service_key(parse_keytab(keytab, limits)?, &principal)?;
    Ok(SelectedKeyMaterial {
        encryption_type: selected.encryption_type,
        key: selected.key,
    })
}

fn parse_keytab(bytes: &[u8], limits: SspiGssProviderLimits) -> Result<Vec<KeytabEntry>, SspiGssProviderConfigError> {
    let mut keytab = KeytabDecoder::new(bytes);
    let version = keytab.u16()?;
    if version != MIT_KEYTAB_V2 {
        return Err(SspiGssProviderConfigError::UnsupportedKeytabVersion(version));
    }

    let mut entries = Vec::new();
    while !keytab.is_empty() {
        let record_length = keytab.i32()?;
        if record_length == 0 {
            return Err(SspiGssProviderConfigError::InvalidKeytab("zero-length keytab record"));
        }
        if record_length < 0 {
            let hole_length = usize::try_from(
                record_length
                    .checked_abs()
                    .ok_or(SspiGssProviderConfigError::InvalidKeytab("keytab hole length overflow"))?,
            )
            .map_err(|_| SspiGssProviderConfigError::InvalidKeytab("keytab hole length overflow"))?;
            keytab.take(hole_length)?;
            continue;
        }
        if entries.len() >= limits.max_keytab_entries {
            return Err(SspiGssProviderConfigError::InvalidKeytab("keytab entry limit exceeded"));
        }
        let record_length = usize::try_from(record_length)
            .map_err(|_| SspiGssProviderConfigError::InvalidKeytab("keytab record length overflow"))?;
        let mut record = KeytabDecoder::new(keytab.take(record_length)?);
        let component_count = usize::from(record.u16()?);
        if component_count == 0 || component_count > limits.max_keytab_entries {
            return Err(SspiGssProviderConfigError::InvalidKeytab("invalid keytab component count"));
        }
        let realm = record.counted_string(limits.max_principal_bytes)?;
        let mut components = Vec::with_capacity(component_count);
        let mut principal_bytes = realm.len();
        for _ in 0..component_count {
            let component = record.counted_string(limits.max_principal_bytes)?;
            principal_bytes = principal_bytes
                .checked_add(component.len())
                .ok_or(SspiGssProviderConfigError::InvalidKeytab("keytab principal length overflow"))?;
            if component.is_empty() || principal_bytes > limits.max_principal_bytes {
                return Err(SspiGssProviderConfigError::InvalidKeytab("keytab principal limit exceeded"));
            }
            components.push(component);
        }
        if realm.is_empty() || !realm.is_ascii() || components.iter().any(|component| !component.is_ascii()) {
            return Err(SspiGssProviderConfigError::InvalidKeytab("keytab principal is not non-empty ASCII"));
        }
        let _name_type = record.u32()?;
        let _timestamp = record.u32()?;
        let kvno8 = u32::from(record.u8()?);
        let encryption_type = record.u16()?;
        let key_length = usize::from(record.u16()?);
        if key_length == 0 || key_length > limits.max_key_bytes {
            return Err(SspiGssProviderConfigError::InvalidKeytab("keytab key length is invalid"));
        }
        let key = Secret::new(record.take(key_length)?.to_vec());
        let kvno = if record.remaining() == 0 {
            kvno8
        } else if matches!(record.remaining(), 4 | 8) {
            let kvno32 = record.u32()?;
            if record.remaining() == 4 {
                // Heimdal appends a bounded 32-bit entry-flags extension
                // after the optional 32-bit kvno.
                let _flags = record.u32()?;
            }
            if kvno32 == 0 {
                kvno8
            } else {
                kvno32
            }
        } else {
            return Err(SspiGssProviderConfigError::InvalidKeytab("keytab record has trailing bytes"));
        };
        entries.push(KeytabEntry {
            principal: ServicePrincipal { components, realm },
            kvno,
            encryption_type,
            key,
        });
    }
    Ok(entries)
}

fn select_service_key(
    entries: Vec<KeytabEntry>,
    principal: &ServicePrincipal,
) -> Result<KeytabEntry, SspiGssProviderConfigError> {
    let mut saw_principal = false;
    let mut selected: Option<KeytabEntry> = None;
    for entry in entries {
        if entry.principal != *principal {
            continue;
        }
        saw_principal = true;
        let expected_key_length = match entry.encryption_type {
            ETYPE_AES256_CTS_HMAC_SHA1_96 => AES256_KEY_SIZE,
            ETYPE_AES128_CTS_HMAC_SHA1_96 => AES128_KEY_SIZE,
            _ => continue,
        };
        if entry.key.as_ref().len() != expected_key_length {
            continue;
        }
        let replace = selected.as_ref().is_none_or(|current| {
            (entry.kvno, encryption_strength(entry.encryption_type))
                > (current.kvno, encryption_strength(current.encryption_type))
        });
        if replace {
            selected = Some(entry);
        }
    }
    match (selected, saw_principal) {
        (Some(entry), _) => Ok(entry),
        (None, true) => Err(SspiGssProviderConfigError::UnsupportedEncryptionType),
        (None, false) => Err(SspiGssProviderConfigError::PrincipalNotFound),
    }
}

fn encryption_strength(encryption_type: u16) -> u8 {
    match encryption_type {
        ETYPE_AES256_CTS_HMAC_SHA1_96 => 2,
        ETYPE_AES128_CTS_HMAC_SHA1_96 => 1,
        _ => 0,
    }
}

struct KeytabDecoder<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> KeytabDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], SspiGssProviderConfigError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(SspiGssProviderConfigError::InvalidKeytab("keytab length overflow"))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(SspiGssProviderConfigError::InvalidKeytab("truncated keytab"))?;
        self.position = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, SspiGssProviderConfigError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, SspiGssProviderConfigError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| SspiGssProviderConfigError::InvalidKeytab("truncated keytab integer"))?,
        ))
    }

    fn u32(&mut self) -> Result<u32, SspiGssProviderConfigError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| SspiGssProviderConfigError::InvalidKeytab("truncated keytab integer"))?,
        ))
    }

    fn i32(&mut self) -> Result<i32, SspiGssProviderConfigError> {
        Ok(i32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| SspiGssProviderConfigError::InvalidKeytab("truncated keytab integer"))?,
        ))
    }

    fn counted_string(&mut self, maximum: usize) -> Result<String, SspiGssProviderConfigError> {
        let length = usize::from(self.u16()?);
        if length > maximum {
            return Err(SspiGssProviderConfigError::InvalidKeytab("keytab string limit exceeded"));
        }
        std::str::from_utf8(self.take(length)?)
            .map(str::to_owned)
            .map_err(|_| SspiGssProviderConfigError::InvalidKeytab("keytab string is not UTF-8"))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use sspi::kerberos::test_data;

    use super::*;

    const SERVICE_PRINCIPAL: &str = "nfs/server.example.test@EXAMPLE.TEST";

    struct TestKeytabEntry<'a> {
        principal: &'a str,
        kvno: u32,
        encryption_type: u16,
        key: &'a [u8],
    }

    fn keytab(entries: &[TestKeytabEntry<'_>]) -> Bytes {
        let mut encoded = MIT_KEYTAB_V2.to_be_bytes().to_vec();
        for entry in entries {
            let (name, realm) = entry.principal.rsplit_once('@').expect("test principal has a realm");
            let components = name.split('/').collect::<Vec<_>>();
            let mut record = Vec::new();
            record.extend_from_slice(
                &u16::try_from(components.len())
                    .expect("test component count fits")
                    .to_be_bytes(),
            );
            push_counted_string(&mut record, realm);
            for component in components {
                push_counted_string(&mut record, component);
            }
            record.extend_from_slice(&2_u32.to_be_bytes());
            record.extend_from_slice(&0_u32.to_be_bytes());
            record.push(entry.kvno as u8);
            record.extend_from_slice(&entry.encryption_type.to_be_bytes());
            record.extend_from_slice(&u16::try_from(entry.key.len()).expect("test key length fits").to_be_bytes());
            record.extend_from_slice(entry.key);
            record.extend_from_slice(&entry.kvno.to_be_bytes());
            record.extend_from_slice(&0_u32.to_be_bytes());
            encoded.extend_from_slice(&i32::try_from(record.len()).expect("test record length fits").to_be_bytes());
            encoded.extend_from_slice(&record);
        }
        Bytes::from(encoded)
    }

    fn push_counted_string(output: &mut Vec<u8>, value: &str) {
        output.extend_from_slice(&u16::try_from(value.len()).expect("test string length fits").to_be_bytes());
        output.extend_from_slice(value.as_bytes());
    }

    fn test_provider() -> SspiGssProvider {
        SspiGssProvider::from_keytab_bytes(
            SERVICE_PRINCIPAL,
            keytab(&[TestKeytabEntry {
                principal: SERVICE_PRINCIPAL,
                kvno: 7,
                encryption_type: ETYPE_AES256_CTS_HMAC_SHA1_96,
                key: &[0x42; AES256_KEY_SIZE],
            }]),
        )
        .expect("test provider")
    }

    async fn insert_established_context(
        provider: &SspiGssProvider,
        context_id: ProviderContextId,
        kerberos: Kerberos,
        expires_at: Instant,
    ) {
        provider.state.lock().await.contexts.insert(
            context_id,
            ContextSlot {
                context: Arc::new(Mutex::new(ProviderContext {
                    kerberos,
                    credentials_handle: None,
                    version: Version::V1,
                    phase: ProviderPhase::Established,
                    accept_steps: 1,
                    expires_at,
                })),
                expires_at,
            },
        );
    }

    fn decrypt_stream(kerberos: &mut Kerberos, token: &[u8]) -> Vec<u8> {
        let mut stream = token.to_vec();
        let mut empty = [];
        let plaintext = {
            let mut buffers = [
                SecurityBufferRef::stream_buf(&mut stream),
                SecurityBufferRef::data_buf(&mut empty),
            ];
            kerberos.decrypt_message(&mut buffers).expect("SSPI decrypts token");
            buffers[1].data().to_vec()
        };
        plaintext
    }

    #[test]
    fn keytab_selects_highest_kvno_then_strongest_aes_key() {
        let aes128 = [0x11; AES128_KEY_SIZE];
        let aes256 = [0x22; AES256_KEY_SIZE];
        let encoded = keytab(&[
            TestKeytabEntry {
                principal: "nfs/other.example.test@EXAMPLE.TEST",
                kvno: 99,
                encryption_type: ETYPE_AES256_CTS_HMAC_SHA1_96,
                key: &aes256,
            },
            TestKeytabEntry {
                principal: SERVICE_PRINCIPAL,
                kvno: 8,
                encryption_type: ETYPE_AES128_CTS_HMAC_SHA1_96,
                key: &aes128,
            },
            TestKeytabEntry {
                principal: SERVICE_PRINCIPAL,
                kvno: 7,
                encryption_type: ETYPE_AES256_CTS_HMAC_SHA1_96,
                key: &aes256,
            },
            TestKeytabEntry {
                principal: SERVICE_PRINCIPAL,
                kvno: 8,
                encryption_type: ETYPE_AES256_CTS_HMAC_SHA1_96,
                key: &aes256,
            },
        ]);

        let provider = SspiGssProvider::from_keytab_bytes(SERVICE_PRINCIPAL, encoded).expect("valid keytab");

        assert_eq!(
            provider.selected_key,
            SelectedKeyMetadata {
                kvno: 8,
                encryption_type: ETYPE_AES256_CTS_HMAC_SHA1_96,
            }
        );
    }

    #[tokio::test]
    async fn keytab_rejects_unsupported_versions_enctypes_and_size() {
        let version_error =
            SspiGssProvider::from_keytab_bytes(SERVICE_PRINCIPAL, Bytes::from_static(&[0x05, 0x01])).unwrap_err();
        assert!(matches!(version_error, SspiGssProviderConfigError::UnsupportedKeytabVersion(0x0501)));

        let legacy_key = [0x33; 16];
        let legacy = keytab(&[TestKeytabEntry {
            principal: SERVICE_PRINCIPAL,
            kvno: 1,
            encryption_type: 23,
            key: &legacy_key,
        }]);
        let enctype_error = SspiGssProvider::from_keytab_bytes(SERVICE_PRINCIPAL, legacy).unwrap_err();
        assert!(matches!(enctype_error, SspiGssProviderConfigError::UnsupportedEncryptionType));

        let encoded = keytab(&[TestKeytabEntry {
            principal: SERVICE_PRINCIPAL,
            kvno: 1,
            encryption_type: ETYPE_AES256_CTS_HMAC_SHA1_96,
            key: &[0x44; AES256_KEY_SIZE],
        }]);
        let mut config = SspiGssProviderConfig::from_keytab_bytes(SERVICE_PRINCIPAL, encoded.clone());
        config.limits.max_keytab_bytes = encoded.len() - 1;
        let size_error = SspiGssProvider::new(config).await.unwrap_err();
        assert!(matches!(size_error, SspiGssProviderConfigError::KeytabTooLarge));
    }

    #[tokio::test]
    async fn keytab_path_constructor_loads_the_configured_file() {
        let encoded = keytab(&[TestKeytabEntry {
            principal: SERVICE_PRINCIPAL,
            kvno: 5,
            encryption_type: ETYPE_AES128_CTS_HMAC_SHA1_96,
            key: &[0x55; AES128_KEY_SIZE],
        }]);
        let filename = format!("nfsserve-sspi-keytab-{}-{}.keytab", std::process::id(), rand::random::<u64>());
        let path = std::env::temp_dir().join(filename);
        fs::write(&path, &encoded).expect("write test keytab");

        let result = SspiGssProvider::from_keytab_path(SERVICE_PRINCIPAL, &path).await;
        let _ = fs::remove_file(&path);
        let provider = result.expect("load test keytab");

        assert_eq!(provider.service_principal(), SERVICE_PRINCIPAL);
        assert_eq!(provider.selected_key.kvno, 5);
    }

    #[test]
    fn rfc4121_mic_round_trip_rejects_wrong_direction_and_tampering() {
        let key = [0x66; AES256_KEY_SIZE];
        let message = b"header through credential";
        let mic = generate_mic(&key, &AesSize::Aes256, 41, message, false).expect("generate initiator MIC");

        verify_mic(&key, &AesSize::Aes256, message, &mic, false).expect("verify initiator MIC");
        assert_eq!(verify_mic(&key, &AesSize::Aes256, message, &mic, true), Err(ProviderError::InvalidToken));
        assert_eq!(verify_mic(&key, &AesSize::Aes256, b"altered", &mic, false), Err(ProviderError::Integrity));
    }

    #[test]
    fn rfc4121_integrity_unwrap_enforces_direction_integrity_and_bounds() {
        let mut client = test_data::fake_client();
        let session_key = client.query_context_session_key().expect("client session key").session_key;
        let message = b"bounded integrity-only payload";
        let encoded = generate_integrity_wrap(session_key.as_ref(), &AesSize::Aes256, 42, message, true)
            .expect("generate acceptor integrity token");
        assert_eq!(WrapToken::decode(encoded.as_slice()).expect("decode integrity token").flags, 0x05);

        assert_eq!(
            unwrap_message(&mut client, &encoded, message.len(), true).expect("unwrap integrity token"),
            Bytes::from_static(message)
        );
        assert_eq!(unwrap_message(&mut client, &encoded, message.len(), false), Err(ProviderError::InvalidToken));
        assert_eq!(unwrap_message(&mut client, &encoded, message.len() - 1, true), Err(ProviderError::Resource));

        let mut tampered = encoded.clone();
        *tampered.last_mut().expect("token has a checksum") ^= 0x80;
        assert_eq!(unwrap_message(&mut client, &tampered, message.len(), true), Err(ProviderError::Integrity));

        let mut invalid_flags = WrapToken::decode(encoded.as_slice()).expect("decode Wrap token");
        invalid_flags.flags |= 0x08;
        let mut invalid_flags_encoded = Vec::new();
        invalid_flags
            .encode(&mut invalid_flags_encoded)
            .expect("encode invalid flags token");
        assert_eq!(
            unwrap_message(&mut client, &invalid_flags_encoded, message.len(), true),
            Err(ProviderError::InvalidToken)
        );

        let mut invalid_ec = WrapToken::decode(encoded.as_slice()).expect("decode Wrap token");
        invalid_ec.ec = u16::try_from(AES_MAC_SIZE - 1).expect("AES MAC size fits");
        let mut invalid_ec_encoded = Vec::new();
        invalid_ec.encode(&mut invalid_ec_encoded).expect("encode invalid EC token");
        assert_eq!(
            unwrap_message(&mut client, &invalid_ec_encoded, message.len(), true),
            Err(ProviderError::InvalidToken)
        );
    }

    #[tokio::test]
    async fn established_context_interoperates_for_mic_wrap_and_unwrap() {
        let provider = test_provider();
        let context_id = ProviderContextId(0xfeed);
        insert_established_context(
            &provider,
            context_id,
            test_data::fake_server(),
            Instant::now() + Duration::from_secs(60),
        )
        .await;
        let mut client = test_data::fake_client();
        let message = Bytes::from_static(b"portable Kerberos message");

        let integrity_token = provider
            .wrap(context_id, message.clone(), false)
            .await
            .expect("integrity-only Wrap");
        let decoded = WrapToken::decode(integrity_token.as_ref()).expect("decode Wrap token");
        assert_eq!(decoded.flags & 0x03, 0x01);
        assert_eq!(decoded.ec, u16::try_from(AES_MAC_SIZE).expect("AES MAC size fits"));
        assert_eq!(decrypt_stream(&mut client, &integrity_token).as_slice(), message.as_ref());

        let privacy_token = provider.wrap(context_id, message.clone(), true).await.expect("privacy Wrap");
        assert_eq!(WrapToken::decode(privacy_token.as_ref()).expect("decode privacy token").flags & 0x03, 0x03);
        assert_eq!(decrypt_stream(&mut client, &privacy_token).as_slice(), message.as_ref());

        let inbound_privacy = seal_message(&mut client, b"client privacy", 4096).expect("client privacy token");
        assert_eq!(
            provider
                .unwrap(context_id, inbound_privacy)
                .await
                .expect("provider privacy unwrap"),
            Bytes::from_static(b"client privacy")
        );

        let session_key = client.query_context_session_key().expect("client session key").session_key;
        let inbound_integrity =
            generate_integrity_wrap(session_key.as_ref(), &AesSize::Aes256, 93, b"client integrity", false)
                .expect("client integrity token");
        assert_eq!(
            provider
                .unwrap(context_id, Bytes::from(inbound_integrity))
                .await
                .expect("provider integrity unwrap"),
            Bytes::from_static(b"client integrity")
        );

        let outbound_mic = provider
            .get_mic(context_id, Bytes::from_static(b"reply verifier"))
            .await
            .expect("acceptor MIC");
        assert_eq!(MicToken::decode(outbound_mic.as_ref()).expect("decode MIC").flags & 0x03, 0x01);
        let inbound_mic = generate_mic(session_key.as_ref(), &AesSize::Aes256, 94, b"request verifier", false)
            .expect("initiator MIC");
        provider
            .verify_mic(context_id, Bytes::from_static(b"request verifier"), Bytes::from(inbound_mic))
            .await
            .expect("provider MIC verification");

        provider
            .delete_security_context(context_id)
            .await
            .expect("delete established context");
        assert_eq!(provider.get_mic(context_id, Bytes::new()).await, Err(ProviderError::UnknownContext));
    }

    #[tokio::test]
    async fn expired_and_failed_contexts_do_not_consume_context_capacity() {
        let mut provider = test_provider();
        provider.limits.max_contexts = 1;
        provider.limits.max_replay_entries = 1;
        let expired_id = ProviderContextId(0xbeef);
        insert_established_context(&provider, expired_id, test_data::fake_server(), Instant::now()).await;
        let expired_digest = [0x5a; 32];
        {
            let mut state = provider.state.lock().await;
            state.replay_digests.insert(expired_digest);
            state.replay_order.push_back(ReplayEntry {
                digest: expired_digest,
                expires_at: Instant::now(),
            });
        }
        assert_eq!(provider.get_mic(expired_id, Bytes::new()).await, Err(ProviderError::Expired));

        let result = provider
            .accept_security_context(None, Version::V1, Bytes::from_static(b"not a Kerberos token"))
            .await;
        assert!(matches!(result, Err(error) if error != ProviderError::Resource));
        let state = provider.state.lock().await;
        assert!(state.contexts.is_empty());
        assert!(state.replay_digests.is_empty());
        assert!(state.replay_order.is_empty());
    }

    #[tokio::test]
    async fn destroy_frees_the_context_slot_without_erasing_the_init_replay_guard() {
        let mut provider = test_provider();
        provider.limits.max_contexts = 1;
        provider.limits.max_replay_entries = 2;
        let context_id = ProviderContextId(0xcafe);
        insert_established_context(
            &provider,
            context_id,
            test_data::fake_server(),
            Instant::now() + Duration::from_secs(60),
        )
        .await;
        let original_digest = [0x6b; 32];
        {
            let mut state = provider.state.lock().await;
            state.replay_digests.insert(original_digest);
            state.replay_order.push_back(ReplayEntry {
                digest: original_digest,
                expires_at: Instant::now() + Duration::from_secs(60),
            });
        }

        provider
            .delete_security_context(context_id)
            .await
            .expect("destroy removes the provider context");
        let result = provider
            .accept_security_context(None, Version::V1, Bytes::from_static(b"a different invalid Kerberos token"))
            .await;
        assert!(matches!(result, Err(error) if error != ProviderError::Resource));

        let state = provider.state.lock().await;
        assert!(state.contexts.is_empty());
        assert_eq!(state.replay_order.len(), 1);
        assert_eq!(state.replay_order.front().map(|entry| entry.digest), Some(original_digest));
        assert!(state.replay_digests.contains(&original_digest));
    }
}
