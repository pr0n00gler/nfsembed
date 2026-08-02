use std::time::Instant;

use async_trait::async_trait;
use bytes::Bytes;

use super::Version;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProviderContextId(pub u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GssIdentity {
    pub principal: String,
    pub mechanism: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptContext {
    pub provider_context: ProviderContextId,
    pub version: Version,
    /// Absolute monotonic deadline after which the provider context must not
    /// authenticate or protect any more RPC messages.
    pub expires_at: Instant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptOutcome {
    pub context: AcceptContext,
    pub major_status: u32,
    pub minor_status: u32,
    pub output_token: Bytes,
    pub complete_identity: Option<GssIdentity>,
}

impl AcceptOutcome {
    pub fn is_complete(&self) -> bool {
        self.complete_identity.is_some()
    }
}

/// Provider-specific upper bounds used to reserve an RPC reply before the
/// server executes an operation with side effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectionSizes {
    /// Maximum encoded MIC token returned by `get_mic`.
    pub max_mic_token_bytes: usize,
    /// Maximum number of bytes that confidentiality wrapping may add to its
    /// plaintext input.
    pub max_wrap_overhead_bytes: usize,
}

/// Provider boundary used by the portable Kerberos implementation.
///
/// RPCSEC_GSS itself owns handles and sequence windows; the provider's
/// context identifier is never placed on the wire.
#[async_trait]
pub trait GssProvider: Send + Sync + 'static {
    async fn accept_security_context(
        &self,
        continuation: Option<AcceptContext>,
        version: Version,
        token: Bytes,
    ) -> Result<AcceptOutcome, ProviderError>;

    async fn verify_mic(&self, context: ProviderContextId, message: Bytes, mic: Bytes) -> Result<(), ProviderError>;

    async fn get_mic(&self, context: ProviderContextId, message: Bytes) -> Result<Bytes, ProviderError>;

    async fn unwrap(&self, context: ProviderContextId, token: Bytes) -> Result<Bytes, ProviderError>;

    async fn wrap(
        &self,
        context: ProviderContextId,
        message: Bytes,
        confidentiality: bool,
    ) -> Result<Bytes, ProviderError>;

    async fn protection_sizes(&self, context: ProviderContextId) -> Result<ProtectionSizes, ProviderError>;

    async fn delete_security_context(&self, context: ProviderContextId) -> Result<(), ProviderError>;
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProviderError {
    #[error("GSS context is unknown")]
    UnknownContext,
    #[error("GSS context has expired")]
    Expired,
    #[error("GSS token is invalid")]
    InvalidToken,
    #[error("GSS message integrity verification failed")]
    Integrity,
    #[error("GSS confidentiality operation failed")]
    Privacy,
    #[error("GSS mechanism error: major={major}, minor={minor}")]
    Mechanism { major: u32, minor: u32 },
    #[error("GSS provider resource limit was reached")]
    Resource,
}
