//! Provider boundary for outbound RPCSEC_GSS security contexts.
//!
//! The RPCSEC_GSS callback client owns context handles and RPC sequence
//! numbers.  Implementations of this trait own only the mechanism context and
//! its cryptographic operations.  Keeping this boundary independent of SSPI
//! makes the callback wire state machine exactly testable without a KDC.

use std::time::Instant;

use async_trait::async_trait;
use bytes::Bytes;

use super::{ProviderContextId, ProviderError, Version};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitiateContext {
    pub provider_context: ProviderContextId,
    pub version: Version,
    pub target_name: String,
    /// Absolute monotonic deadline after which this context must not
    /// authenticate or protect another callback RPC.
    pub expires_at: Instant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitiateOutcome {
    pub context: InitiateContext,
    pub output_token: Bytes,
    pub complete: bool,
}

/// Portable initiator operations needed by an RPCSEC_GSS callback session.
#[async_trait]
pub trait GssInitiatorProvider: Send + Sync + 'static {
    /// Starts or advances one GSS context.
    ///
    /// `input_token` is empty for the first call.  A continuation must retain
    /// the same version and target name.
    async fn initiate_security_context(
        &self,
        continuation: Option<InitiateContext>,
        version: Version,
        target_name: &str,
        input_token: Bytes,
    ) -> Result<InitiateOutcome, ProviderError>;

    async fn verify_mic(&self, context: ProviderContextId, message: Bytes, mic: Bytes) -> Result<(), ProviderError>;

    async fn get_mic(&self, context: ProviderContextId, message: Bytes) -> Result<Bytes, ProviderError>;

    async fn unwrap(&self, context: ProviderContextId, token: Bytes) -> Result<Bytes, ProviderError>;

    async fn wrap(
        &self,
        context: ProviderContextId,
        message: Bytes,
        confidentiality: bool,
    ) -> Result<Bytes, ProviderError>;

    async fn delete_security_context(&self, context: ProviderContextId) -> Result<(), ProviderError>;
}
