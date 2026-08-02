//! RPCSEC_GSS versions 1 and 2.
//!
//! The wire layer and replay window are provider-independent. The Kerberos
//! provider supplies context establishment, MIC, wrap, and unwrap operations.

mod context;
mod initiator;
mod provider;
mod sequence;
mod sspi;
mod sspi_initiator;
mod xdr;

pub use context::{
    AuthenticatedGssRequest, ChannelBindingMaterial, ChannelBindingOutcome, GssContextError, GssContextLimits,
    GssContextRegistry,
};
pub use initiator::{GssInitiatorProvider, InitiateContext, InitiateOutcome};
pub use provider::{
    AcceptContext, AcceptOutcome, GssIdentity, GssProvider, ProtectionSizes, ProviderContextId, ProviderError,
};
pub use sequence::{SequenceWindow, SequenceWindowError};
pub use sspi::{
    SspiGssProvider, SspiGssProviderConfig, SspiGssProviderConfigError, SspiGssProviderLimits, SspiKeytabSource,
};
pub use sspi_initiator::{
    SspiGssInitiator, SspiGssInitiatorConfig, SspiGssInitiatorConfigError, SspiGssInitiatorLimits,
};
pub use xdr::{
    encode_channel_binding_mic_in_args, encode_channel_binding_mic_in_result, ChannelBindingStatus,
    ChannelBindingVerifierArgs, ChannelBindingVerifierResult, Credential, GssLimits, InitArgs, InitResult,
    IntegrityBody, PrivacyBody, Procedure, Service, Version, MAX_SEQUENCE_NUMBER, RPCSEC_GSS,
};
