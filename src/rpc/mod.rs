pub mod auth;
pub mod codec;
pub mod message;
#[cfg(feature = "demo")]
mod message_legacy;
pub mod record;

#[cfg(feature = "demo")]
pub use message_legacy::*;
