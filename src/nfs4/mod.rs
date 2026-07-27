//! NFS version 4.0 wire types and bounded XDR codecs.
//!
//! The protocol definitions follow RFC 7530 and the canonical XDR in
//! RFC 7531. This module intentionally models only NFSv4.0: callers must
//! reject non-zero `minorversion` values at the protocol layer.

pub mod attribute_engine;
pub mod attributes;
pub(crate) mod callback;
pub mod codec;
pub(crate) mod compound;
pub(crate) mod delegation;
pub mod legal_errors;
pub mod locations;
pub(crate) mod namespace;
pub(crate) mod open_pins;
pub(crate) mod reply_budget;
pub(crate) mod runtime;
pub(crate) mod stable;
pub(crate) mod state;
pub mod types;

pub use attributes::{bitmap_contains, bitmap_from_attributes, AttributeEncodeError, AttributeEncoder};
pub use codec::{
    decode_callback_compound_args, decode_callback_compound_res, decode_compound_args, decode_compound_res,
    encode_callback_compound_args, encode_callback_compound_res, encode_compound_args, encode_compound_res,
    DecodeLimits,
};
pub use types::*;
