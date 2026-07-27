mod codec;

pub use codec::{HandleCodec, HandleError, HandleTarget, HANDLE_SIZE, ROUTED_HANDLE_SIZE};
pub(crate) use codec::{HandleCodecSet, HandleLifetime};
