#![cfg_attr(feature = "strict", deny(warnings))]

#[cfg(feature = "demo")]
mod context;
pub mod rpc;
#[cfg(feature = "demo")]
mod rpcwire;
#[cfg(feature = "demo")]
mod write_counter;
#[cfg(feature = "demo")]
pub mod xdr;

#[cfg(feature = "demo")]
mod mount;
#[cfg(feature = "demo")]
mod mount_handlers;

pub mod portmap;
#[cfg(feature = "demo")]
mod portmap_handlers;

#[cfg(feature = "demo")]
pub mod nfs;
#[cfg(feature = "demo")]
mod nfs_handlers;

pub mod handles;
pub mod mount3;
pub mod nfs3;
pub mod observability;
pub mod replay;
pub mod server;

#[cfg(all(feature = "demo", any(unix, windows)))]
pub mod fs_util;

#[cfg(feature = "demo")]
pub mod tcp;
#[cfg(feature = "demo")]
mod transaction_tracker;
pub mod vfs;

pub use server::{
    AuthPolicy, MountInfo, NfsServer, NfsServerBuilder, PortmapperMode, PortmapperSockets, ServerError, ServerHandle,
    ServerLimits,
};
pub use vfs::{ExportId, Principal, RequestContext, VirtualFileSystem};
