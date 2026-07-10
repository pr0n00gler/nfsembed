use std::net::SocketAddr;

/// Identifies one export within a server instance.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ExportId(pub u32);

/// The authenticated caller of an RPC request.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Principal {
    Anonymous,
    AuthSys {
        uid: u32,
        gid: u32,
        supplementary_gids: Vec<u32>,
        machine_name: Vec<u8>,
    },
}

/// Context supplied to every backend operation.
#[derive(Clone, Debug)]
pub struct RequestContext {
    pub principal: Principal,
    pub client_addr: SocketAddr,
    pub export_id: ExportId,
}
