use std::net::SocketAddr;

/// Identifies one export within a server instance.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExportId(pub u32);

/// The authenticated caller of an RPC request.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Principal {
    Anonymous,
    AuthSys {
        uid: u32,
        gid: u32,
        supplementary_gids: Vec<u32>,
        machine_name: Vec<u8>,
    },
    Gss {
        canonical_name: String,
        mechanism: Vec<u8>,
        version: GssVersion,
        service: GssService,
    },
}

/// Fully authenticated security identity supplied to backend authorization.
///
/// `Principal` already records the RPC authentication mechanism and service,
/// so this alias keeps the public contract version-neutral.
pub type SecurityContext = Principal;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GssVersion {
    V1,
    V2,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GssService {
    Authentication,
    Integrity,
    Privacy,
    ChannelProtection,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProtocolVersion {
    V3,
    V4,
}

/// Context supplied to every backend operation.
#[derive(Clone, Debug)]
pub struct RequestContext {
    pub principal: Principal,
    pub client_addr: SocketAddr,
    pub export_id: ExportId,
    pub protocol: ProtocolVersion,
    /// NFSv4 client ID after SETCLIENTID confirmation. It is absent for NFSv3
    /// and for NFSv4 operations that precede client identification.
    pub client_id: Option<u64>,
}

impl RequestContext {
    pub fn security_context(&self) -> &SecurityContext {
        &self.principal
    }
}
