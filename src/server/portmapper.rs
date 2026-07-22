use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;
use tokio::time::timeout;

use super::{ServerError, ServerLimits};
use crate::portmap::mapping;
use crate::rpc::auth::{decode_principal, AUTH_NONE};
use crate::rpc::codec::{Decoder, Encoder};
use crate::rpc::record::{read_record, write_record_limited, RecordLimits};

const RPC_CALL: u32 = 0;
const RPC_REPLY: u32 = 1;
const MSG_ACCEPTED: u32 = 0;
const MSG_DENIED: u32 = 1;
const SUCCESS: u32 = 0;
const PROG_UNAVAIL: u32 = 1;
const PROG_MISMATCH: u32 = 2;
const PROC_UNAVAIL: u32 = 3;
const GARBAGE_ARGS: u32 = 4;
const RPC_MISMATCH: u32 = 0;
const AUTH_ERROR: u32 = 1;
const AUTH_BAD_CRED: u32 = 1;
const AUTH_BAD_VERF: u32 = 3;
const PORTMAP_NULL: u32 = 0;
const PORTMAP_GETPORT: u32 = 3;
const MAX_PORTMAP_RECORD_SIZE: usize = 4096;
const MAX_PORTMAP_FRAGMENTS: usize = 16;
const MAX_UDP_DATAGRAM_SIZE: usize = u16::MAX as usize;

/// Caller-owned TCP and UDP sockets for a standalone portmapper v2 endpoint.
///
/// Windows Client for NFS discovers NFSv3 and MOUNTv3 through portmapper on
/// TCP and UDP port 111. Applications remain responsible for binding that
/// privileged port and pass both sockets to [`crate::NfsServer`].
pub struct PortmapperSockets {
    tcp: TcpListener,
    udp: UdpSocket,
    advertised_ports: Option<(u16, u16)>,
}

impl PortmapperSockets {
    pub fn new(tcp: TcpListener, udp: UdpSocket) -> Self {
        Self {
            tcp,
            udp,
            advertised_ports: None,
        }
    }

    /// Overrides the NFS and MOUNT ports returned by `GETPORT`.
    ///
    /// By default both mappings use the primary NFS listener's bound port.
    /// This override is useful when a transport proxy sits in front of the
    /// embedded server.
    pub fn advertised_ports(mut self, nfs_port: u16, mount_port: u16) -> Self {
        self.advertised_ports = Some((nfs_port, mount_port));
        self
    }

    pub(crate) fn prepare(self, primary_port: u16) -> Result<PreparedPortmapper, ServerError> {
        let tcp_addr = self.tcp.local_addr()?;
        let udp_addr = self.udp.local_addr()?;
        if tcp_addr != udp_addr {
            return Err(ServerError::InvalidConfiguration(
                "portmapper TCP and UDP sockets must use the same local address",
            ));
        }
        if tcp_addr.port() == 0 || primary_port == 0 {
            return Err(ServerError::InvalidConfiguration("listener ports must be bound and non-zero"));
        }
        let (nfs_port, mount_port) = self.advertised_ports.unwrap_or((primary_port, primary_port));
        if nfs_port == 0 || mount_port == 0 {
            return Err(ServerError::InvalidConfiguration("advertised NFS and MOUNT ports must be non-zero"));
        }
        Ok(PreparedPortmapper {
            tcp: self.tcp,
            udp: self.udp,
            local_addr: tcp_addr,
            nfs_port,
            mount_port,
        })
    }
}

pub(crate) struct PreparedPortmapper {
    tcp: TcpListener,
    udp: UdpSocket,
    pub local_addr: SocketAddr,
    nfs_port: u16,
    mount_port: u16,
}

pub(crate) async fn run_portmapper(
    portmapper: PreparedPortmapper,
    mut shutdown: watch::Receiver<bool>,
    connections: Arc<Semaphore>,
    limits: ServerLimits,
) -> Result<(), ServerError> {
    let PreparedPortmapper {
        tcp,
        udp,
        local_addr,
        nfs_port,
        mount_port,
    } = portmapper;
    tracing::debug!(address = %local_addr, nfs_port, mount_port, "portmapper started");
    let mut tasks = JoinSet::new();
    // Winsock reports WSAEMSGSIZE instead of returning a truncated length when
    // the receive buffer is too small. A maximum-size buffer lets every valid
    // UDP datagram be received and rejected as a packet-local protocol error.
    let mut datagram = vec![0u8; MAX_UDP_DATAGRAM_SIZE];
    loop {
        while let Some(result) = tasks.try_join_next() {
            if let Err(error) = result {
                tracing::warn!(error = %error, "portmapper connection task failed");
            }
        }
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = tcp.accept() => {
                let (stream, client_addr) = accepted?;
                let permit = match connections.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        tracing::warn!(client = %client_addr, "portmapper connection rejected: limit reached");
                        continue;
                    }
                };
                let connection_shutdown = shutdown.clone();
                let connection_limits = limits.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = serve_tcp_connection(
                        stream,
                        client_addr,
                        nfs_port,
                        mount_port,
                        connection_shutdown,
                        &connection_limits,
                    ).await {
                        tracing::debug!(client = %client_addr, error = %error, "portmapper connection closed with error");
                    }
                });
            }
            received = udp.recv_from(&mut datagram) => {
                let (length, client_addr) = match received {
                    Ok(received) => received,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused
                        ) =>
                    {
                        tracing::debug!(error = %error, "portmapper UDP peer became unreachable");
                        continue;
                    },
                    Err(error) => return Err(error.into()),
                };
                if length > MAX_PORTMAP_RECORD_SIZE {
                    tracing::debug!(client = %client_addr, bytes = length, "oversized portmapper datagram dropped");
                    continue;
                }
                if let Some(reply) = dispatch_record(&datagram[..length], nfs_port, mount_port) {
                    match timeout(limits.request_timeout, udp.send_to(&reply, client_addr)).await {
                        Ok(Ok(_)) => {},
                        Ok(Err(error)) => tracing::debug!(client = %client_addr, error = %error, "portmapper UDP reply failed"),
                        Err(_) => tracing::debug!(client = %client_addr, "portmapper UDP reply timed out"),
                    }
                }
            }
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(error) = result {
                    tracing::warn!(error = %error, "portmapper connection task failed");
                }
            }
        }
    }
    while tasks.join_next().await.is_some() {}
    tracing::debug!(address = %local_addr, "portmapper stopped");
    Ok(())
}

async fn serve_tcp_connection(
    mut stream: TcpStream,
    client_addr: SocketAddr,
    nfs_port: u16,
    mount_port: u16,
    mut shutdown: watch::Receiver<bool>,
    limits: &ServerLimits,
) -> Result<(), ServerError> {
    stream.set_nodelay(true)?;
    let record_limits = RecordLimits {
        max_record_size: MAX_PORTMAP_RECORD_SIZE,
        max_fragment_size: MAX_PORTMAP_RECORD_SIZE,
        max_fragments: MAX_PORTMAP_FRAGMENTS,
    };
    loop {
        let record = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
                continue;
            }
            result = timeout(limits.idle_connection_timeout, read_record(&mut stream, record_limits)) => {
                match result {
                    Err(_) => return Ok(()),
                    Ok(Err(crate::rpc::record::RecordError::Io(error)))
                        if matches!(error.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset) =>
                    {
                        return Ok(())
                    },
                    Ok(Err(error)) => return Err(error.into()),
                    Ok(Ok(record)) => record,
                }
            }
        };
        let Some(reply) = dispatch_record(&record, nfs_port, mount_port) else {
            tracing::debug!(client = %client_addr, "malformed portmapper record dropped");
            continue;
        };
        match timeout(limits.request_timeout, write_record_limited(&mut stream, &reply, record_limits)).await {
            Ok(result) => result?,
            Err(_) => return Err(ServerError::RequestTimeout),
        }
    }
}

fn dispatch_record(record: &[u8], nfs_port: u16, mount_port: u16) -> Option<Vec<u8>> {
    let mut decoder = Decoder::new(record);
    let xid = decoder.read_u32().ok()?;
    let message_type = match decoder.read_u32() {
        Ok(message_type) => message_type,
        Err(_) => return Some(accepted_reply(xid, GARBAGE_ARGS, &[])),
    };
    if message_type != RPC_CALL {
        return None;
    }
    let rpc_version = match decoder.read_u32() {
        Ok(version) => version,
        Err(_) => return Some(accepted_reply(xid, GARBAGE_ARGS, &[])),
    };
    if rpc_version != 2 {
        return Some(rpc_mismatch(xid));
    }
    let program = match decoder.read_u32() {
        Ok(program) => program,
        Err(_) => return Some(accepted_reply(xid, GARBAGE_ARGS, &[])),
    };
    let version = match decoder.read_u32() {
        Ok(version) => version,
        Err(_) => return Some(accepted_reply(xid, GARBAGE_ARGS, &[])),
    };
    let procedure = match decoder.read_u32() {
        Ok(procedure) => procedure,
        Err(_) => return Some(accepted_reply(xid, GARBAGE_ARGS, &[])),
    };
    let credential_flavor = match decoder.read_u32() {
        Ok(flavor) => flavor,
        Err(_) => return Some(accepted_reply(xid, GARBAGE_ARGS, &[])),
    };
    let credential = match decoder.read_opaque_slice("RPC credential", 400) {
        Ok(credential) => credential,
        Err(_) => return Some(auth_error(xid, AUTH_BAD_CRED)),
    };
    if decode_principal(credential_flavor, credential).is_err() {
        return Some(auth_error(xid, AUTH_BAD_CRED));
    }
    let verifier_flavor = match decoder.read_u32() {
        Ok(flavor) => flavor,
        Err(_) => return Some(auth_error(xid, AUTH_BAD_VERF)),
    };
    let verifier = match decoder.read_opaque_slice("RPC verifier", 400) {
        Ok(verifier) => verifier,
        Err(_) => return Some(auth_error(xid, AUTH_BAD_VERF)),
    };
    if verifier_flavor != AUTH_NONE || !verifier.is_empty() {
        return Some(auth_error(xid, AUTH_BAD_VERF));
    }
    if program != crate::portmap::PROGRAM {
        return Some(accepted_reply(xid, PROG_UNAVAIL, &[]));
    }
    if version != crate::portmap::VERSION {
        let mut body = Encoder::new();
        body.write_u32(crate::portmap::VERSION);
        body.write_u32(crate::portmap::VERSION);
        return Some(accepted_reply(xid, PROG_MISMATCH, &body.into_bytes()));
    }
    let args = &record[decoder.position()..];
    match procedure {
        PORTMAP_NULL if args.is_empty() => Some(accepted_reply(xid, SUCCESS, &[])),
        PORTMAP_NULL => Some(accepted_reply(xid, GARBAGE_ARGS, &[])),
        PORTMAP_GETPORT => {
            let request = (|| {
                let mut decoder = Decoder::new(args);
                let request = mapping {
                    prog: decoder.read_u32()?,
                    vers: decoder.read_u32()?,
                    prot: decoder.read_u32()?,
                    port: decoder.read_u32()?,
                };
                decoder.finish()?;
                Ok::<_, crate::rpc::codec::DecodeError>(request)
            })();
            let Ok(request) = request else {
                return Some(accepted_reply(xid, GARBAGE_ARGS, &[]));
            };
            let mut body = Encoder::new();
            body.write_u32(crate::portmap::dispatch::get_port(&request, nfs_port, mount_port));
            Some(accepted_reply(xid, SUCCESS, &body.into_bytes()))
        },
        _ => Some(accepted_reply(xid, PROC_UNAVAIL, &[])),
    }
}

fn accepted_reply(xid: u32, status: u32, body: &[u8]) -> Vec<u8> {
    let mut reply = Encoder::new();
    reply.write_u32(xid);
    reply.write_u32(RPC_REPLY);
    reply.write_u32(MSG_ACCEPTED);
    reply.write_u32(AUTH_NONE);
    reply.write_u32(0);
    reply.write_u32(status);
    reply.write_fixed(body);
    reply.into_bytes()
}

fn rpc_mismatch(xid: u32) -> Vec<u8> {
    let mut reply = Encoder::new();
    reply.write_u32(xid);
    reply.write_u32(RPC_REPLY);
    reply.write_u32(MSG_DENIED);
    reply.write_u32(RPC_MISMATCH);
    reply.write_u32(2);
    reply.write_u32(2);
    reply.into_bytes()
}

fn auth_error(xid: u32, status: u32) -> Vec<u8> {
    let mut reply = Encoder::new();
    reply.write_u32(xid);
    reply.write_u32(RPC_REPLY);
    reply.write_u32(MSG_DENIED);
    reply.write_u32(AUTH_ERROR);
    reply.write_u32(status);
    reply.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(xid: u32, rpc_version: u32, program: u32, version: u32, procedure: u32, args: &[u8]) -> Vec<u8> {
        let mut request = Encoder::new();
        request.write_u32(xid);
        request.write_u32(RPC_CALL);
        request.write_u32(rpc_version);
        request.write_u32(program);
        request.write_u32(version);
        request.write_u32(procedure);
        request.write_u32(AUTH_NONE);
        request.write_u32(0);
        request.write_u32(AUTH_NONE);
        request.write_u32(0);
        request.write_fixed(args);
        request.into_bytes()
    }

    fn outcome(reply: &[u8]) -> (u32, u32, Vec<u8>) {
        let mut decoder = Decoder::new(reply);
        let xid = decoder.read_u32().unwrap();
        assert_eq!(decoder.read_u32().unwrap(), RPC_REPLY);
        let reply_status = decoder.read_u32().unwrap();
        if reply_status == MSG_ACCEPTED {
            assert_eq!(decoder.read_u32().unwrap(), AUTH_NONE);
            assert!(decoder.read_opaque("verifier", 400).unwrap().is_empty());
        }
        let status = decoder.read_u32().unwrap();
        (xid, status, reply[decoder.position()..].to_vec())
    }

    #[test]
    fn getport_and_rpc_error_shapes_are_exact() {
        let mut args = Encoder::new();
        args.write_u32(crate::nfs3::types::PROGRAM);
        args.write_u32(crate::nfs3::types::VERSION);
        args.write_u32(crate::portmap::IPPROTO_TCP);
        args.write_u32(0);
        let reply = dispatch_record(
            &call(7, 2, crate::portmap::PROGRAM, crate::portmap::VERSION, PORTMAP_GETPORT, &args.into_bytes()),
            40_049,
            40_048,
        )
        .unwrap();
        let (xid, status, body) = outcome(&reply);
        assert_eq!((xid, status), (7, SUCCESS));
        assert_eq!(u32::from_be_bytes(body.try_into().unwrap()), 40_049);

        let mismatch =
            dispatch_record(&call(8, 1, crate::portmap::PROGRAM, crate::portmap::VERSION, PORTMAP_NULL, &[]), 1, 1)
                .unwrap();
        let mut decoder = Decoder::new(&mismatch);
        assert_eq!(decoder.read_u32().unwrap(), 8);
        assert_eq!(decoder.read_u32().unwrap(), RPC_REPLY);
        assert_eq!(decoder.read_u32().unwrap(), MSG_DENIED);
        assert_eq!(decoder.read_u32().unwrap(), RPC_MISMATCH);
        assert_eq!((decoder.read_u32().unwrap(), decoder.read_u32().unwrap()), (2, 2));
        decoder.finish().unwrap();

        let unavailable = dispatch_record(&call(9, 2, 999_999, 1, 0, &[]), 1, 1).unwrap();
        assert_eq!(outcome(&unavailable).1, PROG_UNAVAIL);
        let bad_args =
            dispatch_record(&call(10, 2, crate::portmap::PROGRAM, crate::portmap::VERSION, PORTMAP_GETPORT, &[]), 1, 1)
                .unwrap();
        assert_eq!(outcome(&bad_args).1, GARBAGE_ARGS);
    }
}
