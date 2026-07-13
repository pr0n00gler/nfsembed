use std::io::{Cursor, Read, Write};
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use tokio::io::{AsyncRead, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use tracing::{debug, error, trace, warn};

use crate::context::RPCContext;
use crate::rpc::record::{read_record_budgeted, RecordLimits};
use crate::rpc::*;
use crate::xdr::*;
use crate::{mount, mount_handlers, nfs, nfs_handlers, portmap, portmap_handlers};

// Information from RFC 5531
// https://datatracker.ietf.org/doc/html/rfc5531

const NFS_ACL_PROGRAM: u32 = 100227;
const NFS_ID_MAP_PROGRAM: u32 = 100270;
const NFS_METADATA_PROGRAM: u32 = 200024;
const MAX_IN_FLIGHT_MESSAGES: usize = 64;
const MAX_QUEUED_REPLIES: usize = 64;
const RPC_RECORD_READ_TIMEOUT: Duration = Duration::from_secs(30);
const RPC_RECORD_LIMITS: RecordLimits = RecordLimits {
    max_record_size: 2 * 1024 * 1024,
    max_fragment_size: 1024 * 1024,
    max_fragments: 16,
};

async fn handle_rpc(
    input: &mut impl Read,
    output: &mut impl Write,
    mut context: RPCContext,
) -> Result<bool, anyhow::Error> {
    let mut recv = rpc_msg::default();
    recv.deserialize(input)?;
    let xid = recv.xid;
    if let rpc_body::CALL(call) = recv.body {
        if let auth_flavor::AUTH_UNIX = call.cred.flavor {
            let mut auth = auth_unix::default();
            auth.deserialize(&mut Cursor::new(&call.cred.body))?;
            context.auth = auth;
        }
        if call.rpcvers != 2 {
            warn!("Invalid RPC version {} != 2", call.rpcvers);
            rpc_vers_mismatch(xid).serialize(output)?;
            return Ok(true);
        }

        if context.transaction_tracker.is_retransmission(xid, &context.client_addr) {
            // This is a retransmission
            // Drop the message and return
            debug!("Retransmission detected, xid: {}, client_addr: {}, call: {:?}", xid, context.client_addr, call);
            return Ok(false);
        }

        let res = {
            if call.prog == nfs::PROGRAM {
                nfs_handlers::handle_nfs(xid, call, input, output, &context).await
            } else if call.prog == portmap::PROGRAM {
                portmap_handlers::handle_portmap(xid, call, input, output, &context)
            } else if call.prog == mount::PROGRAM {
                mount_handlers::handle_mount(xid, call, input, output, &context).await
            } else if call.prog == NFS_ACL_PROGRAM
                || call.prog == NFS_ID_MAP_PROGRAM
                || call.prog == NFS_METADATA_PROGRAM
            {
                trace!("ignoring NFS_ACL packet");
                prog_unavail_reply_message(xid).serialize(output)?;
                Ok(())
            } else {
                warn!("Unknown RPC Program number {} != {}", call.prog, nfs::PROGRAM);
                prog_unavail_reply_message(xid).serialize(output)?;
                Ok(())
            }
        }
        .map(|_| true);
        context.transaction_tracker.mark_processed(xid, &context.client_addr);
        res
    } else {
        error!("Unexpectedly received a Reply instead of a Call");
        Err(anyhow!("Bad RPC Call format"))
    }
}

pub async fn write_fragment(socket: &mut tokio::net::TcpStream, buf: &[u8]) -> Result<(), anyhow::Error> {
    // TODO: split into many fragments
    assert!(buf.len() < (1 << 31));
    // set the last flag
    let fragment_header = buf.len() as u32 + (1 << 31);
    let header_buf = u32::to_be_bytes(fragment_header);
    socket.write_all(&header_buf).await?;
    trace!("Writing fragment length:{}", buf.len());
    socket.write_all(buf).await?;
    Ok(())
}

pub type SocketMessageType = Result<Vec<u8>, anyhow::Error>;

/// Applies one absolute deadline to header, budget acquisition, and body
/// receipt. This is intentionally a whole-record deadline rather than a
/// progress-resetting idle timeout. Cancelling the future drops any acquired
/// aggregate-memory permit together with the partial record allocation.
async fn read_record_with_timeout<R: AsyncRead + Unpin>(
    reader: &mut R,
    limits: RecordLimits,
    request_buffers: Arc<Semaphore>,
    read_timeout: Duration,
) -> Result<(Vec<u8>, OwnedSemaphorePermit), anyhow::Error> {
    timeout(read_timeout, read_record_budgeted(reader, limits, request_buffers))
        .await
        .map_err(|_| anyhow!("RPC record read exceeded the {read_timeout:?} read timeout"))?
        .map_err(Into::into)
}

/// The Socket Message Handler reads from a TcpStream and spawns off
/// subtasks to handle each message. replies are queued into the
/// reply_send_channel.
#[derive(Debug)]
pub struct SocketMessageHandler {
    socket_receive_channel: DuplexStream,
    reply_send_channel: mpsc::Sender<SocketMessageType>,
    in_flight: Arc<Semaphore>,
    request_buffers: Arc<Semaphore>,
    context: RPCContext,
}

impl SocketMessageHandler {
    /// Creates a new SocketMessageHandler with the receiver for queued message replies
    pub fn new(
        context: &RPCContext,
        request_buffers: Arc<Semaphore>,
    ) -> (Self, DuplexStream, mpsc::Receiver<SocketMessageType>) {
        let (socksend, sockrecv) = tokio::io::duplex(256000);
        let (msgsend, msgrecv) = mpsc::channel(MAX_QUEUED_REPLIES);
        (
            Self {
                socket_receive_channel: sockrecv,
                reply_send_channel: msgsend,
                in_flight: Arc::new(Semaphore::new(MAX_IN_FLIGHT_MESSAGES)),
                request_buffers,
                context: context.clone(),
            },
            socksend,
            msgrecv,
        )
    }

    /// Reads and dispatches one size-, fragment-, and byte-budget-bounded RPC
    /// record from the socket. This should be looped.
    pub async fn read(&mut self) -> Result<(), anyhow::Error> {
        let (record, request_budget) = read_record_with_timeout(
            &mut self.socket_receive_channel,
            RPC_RECORD_LIMITS,
            self.request_buffers.clone(),
            RPC_RECORD_READ_TIMEOUT,
        )
        .await?;
        let context = self.context.clone();
        let send = self.reply_send_channel.clone();
        let permit = self
            .in_flight
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("RPC message concurrency limiter closed"))?;
        tokio::spawn(async move {
            let _permit = permit;
            let _request_budget = request_budget;
            let mut write_buf: Vec<u8> = Vec::new();
            let mut write_cursor = Cursor::new(&mut write_buf);
            let maybe_reply = handle_rpc(&mut Cursor::new(record), &mut write_cursor, context).await;
            match maybe_reply {
                Err(e) => {
                    error!("RPC Error: {:?}", e);
                    let _ = send.send(Err(e)).await;
                },
                Ok(true) => {
                    let _ = std::io::Write::flush(&mut write_cursor);
                    let _ = send.send(Ok(write_buf)).await;
                },
                Ok(false) => {
                    // do not reply
                },
            }
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stalled_record_timeout_releases_the_shared_request_budget() {
        let limits = RecordLimits {
            max_record_size: 8,
            max_fragment_size: 8,
            max_fragments: 1,
        };
        let request_buffers = Arc::new(Semaphore::new(limits.max_record_size));
        let (mut client, mut server) = tokio::io::duplex(16);
        client.write_all(&4u32.to_be_bytes()).await.unwrap();

        let read_buffers = request_buffers.clone();
        let read = tokio::spawn(async move {
            read_record_with_timeout(&mut server, limits, read_buffers, Duration::from_millis(50)).await
        });
        timeout(Duration::from_secs(1), async {
            while request_buffers.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("reader should reserve the aggregate record budget");

        let error = read.await.unwrap().unwrap_err();
        assert!(error.to_string().contains("read timeout"));
        assert_eq!(request_buffers.available_permits(), limits.max_record_size);
    }
}
