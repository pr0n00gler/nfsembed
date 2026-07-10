use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Weak};

use bytes::Bytes;
use sha2::{Digest, Sha256};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch, Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{timeout, timeout_at, Instant};
use tracing::Instrument;

use super::{AuthPolicy, ExecutionTracker, ExportState, PortmapperMode, ServerError, ServerLimits};
use crate::handles::HandleCodec;
use crate::mount3::codec::EncodeMountResult;
use crate::mount3::types::{DumpResult, ExportEntry, ExportResult, MountEntry, MountResult, MountStatus};
use crate::nfs3::codec::{encode_readdir_entry, truncate_readdir_result, EncodeNfsResult};
use crate::nfs3::procedures::{
    AccessResult, CommitResult, CreateResult, DirectoryOperationArgs, FsInfoResult, FsStatResult, GetAttrResult,
    LinkResult, LookupResult, NfsArguments, PathConfResult, ReadDirEntry, ReadDirEntryExtension, ReadDirResult,
    ReadLinkResult, ReadResult, RenameResult, SetAttrResult, WccResult, WriteResult,
};
use crate::nfs3::types::{NfsStatus, WccData};
use crate::replay::{ReplayCache, ReplayDecision, ReplayKey, RequestFingerprint};
use crate::rpc::auth::{decode_principal, AUTH_NONE};
use crate::rpc::codec::{DecodeError, Decoder, EncodeError, Encoder};
use crate::rpc::record::{read_record_budgeted, validate_record, write_record_limited, RecordLimits};
use crate::vfs::{
    ExportId, FileAttributes, FileType, MutationResult, NfsError, NfsName, ObjectKey, Principal, RequestContext,
};

const RPC_CALL: u32 = 0;
const RPC_REPLY: u32 = 1;
const MSG_ACCEPTED: u32 = 0;
const SUCCESS: u32 = 0;
const PROG_UNAVAIL: u32 = 1;
const PROG_MISMATCH: u32 = 2;
const PROC_UNAVAIL: u32 = 3;
const GARBAGE_ARGS: u32 = 4;
const SYSTEM_ERR: u32 = 5;

pub(crate) struct ConnectionState {
    pub exports: Arc<Vec<ExportState>>,
    pub limits: ServerLimits,
    pub auth_policy: AuthPolicy,
    pub portmapper: PortmapperMode,
    pub handles: HandleCodec,
    pub replay: Arc<ReplayCache>,
    pub requests: Arc<Semaphore>,
    pub request_buffers: Arc<Semaphore>,
    pub reply_buffers: Arc<Semaphore>,
    pub executions: Weak<ExecutionTracker>,
    pub mounts: MountTable,
    pub local_port: u16,
}

type MountTable = Arc<Mutex<Vec<(IpAddr, Vec<u8>)>>>;

struct QueuedRequest {
    record: Vec<u8>,
    _budget: Arc<OwnedSemaphorePermit>,
    deadline: Instant,
}

struct QueuedReply {
    reply: Bytes,
    _budget: Arc<OwnedSemaphorePermit>,
}

pub(crate) async fn serve_connection(
    stream: TcpStream,
    client_addr: SocketAddr,
    state: Arc<ConnectionState>,
    shutdown: watch::Receiver<bool>,
) -> Result<(), ServerError> {
    stream.set_nodelay(true)?;
    let record_limits = RecordLimits {
        max_record_size: state.limits.max_rpc_record_size,
        max_fragment_size: state.limits.max_rpc_fragment_size,
        max_fragments: state.limits.max_fragments_per_record,
    };
    let queue_capacity = state.limits.max_requests_per_connection;
    let (request_sender, request_receiver) = mpsc::channel(queue_capacity);
    let (reply_sender, reply_receiver) = mpsc::channel(queue_capacity);
    let (read_half, write_half) = stream.into_split();

    let reader = connection_reader(
        read_half,
        request_sender,
        record_limits,
        state.limits.idle_connection_timeout,
        state.limits.request_timeout,
        state.request_buffers.clone(),
        shutdown.clone(),
    );
    let processor = connection_processor(request_receiver, reply_sender, client_addr, state.clone(), shutdown);
    let writer = connection_writer(write_half, reply_receiver, record_limits, state.limits.request_timeout);
    tokio::try_join!(reader, processor, writer)?;
    Ok(())
}

async fn connection_reader(
    mut reader: OwnedReadHalf,
    sender: mpsc::Sender<QueuedRequest>,
    limits: RecordLimits,
    idle_timeout: std::time::Duration,
    progress_timeout: std::time::Duration,
    request_buffers: Arc<Semaphore>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ServerError> {
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let read = timeout(idle_timeout, read_record_budgeted(&mut reader, limits, request_buffers.clone()));
        let (record, reservation) = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
                continue;
            },
            result = read => match result {
                Err(_) => return Ok(()),
                Ok(Err(crate::rpc::record::RecordError::Io(error)))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                    ) => return Ok(()),
                Ok(Err(error)) => return Err(ServerError::Record(error)),
                Ok(Ok(record)) => record,
            },
        };
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            },
            result = timeout(progress_timeout, sender.send(QueuedRequest {
                record,
                _budget: Arc::new(reservation),
                deadline: Instant::now() + progress_timeout,
            })) => {
                match result {
                    Ok(Ok(())) => {},
                    Ok(Err(_)) => return Ok(()),
                    Err(_) => return Err(ServerError::RequestTimeout),
                }
            },
        }
    }
}

async fn connection_processor(
    mut receiver: mpsc::Receiver<QueuedRequest>,
    reply_sender: mpsc::Sender<QueuedReply>,
    client_addr: SocketAddr,
    state: Arc<ConnectionState>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ServerError> {
    let mut requests = JoinSet::new();
    let mut shutting_down = *shutdown.borrow();
    if shutting_down {
        receiver.close();
    }
    loop {
        if receiver.is_closed() && receiver.is_empty() && requests.is_empty() {
            return Ok(());
        }
        tokio::select! {
            changed = shutdown.changed(), if !shutting_down => {
                if changed.is_err() || *shutdown.borrow() {
                    shutting_down = true;
                    receiver.close();
                }
            },
            record = receiver.recv(), if requests.len() < state.limits.max_requests_per_connection
                && (!receiver.is_closed() || !receiver.is_empty()) => {
                if let Some(record) = record {
                    let state = state.clone();
                    let reply_sender = reply_sender.clone();
                    requests.spawn(async move {
                        let deadline = record.deadline;
                        let xid = record.record.get(..4).map(|bytes| bytes.to_vec());
                        let reply_budget = Arc::new(timeout_at(
                            deadline,
                            state
                                .reply_buffers
                                .clone()
                                .acquire_many_owned(state.limits.max_rpc_record_size as u32),
                        )
                        .await
                        .map_err(|_| ServerError::RequestTimeout)?
                        .map_err(|_| ServerError::ShuttingDown)?);
                        let reply = dispatch_record(
                            record,
                            client_addr,
                            state.clone(),
                            reply_budget.clone(),
                            deadline,
                        )
                        .await;
                        let reply = match reply {
                            Ok(reply) => reply,
                            Err(error) => {
                                tracing::debug!(client = %client_addr, error = %error, "RPC request rejected");
                                error_reply(xid.as_deref(), SYSTEM_ERR)
                            },
                        };
                        match timeout_at(
                            deadline,
                            reply_sender.send(QueuedReply {
                                reply,
                                _budget: reply_budget,
                            }),
                        )
                        .await
                        {
                            Ok(Ok(())) | Ok(Err(_)) => {},
                            Err(_) => return Err(ServerError::RequestTimeout),
                        }
                        Ok::<(), ServerError>(())
                    });
                }
            },
            joined = requests.join_next(), if !requests.is_empty() => {
                if let Some(result) = joined {
                    result.map_err(ServerError::Task)??;
                }
            },
        }
    }
}

async fn connection_writer(
    mut writer: OwnedWriteHalf,
    mut receiver: mpsc::Receiver<QueuedReply>,
    limits: RecordLimits,
    progress_timeout: std::time::Duration,
) -> Result<(), ServerError> {
    while let Some(reply) = receiver.recv().await {
        match timeout(progress_timeout, write_record_limited(&mut writer, &reply.reply, limits)).await {
            Ok(result) => result?,
            Err(_) => return Err(ServerError::RequestTimeout),
        }
    }
    Ok(())
}

async fn dispatch_record(
    request: QueuedRequest,
    client_addr: SocketAddr,
    state: Arc<ConnectionState>,
    reply_budget: Arc<OwnedSemaphorePermit>,
    deadline: Instant,
) -> Result<Bytes, ServerError> {
    let QueuedRequest {
        record,
        _budget: request_budget,
        deadline: _,
    } = request;
    let record = Bytes::from(record);
    let mut decoder = Decoder::new(&record);
    let xid = decoder.read_u32()?;
    if decoder.read_u32()? != RPC_CALL {
        return Err(ServerError::Protocol("received an RPC reply on a server connection"));
    }
    let rpc_version = decoder.read_u32()?;
    let program = decoder.read_u32()?;
    let version = decoder.read_u32()?;
    let procedure = decoder.read_u32()?;
    let credential_flavor = decoder.read_u32()?;
    let credential_body = decoder.read_opaque("RPC credential", 400)?;
    let verifier_flavor = decoder.read_u32()?;
    let verifier = decoder.read_opaque("RPC verifier", 400)?;
    if verifier_flavor != AUTH_NONE || !verifier.is_empty() {
        return Ok(Bytes::from(auth_error(xid, 3)));
    }
    let args_offset = decoder.position();
    let principal = match decode_principal(credential_flavor, &credential_body) {
        Ok(principal) => principal,
        Err(_) => return Ok(Bytes::from(auth_error(xid, 1))),
    };
    let request_export_id = request_export_id(program, procedure, &record[args_offset..], &state);

    if rpc_version != 2 {
        return Ok(Bytes::from(rpc_mismatch(xid, 2, 2)));
    }
    if program != crate::portmap::PROGRAM && !principal_allowed(state.auth_policy, &principal) {
        return Ok(Bytes::from(auth_error(xid, 5)));
    }

    let mut hasher = Sha256::new();
    hasher.update(program.to_be_bytes());
    hasher.update(version.to_be_bytes());
    hasher.update(procedure.to_be_bytes());
    hasher.update(&record[args_offset..]);
    hash_principal(&mut hasher, &principal);
    let fingerprint = RequestFingerprint(hasher.finalize().into());
    let replay_key = ReplayKey {
        client_addr: SocketAddr::new(client_addr.ip(), 0),
        export_id: request_export_id,
        xid,
    };
    let lease = match state.replay.begin(replay_key, fingerprint).await? {
        ReplayDecision::Replay(reply) => {
            tracing::debug!(xid, client = %client_addr, replay = "hit", "RPC reply replayed");
            return Ok(reply);
        },
        ReplayDecision::Wait(waiter) => {
            tracing::debug!(xid, client = %client_addr, replay = "wait", "waiting for in-flight duplicate");
            return match timeout_at(deadline, waiter).await {
                Ok(reply) => Ok(reply??),
                Err(_) => {
                    tracing::warn!(client = %client_addr, xid, "duplicate RPC request timed out");
                    Err(ServerError::RequestTimeout)
                },
            };
        },
        ReplayDecision::Execute(lease) => {
            tracing::trace!(xid, client = %client_addr, replay = "miss", "new RPC request");
            lease
        },
    };

    let context = RequestContext {
        principal,
        client_addr,
        export_id: request_export_id,
    };
    let arguments = record.slice(args_offset..);
    let request_bytes = record.len();
    let permit = match timeout_at(deadline, state.requests.clone().acquire_owned()).await {
        Ok(Ok(permit)) => permit,
        Ok(Err(_)) => return Err(ServerError::ShuttingDown),
        Err(_) => {
            tracing::warn!(client = %client_addr, xid, "RPC request timed out waiting for execution capacity");
            return Err(ServerError::RequestTimeout);
        },
    };
    let execution_state = state.clone();
    let (send, receive) = tokio::sync::oneshot::channel();
    let executions = state.executions.upgrade().ok_or(ServerError::ShuttingDown)?;
    executions
        .spawn(async move {
            let _permit = permit;
            // The execution tracker outlives a disconnected connection. Keep
            // both aggregate buffer charges until its request bytes and any
            // constructed reply have been released.
            let _request_budget = request_budget;
            let _reply_budget = reply_budget;
            let result = match timeout_at(
                deadline,
                execute_request(
                    xid,
                    program,
                    version,
                    procedure,
                    arguments,
                    context,
                    client_addr,
                    request_bytes,
                    execution_state,
                ),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => {
                    tracing::warn!(client = %client_addr, xid, "RPC execution reached its deadline and was cancelled");
                    Err(ServerError::RequestTimeout)
                },
            };
            match result {
                Ok(reply) => {
                    lease.complete(reply.clone());
                    let _ = send.send(Ok(reply));
                },
                Err(error) => {
                    lease.cancel();
                    let _ = send.send(Err(error));
                },
            }
        })
        .await;

    receive.await?
}

#[allow(clippy::too_many_arguments)]
async fn execute_request(
    xid: u32,
    program: u32,
    version: u32,
    procedure: u32,
    arguments: Bytes,
    context: RequestContext,
    client_addr: SocketAddr,
    request_bytes: usize,
    state: Arc<ConnectionState>,
) -> Result<Bytes, ServerError> {
    let started_at = std::time::Instant::now();
    let span = tracing::info_span!(
        "rpc_request",
        xid,
        client = %client_addr,
        program,
        version,
        procedure,
        procedure_name = procedure_name(program, procedure),
        request_bytes,
    );
    let reply = match dispatch_call(xid, program, version, procedure, &arguments, &context, &state)
        .instrument(span)
        .await
    {
        Ok(reply) => Bytes::from(reply),
        Err(ServerError::Decode(_)) => Bytes::from(accepted_reply(xid, GARBAGE_ARGS, &[])),
        Err(ServerError::Encode(error)) => {
            tracing::warn!(client = %client_addr, xid, error = %error, "RPC result could not be encoded");
            Bytes::from(accepted_reply(xid, SYSTEM_ERR, &[]))
        },
        Err(error) => return Err(error),
    };
    let limits = RecordLimits {
        max_record_size: state.limits.max_rpc_record_size,
        max_fragment_size: state.limits.max_rpc_fragment_size,
        max_fragments: state.limits.max_fragments_per_record,
    };
    if let Err(error) = validate_record(&reply, limits) {
        tracing::warn!(client = %client_addr, xid, error = %error, "RPC result exceeded outbound limits");
        let bounded_error = Bytes::from(accepted_reply(xid, SYSTEM_ERR, &[]));
        validate_record(&bounded_error, limits)?;
        return Ok(bounded_error);
    }
    let protocol_status =
        if (program == crate::nfs3::types::PROGRAM || program == crate::mount3::types::PROGRAM) && reply.len() >= 28 {
            u32::from_be_bytes(reply[24..28].try_into().unwrap_or_default())
        } else {
            0
        };
    tracing::debug!(
        xid,
        client = %client_addr,
        procedure = procedure_name(program, procedure),
        duration_micros = started_at.elapsed().as_micros(),
        protocol_status,
        request_bytes,
        reply_bytes = reply.len(),
        active_requests = state.limits.max_inflight_requests - state.requests.available_permits(),
        "RPC request completed"
    );
    Ok(reply)
}

fn hash_principal(hasher: &mut Sha256, principal: &Principal) {
    match principal {
        Principal::Anonymous => hasher.update([0]),
        Principal::AuthSys {
            uid,
            gid,
            supplementary_gids,
            machine_name,
        } => {
            hasher.update([1]);
            hasher.update(uid.to_be_bytes());
            hasher.update(gid.to_be_bytes());
            hasher.update((supplementary_gids.len() as u32).to_be_bytes());
            for group in supplementary_gids {
                hasher.update(group.to_be_bytes());
            }
            hasher.update((machine_name.len() as u32).to_be_bytes());
            hasher.update(machine_name);
        },
    }
}

fn procedure_name(program: u32, procedure: u32) -> &'static str {
    if program == crate::nfs3::types::PROGRAM {
        return match procedure {
            0 => "NULL",
            1 => "GETATTR",
            2 => "SETATTR",
            3 => "LOOKUP",
            4 => "ACCESS",
            5 => "READLINK",
            6 => "READ",
            7 => "WRITE",
            8 => "CREATE",
            9 => "MKDIR",
            10 => "SYMLINK",
            11 => "MKNOD",
            12 => "REMOVE",
            13 => "RMDIR",
            14 => "RENAME",
            15 => "LINK",
            16 => "READDIR",
            17 => "READDIRPLUS",
            18 => "FSSTAT",
            19 => "FSINFO",
            20 => "PATHCONF",
            21 => "COMMIT",
            _ => "UNKNOWN_NFS",
        };
    }
    if program == crate::mount3::types::PROGRAM {
        return match procedure {
            0 => "MOUNT_NULL",
            1 => "MNT",
            2 => "DUMP",
            3 => "UMNT",
            4 => "UMNTALL",
            5 => "EXPORT",
            _ => "UNKNOWN_MOUNT",
        };
    }
    if program == crate::portmap::PROGRAM {
        return match procedure {
            0 => "PMAP_NULL",
            3 => "GETPORT",
            _ => "UNKNOWN_PORTMAP",
        };
    }
    "UNKNOWN_RPC"
}

fn request_export_id(program: u32, procedure: u32, args: &[u8], state: &ConnectionState) -> ExportId {
    if program == crate::nfs3::types::PROGRAM && procedure != 0 {
        let mut decoder = Decoder::new(args);
        if let Ok(handle) = decoder.read_opaque("NFS file handle", 64) {
            if let Ok((export_id, _)) = state.handles.decode_any(&handle) {
                return export_id;
            }
        }
        return state.exports.first().map_or(ExportId(0), |export| export.id);
    }
    if program == crate::mount3::types::PROGRAM && matches!(procedure, 1 | 3) {
        let mut decoder = Decoder::new(args);
        if let Ok(path) = decoder.read_string("MOUNT path", 1024) {
            if let Some(export) = select_export(state, &path) {
                return export.id;
            }
        }
    }
    ExportId(0)
}

fn select_export<'a>(state: &'a ConnectionState, requested: &[u8]) -> Option<&'a ExportState> {
    state
        .exports
        .iter()
        .filter(|export| export_matches(&export.path, requested))
        .max_by_key(|export| export.path.len())
}

async fn dispatch_call(
    xid: u32,
    program: u32,
    version: u32,
    procedure: u32,
    args: &[u8],
    context: &RequestContext,
    state: &ConnectionState,
) -> Result<Vec<u8>, ServerError> {
    match program {
        crate::nfs3::types::PROGRAM => {
            if version != crate::nfs3::types::VERSION {
                return Ok(program_mismatch(xid, crate::nfs3::types::VERSION, crate::nfs3::types::VERSION));
            }
            dispatch_nfs(xid, procedure, args, context, state).await
        },
        crate::mount3::types::PROGRAM => {
            if version != crate::mount3::types::VERSION {
                return Ok(program_mismatch(xid, crate::mount3::types::VERSION, crate::mount3::types::VERSION));
            }
            dispatch_mount(xid, procedure, args, context, state).await
        },
        crate::portmap::PROGRAM if state.portmapper == PortmapperMode::Enabled => {
            if version != crate::portmap::VERSION {
                return Ok(program_mismatch(xid, crate::portmap::VERSION, crate::portmap::VERSION));
            }
            dispatch_portmap(xid, procedure, args, state)
        },
        _ => Ok(accepted_reply(xid, PROG_UNAVAIL, &[])),
    }
}

async fn dispatch_nfs(
    xid: u32,
    procedure: u32,
    args: &[u8],
    context: &RequestContext,
    state: &ConnectionState,
) -> Result<Vec<u8>, ServerError> {
    if procedure > 21 {
        return Ok(accepted_reply(xid, PROC_UNAVAIL, &[]));
    }
    let arguments = NfsArguments::decode(procedure, args, state.limits.max_rpc_record_size)?;
    if matches!(arguments, NfsArguments::Null) {
        return Ok(accepted_reply(xid, SUCCESS, &[]));
    }
    let Some(export) = state.exports.iter().find(|export| export.id == context.export_id) else {
        return Ok(nfs_failure_reply_for_procedure(xid, procedure, NfsStatus::BadHandle)?);
    };
    let vfs = &export.vfs;
    let reply = match arguments {
        NfsArguments::GetAttr(arguments) => {
            let object = match decode_object(&arguments.object, state, context.export_id) {
                Ok(object) => object,
                Err(status) => {
                    return Ok(typed_nfs_reply(
                        xid,
                        &GetAttrResult::Err {
                            status: wire_nfs_status(status)?,
                        },
                    )?)
                },
            };
            let result = match vfs.getattr(context, object).await {
                Ok(attributes) => GetAttrResult::Ok { attributes },
                Err(error) => GetAttrResult::Err { status: error.into() },
            };
            typed_nfs_reply(xid, &result)?
        },
        NfsArguments::SetAttr(arguments) => {
            let object = match decode_object(&arguments.object, state, context.export_id) {
                Ok(object) => object,
                Err(status) => {
                    return Ok(typed_nfs_reply(
                        xid,
                        &SetAttrResult::Err {
                            status: wire_nfs_status(status)?,
                            object_wcc: WccData::default(),
                        },
                    )?)
                },
            };
            let result = match vfs.setattr(context, object, arguments.attributes, arguments.guard).await {
                Ok(result) => SetAttrResult::Ok {
                    object_wcc: WccData {
                        before: result.before,
                        after: result.after,
                    },
                },
                Err(error) => SetAttrResult::Err {
                    status: error.into(),
                    object_wcc: WccData::default(),
                },
            };
            typed_nfs_reply(xid, &result)?
        },
        NfsArguments::Lookup(arguments) => {
            let (parent, name) = match decode_directory_operation(arguments, state, context.export_id) {
                Ok(value) => value,
                Err(status) => {
                    return Ok(typed_nfs_reply(
                        xid,
                        &LookupResult::Err {
                            status: wire_nfs_status(status)?,
                            directory_attributes: None,
                        },
                    )?)
                },
            };
            let result = match vfs.lookup(context, parent, &name).await {
                Ok(found) => {
                    let parent_attributes = vfs.getattr(context, parent).await.ok();
                    LookupResult::Ok {
                        object_handle: state.handles.encode(context.export_id, found.object).to_vec(),
                        object_attributes: found.attributes,
                        directory_attributes: parent_attributes,
                    }
                },
                Err(error) => {
                    let parent_attributes = vfs.getattr(context, parent).await.ok();
                    LookupResult::Err {
                        status: error.into(),
                        directory_attributes: parent_attributes,
                    }
                },
            };
            typed_nfs_reply(xid, &result)?
        },
        NfsArguments::Access(arguments) => {
            let object = match decode_object(&arguments.object, state, context.export_id) {
                Ok(object) => object,
                Err(status) => {
                    return Ok(typed_nfs_reply(
                        xid,
                        &AccessResult::Err {
                            status: wire_nfs_status(status)?,
                            attributes: None,
                        },
                    )?)
                },
            };
            const ACCESS_MASK: u32 = 0x3f;
            let requested = arguments.requested & ACCESS_MASK;
            let result = match vfs.access(context, object, requested).await {
                Ok(allowed) => {
                    let attributes = vfs.getattr(context, object).await.ok();
                    AccessResult::Ok {
                        attributes,
                        access: allowed & requested & ACCESS_MASK,
                    }
                },
                Err(error) => {
                    let attributes = vfs.getattr(context, object).await.ok();
                    AccessResult::Err {
                        status: error.into(),
                        attributes,
                    }
                },
            };
            typed_nfs_reply(xid, &result)?
        },
        NfsArguments::ReadLink(arguments) => {
            let object = match decode_object(&arguments.object, state, context.export_id) {
                Ok(object) => object,
                Err(status) => {
                    return Ok(typed_nfs_reply(
                        xid,
                        &ReadLinkResult::Err {
                            status: wire_nfs_status(status)?,
                            attributes: None,
                        },
                    )?)
                },
            };
            match vfs.readlink(context, object).await {
                Ok(path) => {
                    let attributes = vfs.getattr(context, object).await.ok();
                    typed_nfs_reply(xid, &ReadLinkResult::Ok { attributes, path })?
                },
                Err(error) => {
                    let attributes = vfs.getattr(context, object).await.ok();
                    typed_nfs_reply(
                        xid,
                        &ReadLinkResult::Err {
                            status: error.into(),
                            attributes,
                        },
                    )?
                },
            }
        },
        NfsArguments::Read(arguments) => {
            let object = match decode_object(&arguments.object, state, context.export_id) {
                Ok(object) => object,
                Err(status) => {
                    return Ok(typed_nfs_reply(
                        xid,
                        &ReadResult::Err {
                            status: wire_nfs_status(status)?,
                            attributes: None,
                        },
                    )?)
                },
            };
            let offset = arguments.offset;
            let count = arguments.count.min(state.limits.max_read_size);
            let result = match vfs.read(context, object, offset, count).await {
                Ok(mut result) => {
                    result.data.truncate(count as usize);
                    ReadResult::Ok {
                        attributes: result.attributes,
                        data: result.data,
                        eof: result.eof,
                    }
                },
                Err(error) => ReadResult::Err {
                    status: error.into(),
                    attributes: None,
                },
            };
            typed_nfs_reply(xid, &result)?
        },
        NfsArguments::Write(arguments) => {
            if let Err(status) = arguments.validate() {
                return Ok(typed_nfs_reply(
                    xid,
                    &WriteResult::Err {
                        status,
                        file_wcc: WccData::default(),
                    },
                )?);
            }
            let object = match decode_object(&arguments.object, state, context.export_id) {
                Ok(object) => object,
                Err(status) => {
                    return Ok(typed_nfs_reply(
                        xid,
                        &WriteResult::Err {
                            status: wire_nfs_status(status)?,
                            file_wcc: WccData::default(),
                        },
                    )?)
                },
            };
            let offset = arguments.offset;
            let requested = arguments.requested;
            let permitted_count = arguments.data.len().min(state.limits.max_write_size as usize);
            let data = &arguments.data[..permitted_count];
            let result = match vfs.write(context, object, offset, data, requested).await {
                Ok(result)
                    if result.value.count as usize <= data.len()
                        && (data.is_empty() || result.value.count != 0)
                        && durability_satisfies(result.value.committed, requested) =>
                {
                    WriteResult::Ok {
                        file_wcc: WccData {
                            before: result.before,
                            after: result.after,
                        },
                        count: result.value.count,
                        committed: result.value.committed,
                        verifier: state.handles.instance_id(),
                    }
                },
                Ok(result) => WriteResult::Err {
                    status: NfsStatus::ServerFault,
                    file_wcc: WccData {
                        before: result.before,
                        after: result.after,
                    },
                },
                Err(error) => WriteResult::Err {
                    status: error.into(),
                    file_wcc: WccData::default(),
                },
            };
            typed_nfs_reply(xid, &result)?
        },
        NfsArguments::Create(arguments) => {
            let (parent, name) = match decode_directory_operation(arguments.target, state, context.export_id) {
                Ok(value) => value,
                Err(status) => return create_failure_reply(xid, status),
            };
            create_reply(
                xid,
                state,
                context.export_id,
                vfs.create(context, parent, &name, arguments.attributes, arguments.mode).await,
            )?
        },
        NfsArguments::Mkdir(arguments) => {
            let (parent, name) = match decode_directory_operation(arguments.target, state, context.export_id) {
                Ok(value) => value,
                Err(status) => return create_failure_reply(xid, status),
            };
            create_reply(xid, state, context.export_id, vfs.mkdir(context, parent, &name, arguments.attributes).await)?
        },
        NfsArguments::Symlink(arguments) => {
            let (parent, name) = match decode_directory_operation(arguments.target, state, context.export_id) {
                Ok(value) => value,
                Err(status) => return create_failure_reply(xid, status),
            };
            create_reply(
                xid,
                state,
                context.export_id,
                vfs.symlink(context, parent, &name, &arguments.path, arguments.attributes).await,
            )?
        },
        NfsArguments::Mknod(arguments) => {
            let (parent, name) = match decode_directory_operation(arguments.target, state, context.export_id) {
                Ok(value) => value,
                Err(status) => return create_failure_reply(xid, status),
            };
            create_reply(
                xid,
                state,
                context.export_id,
                vfs.mknod(context, parent, &name, arguments.node_type, arguments.attributes)
                    .await,
            )?
        },
        NfsArguments::Remove(arguments) => {
            let (parent, name) = match decode_directory_operation(arguments, state, context.export_id) {
                Ok(value) => value,
                Err(status) => {
                    return Ok(typed_nfs_reply(
                        xid,
                        &WccResult::Err {
                            status: wire_nfs_status(status)?,
                            object_wcc: WccData::default(),
                        },
                    )?)
                },
            };
            mutation_void_reply(xid, vfs.remove(context, parent, &name).await)?
        },
        NfsArguments::Rmdir(arguments) => {
            let (parent, name) = match decode_directory_operation(arguments, state, context.export_id) {
                Ok(value) => value,
                Err(status) => {
                    return Ok(typed_nfs_reply(
                        xid,
                        &WccResult::Err {
                            status: wire_nfs_status(status)?,
                            object_wcc: WccData::default(),
                        },
                    )?)
                },
            };
            mutation_void_reply(xid, vfs.rmdir(context, parent, &name).await)?
        },
        NfsArguments::Rename(arguments) => {
            let (from_parent, from_name) = match decode_directory_operation(arguments.from, state, context.export_id) {
                Ok(value) => value,
                Err(status) => return rename_failure_reply(xid, status),
            };
            let (to_parent, to_name) = match decode_directory_operation(arguments.to, state, context.export_id) {
                Ok(value) => value,
                Err(status) => return rename_failure_reply(xid, status),
            };
            match vfs.rename(context, from_parent, &from_name, to_parent, &to_name).await {
                Ok((from, to)) => typed_nfs_reply(
                    xid,
                    &RenameResult::Ok {
                        from_directory_wcc: WccData {
                            before: from.before,
                            after: from.after,
                        },
                        to_directory_wcc: WccData {
                            before: to.before,
                            after: to.after,
                        },
                    },
                )?,
                Err(error) => typed_nfs_reply(
                    xid,
                    &RenameResult::Err {
                        status: error.into(),
                        from_directory_wcc: WccData::default(),
                        to_directory_wcc: WccData::default(),
                    },
                )?,
            }
        },
        NfsArguments::Link(arguments) => {
            let object = match decode_object(&arguments.object, state, context.export_id) {
                Ok(object) => object,
                Err(status) => return link_failure_reply(xid, status),
            };
            let (parent, name) = match decode_directory_operation(arguments.target, state, context.export_id) {
                Ok(value) => value,
                Err(status) => return link_failure_reply(xid, status),
            };
            let result = match vfs.link(context, object, parent, &name).await {
                Ok(result) => {
                    let object_attributes = vfs.getattr(context, object).await.ok();
                    LinkResult::Ok {
                        object_attributes,
                        directory_wcc: WccData {
                            before: result.before,
                            after: result.after,
                        },
                    }
                },
                Err(error) => LinkResult::Err {
                    status: error.into(),
                    object_attributes: None,
                    directory_wcc: WccData::default(),
                },
            };
            typed_nfs_reply(xid, &result)?
        },
        NfsArguments::ReadDir(arguments) => {
            let directory = match decode_object(&arguments.directory, state, context.export_id) {
                Ok(object) => object,
                Err(status) => {
                    return Ok(typed_nfs_reply(
                        xid,
                        &ReadDirResult::Err {
                            status: wire_nfs_status(status)?,
                            directory_attributes: None,
                        },
                    )?)
                },
            };
            let cookie = arguments.cookie;
            let verifier = arguments.verifier;
            let max_count = arguments.count;
            let wire_limit = max_count.min(state.limits.max_readdir_response_size) as usize;
            if wire_limit < 20 {
                return Ok(typed_nfs_reply(
                    xid,
                    &ReadDirResult::Err {
                        status: NfsStatus::TooSmall,
                        directory_attributes: None,
                    },
                )?);
            }
            let directory_limit: Option<usize> = None;
            let hint_limit = directory_limit.map_or(wire_limit, |limit| limit.min(wire_limit));
            let hint = (hint_limit / 32).clamp(1, 4096);
            match vfs.readdir(context, directory, cookie, verifier, hint).await {
                Ok(page) => {
                    let attributes = vfs.getattr(context, directory).await.ok();
                    readdir_reply(
                        xid,
                        state,
                        context.export_id,
                        false,
                        attributes.as_ref(),
                        page,
                        (directory_limit, wire_limit),
                    )?
                },
                Err(error) => typed_nfs_reply(
                    xid,
                    &ReadDirResult::Err {
                        status: error.into(),
                        directory_attributes: None,
                    },
                )?,
            }
        },
        NfsArguments::ReadDirPlus(arguments) => {
            let directory = match decode_object(&arguments.directory, state, context.export_id) {
                Ok(object) => object,
                Err(status) => {
                    return Ok(typed_nfs_reply(
                        xid,
                        &ReadDirResult::Err {
                            status: wire_nfs_status(status)?,
                            directory_attributes: None,
                        },
                    )?)
                },
            };
            let wire_limit = arguments.max_count.min(state.limits.max_readdir_response_size) as usize;
            if wire_limit < 20 {
                return Ok(typed_nfs_reply(
                    xid,
                    &ReadDirResult::Err {
                        status: NfsStatus::TooSmall,
                        directory_attributes: None,
                    },
                )?);
            }
            let directory_limit = Some(arguments.directory_count as usize);
            let hint_limit = directory_limit.map_or(wire_limit, |limit| limit.min(wire_limit));
            let hint = (hint_limit / 32).clamp(1, 4096);
            match vfs
                .readdir(context, directory, arguments.cookie, arguments.verifier, hint)
                .await
            {
                Ok(page) => {
                    let attributes = vfs.getattr(context, directory).await.ok();
                    readdir_reply(
                        xid,
                        state,
                        context.export_id,
                        true,
                        attributes.as_ref(),
                        page,
                        (directory_limit, wire_limit),
                    )?
                },
                Err(error) => typed_nfs_reply(
                    xid,
                    &ReadDirResult::Err {
                        status: error.into(),
                        directory_attributes: None,
                    },
                )?,
            }
        },
        NfsArguments::FsStat(arguments) => {
            let object = match decode_object(&arguments.object, state, context.export_id) {
                Ok(object) => object,
                Err(status) => {
                    return Ok(typed_nfs_reply(
                        xid,
                        &FsStatResult::Err {
                            status: wire_nfs_status(status)?,
                            attributes: None,
                        },
                    )?)
                },
            };
            let result = match vfs.fsstat(context, object).await {
                Ok(info) => {
                    let attributes = vfs.getattr(context, object).await.ok();
                    FsStatResult::Ok { attributes, info }
                },
                Err(error) => FsStatResult::Err {
                    status: error.into(),
                    attributes: None,
                },
            };
            typed_nfs_reply(xid, &result)?
        },
        NfsArguments::FsInfo(arguments) => {
            let object = match decode_object(&arguments.object, state, context.export_id) {
                Ok(object) => object,
                Err(status) => {
                    return Ok(typed_nfs_reply(
                        xid,
                        &FsInfoResult::Err {
                            status: wire_nfs_status(status)?,
                            attributes: None,
                        },
                    )?)
                },
            };
            match vfs.fsinfo(context, object).await {
                Ok(info) => {
                    let attributes = vfs.getattr(context, object).await.ok();
                    let capabilities = vfs.capabilities();
                    let max_read = info.max_read.min(state.limits.max_read_size);
                    let max_write = info.max_write.min(state.limits.max_write_size);
                    let properties = u32::from(capabilities.hard_links)
                        | (u32::from(capabilities.symbolic_links) << 1)
                        | (u32::from(capabilities.homogeneous) << 3)
                        | (u32::from(capabilities.can_set_time) << 4);
                    typed_nfs_reply(
                        xid,
                        &FsInfoResult::Ok {
                            attributes,
                            info: crate::vfs::FsInfo {
                                max_read,
                                preferred_read: info.preferred_read.min(max_read),
                                read_multiple: info.read_multiple.min(max_read),
                                max_write,
                                preferred_write: info.preferred_write.min(max_write),
                                write_multiple: info.write_multiple.min(max_write),
                                preferred_readdir: info.preferred_readdir.min(state.limits.max_readdir_response_size),
                                ..info
                            },
                            properties,
                        },
                    )?
                },
                Err(error) => typed_nfs_reply(
                    xid,
                    &FsInfoResult::Err {
                        status: error.into(),
                        attributes: None,
                    },
                )?,
            }
        },
        NfsArguments::PathConf(arguments) => {
            let object = match decode_object(&arguments.object, state, context.export_id) {
                Ok(object) => object,
                Err(status) => {
                    return Ok(typed_nfs_reply(
                        xid,
                        &PathConfResult::Err {
                            status: wire_nfs_status(status)?,
                            attributes: None,
                        },
                    )?)
                },
            };
            let result = match vfs.pathconf(context, object).await {
                Ok(mut info) => {
                    let attributes = vfs.getattr(context, object).await.ok();
                    info.max_name_length = info.max_name_length.min(NfsName::MAX_LEN as u32);
                    PathConfResult::Ok { attributes, info }
                },
                Err(error) => PathConfResult::Err {
                    status: error.into(),
                    attributes: None,
                },
            };
            typed_nfs_reply(xid, &result)?
        },
        NfsArguments::Commit(arguments) => {
            let object = match decode_object(&arguments.object, state, context.export_id) {
                Ok(object) => object,
                Err(status) => {
                    return Ok(typed_nfs_reply(
                        xid,
                        &CommitResult::Err {
                            status: wire_nfs_status(status)?,
                            file_wcc: WccData::default(),
                        },
                    )?)
                },
            };
            let result = match vfs.commit(context, object, arguments.offset, arguments.count).await {
                Ok(result) => CommitResult::Ok {
                    file_wcc: WccData {
                        before: result.before,
                        after: result.after,
                    },
                    verifier: state.handles.instance_id(),
                },
                Err(error) => CommitResult::Err {
                    status: error.into(),
                    file_wcc: WccData::default(),
                },
            };
            typed_nfs_reply(xid, &result)?
        },
        NfsArguments::Null => accepted_reply(xid, SUCCESS, &[]),
    };
    Ok(reply)
}

fn durability_satisfies(actual: crate::vfs::WriteStability, requested: crate::vfs::WriteStability) -> bool {
    use crate::vfs::WriteStability::{DataSync, FileSync, Unstable};
    matches!((actual, requested), (FileSync, _) | (DataSync, DataSync | Unstable) | (Unstable, Unstable))
}

fn decode_object(handle: &[u8], state: &ConnectionState, export_id: ExportId) -> Result<ObjectKey, u32> {
    state.handles.decode(export_id, handle).map_err(|error| match error {
        crate::handles::HandleError::StaleInstance => 70,
        _ => 10001,
    })
}

fn decode_directory_operation(
    arguments: DirectoryOperationArgs,
    state: &ConnectionState,
    export_id: ExportId,
) -> Result<(ObjectKey, NfsName), u32> {
    let parent = decode_object(&arguments.directory, state, export_id)?;
    if arguments.name.len() > NfsName::MAX_LEN {
        return Err(NfsStatus::NameTooLong as u32);
    }
    let name = NfsName::new(arguments.name).map_err(nfs_status)?;
    Ok((parent, name))
}

fn wire_nfs_status(status: u32) -> Result<NfsStatus, DecodeError> {
    Ok(NfsStatus::from_code(status).unwrap_or(NfsStatus::ServerFault))
}

fn nfs_failure_reply_for_procedure(xid: u32, procedure: u32, status: NfsStatus) -> Result<Vec<u8>, EncodeError> {
    let wcc = WccData::default();
    match procedure {
        1 => typed_nfs_reply(xid, &GetAttrResult::Err { status }),
        2 => typed_nfs_reply(
            xid,
            &SetAttrResult::Err {
                status,
                object_wcc: wcc,
            },
        ),
        3 => typed_nfs_reply(
            xid,
            &LookupResult::Err {
                status,
                directory_attributes: None,
            },
        ),
        4 => typed_nfs_reply(
            xid,
            &AccessResult::Err {
                status,
                attributes: None,
            },
        ),
        5 => typed_nfs_reply(
            xid,
            &ReadLinkResult::Err {
                status,
                attributes: None,
            },
        ),
        6 => typed_nfs_reply(
            xid,
            &ReadResult::Err {
                status,
                attributes: None,
            },
        ),
        7 => typed_nfs_reply(xid, &WriteResult::Err { status, file_wcc: wcc }),
        8..=11 => typed_nfs_reply(
            xid,
            &CreateResult::Err {
                status,
                directory_wcc: wcc,
            },
        ),
        12 | 13 => typed_nfs_reply(
            xid,
            &WccResult::Err {
                status,
                object_wcc: wcc,
            },
        ),
        14 => typed_nfs_reply(
            xid,
            &RenameResult::Err {
                status,
                from_directory_wcc: WccData::default(),
                to_directory_wcc: WccData::default(),
            },
        ),
        15 => typed_nfs_reply(
            xid,
            &LinkResult::Err {
                status,
                object_attributes: None,
                directory_wcc: wcc,
            },
        ),
        16 | 17 => typed_nfs_reply(
            xid,
            &ReadDirResult::Err {
                status,
                directory_attributes: None,
            },
        ),
        18 => typed_nfs_reply(
            xid,
            &FsStatResult::Err {
                status,
                attributes: None,
            },
        ),
        19 => typed_nfs_reply(
            xid,
            &FsInfoResult::Err {
                status,
                attributes: None,
            },
        ),
        20 => typed_nfs_reply(
            xid,
            &PathConfResult::Err {
                status,
                attributes: None,
            },
        ),
        21 => typed_nfs_reply(xid, &CommitResult::Err { status, file_wcc: wcc }),
        _ => Ok(accepted_reply(xid, PROC_UNAVAIL, &[])),
    }
}

fn typed_nfs_reply<T: EncodeNfsResult>(xid: u32, result: &T) -> Result<Vec<u8>, EncodeError> {
    let mut body = Encoder::new();
    result.encode_result(&mut body)?;
    Ok(accepted_reply(xid, SUCCESS, &body.into_bytes()))
}

fn mutation_void_reply(xid: u32, result: Result<MutationResult<()>, NfsError>) -> Result<Vec<u8>, EncodeError> {
    let result = match result {
        Ok(result) => WccResult::Ok {
            object_wcc: WccData {
                before: result.before,
                after: result.after,
            },
        },
        Err(error) => WccResult::Err {
            status: error.into(),
            object_wcc: WccData::default(),
        },
    };
    typed_nfs_reply(xid, &result)
}

fn create_failure_reply(xid: u32, status: u32) -> Result<Vec<u8>, ServerError> {
    Ok(typed_nfs_reply(
        xid,
        &CreateResult::Err {
            status: wire_nfs_status(status)?,
            directory_wcc: WccData::default(),
        },
    )?)
}

fn create_reply(
    xid: u32,
    state: &ConnectionState,
    export_id: ExportId,
    result: Result<MutationResult<crate::vfs::CreatedObject>, NfsError>,
) -> Result<Vec<u8>, EncodeError> {
    let result = match result {
        Ok(result) => CreateResult::Ok {
            object_handle: Some(state.handles.encode(export_id, result.value.object).to_vec()),
            object_attributes: result.value.attributes,
            directory_wcc: WccData {
                before: result.before,
                after: result.after,
            },
        },
        Err(error) => CreateResult::Err {
            status: error.into(),
            directory_wcc: WccData::default(),
        },
    };
    typed_nfs_reply(xid, &result)
}

fn rename_failure_reply(xid: u32, status: u32) -> Result<Vec<u8>, ServerError> {
    Ok(typed_nfs_reply(
        xid,
        &RenameResult::Err {
            status: wire_nfs_status(status)?,
            from_directory_wcc: WccData::default(),
            to_directory_wcc: WccData::default(),
        },
    )?)
}

fn link_failure_reply(xid: u32, status: u32) -> Result<Vec<u8>, ServerError> {
    Ok(typed_nfs_reply(
        xid,
        &LinkResult::Err {
            status: wire_nfs_status(status)?,
            object_attributes: None,
            directory_wcc: WccData::default(),
        },
    )?)
}

fn readdir_reply(
    xid: u32,
    state: &ConnectionState,
    export_id: ExportId,
    plus: bool,
    directory_attributes: Option<&FileAttributes>,
    page: crate::vfs::ReadDirectoryPage,
    limits: (Option<usize>, usize),
) -> Result<Vec<u8>, EncodeError> {
    let (directory_limit, wire_limit) = limits;
    let mut selected_attributes = directory_attributes.cloned();
    let mut empty_result = ReadDirResult::Ok {
        directory_attributes: directory_attributes.cloned(),
        verifier: page.verifier,
        entries: Vec::new(),
        eof: false,
    };
    let mut empty = Encoder::new();
    empty_result.encode_result(&mut empty)?;
    if empty.len().saturating_sub(4) > wire_limit {
        selected_attributes = None;
        empty_result = ReadDirResult::Ok {
            directory_attributes: None,
            verifier: page.verifier,
            entries: Vec::new(),
            eof: false,
        };
        empty = Encoder::new();
        empty_result.encode_result(&mut empty)?;
    }
    if empty.len().saturating_sub(4) > wire_limit {
        return typed_nfs_reply(
            xid,
            &ReadDirResult::Err {
                status: NfsStatus::TooSmall,
                directory_attributes: directory_attributes.cloned(),
            },
        );
    }
    let had_entries = !page.entries.is_empty();
    let mut entries = Vec::new();
    let mut encoded_entries = 0usize;
    let mut directory_bytes = 0usize;
    let mut truncated = false;
    for entry in page.entries {
        let basic = ReadDirEntry {
            file_id: entry.file_id,
            name: entry.name.as_bytes().to_vec(),
            cookie: entry.cookie,
            extension: ReadDirEntryExtension::Basic,
        };
        let mut directory_part = Encoder::new();
        encode_readdir_entry(&mut directory_part, &basic)?;
        if directory_limit
            .is_some_and(|limit| directory_bytes.saturating_add(directory_part.len()).saturating_add(4) > limit)
        {
            truncated = true;
            break;
        }
        directory_bytes = directory_bytes.saturating_add(directory_part.len());
        let typed_entry = if plus {
            ReadDirEntry {
                extension: ReadDirEntryExtension::Plus {
                    attributes: entry.attributes,
                    handle: Some(state.handles.encode(export_id, entry.object).to_vec()),
                },
                ..basic
            }
        } else {
            basic
        };
        let mut encoded = Encoder::new();
        encode_readdir_entry(&mut encoded, &typed_entry)?;
        if empty
            .len()
            .saturating_sub(4)
            .saturating_add(encoded_entries)
            .saturating_add(encoded.len())
            > wire_limit
        {
            truncated = true;
            break;
        }
        encoded_entries = encoded_entries.saturating_add(encoded.len());
        entries.push(typed_entry);
    }
    if had_entries && truncated && entries.is_empty() {
        return typed_nfs_reply(
            xid,
            &ReadDirResult::Err {
                status: NfsStatus::TooSmall,
                directory_attributes: directory_attributes.cloned(),
            },
        );
    }
    let mut result = ReadDirResult::Ok {
        directory_attributes: selected_attributes,
        verifier: page.verifier,
        entries,
        eof: page.eof && !truncated,
    };
    if !truncate_readdir_result(&mut result, wire_limit)? {
        return typed_nfs_reply(
            xid,
            &ReadDirResult::Err {
                status: NfsStatus::TooSmall,
                directory_attributes: directory_attributes.cloned(),
            },
        );
    }
    typed_nfs_reply(xid, &result)
}

async fn dispatch_mount(
    xid: u32,
    procedure: u32,
    args: &[u8],
    context: &RequestContext,
    state: &ConnectionState,
) -> Result<Vec<u8>, ServerError> {
    if matches!(procedure, 0 | 2 | 4 | 5) && !args.is_empty() {
        return Ok(accepted_reply(xid, GARBAGE_ARGS, &[]));
    }
    match procedure {
        0 => Ok(accepted_reply(xid, SUCCESS, &[])),
        1 => {
            let mut decoder = Decoder::new(args);
            let path = decoder.read_string("MOUNT path", 1024)?;
            decoder.finish()?;
            let Some(export) = select_export(state, &path) else {
                return Ok(typed_mount_reply(xid, &MountResult::Err(MountStatus::NotFound))?);
            };
            let request_context = RequestContext {
                principal: context.principal.clone(),
                client_addr: context.client_addr,
                export_id: export.id,
            };
            let vfs = &export.vfs;
            let root = match resolve_mount_object(export, &request_context, &path).await {
                Ok(object) => object,
                Err(error) => return Ok(typed_mount_reply(xid, &MountResult::Err(mount_status(error)))?),
            };
            let attributes = match vfs.getattr(&request_context, root).await {
                Ok(attributes) => attributes,
                Err(error) => return Ok(typed_mount_reply(xid, &MountResult::Err(mount_status(error)))?),
            };
            if attributes.file_type != FileType::Directory {
                return Ok(typed_mount_reply(xid, &MountResult::Err(MountStatus::NotDirectory))?);
            }
            let mut mounts = state.mounts.lock().await;
            let already_mounted = mounts
                .iter()
                .any(|entry| entry.0 == context.client_addr.ip() && entry.1 == path);
            if !already_mounted && mounts.len() >= state.limits.max_mounts {
                return Ok(typed_mount_reply(xid, &MountResult::Err(MountStatus::Io))?);
            }
            if !already_mounted {
                mounts.push((context.client_addr.ip(), path));
            }
            drop(mounts);
            let auth_flavors = match state.auth_policy {
                AuthPolicy::Anonymous => vec![AUTH_NONE],
                AuthPolicy::AuthSys => vec![crate::rpc::auth::AUTH_SYS],
                AuthPolicy::AuthSysOrAnonymous => vec![crate::rpc::auth::AUTH_SYS, AUTH_NONE],
            };
            typed_mount_reply(
                xid,
                &MountResult::Ok {
                    file_handle: state.handles.encode(export.id, root).to_vec(),
                    auth_flavors,
                },
            )
            .map_err(ServerError::from)
        },
        2 => {
            let mounts = state.mounts.lock().await;
            let encoded_length = mounts.iter().try_fold(24usize + 4, |length, (client, path)| {
                length
                    .checked_add(4)
                    .and_then(|length| length.checked_add(xdr_opaque_size(client.to_string().len())?))
                    .and_then(|length| length.checked_add(xdr_opaque_size(path.len())?))
            });
            if encoded_length.is_none_or(|length| !outbound_length_fits(length, &state.limits)) {
                return Ok(accepted_reply(xid, SYSTEM_ERR, &[]));
            }
            let result = DumpResult {
                mounts: mounts
                    .iter()
                    .map(|(client, path)| MountEntry {
                        host: client.to_string().into_bytes(),
                        path: path.clone(),
                    })
                    .collect(),
            };
            Ok(typed_mount_reply(xid, &result)?)
        },
        3 => {
            let mut decoder = Decoder::new(args);
            let path = decoder.read_string("MOUNT path", 1024)?;
            decoder.finish()?;
            state
                .mounts
                .lock()
                .await
                .retain(|entry| entry.0 != context.client_addr.ip() || entry.1 != path);
            Ok(accepted_reply(xid, SUCCESS, &[]))
        },
        4 => {
            state.mounts.lock().await.retain(|entry| entry.0 != context.client_addr.ip());
            Ok(accepted_reply(xid, SUCCESS, &[]))
        },
        5 => {
            let encoded_length = state.exports.iter().try_fold(24usize + 4, |length, export| {
                length
                    .checked_add(4)
                    .and_then(|length| length.checked_add(xdr_opaque_size(export.path.len())?))
                    // Empty group list terminator.
                    .and_then(|length| length.checked_add(4))
            });
            if encoded_length.is_none_or(|length| !outbound_length_fits(length, &state.limits)) {
                return Ok(accepted_reply(xid, SYSTEM_ERR, &[]));
            }
            let result = ExportResult {
                exports: state
                    .exports
                    .iter()
                    .map(|export| ExportEntry {
                        path: export.path.as_bytes().to_vec(),
                        groups: Vec::new(),
                    })
                    .collect(),
            };
            Ok(typed_mount_reply(xid, &result)?)
        },
        _ => Ok(accepted_reply(xid, PROC_UNAVAIL, &[])),
    }
}

fn xdr_opaque_size(length: usize) -> Option<usize> {
    4usize.checked_add(length)?.checked_add((4 - length % 4) % 4)
}

fn outbound_length_fits(length: usize, limits: &ServerLimits) -> bool {
    length <= limits.max_rpc_record_size
        && length.div_ceil(limits.max_rpc_fragment_size) <= limits.max_fragments_per_record
}

fn dispatch_portmap(xid: u32, procedure: u32, args: &[u8], state: &ConnectionState) -> Result<Vec<u8>, ServerError> {
    match procedure {
        0 if args.is_empty() => Ok(accepted_reply(xid, SUCCESS, &[])),
        0 => Ok(accepted_reply(xid, GARBAGE_ARGS, &[])),
        3 => {
            let mut decoder = Decoder::new(args);
            let program = decoder.read_u32()?;
            let version = decoder.read_u32()?;
            let transport = decoder.read_u32()?;
            let _port = decoder.read_u32()?;
            decoder.finish()?;
            let port = if transport == crate::portmap::IPPROTO_TCP
                && ((program == crate::nfs3::types::PROGRAM && version == crate::nfs3::types::VERSION)
                    || (program == crate::mount3::types::PROGRAM && version == crate::mount3::types::VERSION))
            {
                u32::from(state.local_port)
            } else {
                0
            };
            let mut body = Encoder::new();
            body.write_u32(port);
            Ok(accepted_reply(xid, SUCCESS, &body.into_bytes()))
        },
        _ => Ok(accepted_reply(xid, PROC_UNAVAIL, &[])),
    }
}

fn nfs_status(error: crate::vfs::NfsError) -> u32 {
    use crate::vfs::NfsError;
    match error {
        NfsError::Permission => 1,
        NfsError::NotFound => 2,
        NfsError::Io => 5,
        NfsError::NoDeviceOrAddress => 6,
        NfsError::Access => 13,
        NfsError::Exists => 17,
        NfsError::CrossDevice => 18,
        NfsError::NoDevice => 19,
        NfsError::NotDirectory => 20,
        NfsError::IsDirectory => 21,
        NfsError::Invalid => 22,
        NfsError::FileTooLarge => 27,
        NfsError::NoSpace => 28,
        NfsError::ReadOnly => 30,
        NfsError::TooManyLinks => 31,
        NfsError::NameTooLong => 63,
        NfsError::NotEmpty => 66,
        NfsError::Quota => 69,
        NfsError::Stale => 70,
        NfsError::Remote => 71,
        NfsError::NotSynchronized => 10002,
        NfsError::BadCookie => 10003,
        NfsError::NotSupported => 10004,
        NfsError::TooSmall => 10005,
        NfsError::ServerFault => 10006,
        NfsError::BadType => 10007,
        NfsError::Jukebox => 10008,
    }
}

fn principal_allowed(policy: AuthPolicy, principal: &Principal) -> bool {
    matches!(
        (policy, principal),
        (AuthPolicy::AuthSys, Principal::AuthSys { .. })
            | (AuthPolicy::Anonymous, Principal::Anonymous)
            | (AuthPolicy::AuthSysOrAnonymous, _)
    )
}

fn export_matches(export: &str, requested: &[u8]) -> bool {
    crate::mount3::dispatch::export_matches(export.as_bytes(), requested)
}

async fn resolve_mount_object(
    export: &ExportState,
    context: &RequestContext,
    requested: &[u8],
) -> Result<ObjectKey, NfsError> {
    let export_path = export.path.as_bytes();
    let suffix = if export_path == b"/" {
        requested.strip_prefix(b"/").ok_or(NfsError::NotFound)?
    } else {
        requested
            .strip_prefix(export_path)
            .ok_or(NfsError::NotFound)?
            .strip_prefix(b"/")
            .unwrap_or_default()
    };
    let mut object = export.vfs.root();
    for component in suffix.split(|byte| *byte == b'/').filter(|component| !component.is_empty()) {
        let name = NfsName::new(component.to_vec())?;
        object = export.vfs.lookup(context, object, &name).await?.object;
    }
    Ok(object)
}

fn mount_status(error: NfsError) -> MountStatus {
    match error {
        NfsError::Permission => MountStatus::Permission,
        NfsError::NotFound => MountStatus::NotFound,
        NfsError::Io => MountStatus::Io,
        NfsError::Access => MountStatus::Access,
        NfsError::NotDirectory => MountStatus::NotDirectory,
        NfsError::Invalid => MountStatus::Invalid,
        NfsError::NameTooLong => MountStatus::NameTooLong,
        NfsError::NotSupported => MountStatus::NotSupported,
        _ => MountStatus::ServerFault,
    }
}

fn typed_mount_reply<T: EncodeMountResult>(xid: u32, result: &T) -> Result<Vec<u8>, EncodeError> {
    let mut body = Encoder::new();
    result.encode_result(&mut body)?;
    Ok(accepted_reply(xid, SUCCESS, &body.into_bytes()))
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

fn program_mismatch(xid: u32, low: u32, high: u32) -> Vec<u8> {
    let mut body = Encoder::new();
    body.write_u32(low);
    body.write_u32(high);
    accepted_reply(xid, PROG_MISMATCH, &body.into_bytes())
}

fn rpc_mismatch(xid: u32, low: u32, high: u32) -> Vec<u8> {
    let mut reply = Encoder::new();
    reply.write_u32(xid);
    reply.write_u32(RPC_REPLY);
    reply.write_u32(1);
    reply.write_u32(0);
    reply.write_u32(low);
    reply.write_u32(high);
    reply.into_bytes()
}

fn auth_error(xid: u32, status: u32) -> Vec<u8> {
    let mut reply = Encoder::new();
    reply.write_u32(xid);
    reply.write_u32(RPC_REPLY);
    reply.write_u32(1);
    reply.write_u32(1);
    reply.write_u32(status);
    reply.into_bytes()
}

fn error_reply(xid: Option<&[u8]>, status: u32) -> Bytes {
    let xid = xid.and_then(|bytes| bytes.try_into().ok()).map(u32::from_be_bytes).unwrap_or(0);
    Bytes::from(accepted_reply(xid, status, &[]))
}

impl From<DecodeError> for ServerError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}
