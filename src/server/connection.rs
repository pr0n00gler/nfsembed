use std::collections::HashMap;
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

use super::{
    AuthPolicy, ExecutionTracker, ExportState, FileHandlePolicy, Nfs4Limits, ProtocolSet, RpcGssService,
    RpcSecurityFlavor, ServerError, ServerLimits,
};
use crate::handles::{HandleCodecSet, HandleError, HandleTarget};
use crate::mount3::codec::EncodeMountResult;
use crate::mount3::types::{DumpResult, ExportEntry, ExportResult, MountEntry, MountResult, MountStatus};
use crate::nfs3::codec::{encode_post_attributes, encode_readdir_entry, EncodeNfsResult};
use crate::nfs3::procedures::{
    AccessResult, CommitResult, CreateResult, DirectoryOperationArgs, FsInfoResult, FsStatResult, GetAttrResult,
    LinkResult, LookupResult, NfsArguments, PathConfResult, ReadDirEntry, ReadDirEntryExtension, ReadDirResult,
    ReadLinkResult, ReadResult, RenameResult, SetAttrResult, WccResult, WriteRequest, WriteResult,
};
use crate::nfs3::types::{NfsStatus, WccData};
use crate::replay::{ReplayCache, ReplayDecision, ReplayKey, RequestFingerprint};
use crate::rpc::auth::{decode_principal, AUTH_NONE};
use crate::rpc::codec::{DecodeError, Decoder, EncodeError, Encoder};
use crate::rpc::gss::{
    AuthenticatedGssRequest, ChannelBindingMaterial, Credential as GssCredential, GssContextError, GssContextRegistry,
    InitArgs, Procedure as GssProcedure, SequenceWindowError, Service as RpcGssWireService, RPCSEC_GSS,
};
use crate::rpc::record::{read_record_budgeted, validate_record_length, write_record_segments_limited, RecordLimits};
use crate::rpc::reply::EncodedReply;
use crate::vfs::{
    ExportId, FileAttributes, FileType, GssService, GssVersion, MutationResult, NfsError, NfsName, ObjectKey,
    Principal, ProtocolVersion, RequestContext, VirtualFileSystem,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ListenerRole {
    Nfs,
    Mount,
}

impl ListenerRole {
    const fn accepts(self, program: u32) -> bool {
        match self {
            Self::Nfs => program == crate::nfs3::types::PROGRAM,
            Self::Mount => program == crate::mount3::types::PROGRAM,
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Nfs => "NFS",
            Self::Mount => "MOUNTv3",
        }
    }
}

pub(crate) struct ConnectionState {
    pub protocols: ProtocolSet,
    pub exports: Arc<Vec<ExportState>>,
    pub limits: ServerLimits,
    pub nfs4_limits: Nfs4Limits,
    pub nfs4_namespace: Arc<crate::nfs4::namespace::PseudoNamespace>,
    pub nfs4_public_filehandle_node: crate::nfs4::namespace::NamespaceNodeId,
    pub nfs4_lease_seconds: u32,
    pub nfs4_runtime: crate::nfs4::runtime::Nfs4Runtime,
    pub nfs4_open_pins: crate::nfs4::open_pins::OpenPinManager,
    pub nfs4_delegations: Arc<HashMap<ExportId, Arc<crate::nfs4::delegation::DelegationManager>>>,
    pub migration: Option<Arc<crate::server::migration::MigrationControl>>,
    pub stable_journal: Option<Arc<Mutex<crate::nfs4::stable::StableJournal>>>,
    pub gss_contexts: Option<Arc<GssContextRegistry>>,
    pub nfs4_identity_mapper: Option<Arc<dyn crate::vfs::IdentityMapper>>,
    pub nfs4_namespace_locations: Arc<std::collections::BTreeMap<ExportId, crate::vfs::Nfs4FsLocations>>,
    pub nfs4_callback_connector: Option<Arc<dyn crate::server::CallbackConnector>>,
    pub nfs4_callback_attempt_timeout: std::time::Duration,
    pub nfs4_callback_gss_initiator: Option<Arc<dyn crate::rpc::gss::GssInitiatorProvider>>,
    pub channel_binding_provider: Option<Arc<dyn crate::server::ChannelBindingProvider>>,
    pub auth_policy: AuthPolicy,
    pub handles: HandleCodecSet,
    pub write_verifier: [u8; 8],
    pub replay: Arc<ReplayCache>,
    pub requests: Arc<Semaphore>,
    pub request_buffers: Arc<Semaphore>,
    pub reply_buffers: Arc<Semaphore>,
    pub executions: Weak<ExecutionTracker>,
    pub mounts: MountTable,
}

type MountTable = Arc<Mutex<Vec<(IpAddr, Vec<u8>)>>>;

struct QueuedRequest {
    record: Vec<u8>,
    _budget: Arc<OwnedSemaphorePermit>,
    deadline: Instant,
}

struct QueuedReply {
    reply: EncodedReply,
    _budget: Arc<OwnedSemaphorePermit>,
}

pub(crate) async fn serve_connection(
    stream: TcpStream,
    client_addr: SocketAddr,
    role: ListenerRole,
    state: Arc<ConnectionState>,
    shutdown: watch::Receiver<bool>,
) -> Result<(), ServerError> {
    stream.set_nodelay(true)?;
    let local_addr = stream.local_addr()?;
    let channel_binding = match &state.channel_binding_provider {
        Some(provider) => timeout(state.limits.request_timeout, provider.channel_binding(client_addr, local_addr))
            .await
            .map_err(|_| ServerError::RequestTimeout)?
            .map_err(|error| ServerError::Gss(error.to_string()))?
            .map(Arc::new),
        None => None,
    };
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
    let processor = connection_processor(
        request_receiver,
        reply_sender,
        client_addr,
        channel_binding,
        role,
        state.clone(),
        shutdown,
    );
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
    channel_binding: Option<Arc<crate::server::RpcChannelBinding>>,
    role: ListenerRole,
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
                    let channel_binding = channel_binding.clone();
                    requests.spawn(async move {
                        let deadline = record.deadline;
                        let xid = record
                            .record
                            .get(..4)
                            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                            .map(u32::from_be_bytes);
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
                        let dispatch_state = state.clone();
                        let dispatch_reply_budget = reply_budget.clone();
                        let reply = match timeout_at(
                            deadline,
                            dispatch_record(
                                record,
                                client_addr,
                                channel_binding,
                                role,
                                dispatch_state,
                                dispatch_reply_budget,
                                deadline,
                            ),
                        )
                        .await
                        {
                            Ok(result) => result,
                            Err(_) => Err(ServerError::RequestTimeout),
                        };
                        let (reply, deadline_elapsed) = match reply {
                            Ok(Some(reply)) => (reply, false),
                            Ok(None) => return Ok(()),
                            Err(ServerError::RequestTimeout) => {
                                // If execution used its entire deadline, make
                                // one non-blocking attempt to report SYSTEM_ERR.
                                // A shielded mutation may still complete and
                                // populate replay state with its real result.
                                (error_reply(xid, SYSTEM_ERR), true)
                            },
                            Err(error) => {
                                tracing::debug!(client = %client_addr, error = %error, "RPC request rejected");
                                (error_reply(xid, SYSTEM_ERR), false)
                            },
                        };
                        let queued_reply = QueuedReply {
                            reply,
                            _budget: reply_budget,
                        };
                        if deadline_elapsed {
                            reply_sender
                                .try_send(queued_reply)
                                .map_err(|_| ServerError::RequestTimeout)?;
                        } else {
                            match timeout_at(
                                deadline,
                                reply_sender.send(queued_reply),
                            )
                            .await
                            {
                                Ok(Ok(())) | Ok(Err(_)) => {},
                                Err(_) => return Err(ServerError::RequestTimeout),
                            }
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
        match timeout(progress_timeout, write_record_segments_limited(&mut writer, reply.reply.segments(), limits))
            .await
        {
            Ok(result) => result?,
            Err(_) => return Err(ServerError::RequestTimeout),
        }
    }
    Ok(())
}

async fn dispatch_record(
    request: QueuedRequest,
    client_addr: SocketAddr,
    channel_binding: Option<Arc<crate::server::RpcChannelBinding>>,
    role: ListenerRole,
    state: Arc<ConnectionState>,
    reply_budget: Arc<OwnedSemaphorePermit>,
    deadline: Instant,
) -> Result<Option<EncodedReply>, ServerError> {
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
    let credential_body = decoder.read_opaque_slice("RPC credential", 400)?;
    let credential_end = decoder.position();
    let verifier_flavor = decoder.read_u32()?;
    let verifier = decoder.read_opaque_slice("RPC verifier", 400)?;
    let args_offset = decoder.position();

    if rpc_version != 2 {
        return Ok(Some(rpc_mismatch(xid, 2, 2).into()));
    }
    if !role.accepts(program) {
        return Ok(Some(accepted_reply(xid, PROG_UNAVAIL, &[]).into()));
    }

    let mut gss_request = None;
    let channel_binding_material = channel_binding.as_deref().map(rpc_channel_binding_material);
    let (principal, arguments) = if credential_flavor == RPCSEC_GSS {
        let Some(registry) = state.gss_contexts.as_ref() else {
            return Ok(Some(auth_error(xid, 1).into()));
        };
        let credential = match GssCredential::decode(credential_body, registry.limits().wire) {
            Ok(credential) => credential,
            Err(_) => return Ok(Some(auth_error(xid, 1).into())),
        };
        match credential.procedure {
            GssProcedure::Init | GssProcedure::ContinueInit => {
                if verifier_flavor != AUTH_NONE
                    || !verifier.is_empty()
                    || procedure != crate::nfs4::NULL_PROCEDURE
                    || program != crate::nfs4::PROGRAM
                    || version != crate::nfs4::VERSION
                    || !state.protocols.includes_v4()
                {
                    return Ok(Some(auth_error(xid, 1).into()));
                }
                let init = match InitArgs::decode(&record[args_offset..], registry.limits().wire) {
                    Ok(init) => init,
                    Err(_) => return Ok(Some(accepted_reply(xid, GARBAGE_ARGS, &[]).into())),
                };
                let result = match registry.accept_init(&credential, Bytes::from(init.token)).await {
                    Ok(result) => result,
                    Err(_) => return Ok(Some(auth_error(xid, 2).into())),
                };
                let reply_verifier = if result.major_status == 0 {
                    Some(
                        registry
                            .init_reply_verifier(&result.handle, result.sequence_window)
                            .await
                            .map_err(|error| ServerError::Gss(error.to_string()))?,
                    )
                } else {
                    None
                };
                let body = result.encode()?;
                let reply = match reply_verifier {
                    Some(verifier) => accepted_reply_with_verifier(xid, SUCCESS, RPCSEC_GSS, &verifier, &body)?,
                    None => accepted_reply(xid, SUCCESS, &body),
                };
                return Ok(Some(reply.into()));
            },
            GssProcedure::Data | GssProcedure::Destroy => {
                let expected_verifier_flavor = if credential.service == RpcGssWireService::ChannelProtection {
                    AUTH_NONE
                } else {
                    RPCSEC_GSS
                };
                if verifier_flavor != expected_verifier_flavor {
                    return Ok(Some(auth_error(xid, 3).into()));
                }
                let authenticated = match registry
                    .authenticate_data(
                        &credential,
                        record.slice(..credential_end),
                        Bytes::copy_from_slice(verifier),
                        channel_binding_material.as_ref().map(|binding| binding.channel_id),
                    )
                    .await
                {
                    Ok(authenticated) => authenticated,
                    Err(GssContextError::Sequence(SequenceWindowError::Discard)) => return Ok(None),
                    Err(error) => return Ok(Some(gss_auth_error(xid, &error).into())),
                };
                let arguments = match registry.unwrap_call(&authenticated, record.slice(args_offset..)).await {
                    Ok(arguments) => arguments,
                    Err(_) => {
                        let reply =
                            protect_gss_reply(registry, &authenticated, accepted_reply(xid, GARBAGE_ARGS, &[]).into())
                                .await?;
                        return Ok(Some(reply));
                    },
                };
                let canonical_name = if let Some(mapper) = &state.nfs4_identity_mapper {
                    match mapper.canonicalize_gss(&authenticated.identity.principal).await {
                        Ok(name) => name,
                        Err(_) => return Ok(Some(auth_error(xid, 1).into())),
                    }
                } else {
                    authenticated.identity.principal.clone()
                };
                let service = match authenticated.service {
                    RpcGssWireService::None => GssService::Authentication,
                    RpcGssWireService::Integrity => GssService::Integrity,
                    RpcGssWireService::Privacy => GssService::Privacy,
                    RpcGssWireService::ChannelProtection => GssService::ChannelProtection,
                };
                let principal = Principal::Gss {
                    canonical_name,
                    mechanism: authenticated.identity.mechanism.clone(),
                    version: match credential.version {
                        crate::rpc::gss::Version::V1 => GssVersion::V1,
                        crate::rpc::gss::Version::V2 => GssVersion::V2,
                    },
                    service,
                };
                if credential.procedure == GssProcedure::Destroy {
                    if !arguments.is_empty() {
                        let reply =
                            protect_gss_reply(registry, &authenticated, accepted_reply(xid, GARBAGE_ARGS, &[]).into())
                                .await?;
                        return Ok(Some(reply));
                    }
                    let reply =
                        protect_gss_reply(registry, &authenticated, accepted_reply(xid, SUCCESS, &[]).into()).await?;
                    if let Err(error) = registry.destroy(&authenticated).await {
                        return Ok(Some(gss_auth_error(xid, &error).into()));
                    }
                    return Ok(Some(reply));
                }
                gss_request = Some(authenticated);
                (principal, arguments)
            },
            GssProcedure::BindChannel => {
                if verifier_flavor != RPCSEC_GSS
                    || procedure != crate::nfs4::NULL_PROCEDURE
                    || program != crate::nfs4::PROGRAM
                    || version != crate::nfs4::VERSION
                    || !state.protocols.includes_v4()
                    || !record[args_offset..].is_empty()
                {
                    return Ok(Some(auth_error(xid, 1).into()));
                }
                let Some(binding) = channel_binding_material.as_ref() else {
                    return Ok(Some(auth_error(xid, 5).into()));
                };
                let outcome = match registry
                    .bind_channel(
                        &credential,
                        record.slice(..credential_end),
                        Bytes::copy_from_slice(verifier),
                        binding,
                    )
                    .await
                {
                    Ok(outcome) => outcome,
                    Err(GssContextError::Sequence(SequenceWindowError::Discard)) => return Ok(None),
                    Err(error) => return Ok(Some(gss_auth_error(xid, &error).into())),
                };
                return Ok(Some(
                    accepted_reply_with_verifier(xid, SUCCESS, RPCSEC_GSS, &outcome.reply_verifier, &[])?.into(),
                ));
            },
        }
    } else {
        if verifier_flavor != AUTH_NONE || !verifier.is_empty() {
            return Ok(Some(auth_error(xid, 3).into()));
        }
        let principal = match decode_principal(credential_flavor, credential_body) {
            Ok(principal) => principal,
            Err(_) => return Ok(Some(auth_error(xid, 1).into())),
        };
        (principal, record.slice(args_offset..))
    };

    let request_export_id = request_export_id(program, procedure, &arguments, &state);
    if program != crate::portmap::PROGRAM
        && !principal_allowed_for_call(&state, program, version, procedure, request_export_id, &principal)
    {
        return Ok(Some(auth_error(xid, 5).into()));
    }

    let fingerprint = canonical_request_fingerprint(program, version, procedure, &arguments, &principal);
    let replay_key = ReplayKey {
        client_addr: SocketAddr::new(client_addr.ip(), 0),
        export_id: request_export_id,
        xid,
    };
    let lease = match state.replay.begin(replay_key, fingerprint).await? {
        ReplayDecision::Replay(reply) => {
            tracing::debug!(xid, client = %client_addr, replay = "hit", "RPC reply replayed");
            return protect_reply_for_delivery(&state, gss_request.as_ref(), reply, client_addr, xid)
                .await
                .map(Some);
        },
        ReplayDecision::Wait(waiter) => {
            tracing::debug!(xid, client = %client_addr, replay = "wait", "waiting for in-flight duplicate");
            return match timeout_at(deadline, waiter).await {
                Ok(reply) => protect_reply_for_delivery(&state, gss_request.as_ref(), reply??, client_addr, xid)
                    .await
                    .map(Some),
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

    let protocol = if program == crate::nfs3::types::PROGRAM && version == crate::nfs4::VERSION {
        ProtocolVersion::V4
    } else {
        ProtocolVersion::V3
    };
    let context = RequestContext {
        principal,
        client_addr,
        export_id: request_export_id,
        protocol,
        client_id: None,
    };
    let request_bytes = record.len();
    let permit = match timeout_at(deadline, state.requests.clone().acquire_owned()).await {
        Ok(Ok(permit)) => permit,
        Ok(Err(_)) => return Err(ServerError::ShuttingDown),
        Err(_) => {
            tracing::warn!(client = %client_addr, xid, "RPC request timed out waiting for execution capacity");
            return Err(ServerError::RequestTimeout);
        },
    };
    if request_may_mutate(program, version, procedure) {
        let execution_state = state.clone();
        let execution_gss_request = gss_request.clone();
        let (send, receive) = tokio::sync::oneshot::channel();
        let executions = state.executions.upgrade().ok_or(ServerError::ShuttingDown)?;
        executions
            .spawn(async move {
                let _permit = permit;
                // The execution tracker outlives a disconnected connection.
                // Keep both aggregate buffer charges until its request bytes
                // and any constructed reply have been released.
                let _request_budget = request_budget;
                let _reply_budget = reply_budget;
                // Mutation execution is deliberately shielded once admitted.
                // The tracker retains the task and its memory permits through
                // completion so its result can still enter replay state.
                let result = execute_request(
                    xid,
                    program,
                    version,
                    procedure,
                    arguments,
                    context,
                    client_addr,
                    request_bytes,
                    execution_gss_request,
                    execution_state,
                )
                .await;
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
            .await?;

        match timeout_at(deadline, receive).await {
            Ok(result) => protect_reply_for_delivery(&state, gss_request.as_ref(), result??, client_addr, xid)
                .await
                .map(Some),
            Err(_) => {
                tracing::warn!(client = %client_addr, xid, "RPC reply deadline elapsed while mutation continues");
                Err(ServerError::RequestTimeout)
            },
        }
    } else {
        let _permit = permit;
        let _request_budget = request_budget;
        let result = timeout_at(
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
                gss_request.clone(),
                state.clone(),
            ),
        )
        .await;
        match result {
            Ok(Ok(reply)) => {
                lease.complete(reply.clone());
                protect_reply_for_delivery(&state, gss_request.as_ref(), reply, client_addr, xid)
                    .await
                    .map(Some)
            },
            Ok(Err(error)) => {
                lease.cancel();
                Err(error)
            },
            Err(_) => {
                lease.cancel();
                tracing::warn!(client = %client_addr, xid, "RPC request execution timed out and was cancelled");
                Err(ServerError::RequestTimeout)
            },
        }
    }
}

fn request_may_mutate(program: u32, version: u32, procedure: u32) -> bool {
    if program != crate::nfs3::types::PROGRAM {
        return false;
    }
    match version {
        crate::nfs3::types::VERSION => matches!(procedure, 2 | 7..=15 | 21),
        // NFSv4 mutations are carried inside COMPOUND. Until operation-level
        // shielding owns each mutating backend call, conservatively keep the
        // fully decoded COMPOUND alive once admitted.
        crate::nfs4::VERSION => procedure == crate::nfs4::COMPOUND_PROCEDURE,
        _ => false,
    }
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
    gss_request: Option<AuthenticatedGssRequest>,
    state: Arc<ConnectionState>,
) -> Result<EncodedReply, ServerError> {
    let started_at = std::time::Instant::now();
    let span = tracing::info_span!(
        "rpc_request",
        xid,
        client = %client_addr,
        program,
        version,
        procedure,
        procedure_name = procedure_name(program, version, procedure),
        request_bytes,
    );
    let transport_capacity = state.limits.transport_record_capacity();
    let max_success_body_size = if let Some(request) = gss_request.as_ref() {
        let registry = state
            .gss_contexts
            .as_ref()
            .ok_or(ServerError::Protocol("RPCSEC_GSS registry disappeared"))?;
        registry
            .max_reply_body_size(request, transport_capacity)
            .await
            .map_err(|error| ServerError::Gss(error.to_string()))?
    } else {
        transport_capacity.saturating_sub(accepted_reply(xid, SUCCESS, &[]).len())
    };
    let reply =
        match dispatch_call(xid, program, version, procedure, &arguments, &context, max_success_body_size, &state)
            .instrument(span)
            .await
        {
            Ok(reply) => reply,
            Err(ServerError::Decode(_)) => accepted_reply(xid, GARBAGE_ARGS, &[]).into(),
            Err(ServerError::Encode(error)) => {
                tracing::warn!(client = %client_addr, xid, error = %error, "RPC result could not be encoded");
                accepted_reply(xid, SYSTEM_ERR, &[]).into()
            },
            Err(error) => return Err(error),
        };
    let limits = RecordLimits {
        max_record_size: state.limits.max_rpc_record_size,
        max_fragment_size: state.limits.max_rpc_fragment_size,
        max_fragments: state.limits.max_fragments_per_record,
    };
    if let Err(error) = validate_record_length(reply.len(), limits) {
        tracing::warn!(client = %client_addr, xid, error = %error, "RPC result exceeded outbound limits");
        let bounded_error = EncodedReply::from(accepted_reply(xid, SYSTEM_ERR, &[]));
        validate_record_length(bounded_error.len(), limits)?;
        return Ok(bounded_error);
    }
    let reply_prefix = reply.prefix();
    let protocol_status = if (program == crate::nfs3::types::PROGRAM || program == crate::mount3::types::PROGRAM)
        && reply_prefix.len() >= 28
    {
        u32::from_be_bytes(reply_prefix[24..28].try_into().unwrap_or_default())
    } else {
        0
    };
    tracing::debug!(
        xid,
        client = %client_addr,
        procedure = procedure_name(program, version, procedure),
        duration_micros = started_at.elapsed().as_micros(),
        protocol_status,
        request_bytes,
        reply_bytes = reply.len(),
        active_requests = state.limits.max_inflight_requests - state.requests.available_permits(),
        "RPC request completed"
    );
    Ok(reply)
}

fn canonical_request_fingerprint(
    program: u32,
    version: u32,
    procedure: u32,
    arguments: &[u8],
    principal: &Principal,
) -> RequestFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(program.to_be_bytes());
    hasher.update(version.to_be_bytes());
    hasher.update(procedure.to_be_bytes());
    hasher.update(arguments);
    hash_principal(&mut hasher, principal);
    RequestFingerprint(hasher.finalize().into())
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
        Principal::Gss {
            canonical_name,
            mechanism,
            version: _,
            service: _,
        } => {
            hasher.update([2]);
            hasher.update((canonical_name.len() as u32).to_be_bytes());
            hasher.update(canonical_name.as_bytes());
            hasher.update((mechanism.len() as u32).to_be_bytes());
            hasher.update(mechanism);
        },
    }
}

const SHA256_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

fn rpc_channel_binding_material(binding: &crate::server::RpcChannelBinding) -> ChannelBindingMaterial {
    let channel_hash: [u8; 32] = Sha256::digest(binding.canonical()).into();
    let mut identity_hasher = Sha256::new();
    identity_hasher.update(b"nfsembed rpc channel binding\0");
    identity_hasher.update(binding.canonical());
    let channel_id: [u8; 32] = identity_hasher.finalize().into();
    ChannelBindingMaterial {
        channel_id,
        prefix: binding.prefix().to_vec(),
        hash_oid: SHA256_OID.to_vec(),
        hash: channel_hash.to_vec(),
    }
}

fn procedure_name(program: u32, version: u32, procedure: u32) -> &'static str {
    if program == crate::nfs3::types::PROGRAM {
        if version == crate::nfs4::VERSION {
            return match procedure {
                crate::nfs4::NULL_PROCEDURE => "NFS4_NULL",
                crate::nfs4::COMPOUND_PROCEDURE => "NFS4_COMPOUND",
                _ => "UNKNOWN_NFS4",
            };
        }
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
        if let Ok(handle) = decoder.read_opaque_slice("NFS file handle", 64) {
            if let Ok((export_id, _)) = state.handles.decode_any(handle) {
                return export_id;
            }
            if let Some(Ok(HandleTarget::Backend { export_id, .. })) = state
                .migration
                .as_ref()
                .and_then(|migration| migration.imported_handles().decode_any(handle))
            {
                if state
                    .exports
                    .iter()
                    .any(|export| export.id == export_id && export.filehandle_policy == FileHandlePolicy::Persistent)
                {
                    return export_id;
                }
            }
        }
        return state.exports.first().map_or(ExportId(0), |export| export.id);
    }
    if program == crate::mount3::types::PROGRAM && matches!(procedure, 1 | 3) {
        let mut decoder = Decoder::new(args);
        if let Ok(path) = decoder.read_opaque_slice("MOUNT path", 1024) {
            if let Some(export) = select_export(state, path) {
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

#[allow(clippy::too_many_arguments)]
async fn dispatch_call(
    xid: u32,
    program: u32,
    version: u32,
    procedure: u32,
    args: &Bytes,
    context: &RequestContext,
    max_success_body_size: usize,
    state: &ConnectionState,
) -> Result<EncodedReply, ServerError> {
    match program {
        crate::nfs3::types::PROGRAM => {
            let supported = match state.protocols {
                ProtocolSet::V3 => crate::nfs3::types::VERSION..=crate::nfs3::types::VERSION,
                ProtocolSet::V4 => crate::nfs4::VERSION..=crate::nfs4::VERSION,
                ProtocolSet::V3AndV4 => crate::nfs3::types::VERSION..=crate::nfs4::VERSION,
            };
            if !supported.contains(&version) {
                return Ok(program_mismatch(xid, *supported.start(), *supported.end()).into());
            }
            if version == crate::nfs4::VERSION {
                return dispatch_nfs4(xid, procedure, args, context, max_success_body_size, state).await;
            }
            dispatch_nfs(xid, procedure, args, context, state).await
        },
        crate::mount3::types::PROGRAM => {
            if !state.protocols.includes_v3() {
                return Ok(accepted_reply(xid, PROG_UNAVAIL, &[]).into());
            }
            if version != crate::mount3::types::VERSION {
                return Ok(program_mismatch(xid, crate::mount3::types::VERSION, crate::mount3::types::VERSION).into());
            }
            dispatch_mount(xid, procedure, args, context, state).await.map(Into::into)
        },
        _ => Ok(accepted_reply(xid, PROG_UNAVAIL, &[]).into()),
    }
}

async fn dispatch_nfs4(
    xid: u32,
    procedure: u32,
    args: &Bytes,
    context: &RequestContext,
    max_success_body_size: usize,
    state: &ConnectionState,
) -> Result<EncodedReply, ServerError> {
    match procedure {
        crate::nfs4::NULL_PROCEDURE if args.is_empty() => Ok(accepted_reply(xid, SUCCESS, &[]).into()),
        crate::nfs4::NULL_PROCEDURE => Ok(accepted_reply(xid, GARBAGE_ARGS, &[]).into()),
        crate::nfs4::COMPOUND_PROCEDURE => {
            let mut limits = crate::nfs4::DecodeLimits::default();
            limits.max_operations = state.nfs4_limits.max_compound_operations;
            limits.max_attribute_bytes = limits.max_attribute_bytes.min(state.limits.max_rpc_record_size);
            limits.max_io_bytes = state.limits.max_rpc_record_size;
            let compound = match predecode_nfs4_compound(args, limits)? {
                PredecodedNfs4Compound::Execute(compound) => compound,
                PredecodedNfs4Compound::Reject {
                    response,
                    operation_count,
                    operation_limit,
                } => {
                    tracing::debug!(
                        xid,
                        operation_count,
                        operation_limit,
                        "rejecting otherwise valid over-limit NFSv4 COMPOUND"
                    );
                    return Ok(encode_nfs4_compound_reply(
                        xid,
                        response,
                        limits,
                        state.limits.transport_record_capacity(),
                    ));
                },
            };
            let response = crate::nfs4::compound::CompoundExecutor::new(
                &state.exports,
                &state.handles,
                &state.nfs4_namespace,
                state.nfs4_public_filehandle_node,
                &state.nfs4_runtime,
                &state.nfs4_open_pins,
                &state.nfs4_delegations,
                state.migration.as_deref(),
                state.nfs4_identity_mapper.as_ref(),
                &state.nfs4_namespace_locations,
                context,
                state.limits.max_read_size,
                state.limits.max_write_size,
                state.nfs4_lease_seconds,
                max_success_body_size,
                state.nfs4_callback_connector.as_ref(),
                state.nfs4_callback_attempt_timeout,
                state.nfs4_callback_gss_initiator.as_ref(),
                state.executions.clone(),
            )
            .execute(compound)
            .await;
            Ok(encode_nfs4_compound_reply(xid, response, limits, state.limits.transport_record_capacity()))
        },
        _ => Ok(accepted_reply(xid, PROC_UNAVAIL, &[]).into()),
    }
}

#[derive(Debug, Eq, PartialEq)]
enum PredecodedNfs4Compound {
    Execute(crate::nfs4::CompoundArgs),
    Reject {
        response: crate::nfs4::CompoundRes,
        operation_count: usize,
        operation_limit: usize,
    },
}

fn predecode_nfs4_compound(
    args: &[u8],
    limits: crate::nfs4::DecodeLimits,
) -> Result<PredecodedNfs4Compound, DecodeError> {
    match crate::nfs4::codec::predecode_compound_args(args, limits)? {
        crate::nfs4::codec::PredecodedCompoundArgs::Ready(compound) => Ok(PredecodedNfs4Compound::Execute(compound)),
        crate::nfs4::codec::PredecodedCompoundArgs::TooManyOperations {
            tag,
            minor_version,
            actual,
            limit,
        } => Ok(PredecodedNfs4Compound::Reject {
            response: crate::nfs4::CompoundRes {
                status: if minor_version == 0 {
                    crate::nfs4::NfsStatus::Resource
                } else {
                    crate::nfs4::NfsStatus::MinorVersionMismatch
                },
                tag,
                operations: Vec::new(),
            },
            operation_count: actual,
            operation_limit: limit,
        }),
    }
}

fn encode_nfs4_compound_reply(
    xid: u32,
    response: crate::nfs4::CompoundRes,
    limits: crate::nfs4::DecodeLimits,
    max_rpc_record_size: usize,
) -> EncodedReply {
    let rpc_prefix = Bytes::from(accepted_reply(xid, SUCCESS, &[]));
    match crate::nfs4::codec::encode_compound_res_segmented(response, rpc_prefix, limits, max_rpc_record_size) {
        Ok(reply) => reply,
        Err(error) => {
            tracing::warn!(xid, error = %error, "NFSv4 COMPOUND reply exceeded encoding limits");
            accepted_reply(xid, SYSTEM_ERR, &[]).into()
        },
    }
}

async fn dispatch_nfs(
    xid: u32,
    procedure: u32,
    args: &Bytes,
    context: &RequestContext,
    state: &ConnectionState,
) -> Result<EncodedReply, ServerError> {
    if procedure > 21 {
        return Ok(accepted_reply(xid, PROC_UNAVAIL, &[]).into());
    }
    if procedure == 7 {
        let arguments = WriteRequest::decode(args.clone(), state.limits.max_rpc_record_size)?;
        let Some(export) = state.exports.iter().find(|export| export.id == context.export_id) else {
            return Ok(nfs_failure_reply_for_procedure(xid, procedure, NfsStatus::BadHandle)?.into());
        };
        return Ok(dispatch_write(xid, arguments, context, state, export.vfs.as_ref())
            .await?
            .into());
    }
    let arguments = NfsArguments::decode(procedure, args, state.limits.max_rpc_record_size)?;
    if matches!(arguments, NfsArguments::Null) {
        return Ok(accepted_reply(xid, SUCCESS, &[]).into());
    }
    let Some(export) = state.exports.iter().find(|export| export.id == context.export_id) else {
        return Ok(nfs_failure_reply_for_procedure(xid, procedure, NfsStatus::BadHandle)?.into());
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
                    )?
                    .into())
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
                    )?
                    .into())
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
                    )?
                    .into())
                },
            };
            let result = match vfs.lookup(context, parent, &name).await {
                Ok(found) => {
                    let parent_attributes = vfs.getattr(context, parent).await.ok();
                    LookupResult::Ok {
                        object_handle: state
                            .handles
                            .encode(context.export_id, found.object)
                            .expect("request export has a configured filehandle lifetime")
                            .to_vec(),
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
                    )?
                    .into())
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
                    )?
                    .into())
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
            return dispatch_read(xid, arguments, context, state, vfs.as_ref()).await;
        },
        NfsArguments::Write(arguments) => {
            return Ok(dispatch_write(xid, arguments.into(), context, state, vfs.as_ref())
                .await?
                .into());
        },
        NfsArguments::Create(arguments) => {
            let (parent, name) = match decode_directory_operation(arguments.target, state, context.export_id) {
                Ok(value) => value,
                Err(status) => return create_failure_reply(xid, status).map(Into::into),
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
                Err(status) => return create_failure_reply(xid, status).map(Into::into),
            };
            create_reply(xid, state, context.export_id, vfs.mkdir(context, parent, &name, arguments.attributes).await)?
        },
        NfsArguments::Symlink(arguments) => {
            let (parent, name) = match decode_directory_operation(arguments.target, state, context.export_id) {
                Ok(value) => value,
                Err(status) => return create_failure_reply(xid, status).map(Into::into),
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
                Err(status) => return create_failure_reply(xid, status).map(Into::into),
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
                    )?
                    .into())
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
                    )?
                    .into())
                },
            };
            mutation_void_reply(xid, vfs.rmdir(context, parent, &name).await)?
        },
        NfsArguments::Rename(arguments) => {
            let (from_parent, from_name) = match decode_directory_operation(arguments.from, state, context.export_id) {
                Ok(value) => value,
                Err(status) => return rename_failure_reply(xid, status).map(Into::into),
            };
            let (to_parent, to_name) = match decode_directory_operation(arguments.to, state, context.export_id) {
                Ok(value) => value,
                Err(status) => return rename_failure_reply(xid, status).map(Into::into),
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
                Err(status) => return link_failure_reply(xid, status).map(Into::into),
            };
            let (parent, name) = match decode_directory_operation(arguments.target, state, context.export_id) {
                Ok(value) => value,
                Err(status) => return link_failure_reply(xid, status).map(Into::into),
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
                    )?
                    .into())
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
                )?
                .into());
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
                    )?
                    .into())
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
                )?
                .into());
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
                    )?
                    .into())
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
                    )?
                    .into())
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
                    )?
                    .into())
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
                    )?
                    .into())
                },
            };
            let result = match vfs.commit(context, object, arguments.offset, arguments.count).await {
                Ok(result) => CommitResult::Ok {
                    file_wcc: WccData {
                        before: result.before,
                        after: result.after,
                    },
                    verifier: state.write_verifier,
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
    Ok(reply.into())
}

async fn dispatch_read(
    xid: u32,
    arguments: crate::nfs3::procedures::ReadArgs,
    context: &RequestContext,
    state: &ConnectionState,
    vfs: &dyn VirtualFileSystem,
) -> Result<EncodedReply, ServerError> {
    let object = match decode_object(&arguments.object, state, context.export_id) {
        Ok(object) => object,
        Err(status) => {
            return Ok(typed_nfs_reply(
                xid,
                &ReadResult::Err {
                    status: wire_nfs_status(status)?,
                    attributes: None,
                },
            )?
            .into())
        },
    };
    let count = arguments.count.min(state.limits.max_read_size) as usize;
    match vfs.read_bytes(context, object, arguments.offset, count as u32).await {
        Ok(result) => {
            // `Bytes::slice` retains the backend allocation without copying;
            // the segmented reply keeps it alive through replay and socket I/O.
            let data = if result.data.len() > count {
                result.data.slice(..count)
            } else {
                result.data
            };
            read_success_reply(xid, result.attributes.as_ref(), data, result.eof).map_err(Into::into)
        },
        Err(error) => Ok(typed_nfs_reply(
            xid,
            &ReadResult::Err {
                status: error.into(),
                attributes: None,
            },
        )?
        .into()),
    }
}

fn read_success_reply(
    xid: u32,
    attributes: Option<&FileAttributes>,
    data: Bytes,
    eof: bool,
) -> Result<EncodedReply, EncodeError> {
    // Encode only the fixed RPC/NFS fields here. The potentially large opaque
    // payload and its static zero padding remain separate transport segments.
    let data_length = u32::try_from(data.len()).map_err(|_| EncodeError::TooLarge(data.len()))?;
    let mut prefix = accepted_reply_encoder(xid, SUCCESS, 128);
    prefix.write_u32(NfsStatus::Ok as u32);
    encode_post_attributes(&mut prefix, attributes)?;
    prefix.write_u32(data_length);
    prefix.write_bool(eof);
    prefix.write_u32(data_length);
    let padding = (4 - data.len() % 4) % 4;
    Ok(EncodedReply::segmented(Bytes::from(prefix.into_bytes()), data, padding))
}

async fn dispatch_write(
    xid: u32,
    arguments: WriteRequest,
    context: &RequestContext,
    state: &ConnectionState,
    vfs: &dyn VirtualFileSystem,
) -> Result<Vec<u8>, ServerError> {
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
    let requested = arguments.requested;
    let permitted_count = arguments.data.len().min(state.limits.max_write_size as usize);
    // `WriteRequest` owns the RPC record, so this borrowed range stays valid
    // for the complete asynchronous backend call without another allocation.
    let data = &arguments.data[..permitted_count];
    let result = match vfs.write(context, object, arguments.offset, data, requested).await {
        Ok(result)
            if result.value.count as usize <= data.len()
                && (data.is_empty() || result.value.count != 0)
                && result.value.committed.satisfies(requested) =>
        {
            WriteResult::Ok {
                file_wcc: WccData {
                    before: result.before,
                    after: result.after,
                },
                count: result.value.count,
                committed: result.value.committed,
                verifier: state.write_verifier,
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
    Ok(typed_nfs_reply(xid, &result)?)
}

fn decode_object(handle: &[u8], state: &ConnectionState, export_id: ExportId) -> Result<ObjectKey, u32> {
    match state.handles.decode(export_id, handle) {
        Ok(object) => Ok(object),
        Err(primary_error) => {
            let Some(imported) = state
                .migration
                .as_ref()
                .and_then(|migration| migration.imported_handles().decode_any(handle))
            else {
                return Err(nfs3_handle_error_status(primary_error));
            };
            match imported {
                Ok(HandleTarget::Backend {
                    export_id: decoded_export,
                    object,
                    ..
                }) if decoded_export == export_id
                    && state.exports.iter().any(|export| {
                        export.id == export_id && export.filehandle_policy == FileHandlePolicy::Persistent
                    }) =>
                {
                    Ok(object)
                },
                Ok(_) => Err(NfsStatus::BadHandle as u32),
                Err(imported_error) => {
                    Err(nfs3_handle_error_status(prefer_handle_error(primary_error, imported_error)))
                },
            }
        },
    }
}

const fn nfs3_handle_error_status(error: HandleError) -> u32 {
    match error {
        HandleError::StaleInstance => NfsStatus::Stale as u32,
        _ => NfsStatus::BadHandle as u32,
    }
}

const fn prefer_handle_error(left: HandleError, right: HandleError) -> HandleError {
    if handle_error_rank(left) >= handle_error_rank(right) {
        left
    } else {
        right
    }
}

const fn handle_error_rank(error: HandleError) -> u8 {
    match error {
        HandleError::InvalidTarget => 6,
        HandleError::WrongExport => 5,
        HandleError::InvalidTag => 4,
        HandleError::InvalidFormat => 3,
        HandleError::InvalidLength => 2,
        HandleError::StaleInstance => 1,
    }
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
    let mut reply = accepted_reply_encoder(xid, SUCCESS, 128);
    result.encode_result(&mut reply)?;
    Ok(reply.into_bytes())
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
            object_handle: Some(
                state
                    .handles
                    .encode(export_id, result.value.object)
                    .expect("response export has a configured filehandle lifetime")
                    .to_vec(),
            ),
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
    // Preallocate only a conservative number of entries; the client-controlled
    // wire limit must not trigger an oversized speculative allocation.
    let mut entries = Vec::with_capacity(page.entries.len().min(wire_limit / 32));
    let mut encoded_entries = 0usize;
    let mut directory_bytes = 0usize;
    let mut truncated = false;
    for entry in page.entries {
        let basic = ReadDirEntry {
            file_id: entry.file_id,
            name: entry.name.into_bytes(),
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
                    handle: Some(
                        state
                            .handles
                            .encode(export_id, entry.object)
                            .expect("directory export has a configured filehandle lifetime")
                            .to_vec(),
                    ),
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
    let result = ReadDirResult::Ok {
        directory_attributes: selected_attributes,
        verifier: page.verifier,
        entries,
        eof: page.eof && !truncated,
    };
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
                protocol: context.protocol,
                client_id: context.client_id,
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
            let mut auth_flavors = Vec::with_capacity(export.security_policy.flavors().len());
            for flavor in export.security_policy.flavors() {
                let flavor = match flavor {
                    RpcSecurityFlavor::AuthNone => AUTH_NONE,
                    RpcSecurityFlavor::AuthSys => crate::rpc::auth::AUTH_SYS,
                    RpcSecurityFlavor::RpcSecGss { .. } => RPCSEC_GSS,
                };
                if !auth_flavors.contains(&flavor) {
                    auth_flavors.push(flavor);
                }
            }
            typed_mount_reply(
                xid,
                &MountResult::Ok {
                    file_handle: state
                        .handles
                        .encode(export.id, root)
                        .expect("mounted export has a configured filehandle lifetime")
                        .to_vec(),
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
            | (AuthPolicy::AuthSysOrAnonymous, Principal::AuthSys { .. } | Principal::Anonymous)
    )
}

fn principal_allowed_for_call(
    state: &ConnectionState,
    program: u32,
    version: u32,
    procedure: u32,
    export_id: ExportId,
    principal: &Principal,
) -> bool {
    // Native clients probe the NFS endpoint with an AUTH_NONE NULL call
    // before selecting one of the export's advertised security flavors.
    // NULL has no arguments, result, or export access to authorize.
    if program == crate::nfs3::types::PROGRAM && procedure == 0 {
        return true;
    }
    if program != crate::nfs4::PROGRAM {
        return principal_allowed(state.auth_policy, principal);
    }

    let selected_export = state.exports.iter().find(|export| export.id == export_id);
    let exports: Box<dyn Iterator<Item = &ExportState> + '_> =
        if version == crate::nfs3::types::VERSION && selected_export.is_some() {
            Box::new(selected_export.into_iter())
        } else {
            // Before a v4 COMPOUND establishes a current filehandle, PUTROOTFH and
            // SECINFO must remain reachable with any flavor configured somewhere
            // in the pseudo-filesystem. Per-export transitions enforce the
            // selected edge policy.
            Box::new(state.exports.iter())
        };
    exports.into_iter().any(|export| {
        export.security_policy.flavors().iter().any(|flavor| match (flavor, principal) {
            (RpcSecurityFlavor::AuthNone, Principal::Anonymous)
            | (RpcSecurityFlavor::AuthSys, Principal::AuthSys { .. }) => true,
            (
                RpcSecurityFlavor::RpcSecGss {
                    mechanism,
                    qop,
                    service,
                },
                Principal::Gss {
                    mechanism: principal_mechanism,
                    service: principal_service,
                    ..
                },
            ) => {
                let expected_service = match principal_service {
                    GssService::Authentication => RpcGssService::None,
                    GssService::Integrity => RpcGssService::Integrity,
                    GssService::Privacy => RpcGssService::Privacy,
                    GssService::ChannelProtection => RpcGssService::ChannelProtection,
                };
                *qop == 0 && mechanism == principal_mechanism && *service == expected_service
            },
            _ => false,
        })
    })
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
    let mut reply = accepted_reply_encoder(xid, SUCCESS, 64);
    result.encode_result(&mut reply)?;
    Ok(reply.into_bytes())
}

async fn protect_reply_for_delivery(
    state: &ConnectionState,
    request: Option<&AuthenticatedGssRequest>,
    canonical_reply: EncodedReply,
    client_addr: SocketAddr,
    xid: u32,
) -> Result<EncodedReply, ServerError> {
    let limits = RecordLimits {
        max_record_size: state.limits.max_rpc_record_size,
        max_fragment_size: state.limits.max_rpc_fragment_size,
        max_fragments: state.limits.max_fragments_per_record,
    };
    let protect = |reply| async move {
        match request {
            Some(request) => {
                let registry = state
                    .gss_contexts
                    .as_ref()
                    .ok_or(ServerError::Protocol("RPCSEC_GSS registry disappeared"))?;
                protect_gss_reply(registry, request, reply).await
            },
            None => Ok(reply),
        }
    };
    let reply = protect(canonical_reply).await?;
    if let Err(error) = validate_record_length(reply.len(), limits) {
        tracing::warn!(
            client = %client_addr,
            xid,
            error = %error,
            "protected RPC result exceeded outbound limits"
        );
        let bounded_error = protect(accepted_reply(xid, SYSTEM_ERR, &[]).into()).await?;
        validate_record_length(bounded_error.len(), limits)?;
        return Ok(bounded_error);
    }
    Ok(reply)
}

async fn protect_gss_reply(
    registry: &GssContextRegistry,
    request: &AuthenticatedGssRequest,
    reply: EncodedReply,
) -> Result<EncodedReply, ServerError> {
    let encoded = reply.into_bytes();
    let mut decoder = Decoder::new(&encoded);
    let xid = decoder.read_u32()?;
    if decoder.read_u32()? != RPC_REPLY || decoder.read_u32()? != MSG_ACCEPTED {
        return Err(ServerError::Protocol("RPCSEC_GSS can only protect an accepted RPC reply"));
    }
    let _unprotected_verifier_flavor = decoder.read_u32()?;
    let _unprotected_verifier = decoder.read_opaque_slice("RPC reply verifier", 400)?;
    let accept_status = decoder.read_u32()?;
    let body = encoded.slice(decoder.position()..);

    let verifier = registry
        .reply_verifier(request)
        .await
        .map_err(|error| ServerError::Gss(error.to_string()))?;
    if verifier.len() > 400 {
        return Err(ServerError::Gss("RPCSEC_GSS reply verifier exceeds the RPC opaque-auth limit".to_owned()));
    }
    let protected = if accept_status == SUCCESS {
        registry
            .wrap_reply(request, body)
            .await
            .map_err(|error| ServerError::Gss(error.to_string()))?
    } else {
        body
    };
    let mut output = Encoder::with_capacity(24usize.saturating_add(verifier.len()).saturating_add(protected.len()));
    output.write_u32(xid);
    output.write_u32(RPC_REPLY);
    output.write_u32(MSG_ACCEPTED);
    output.write_u32(if request.service == RpcGssWireService::ChannelProtection {
        AUTH_NONE
    } else {
        RPCSEC_GSS
    });
    output.write_opaque(&verifier)?;
    output.write_u32(accept_status);
    output.write_fixed(&protected);
    Ok(output.into_bytes().into())
}

fn gss_auth_error(xid: u32, error: &GssContextError) -> Vec<u8> {
    let status = match error {
        GssContextError::CredentialProblem | GssContextError::Resource => 13,
        GssContextError::ContextProblem
        | GssContextError::Sequence(SequenceWindowError::ContextProblem)
        | GssContextError::Provider(_) => 14,
        GssContextError::BadCredential
        | GssContextError::GarbageArguments
        | GssContextError::Sequence(SequenceWindowError::InvalidSize)
        | GssContextError::Sequence(SequenceWindowError::Discard)
        | GssContextError::Decode(_)
        | GssContextError::Encode(_) => 1,
    };
    auth_error(xid, status)
}

fn accepted_reply_with_verifier(
    xid: u32,
    status: u32,
    verifier_flavor: u32,
    verifier: &[u8],
    body: &[u8],
) -> Result<Vec<u8>, EncodeError> {
    if verifier.len() > 400 {
        return Err(EncodeError::TooLarge(verifier.len()));
    }
    let mut reply = Encoder::with_capacity(24usize.saturating_add(verifier.len()).saturating_add(body.len()));
    reply.write_u32(xid);
    reply.write_u32(RPC_REPLY);
    reply.write_u32(MSG_ACCEPTED);
    reply.write_u32(verifier_flavor);
    reply.write_opaque(verifier)?;
    reply.write_u32(status);
    reply.write_fixed(body);
    Ok(reply.into_bytes())
}

fn accepted_reply(xid: u32, status: u32, body: &[u8]) -> Vec<u8> {
    let mut reply = accepted_reply_encoder(xid, status, body.len());
    reply.write_fixed(body);
    reply.into_bytes()
}

fn accepted_reply_encoder(xid: u32, status: u32, body_capacity: usize) -> Encoder {
    // Typed result encoders append directly after the accepted-reply header,
    // avoiding a temporary body buffer and a second copy into the final reply.
    let mut reply = Encoder::with_capacity(24usize.saturating_add(body_capacity));
    reply.write_u32(xid);
    reply.write_u32(RPC_REPLY);
    reply.write_u32(MSG_ACCEPTED);
    reply.write_u32(AUTH_NONE);
    reply.write_u32(0);
    reply.write_u32(status);
    reply
}

fn program_mismatch(xid: u32, low: u32, high: u32) -> Vec<u8> {
    let mut reply = accepted_reply_encoder(xid, PROG_MISMATCH, 8);
    reply.write_u32(low);
    reply.write_u32(high);
    reply.into_bytes()
}

fn rpc_mismatch(xid: u32, low: u32, high: u32) -> Vec<u8> {
    let mut reply = Encoder::with_capacity(24);
    reply.write_u32(xid);
    reply.write_u32(RPC_REPLY);
    reply.write_u32(1);
    reply.write_u32(0);
    reply.write_u32(low);
    reply.write_u32(high);
    reply.into_bytes()
}

fn auth_error(xid: u32, status: u32) -> Vec<u8> {
    let mut reply = Encoder::with_capacity(20);
    reply.write_u32(xid);
    reply.write_u32(RPC_REPLY);
    reply.write_u32(1);
    reply.write_u32(1);
    reply.write_u32(status);
    reply.into_bytes()
}

fn error_reply(xid: Option<u32>, status: u32) -> EncodedReply {
    accepted_reply(xid.unwrap_or(0), status, &[]).into()
}

impl From<DecodeError> for ServerError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}

#[cfg(test)]
mod reply_tests {
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;
    use tokio::sync::Notify;

    use super::*;
    use crate::nfs4::{CompoundRes, NfsResult, NfsStatus as Nfs4Status, ReadOk, ResOp};
    use crate::rpc::gss::{
        AcceptContext, AcceptOutcome, Credential, GssContextLimits, GssIdentity, GssProvider, Procedure,
        ProtectionSizes, ProviderContextId, ProviderError, Service, Version,
    };
    use crate::server::{ExportConfig, FileSystemId, NfsServer, RpcSecurityFlavor, SecurityPolicy};
    use crate::vfs::{CreatedObject, FileAttributes, FileType, NfsName, NfsTime, VfsCapabilities, WriteStability};

    const TEST_XID: u32 = 0x1122_3344;
    const TEST_EXPORT_ID: ExportId = ExportId(1);
    const TEST_MECHANISM: &[u8] = &[0x2a, 0x86, 0x48];
    const TEST_OBJECT: ObjectKey = ObjectKey {
        file_id: 1,
        generation: 1,
    };

    struct ReplayWriteVfs {
        writes: AtomicUsize,
        block_first: AtomicBool,
        first_entered: Notify,
        release_first: Notify,
    }

    impl ReplayWriteVfs {
        fn new() -> Self {
            Self {
                writes: AtomicUsize::new(0),
                block_first: AtomicBool::new(true),
                first_entered: Notify::new(),
                release_first: Notify::new(),
            }
        }
    }

    #[async_trait]
    impl VirtualFileSystem for ReplayWriteVfs {
        fn capabilities(&self) -> VfsCapabilities {
            VfsCapabilities::READ_WRITE
        }

        fn root(&self) -> ObjectKey {
            TEST_OBJECT
        }

        async fn getattr(&self, _context: &RequestContext, object: ObjectKey) -> Result<FileAttributes, NfsError> {
            if object != TEST_OBJECT {
                return Err(NfsError::NotFound);
            }
            Ok(FileAttributes {
                file_type: FileType::Regular,
                mode: 0o600,
                links: 1,
                uid: 0,
                gid: 0,
                size: 0,
                used: 0,
                device: None,
                fs_id: 1,
                file_id: object.file_id,
                change_id: 1u64.into(),
                access_time: NfsTime::default(),
                modify_time: NfsTime::default(),
                change_time: NfsTime::default(),
            })
        }

        async fn lookup(
            &self,
            _context: &RequestContext,
            _parent: ObjectKey,
            _name: &NfsName,
        ) -> Result<CreatedObject, NfsError> {
            Err(NfsError::NotFound)
        }

        async fn write(
            &self,
            _context: &RequestContext,
            object: ObjectKey,
            _offset: u64,
            data: &[u8],
            requested: WriteStability,
        ) -> Result<MutationResult<crate::vfs::WriteResult>, NfsError> {
            if object != TEST_OBJECT {
                return Err(NfsError::NotFound);
            }
            let call = self.writes.fetch_add(1, Ordering::SeqCst);
            if call == 0 && self.block_first.swap(false, Ordering::SeqCst) {
                self.first_entered.notify_one();
                self.release_first.notified().await;
            }
            Ok(MutationResult::without_metadata(crate::vfs::WriteResult {
                count: data.len() as u32,
                committed: requested,
            }))
        }
    }

    struct ReplayGssProvider {
        next_context: AtomicU64,
        authenticated_headers: AtomicUsize,
        authenticated_bodies: AtomicUsize,
    }

    impl ReplayGssProvider {
        fn new() -> Self {
            Self {
                next_context: AtomicU64::new(1),
                authenticated_headers: AtomicUsize::new(0),
                authenticated_bodies: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl GssProvider for ReplayGssProvider {
        async fn accept_security_context(
            &self,
            continuation: Option<AcceptContext>,
            version: Version,
            token: Bytes,
        ) -> Result<AcceptOutcome, ProviderError> {
            let provider_context = continuation.map_or_else(
                || ProviderContextId(self.next_context.fetch_add(1, Ordering::SeqCst)),
                |context| context.provider_context,
            );
            let principal = String::from_utf8(token.to_vec()).map_err(|_| ProviderError::InvalidToken)?;
            Ok(AcceptOutcome {
                context: AcceptContext {
                    provider_context,
                    version,
                    expires_at: std::time::Instant::now() + Duration::from_secs(60),
                },
                major_status: 0,
                minor_status: 0,
                output_token: Bytes::new(),
                complete_identity: Some(GssIdentity {
                    principal,
                    mechanism: TEST_MECHANISM.to_vec(),
                }),
            })
        }

        async fn verify_mic(
            &self,
            _context: ProviderContextId,
            message: Bytes,
            mic: Bytes,
        ) -> Result<(), ProviderError> {
            if message.starts_with(&TEST_XID.to_be_bytes()) {
                self.authenticated_headers.fetch_add(1, Ordering::SeqCst);
            } else {
                self.authenticated_bodies.fetch_add(1, Ordering::SeqCst);
            }
            let expected: [u8; 32] = Sha256::digest(&message).into();
            (mic.as_ref() == expected).then_some(()).ok_or(ProviderError::Integrity)
        }

        async fn get_mic(&self, _context: ProviderContextId, message: Bytes) -> Result<Bytes, ProviderError> {
            Ok(Bytes::copy_from_slice(&Sha256::digest(&message)))
        }

        async fn unwrap(&self, _context: ProviderContextId, token: Bytes) -> Result<Bytes, ProviderError> {
            self.authenticated_bodies.fetch_add(1, Ordering::SeqCst);
            Ok(token)
        }

        async fn wrap(
            &self,
            _context: ProviderContextId,
            message: Bytes,
            _confidentiality: bool,
        ) -> Result<Bytes, ProviderError> {
            Ok(message)
        }

        async fn protection_sizes(&self, _context: ProviderContextId) -> Result<ProtectionSizes, ProviderError> {
            Ok(ProtectionSizes {
                max_mic_token_bytes: 32,
                max_wrap_overhead_bytes: 0,
            })
        }

        async fn delete_security_context(&self, _context: ProviderContextId) -> Result<(), ProviderError> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct TestGssContext {
        handle: Vec<u8>,
        provider_context: ProviderContextId,
        principal: String,
    }

    struct ReplayHarness {
        state: Arc<ConnectionState>,
        _executions: Arc<ExecutionTracker>,
        registry: Arc<GssContextRegistry>,
        provider: Arc<ReplayGssProvider>,
        vfs: Arc<ReplayWriteVfs>,
        alice: TestGssContext,
        bob: TestGssContext,
    }

    async fn replay_harness() -> ReplayHarness {
        let vfs = Arc::new(ReplayWriteVfs::new());
        let security_policy = SecurityPolicy::new([
            RpcSecurityFlavor::RpcSecGss {
                mechanism: TEST_MECHANISM.to_vec(),
                qop: 0,
                service: RpcGssService::Integrity,
            },
            RpcSecurityFlavor::RpcSecGss {
                mechanism: TEST_MECHANISM.to_vec(),
                qop: 0,
                service: RpcGssService::Privacy,
            },
        ])
        .unwrap();
        let export = ExportConfig::new(
            TEST_EXPORT_ID,
            "/",
            FileSystemId::new(1, 1),
            security_policy,
            FileHandlePolicy::Volatile,
        );
        let limits = ServerLimits {
            replay_cache_capacity: 1,
            replay_cache_max_bytes: 512,
            ..ServerLimits::default()
        };
        let server = NfsServer::builder(ProtocolSet::V3)
            .add_export(export, vfs.clone())
            .limits(limits)
            .build()
            .unwrap();
        let (mut state, executions, _) = server.connection_state().await.unwrap();

        let provider = Arc::new(ReplayGssProvider::new());
        let registry = Arc::new(GssContextRegistry::new(provider.clone(), GssContextLimits::default()).unwrap());
        Arc::get_mut(&mut state)
            .expect("the test owns the only connection-state reference")
            .gss_contexts = Some(registry.clone());

        let alice = establish_test_context(&registry, "alice@EXAMPLE.TEST", ProviderContextId(1)).await;
        let bob = establish_test_context(&registry, "bob@EXAMPLE.TEST", ProviderContextId(2)).await;
        ReplayHarness {
            state,
            _executions: executions,
            registry,
            provider,
            vfs,
            alice,
            bob,
        }
    }

    #[tokio::test]
    async fn auth_none_can_probe_nfs_null_but_cannot_access_an_auth_sys_export() {
        let export = ExportConfig::new(
            TEST_EXPORT_ID,
            "/",
            FileSystemId::new(1, 1),
            SecurityPolicy::auth_sys(),
            FileHandlePolicy::Volatile,
        );
        let server = NfsServer::builder(ProtocolSet::V3)
            .add_export(export, Arc::new(ReplayWriteVfs::new()))
            .auth_policy(AuthPolicy::AuthSysOrAnonymous)
            .build()
            .unwrap();
        let (state, _executions, _) = server.connection_state().await.unwrap();

        assert!(principal_allowed_for_call(
            &state,
            crate::nfs3::types::PROGRAM,
            crate::nfs3::types::VERSION,
            0,
            ExportId(0),
            &Principal::Anonymous,
        ));
        assert!(!principal_allowed_for_call(
            &state,
            crate::nfs3::types::PROGRAM,
            crate::nfs3::types::VERSION,
            1,
            TEST_EXPORT_ID,
            &Principal::Anonymous,
        ));
    }

    async fn establish_test_context(
        registry: &GssContextRegistry,
        principal: &str,
        provider_context: ProviderContextId,
    ) -> TestGssContext {
        let result = registry
            .accept_init(
                &Credential {
                    version: Version::V1,
                    procedure: Procedure::Init,
                    sequence: 0,
                    service: Service::None,
                    handle: Vec::new(),
                },
                Bytes::copy_from_slice(principal.as_bytes()),
            )
            .await
            .unwrap();
        assert_eq!(result.major_status, 0);
        TestGssContext {
            handle: result.handle,
            provider_context,
            principal: principal.to_owned(),
        }
    }

    fn write_arguments(state: &ConnectionState, data: &[u8]) -> Vec<u8> {
        let handle = state.handles.encode(TEST_EXPORT_ID, TEST_OBJECT).unwrap();
        let mut encoded = Encoder::new();
        encoded.write_opaque(&handle).unwrap();
        encoded.write_u64(0);
        encoded.write_u32(data.len() as u32);
        encoded.write_u32(2);
        encoded.write_opaque(data).unwrap();
        encoded.into_bytes()
    }

    async fn gss_write_call(
        registry: &GssContextRegistry,
        context: &TestGssContext,
        sequence: u32,
        service: Service,
        arguments: &[u8],
    ) -> (Vec<u8>, AuthenticatedGssRequest) {
        let authenticated = AuthenticatedGssRequest {
            context_handle: context.handle.clone(),
            provider_context: context.provider_context,
            identity: GssIdentity {
                principal: context.principal.clone(),
                mechanism: TEST_MECHANISM.to_vec(),
            },
            sequence,
            service,
        };
        let protected_arguments = registry
            .wrap_reply(&authenticated, Bytes::copy_from_slice(arguments))
            .await
            .unwrap();
        let credential = Credential {
            version: Version::V1,
            procedure: Procedure::Data,
            sequence,
            service,
            handle: context.handle.clone(),
        }
        .encode()
        .unwrap();

        let mut header = Encoder::new();
        header.write_u32(TEST_XID);
        header.write_u32(RPC_CALL);
        header.write_u32(2);
        header.write_u32(crate::nfs3::types::PROGRAM);
        header.write_u32(crate::nfs3::types::VERSION);
        header.write_u32(7);
        header.write_u32(RPCSEC_GSS);
        header.write_opaque(&credential).unwrap();
        let header = header.into_bytes();
        let verifier: [u8; 32] = Sha256::digest(&header).into();

        let mut record = Encoder::with_capacity(
            header
                .len()
                .saturating_add(8)
                .saturating_add(verifier.len())
                .saturating_add(protected_arguments.len()),
        );
        record.write_fixed(&header);
        record.write_u32(RPCSEC_GSS);
        record.write_opaque(&verifier).unwrap();
        record.write_fixed(&protected_arguments);
        (record.into_bytes(), authenticated)
    }

    async fn dispatch_test_record(state: Arc<ConnectionState>, record: Vec<u8>) -> EncodedReply {
        let request_bytes = u32::try_from(record.len()).unwrap();
        let reply_bytes = u32::try_from(state.limits.max_rpc_record_size).unwrap();
        let request_budget = Arc::new(state.request_buffers.clone().acquire_many_owned(request_bytes).await.unwrap());
        let reply_budget = Arc::new(state.reply_buffers.clone().acquire_many_owned(reply_bytes).await.unwrap());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        dispatch_record(
            QueuedRequest {
                record,
                _budget: request_budget,
                deadline,
            },
            "127.0.0.1:9000".parse().unwrap(),
            None,
            ListenerRole::Nfs,
            state,
            reply_budget,
            deadline,
        )
        .await
        .unwrap()
        .unwrap()
    }

    async fn decode_protected_write_reply(
        registry: &GssContextRegistry,
        request: &AuthenticatedGssRequest,
        reply: EncodedReply,
    ) -> (Bytes, Bytes) {
        let encoded = reply.into_bytes();
        let mut decoder = Decoder::new(&encoded);
        assert_eq!(decoder.read_u32().unwrap(), TEST_XID);
        assert_eq!(decoder.read_u32().unwrap(), RPC_REPLY);
        assert_eq!(decoder.read_u32().unwrap(), MSG_ACCEPTED);
        assert_eq!(decoder.read_u32().unwrap(), RPCSEC_GSS);
        let verifier = decoder.read_opaque_slice("reply verifier", 400).unwrap();
        let expected_verifier: [u8; 32] = Sha256::digest(request.sequence.to_be_bytes()).into();
        assert_eq!(verifier, expected_verifier);
        assert_eq!(decoder.read_u32().unwrap(), SUCCESS);
        let protected = encoded.slice(decoder.position()..);
        let body = registry.unwrap_call(request, protected).await.unwrap();
        let mut body_decoder = Decoder::new(&body);
        assert_eq!(body_decoder.read_u32().unwrap(), NfsStatus::Ok as u32);
        (encoded, body)
    }

    fn assert_canonical_write_reply(reply: &EncodedReply) {
        let encoded = reply.clone().into_bytes();
        let mut decoder = Decoder::new(&encoded);
        assert_eq!(decoder.read_u32().unwrap(), TEST_XID);
        assert_eq!(decoder.read_u32().unwrap(), RPC_REPLY);
        assert_eq!(decoder.read_u32().unwrap(), MSG_ACCEPTED);
        assert_eq!(decoder.read_u32().unwrap(), AUTH_NONE);
        assert!(decoder.read_opaque_slice("canonical verifier", 400).unwrap().is_empty());
        assert_eq!(decoder.read_u32().unwrap(), SUCCESS);
        assert_eq!(decoder.read_u32().unwrap(), NfsStatus::Ok as u32);
    }

    async fn wait_for_authenticated_bodies(provider: &ReplayGssProvider, expected: usize) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while provider.authenticated_bodies.load(Ordering::SeqCst) < expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("authenticated duplicate did not reach replay lookup");
    }

    async fn assert_gss_replay_service(primary_service: Service) {
        let harness = replay_harness().await;
        let same_arguments = write_arguments(&harness.state, b"same mutation");
        let (first_record, first_request) =
            gss_write_call(&harness.registry, &harness.alice, 1, primary_service, &same_arguments).await;
        let first = tokio::spawn(dispatch_test_record(harness.state.clone(), first_record));
        harness.vfs.first_entered.notified().await;

        let (second_record, second_request) =
            gss_write_call(&harness.registry, &harness.alice, 2, primary_service, &same_arguments).await;
        let second = tokio::spawn(dispatch_test_record(harness.state.clone(), second_record));
        wait_for_authenticated_bodies(&harness.provider, 2).await;
        assert_eq!(harness.state.replay.len().await, 1);
        harness.vfs.release_first.notify_one();

        let first_reply = first.await.unwrap();
        let second_reply = second.await.unwrap();
        let (first_wire, first_body) =
            decode_protected_write_reply(&harness.registry, &first_request, first_reply).await;
        let (second_wire, second_body) =
            decode_protected_write_reply(&harness.registry, &second_request, second_reply).await;
        assert_eq!(first_body, second_body);
        assert_ne!(first_wire, second_wire);
        assert_eq!(harness.vfs.writes.load(Ordering::SeqCst), 1);

        let (replay_record, replay_request) =
            gss_write_call(&harness.registry, &harness.alice, 3, primary_service, &same_arguments).await;
        let replay_reply = dispatch_test_record(harness.state.clone(), replay_record).await;
        let (replay_wire, replay_body) =
            decode_protected_write_reply(&harness.registry, &replay_request, replay_reply).await;
        assert_eq!(first_body, replay_body);
        assert_ne!(first_wire, replay_wire);
        assert_eq!(harness.vfs.writes.load(Ordering::SeqCst), 1);

        let alternate_service = match primary_service {
            Service::Integrity => Service::Privacy,
            Service::Privacy => Service::Integrity,
            _ => unreachable!("the replay test uses protected GSS services"),
        };
        let (cross_service_record, cross_service_request) =
            gss_write_call(&harness.registry, &harness.alice, 4, alternate_service, &same_arguments).await;
        let cross_service_reply = dispatch_test_record(harness.state.clone(), cross_service_record).await;
        let (cross_service_wire, cross_service_body) =
            decode_protected_write_reply(&harness.registry, &cross_service_request, cross_service_reply).await;
        assert_eq!(first_body, cross_service_body);
        assert_ne!(first_wire, cross_service_wire);
        assert_eq!(harness.vfs.writes.load(Ordering::SeqCst), 1);

        let principal = Principal::Gss {
            canonical_name: harness.alice.principal.clone(),
            mechanism: TEST_MECHANISM.to_vec(),
            version: GssVersion::V1,
            service: match alternate_service {
                Service::Integrity => GssService::Integrity,
                Service::Privacy => GssService::Privacy,
                _ => unreachable!(),
            },
        };
        let replay_key = ReplayKey {
            client_addr: "127.0.0.1:0".parse().unwrap(),
            export_id: TEST_EXPORT_ID,
            xid: TEST_XID,
        };
        let fingerprint = canonical_request_fingerprint(
            crate::nfs3::types::PROGRAM,
            crate::nfs3::types::VERSION,
            7,
            &same_arguments,
            &principal,
        );
        let cached = match harness.state.replay.begin(replay_key, fingerprint).await.unwrap() {
            ReplayDecision::Replay(reply) => reply,
            ReplayDecision::Execute(_) | ReplayDecision::Wait(_) => panic!("canonical GSS result was not cached"),
        };
        assert_canonical_write_reply(&cached);
        assert_eq!(harness.state.replay.len().await, 1);
        assert!(harness.state.replay.retained_bytes().await <= 512);

        let (other_identity_record, other_identity_request) =
            gss_write_call(&harness.registry, &harness.bob, 1, primary_service, &same_arguments).await;
        let other_identity_reply = dispatch_test_record(harness.state.clone(), other_identity_record).await;
        let _ = decode_protected_write_reply(&harness.registry, &other_identity_request, other_identity_reply).await;
        assert_eq!(harness.vfs.writes.load(Ordering::SeqCst), 2);

        let changed_arguments = write_arguments(&harness.state, b"changed mutation");
        let (changed_record, changed_request) =
            gss_write_call(&harness.registry, &harness.alice, 5, primary_service, &changed_arguments).await;
        let changed_reply = dispatch_test_record(harness.state.clone(), changed_record).await;
        let _ = decode_protected_write_reply(&harness.registry, &changed_request, changed_reply).await;
        assert_eq!(harness.vfs.writes.load(Ordering::SeqCst), 3);
        assert_eq!(harness.state.replay.len().await, 1);
        assert!(harness.state.replay.retained_bytes().await <= 512);
    }

    #[tokio::test]
    async fn gss_integrity_retries_share_canonical_drc_results_and_use_fresh_protection() {
        assert_gss_replay_service(Service::Integrity).await;
    }

    #[tokio::test]
    async fn gss_privacy_retries_share_canonical_drc_results_and_use_fresh_protection() {
        assert_gss_replay_service(Service::Privacy).await;
    }

    #[test]
    fn oversized_nfs4_compound_is_replaced_by_bounded_rpc_system_error() {
        let xid = 0x1020_3040;
        let response = CompoundRes::from_operations(
            b"oversized".to_vec(),
            vec![ResOp::Read(NfsResult::Ok(ReadOk {
                eof: true,
                data: vec![0x5a; 1024],
            }))],
        );
        assert_eq!(response.status, Nfs4Status::Ok);

        let reply = encode_nfs4_compound_reply(xid, response, crate::nfs4::DecodeLimits::default(), 64);
        assert_eq!(reply.segment_count(), 1);
        assert_eq!(reply.into_bytes().as_ref(), accepted_reply(xid, SYSTEM_ERR, &[]));
    }

    #[test]
    fn overlong_valid_nfs4_compound_returns_resource_without_becoming_executable() {
        let xid = 0x5060_7080;
        let limits = crate::nfs4::DecodeLimits {
            max_operations: 64,
            ..crate::nfs4::DecodeLimits::default()
        };
        let mut operations = Vec::new();
        for _ in 0..50 {
            operations.extend([
                crate::nfs4::ArgOp::PutRootFh,
                crate::nfs4::ArgOp::GetFh,
                crate::nfs4::ArgOp::GetAttr(crate::nfs4::GetAttrArgs {
                    requested_attributes: vec![1],
                }),
            ]);
        }
        let arguments = crate::nfs4::CompoundArgs {
            tag: b"COMP6".to_vec(),
            minor_version: 0,
            operations,
        };
        let encoded = crate::nfs4::encode_compound_args(&arguments).unwrap();
        let (response, operation_count, operation_limit) = match predecode_nfs4_compound(&encoded, limits).unwrap() {
            PredecodedNfs4Compound::Reject {
                response,
                operation_count,
                operation_limit,
            } => (response, operation_count, operation_limit),
            PredecodedNfs4Compound::Execute(_) => panic!("over-limit COMPOUND must not become executable"),
        };
        assert_eq!(operation_count, 150);
        assert_eq!(operation_limit, 64);
        assert_eq!(response.status, Nfs4Status::Resource);
        assert_eq!(response.tag, b"COMP6");
        assert!(response.operations.is_empty());

        let reply = encode_nfs4_compound_reply(xid, response, limits, 4096).into_bytes();
        let mut decoder = Decoder::new(&reply);
        assert_eq!(decoder.read_u32().unwrap(), xid);
        assert_eq!(decoder.read_u32().unwrap(), RPC_REPLY);
        assert_eq!(decoder.read_u32().unwrap(), MSG_ACCEPTED);
        assert_eq!(decoder.read_u32().unwrap(), AUTH_NONE);
        assert!(decoder.read_opaque_slice("RPC verifier", 400).unwrap().is_empty());
        assert_eq!(decoder.read_u32().unwrap(), SUCCESS);
        assert_eq!(decoder.read_u32().unwrap(), Nfs4Status::Resource as u32);
        assert_eq!(decoder.read_opaque_slice("COMPOUND tag", 16).unwrap(), b"COMP6");
        assert_eq!(decoder.read_u32().unwrap(), 0);
        decoder.finish().unwrap();
    }

    #[test]
    fn overlong_valid_compound_keeps_minor_version_mismatch_precedence() {
        let limits = crate::nfs4::DecodeLimits {
            max_operations: 1,
            ..crate::nfs4::DecodeLimits::default()
        };
        let arguments = crate::nfs4::CompoundArgs {
            tag: b"minor".to_vec(),
            minor_version: 1,
            operations: vec![crate::nfs4::ArgOp::PutRootFh; 2],
        };
        let encoded = crate::nfs4::encode_compound_args(&arguments).unwrap();
        let PredecodedNfs4Compound::Reject { response, .. } = predecode_nfs4_compound(&encoded, limits).unwrap() else {
            panic!("over-limit COMPOUND must be rejected before execution");
        };
        assert_eq!(response.status, Nfs4Status::MinorVersionMismatch);
        assert_eq!(response.tag, b"minor");
        assert!(response.operations.is_empty());
    }

    #[test]
    fn nfs3_maps_expired_boot_handles_to_stale_and_policy_mismatches_to_badhandle() {
        assert_eq!(nfs3_handle_error_status(HandleError::StaleInstance), NfsStatus::Stale as u32);
        assert_eq!(nfs3_handle_error_status(HandleError::InvalidTarget), NfsStatus::BadHandle as u32);
    }

    #[test]
    fn request_shielding_covers_nfs3_mutations_without_retaining_reads() {
        for procedure in [2, 7, 8, 9, 10, 11, 12, 13, 14, 15, 21] {
            assert!(request_may_mutate(crate::nfs3::types::PROGRAM, crate::nfs3::types::VERSION, procedure,));
        }
        for procedure in [0, 1, 3, 4, 5, 6, 16, 17, 18, 19, 20] {
            assert!(!request_may_mutate(crate::nfs3::types::PROGRAM, crate::nfs3::types::VERSION, procedure,));
        }
        assert!(request_may_mutate(
            crate::nfs3::types::PROGRAM,
            crate::nfs4::VERSION,
            crate::nfs4::COMPOUND_PROCEDURE,
        ));
    }
}
