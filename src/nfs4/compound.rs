//! Sequential execution of one fully predecoded NFSv4.0 COMPOUND.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Weak};
use std::time::Duration;

use sha2::{Digest, Sha256};

use super::attribute_engine::{
    required_attribute_bitmap, AttributeEngine, AttributeValue, AttributeValues, DecodedSetAttributes,
};
use super::attributes::{bitmap_contains, bitmap_from_attributes, AttributeEncoder};
use super::callback::{auth_for_setclientid_principal, CallbackClientConfig, CallbackRpcClient};
use super::codec::{encode_compound_args, encode_compound_res};
use super::delegation::{
    DelegationCleanupProgress, DelegationGrant, DelegationGrantRequest, DelegationManager, GrantOutcome, RecallOutcome,
    RevocationReason,
};
use super::legal_errors::is_legal_operation_status;
use super::locations::{
    FileSystemLocationRecord, LocationPurpose, LocationRegistry, LocationRegistryError, LocationRegistryLimits,
    PlacementMigrationStatus,
};
use super::namespace::{NamespaceError, NamespaceNodeId, PseudoNamespace, BACKEND_COOKIE_FLAG};
use super::open_pins::{DelegationAttachment, ManagedOpenPin, OpenPinManager};
use super::reply_budget::{CompoundReplyBudget, SIDE_EFFECT_RESULT_RESERVE, SIMPLE_ERROR_RESULT_BYTES};
use super::runtime::{
    IoAccess, LockPreflight, LockTestDecision, Nfs4Runtime, OpenDecision, OpenStateDecision, ReleaseLockOwnerDecision,
    ReplayEffect, RuntimeFile,
};
use super::state::owner::OwnerRequestDigest;
use super::types::{
    AccessArgs, AccessOk, ArgOp, Bitmap, ChangeInfo, CloseArgs, CommitArgs, CommitOk, CompoundArgs, CompoundRes,
    CreateArgs, CreateHow, CreateOk, CreateType, DirectoryEntry, FileAttributes, FsId, GetAttrArgs, LinkArgs, LinkOk,
    LockArgs, LockTestArgs, LockType, LockUnlockArgs, Locker, NfsAce, NfsFileHandle, NfsResult, NfsStatus,
    NotVerifyArgs, OpNum, OpenArgs, OpenAttrArgs, OpenClaim, OpenConfirmArgs, OpenDelegation, OpenDelegationType,
    OpenDowngradeArgs, OpenHow, OpenReadDelegation, OpenWriteDelegation, PutFhArgs, ReadArgs, ReadDirArgs, ReadDirOk,
    ReadLinkOk, ReadOk, RemoveArgs, RemoveOk, RenameArgs, RenameOk, ResOp, RpcGssService, RpcSecGssInfo, SecInfoArgs,
    SecurityInfo, SetAttrArgs, SetAttrResult, SetClientIdArgs, SetClientIdResult, SpaceLimit, StableHow, VerifyArgs,
    WriteArgs, WriteOk, ACCESS4_DELETE, ACCESS4_EXECUTE, ACCESS4_EXTEND, ACCESS4_LOOKUP, ACCESS4_MODIFY, ACCESS4_READ,
    FATTR4_ACL, FATTR4_ACLSUPPORT, FATTR4_CANSETTIME, FATTR4_CASE_INSENSITIVE, FATTR4_CASE_PRESERVING, FATTR4_CHANGE,
    FATTR4_CHOWN_RESTRICTED, FATTR4_FH_EXPIRE_TYPE, FATTR4_FILEID, FATTR4_FILES_AVAIL, FATTR4_FILES_FREE,
    FATTR4_FILES_TOTAL, FATTR4_FSID, FATTR4_FS_LOCATIONS, FATTR4_HOMOGENEOUS, FATTR4_MAXFILESIZE, FATTR4_MAXLINK,
    FATTR4_MAXNAME, FATTR4_MAXREAD, FATTR4_MAXWRITE, FATTR4_MODE, FATTR4_MOUNTED_ON_FILEID, FATTR4_NAMED_ATTR,
    FATTR4_NO_TRUNC, FATTR4_NUMLINKS, FATTR4_OWNER, FATTR4_OWNER_GROUP, FATTR4_QUOTA_AVAIL_HARD,
    FATTR4_QUOTA_AVAIL_SOFT, FATTR4_QUOTA_USED, FATTR4_RAWDEV, FATTR4_RDATTR_ERROR, FATTR4_SIZE, FATTR4_SPACE_AVAIL,
    FATTR4_SPACE_FREE, FATTR4_SPACE_TOTAL, FATTR4_SPACE_USED, FATTR4_SUPPORTED_ATTRS, FATTR4_TIME_ACCESS,
    FATTR4_TIME_ACCESS_SET, FATTR4_TIME_DELTA, FATTR4_TIME_METADATA, FATTR4_TIME_MODIFY, FATTR4_TIME_MODIFY_SET,
    OPEN4_SHARE_ACCESS_BOTH, OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_ACCESS_WRITE,
};
use crate::handles::{HandleCodecSet, HandleError, HandleTarget};
use crate::rpc::gss::GssInitiatorProvider;
use crate::server::migration::{MigrationControl, MigrationGateStatus};
use crate::server::{
    CallbackConnector, CallbackTarget, ExecutionTracker, ExportState, FileHandlePolicy,
    RpcGssService as ConfigGssService, RpcSecurityFlavor,
};
use crate::vfs::{
    CreateMode as VfsCreateMode, DelegationKind, FileAttributes as VfsFileAttributes, FileType, IdentityMapper,
    IdentityMappingError, Nfs4Ace as VfsNfs4Ace, Nfs4AceType as VfsNfs4AceType, Nfs4Acl as VfsNfs4Acl, Nfs4FsLocations,
    Nfs4LocationState, Nfs4OpenAccess, Nfs4OpenCreate, Nfs4OpenExpectation, Nfs4OpenRequest, Nfs4OpenTarget,
    Nfs4OpenTransaction, NfsError, NfsName, NodeType, ObjectKey, RequestContext, SetAttributes as VfsSetAttributes,
    VfsCapabilities, WriteStability as VfsWriteStability,
};

const VALID_ACCESS_MASK: u32 =
    ACCESS4_READ | ACCESS4_LOOKUP | ACCESS4_MODIFY | ACCESS4_EXTEND | ACCESS4_DELETE | ACCESS4_EXECUTE;
const FH4_PERSISTENT: u32 = 0;
const FH4_VOLATILE_ANY: u32 = 0x0000_0002;
const MAX_OVERLAY_READDIR_PAGES: usize = 64;
const MAX_OVERLAY_READDIR_SCANNED_ENTRIES: usize = 16_384;

const fn delegation_cleanup_blocks_grace(cleanup: &DelegationCleanupProgress) -> bool {
    cleanup.pending_reconciliation != 0 || cleanup.pending_detached_removals != 0
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenDelegationRequest {
    None,
    Optional(DelegationKind),
    RequiredReclaim(DelegationKind),
}

/// Executes NFSv4.0 operations against the immutable export topology and the
/// server-wide state runtime.
pub(crate) struct CompoundExecutor<'a> {
    exports: &'a [ExportState],
    handles: &'a HandleCodecSet,
    namespace: &'a PseudoNamespace,
    public_filehandle_node: NamespaceNodeId,
    runtime: &'a Nfs4Runtime,
    open_pins: &'a OpenPinManager,
    delegations: &'a HashMap<crate::vfs::ExportId, Arc<DelegationManager>>,
    migration: Option<&'a MigrationControl>,
    identity_mapper: Option<&'a Arc<dyn IdentityMapper>>,
    namespace_locations: &'a BTreeMap<crate::vfs::ExportId, Nfs4FsLocations>,
    request_context: &'a RequestContext,
    max_read_size: u32,
    max_write_size: u32,
    lease_seconds: u32,
    max_response_body_size: usize,
    callback_connector: Option<&'a Arc<dyn CallbackConnector>>,
    callback_attempt_timeout: Duration,
    callback_gss_initiator: Option<&'a Arc<dyn GssInitiatorProvider>>,
    executions: Weak<ExecutionTracker>,
}

#[derive(Clone, Copy)]
enum ClientLeaseRenewal {
    Explicit,
    ClientId,
    StateId,
}

struct ClientLeaseRenewalOutcome {
    runtime_status: NfsStatus,
    callback_path_down: bool,
}

/// Every delegation manager's renewal fence, acquired in export-ID order.
///
/// Holding this set lets an operation renew the common runtime lease and all
/// delegation leases without allowing a concurrent recall expiry to revoke a
/// record part-way through the update.
struct DelegationRenewalFences<'a> {
    managers: Vec<(crate::vfs::ExportId, &'a Arc<DelegationManager>)>,
    _guards: Vec<tokio::sync::MutexGuard<'a, ()>>,
}

impl<'a> CompoundExecutor<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        exports: &'a [ExportState],
        handles: &'a HandleCodecSet,
        namespace: &'a PseudoNamespace,
        public_filehandle_node: NamespaceNodeId,
        runtime: &'a Nfs4Runtime,
        open_pins: &'a OpenPinManager,
        delegations: &'a HashMap<crate::vfs::ExportId, Arc<DelegationManager>>,
        migration: Option<&'a MigrationControl>,
        identity_mapper: Option<&'a Arc<dyn IdentityMapper>>,
        namespace_locations: &'a BTreeMap<crate::vfs::ExportId, Nfs4FsLocations>,
        request_context: &'a RequestContext,
        max_read_size: u32,
        max_write_size: u32,
        lease_seconds: u32,
        max_response_body_size: usize,
        callback_connector: Option<&'a Arc<dyn CallbackConnector>>,
        callback_attempt_timeout: Duration,
        callback_gss_initiator: Option<&'a Arc<dyn GssInitiatorProvider>>,
        executions: Weak<ExecutionTracker>,
    ) -> Self {
        Self {
            exports,
            handles,
            namespace,
            public_filehandle_node,
            runtime,
            open_pins,
            delegations,
            migration,
            identity_mapper,
            namespace_locations,
            request_context,
            max_read_size,
            max_write_size,
            lease_seconds,
            max_response_body_size,
            callback_connector,
            callback_attempt_timeout,
            callback_gss_initiator,
            executions,
        }
    }

    pub(crate) async fn execute(&self, arguments: CompoundArgs) -> CompoundRes {
        if arguments.minor_version != 0 {
            return CompoundRes {
                status: NfsStatus::MinorVersionMismatch,
                tag: arguments.tag,
                operations: Vec::new(),
            };
        }

        // A previous request can disappear only while a runtime-owned
        // critical transition continues. Drain those short transitions before
        // deciding whether its backend pin was adopted or must be released.
        self.runtime.wait_critical().await;
        self.open_pins.reconcile_committing(self.runtime);
        let _ = self.runtime.expire_due().await;
        self.open_pins.accept_runtime_releases(self.runtime);
        self.open_pins.maintain(self.runtime).await;

        let mut maintenance_error = None;
        let mut reconciliation_pending = false;
        for manager in self.delegations.values() {
            if let Err(error) = manager.revoke_expired().await {
                maintenance_error.get_or_insert(error.status());
            }
            let cleanup = manager.maintain_cleanup().await;
            reconciliation_pending |= delegation_cleanup_blocks_grace(&cleanup);
            if let Some(error) = cleanup.first_release_error.as_ref() {
                // Deferred backend releases retain their exact retry token and
                // constrain future delegation capacity, but must not poison an
                // arbitrary unrelated COMPOUND operation.
                tracing::warn!(
                    error = %error,
                    attempted = cleanup.attempted,
                    pending = cleanup.pending_releases,
                    "NFSv4 delegated-space release remains pending"
                );
            }
            if let Some(error) = cleanup.first_reconciliation_error.as_ref() {
                // Stable rollback repair also remains dependency-scoped, but
                // grace cannot close while its predecessor identity is
                // indeterminate.
                tracing::warn!(
                    error = %error,
                    pending = cleanup.pending_reconciliation,
                    "NFSv4 delegation stable-state reconciliation remains pending"
                );
            }
        }
        if maintenance_error.is_none() && !reconciliation_pending && self.runtime.grace_cleanup_due().await {
            let mut cleanup_complete = true;
            for manager in self.delegations.values() {
                if let Err(error) = manager.revoke_unreclaimed(RevocationReason::LeaseExpired).await {
                    maintenance_error.get_or_insert(error.status());
                    cleanup_complete = false;
                }
            }
            if cleanup_complete {
                if let Err(status) = self.runtime.finish_grace_if_due().await {
                    maintenance_error.get_or_insert(status);
                }
            }
        }
        if let (Some(status), Some(operation)) = (maintenance_error, arguments.operations.first()) {
            return CompoundRes::from_operations(
                arguments.tag,
                vec![normalize_operation_result(
                    operation,
                    operation_error(operation, status),
                )],
            );
        }

        let mut current = None;
        let mut saved = None;
        let mut unstable_writes = HashSet::new();
        let mut probed_moved_exports = HashSet::new();
        let mut results = Vec::with_capacity(arguments.operations.len());
        let reply_budget = CompoundReplyBudget::new(&arguments.tag, self.max_response_body_size);
        for (operation_index, operation) in arguments.operations.iter().enumerate() {
            let has_following_operation = operation_index + 1 < arguments.operations.len();
            let following_reserve = if has_following_operation {
                SIMPLE_ERROR_RESULT_BYTES
            } else {
                0
            };
            let reserve_after_result = if operation_has_side_effects(operation) {
                following_reserve
            } else {
                match arguments.operations.get(operation_index + 1) {
                    Some(next) if operation_has_side_effects(next) => {
                        SIDE_EFFECT_RESULT_RESERVE.saturating_add(if operation_index + 2 < arguments.operations.len() {
                            SIMPLE_ERROR_RESULT_BYTES
                        } else {
                            0
                        })
                    },
                    Some(_) => SIMPLE_ERROR_RESULT_BYTES,
                    None => 0,
                }
            };
            let can_execute = if operation_has_side_effects(operation) {
                reply_budget.can_start_side_effect(&results, following_reserve)
            } else {
                reply_budget.result_fits_with_reserve(
                    &results,
                    &normalize_operation_result(operation, operation_error(operation, NfsStatus::Resource)),
                    reserve_after_result,
                )
            };
            if !matches!(can_execute, Ok(true)) {
                results.push(normalize_operation_result(operation, operation_error(operation, NfsStatus::Resource)));
                break;
            }
            if let Err(status) = self.location_status_for_operation(operation, &current).await {
                let status = if status == NfsStatus::Moved {
                    self.moved_notification_status(operation, &current).await
                } else {
                    status
                };
                results.push(operation_error(operation, status));
                break;
            }
            if operation_uses_current_handle(operation) {
                if let Some(export_id) = current.as_ref().and_then(ResolvedFileHandle::export_id) {
                    if self.migration_status(export_id) == MigrationGateStatus::Moved
                        && !(operation_allows_absent_attributes(operation) && self.has_namespace_locations(export_id))
                    {
                        let status = self.moved_notification_status(operation, &current).await;
                        results.push(operation_error(operation, status));
                        break;
                    }
                }
            }

            let _migration_guard = if operation_mutates_export(operation) {
                match current.as_ref().and_then(ResolvedFileHandle::export_id) {
                    Some(export_id) => match self
                        .migration
                        .map(MigrationControl::gate)
                        .map(|gate| gate.try_enter_mutation(export_id))
                    {
                        Some(Ok(guard)) => Some(guard),
                        Some(Err(MigrationGateStatus::Quiescing)) => {
                            results.push(operation_error(operation, NfsStatus::Delay));
                            break;
                        },
                        Some(Err(MigrationGateStatus::Moved)) => {
                            let status = self.moved_notification_status(operation, &current).await;
                            results.push(operation_error(operation, status));
                            break;
                        },
                        Some(Err(MigrationGateStatus::Active)) | None => None,
                    },
                    None => None,
                }
            } else {
                None
            };

            if operation_requires_prior_stability(operation) && !unstable_writes.is_empty() {
                if let Err(status) = self.stabilize_unstable_writes(&unstable_writes, operation.opcode()).await {
                    results.push(operation_error(operation, status));
                    break;
                }
                unstable_writes.clear();
            }

            if !probed_moved_exports.is_empty() {
                if let Some(client_id) = self.operation_client_id(operation, &current).await {
                    // Invalid or stale client IDs are left for the normal
                    // operation path. Confirmed clients clear only exports
                    // successfully probed earlier in this COMPOUND.
                    let _ = self
                        .runtime
                        .complete_moved_export_probes(client_id, &probed_moved_exports, &self.request_context.principal)
                        .await;
                }
            }

            let mut result = normalize_operation_result(
                operation,
                self.execute_operation(
                    operation,
                    &mut current,
                    &mut saved,
                    reply_budget
                        .operation_result_limit(&results, reserve_after_result)
                        .unwrap_or(SIMPLE_ERROR_RESULT_BYTES),
                )
                .await,
            );
            if result.status() == NfsStatus::Moved {
                let status = self.moved_notification_status(operation, &current).await;
                result = normalize_operation_result(operation, operation_error(operation, status));
            }
            let status = result.status();
            if !matches!(reply_budget.result_fits_with_reserve(&results, &result, reserve_after_result), Ok(true)) {
                let resource = normalize_operation_result(operation, operation_error(operation, NfsStatus::Resource));
                debug_assert!(
                    result.status() != NfsStatus::Ok || !operation_has_side_effects(operation),
                    "successful side-effect result exceeded the reserved COMPOUND reply budget"
                );
                results.push(resource);
                break;
            }
            if let (ArgOp::Write(_), ResOp::Write(NfsResult::Ok(write))) = (operation, &result) {
                if write.committed == StableHow::Unstable {
                    if let Some(file) = current.as_ref().and_then(ResolvedFileHandle::runtime_file) {
                        let client_id = self.operation_client_id(operation, &current).await;
                        unstable_writes.insert((file, client_id));
                    }
                }
            }
            if status == NfsStatus::Ok
                && matches!(result, ResOp::GetAttr(NfsResult::Ok(_)))
                && operation_allows_absent_attributes(operation)
            {
                if let Some(export_id) = current.as_ref().and_then(ResolvedFileHandle::export_id) {
                    probed_moved_exports.insert(export_id);
                }
            }
            results.push(result);
            if status != NfsStatus::Ok {
                break;
            }
        }

        self.open_pins.accept_runtime_releases(self.runtime);
        self.open_pins.maintain(self.runtime).await;
        // Operations detach newly expired delegations while all-manager
        // renewal fences are held.  Persist their tombstones and release
        // backend reservations only after those fences have been dropped.
        // Failed cleanup stays in each manager's outbox for the next bounded
        // maintenance pass and cannot resurrect the detached state.
        for manager in self.delegations.values() {
            let _ = manager.finalize_detached_removals().await;
        }
        CompoundRes::from_operations(arguments.tag, results)
    }

    async fn execute_operation(
        &self,
        operation: &ArgOp,
        current: &mut Option<ResolvedFileHandle>,
        saved: &mut Option<ResolvedFileHandle>,
        max_result_bytes: usize,
    ) -> ResOp {
        match operation {
            ArgOp::PutFh(arguments) => self.put_file_handle(arguments, current),
            ArgOp::GetFh => self.get_file_handle(current),
            ArgOp::PutRootFh => self.put_root_file_handle(current, false),
            ArgOp::PutPublicFh => self.put_root_file_handle(current, true),
            ArgOp::SaveFh => self.save_file_handle(current, saved),
            ArgOp::RestoreFh => self.restore_file_handle(current, saved),
            ArgOp::Lookup(arguments) => self.lookup(&arguments.name, current).await,
            ArgOp::LookupParent => self.lookup_parent(current).await,
            ArgOp::Access(arguments) => self.access(arguments, current).await,
            ArgOp::GetAttr(arguments) => self.get_attributes(arguments, current).await,
            ArgOp::Verify(arguments) => self.verify(arguments, current).await,
            ArgOp::NotVerify(arguments) => self.not_verify(arguments, current).await,
            ArgOp::Read(arguments) => self.read(arguments, current, max_result_bytes).await,
            ArgOp::ReadLink => self.read_link(current).await,
            ArgOp::Commit(arguments) => self.commit(arguments, current).await,
            ArgOp::Close(arguments) => self.close(arguments, current, operation_digest(operation)).await,
            ArgOp::Create(arguments) => self.create(arguments, current).await,
            ArgOp::Link(arguments) => self.link(arguments, current, saved).await,
            ArgOp::Lock(arguments) => self.lock(arguments, current, operation_digest(operation)).await,
            ArgOp::LockTest(arguments) => self.lock_test(arguments, current).await,
            ArgOp::LockUnlock(arguments) => self.unlock(arguments, current, operation_digest(operation)).await,
            ArgOp::Open(arguments) => self.open(arguments, current, operation_digest(operation)).await,
            ArgOp::OpenConfirm(arguments) => self.open_confirm(arguments, current, operation_digest(operation)).await,
            ArgOp::OpenDowngrade(arguments) => {
                self.open_downgrade(arguments, current, operation_digest(operation)).await
            },
            ArgOp::Remove(arguments) => self.remove(arguments, current).await,
            ArgOp::Rename(arguments) => self.rename(arguments, current, saved).await,
            ArgOp::Renew(arguments) => self.renew_client(arguments.client_id).await,
            ArgOp::SetAttr(arguments) => self.set_attributes(arguments, current).await,
            ArgOp::SetClientId(arguments) => self.set_client_id(arguments).await,
            ArgOp::SetClientIdConfirm(arguments) => {
                self.confirm_client(arguments.client_id, arguments.confirmation).await
            },
            ArgOp::Write(arguments) => self.write(arguments, current).await,
            ArgOp::ReleaseLockOwner(arguments) => self.release_lock_owner(&arguments.lock_owner).await,
            ArgOp::DelegPurge(arguments) => self.delegation_purge(arguments.client_id).await,
            ArgOp::DelegReturn(arguments) => self.delegation_return(arguments.delegation_state_id, current).await,
            ArgOp::OpenAttr(arguments) => self.open_attr(arguments, current).await,
            ArgOp::ReadDir(arguments) => self.read_directory(arguments, current, max_result_bytes).await,
            ArgOp::SecInfo(arguments) => self.security_info(arguments, current).await,
            ArgOp::Illegal { .. } => ResOp::Illegal(NfsStatus::OperationIllegal),
        }
    }

    async fn set_client_id(&self, arguments: &SetClientIdArgs) -> ResOp {
        let transition_guard = self.runtime.client_state_transition_guard().await;
        if let Some(collision) = self
            .runtime
            .setclientid_principal_collision(arguments, &self.request_context.principal)
            .await
        {
            for manager in self.delegations.values() {
                if manager
                    .has_client_state(collision.client_id, &collision.previous_client_ids)
                    .await
                {
                    return ResOp::SetClientId(SetClientIdResult::ClientIdInUse(collision.client_using));
                }
            }
        }
        let transition = self.runtime.set_client_id(arguments, &self.request_context.principal).await;
        // Pin retirement awaits backend work under per-file gates; do not hold
        // the global client-transition gate across that cleanup.
        drop(transition_guard);
        self.open_pins.accept_runtime_releases(self.runtime);
        self.open_pins.maintain(self.runtime).await;
        ResOp::SetClientId(transition.result)
    }

    async fn confirm_client(&self, client_id: u64, confirmation: [u8; 8]) -> ResOp {
        let transition = self
            .runtime
            .confirm_client(client_id, confirmation, &self.request_context.principal)
            .await;
        self.open_pins.accept_runtime_releases(self.runtime);
        self.open_pins.maintain(self.runtime).await;
        ResOp::SetClientIdConfirm(transition.result)
    }

    fn put_file_handle(&self, arguments: &PutFhArgs, current: &mut Option<ResolvedFileHandle>) -> ResOp {
        match self.resolve_wire_handle(&arguments.object) {
            Ok(handle) if self.handle_security_status(&handle) == NfsStatus::Ok => {
                *current = Some(handle);
                ResOp::PutFh(NfsStatus::Ok)
            },
            Ok(_) => ResOp::PutFh(NfsStatus::WrongSecurity),
            Err(status) => ResOp::PutFh(status),
        }
    }

    fn get_file_handle(&self, current: &Option<ResolvedFileHandle>) -> ResOp {
        match current {
            Some(current) => ResOp::GetFh(NfsResult::Ok(current.wire.clone())),
            None => ResOp::GetFh(NfsResult::Err(NfsStatus::NoFileHandle)),
        }
    }

    fn put_root_file_handle(&self, current: &mut Option<ResolvedFileHandle>, public: bool) -> ResOp {
        let node = if public {
            self.public_filehandle_node
        } else {
            NamespaceNodeId::ROOT
        };
        match self.enter_namespace_node(node) {
            Ok(handle) if self.handle_security_status(&handle) == NfsStatus::Ok => {
                *current = Some(handle);
                if public {
                    ResOp::PutPublicFh(NfsStatus::Ok)
                } else {
                    ResOp::PutRootFh(NfsStatus::Ok)
                }
            },
            Ok(_) => {
                if public {
                    ResOp::PutPublicFh(NfsStatus::WrongSecurity)
                } else {
                    ResOp::PutRootFh(NfsStatus::WrongSecurity)
                }
            },
            Err(status) => {
                if public {
                    ResOp::PutPublicFh(status)
                } else {
                    ResOp::PutRootFh(status)
                }
            },
        }
    }

    fn save_file_handle(&self, current: &Option<ResolvedFileHandle>, saved: &mut Option<ResolvedFileHandle>) -> ResOp {
        match current {
            Some(current) => {
                *saved = Some(current.clone());
                ResOp::SaveFh(NfsStatus::Ok)
            },
            None => ResOp::SaveFh(NfsStatus::NoFileHandle),
        }
    }

    fn restore_file_handle(
        &self,
        current: &mut Option<ResolvedFileHandle>,
        saved: &Option<ResolvedFileHandle>,
    ) -> ResOp {
        match saved {
            Some(saved) if self.handle_security_status(saved) == NfsStatus::Ok => {
                *current = Some(saved.clone());
                ResOp::RestoreFh(NfsStatus::Ok)
            },
            Some(_) => ResOp::RestoreFh(NfsStatus::WrongSecurity),
            None => ResOp::RestoreFh(NfsStatus::RestoreFileHandle),
        }
    }

    async fn lookup(&self, name: &[u8], current: &mut Option<ResolvedFileHandle>) -> ResOp {
        let name = match validate_lookup_name(name) {
            Ok(name) => name,
            Err(status) => return ResOp::Lookup(status),
        };
        let Some(previous) = current.as_ref().cloned() else {
            return ResOp::Lookup(NfsStatus::NoFileHandle);
        };
        if let ResolvedTarget::Backend { export_id, object, .. } = previous.target {
            match self.backend_file_type(export_id, object, OpNum::Lookup.code()).await {
                Ok(file_type) if file_type.is_directory() => {},
                Ok(FileType::Symlink) => return ResOp::Lookup(NfsStatus::Symlink),
                Ok(_) => return ResOp::Lookup(NfsStatus::NotDirectory),
                Err(status) => return ResOp::Lookup(status),
            }
        }

        let result = match previous.target {
            ResolvedTarget::Pseudo(node) => match self.lookup_namespace_child(node, name.as_bytes()) {
                Ok(child) => self.enter_overlay_node(child, OpNum::Lookup.code()).await,
                Err(status) => Err(status),
            },
            ResolvedTarget::Backend {
                export_id,
                object,
                namespace_node,
            } => {
                if let Some(route) = namespace_node {
                    match self.is_overlay_anchor(export_id, object, route, OpNum::Lookup.code()).await {
                        Ok(true) => match self.lookup_namespace_child(route, name.as_bytes()) {
                            Ok(child) => {
                                self.lookup_overlay_child(export_id, object, child, OpNum::Lookup.code()).await
                            },
                            Err(NfsStatus::NotFound) => {
                                self.lookup_backend(export_id, object, &name, Some(route)).await
                            },
                            Err(status) => Err(status),
                        },
                        Ok(false) => self.lookup_backend(export_id, object, &name, Some(route)).await,
                        Err(status) => Err(status),
                    }
                } else {
                    self.lookup_backend(export_id, object, &name, None).await
                }
            },
        };

        match result {
            Ok(next) if self.handle_security_status(&next) == NfsStatus::Ok => {
                *current = Some(next);
                ResOp::Lookup(NfsStatus::Ok)
            },
            Ok(_) => ResOp::Lookup(NfsStatus::WrongSecurity),
            Err(status) => ResOp::Lookup(status),
        }
    }

    async fn lookup_parent(&self, current: &mut Option<ResolvedFileHandle>) -> ResOp {
        let Some(previous) = current.as_ref().cloned() else {
            return ResOp::LookupParent(NfsStatus::NoFileHandle);
        };
        if let ResolvedTarget::Backend { export_id, object, .. } = previous.target {
            match self.backend_file_type(export_id, object, OpNum::LookupParent.code()).await {
                Ok(file_type) if file_type.is_directory() => {},
                Ok(FileType::Symlink) => return ResOp::LookupParent(NfsStatus::Symlink),
                Ok(_) => return ResOp::LookupParent(NfsStatus::NotDirectory),
                Err(status) => return ResOp::LookupParent(status),
            }
        }

        let result = match previous.target {
            ResolvedTarget::Pseudo(node) => match self.namespace.lookup_parent(node).map_err(map_namespace_error) {
                Ok(parent) => self.enter_overlay_node(parent, OpNum::LookupParent.code()).await,
                Err(status) => Err(status),
            },
            ResolvedTarget::Backend {
                export_id,
                object,
                namespace_node,
            } => match self.export(export_id) {
                None => Err(NfsStatus::Stale),
                Some(export) => {
                    let route = namespace_node.or_else(|| {
                        (object == export.vfs.root())
                            .then(|| self.namespace_node_for_export(export_id))
                            .flatten()
                    });
                    let at_overlay_anchor = match route {
                        Some(route) => match self
                            .is_overlay_anchor(export_id, object, route, OpNum::LookupParent.code())
                            .await
                        {
                            Ok(at_anchor) => at_anchor,
                            Err(status) => return ResOp::LookupParent(status),
                        },
                        None => false,
                    };
                    if at_overlay_anchor {
                        let route = route.expect("overlay anchor has a route");
                        match self.namespace.lookup_parent(route).map_err(map_namespace_error) {
                            Ok(parent) => self.enter_overlay_node(parent, OpNum::LookupParent.code()).await,
                            Err(status) => Err(status),
                        }
                    } else {
                        let context = self.context_for(export_id);
                        match export.vfs.lookup_parent(&context, object).await {
                            Ok(parent) => {
                                let parent_route = if parent.object == export.vfs.root() {
                                    self.namespace_node_for_export(export_id)
                                } else {
                                    route
                                };
                                Ok(self.backend_handle(export_id, parent.object, parent_route))
                            },
                            Err(error) => Err(map_vfs_error_for_operation(OpNum::LookupParent.code(), error)),
                        }
                    }
                },
            },
        };

        match result {
            Ok(parent) if self.handle_security_status(&parent) == NfsStatus::Ok => {
                *current = Some(parent);
                ResOp::LookupParent(NfsStatus::Ok)
            },
            Ok(_) => ResOp::LookupParent(NfsStatus::WrongSecurity),
            Err(status) => ResOp::LookupParent(status),
        }
    }

    async fn access(&self, arguments: &AccessArgs, current: &Option<ResolvedFileHandle>) -> ResOp {
        let requested = arguments.access & VALID_ACCESS_MASK;
        let Some(current) = current else {
            return ResOp::Access(NfsResult::Err(NfsStatus::NoFileHandle));
        };

        match current.target {
            ResolvedTarget::Pseudo(_) => {
                let supported = meaningful_access_mask(FileType::Directory, requested);
                let access = requested & (ACCESS4_READ | ACCESS4_LOOKUP);
                ResOp::Access(NfsResult::Ok(AccessOk { supported, access }))
            },
            ResolvedTarget::Backend { export_id, object, .. } => {
                let Some(export) = self.export(export_id) else {
                    return ResOp::Access(NfsResult::Err(NfsStatus::Stale));
                };
                let context = self.context_for(export_id);
                let file_type = match export.vfs.getattr(&context, object).await {
                    Ok(attributes) => attributes.file_type,
                    Err(error) => {
                        return ResOp::Access(NfsResult::Err(map_vfs_error_for_operation(OpNum::Access.code(), error)))
                    },
                };
                let supported = meaningful_access_mask(file_type, requested);
                match export.vfs.access(&context, object, supported).await {
                    Ok(access) => ResOp::Access(NfsResult::Ok(AccessOk {
                        supported,
                        access: access & supported,
                    })),
                    Err(error) => {
                        ResOp::Access(NfsResult::Err(map_vfs_error_for_operation(OpNum::Access.code(), error)))
                    },
                }
            },
        }
    }

    async fn get_attributes(&self, arguments: &GetAttrArgs, current: &Option<ResolvedFileHandle>) -> ResOp {
        match self
            .attributes_for_current(current, &arguments.requested_attributes, OpNum::GetAttr.code())
            .await
        {
            Ok(attributes) => ResOp::GetAttr(NfsResult::Ok(attributes)),
            Err(status) => ResOp::GetAttr(NfsResult::Err(status)),
        }
    }

    async fn verify(&self, arguments: &VerifyArgs, current: &Option<ResolvedFileHandle>) -> ResOp {
        let status = match self
            .compare_attributes(current, &arguments.attributes, OpNum::Verify.code())
            .await
        {
            Ok(true) => NfsStatus::Ok,
            Ok(false) => NfsStatus::NotSame,
            Err(status) => status,
        };
        ResOp::Verify(status)
    }

    async fn not_verify(&self, arguments: &NotVerifyArgs, current: &Option<ResolvedFileHandle>) -> ResOp {
        let status = match self
            .compare_attributes(current, &arguments.attributes, OpNum::NotVerify.code())
            .await
        {
            Ok(true) => NfsStatus::Same,
            Ok(false) => NfsStatus::Ok,
            Err(status) => status,
        };
        ResOp::NotVerify(status)
    }

    async fn read(&self, arguments: &ReadArgs, current: &Option<ResolvedFileHandle>, max_result_bytes: usize) -> ResOp {
        let Some(current) = current else {
            return ResOp::Read(NfsResult::Err(NfsStatus::NoFileHandle));
        };
        let ResolvedTarget::Backend { export_id, object, .. } = current.target else {
            return ResOp::Read(NfsResult::Err(NfsStatus::IsDirectory));
        };
        let Some(export) = self.export(export_id) else {
            return ResOp::Read(NfsResult::Err(NfsStatus::Stale));
        };
        match self.backend_file_type(export_id, object, OpNum::Read.code()).await {
            Ok(file_type) if file_type.is_regular() => {},
            Ok(file_type) if file_type.is_directory() => return ResOp::Read(NfsResult::Err(NfsStatus::IsDirectory)),
            Ok(_) => return ResOp::Read(NfsResult::Err(NfsStatus::Invalid)),
            Err(status) => return ResOp::Read(NfsResult::Err(status)),
        }
        // opnum + status + eof + opaque length precede the padded payload.
        const FIXED_RESULT_BYTES: usize = 16;
        if max_result_bytes < FIXED_RESULT_BYTES {
            return ResOp::Read(NfsResult::Err(NfsStatus::Resource));
        }
        let reply_limited_count = u32::try_from((max_result_bytes - FIXED_RESULT_BYTES) & !3).unwrap_or(u32::MAX);
        let count = arguments.count.min(self.max_read_size).min(reply_limited_count);
        let permit = match self
            .validate_io_stateid(
                arguments.state_id,
                RuntimeFile { export_id, object },
                IoAccess::Read,
                arguments.offset,
                u64::from(count),
            )
            .await
        {
            Ok(permit) => permit,
            Err(status) => return ResOp::Read(NfsResult::Err(status)),
        };
        let mut context = self.context_for(export_id);
        context.client_id = permit.client_id;
        if let Err(status) = self
            .recall_conflicting_delegations(export_id, object, permit.client_id, DelegationKind::Read, false)
            .await
        {
            return ResOp::Read(NfsResult::Err(status));
        }
        match export.vfs.read_bytes(&context, object, arguments.offset, count).await {
            Ok(result) => {
                let returned = result.data.len().min(count as usize);
                ResOp::Read(NfsResult::Ok(ReadOk {
                    eof: result.eof && returned == result.data.len(),
                    data: result.data[..returned].to_vec(),
                }))
            },
            Err(error) => ResOp::Read(NfsResult::Err(map_vfs_error_for_operation(OpNum::Read.code(), error))),
        }
    }

    async fn read_directory(
        &self,
        arguments: &ReadDirArgs,
        current: &Option<ResolvedFileHandle>,
        max_result_bytes: usize,
    ) -> ResOp {
        if matches!(arguments.cookie, 1 | 2) {
            return ResOp::ReadDir(NfsResult::Err(NfsStatus::BadCookie));
        }
        // RFC 7531 defines maxcount over READDIR4resok, excluding the
        // operation number and status discriminant.
        let mut bounded_arguments = arguments.clone();
        bounded_arguments.max_count = bounded_arguments
            .max_count
            .min(u32::try_from(max_result_bytes.saturating_sub(8)).unwrap_or(u32::MAX));
        let Some(current) = current else {
            return ResOp::ReadDir(NfsResult::Err(NfsStatus::NoFileHandle));
        };
        match current.target {
            ResolvedTarget::Pseudo(node) => self.read_pseudo_directory(&bounded_arguments, node).await,
            ResolvedTarget::Backend {
                export_id,
                object,
                namespace_node,
            } => match namespace_node {
                Some(route) => match self.is_overlay_anchor(export_id, object, route, OpNum::ReadDir.code()).await {
                    Ok(true) => self.read_overlay_directory(&bounded_arguments, export_id, object, route).await,
                    Ok(false) => {
                        self.read_backend_directory(&bounded_arguments, export_id, object, Some(route))
                            .await
                    },
                    Err(status) => ResOp::ReadDir(NfsResult::Err(status)),
                },
                None => self.read_backend_directory(&bounded_arguments, export_id, object, None).await,
            },
        }
    }

    async fn read_pseudo_directory(&self, arguments: &ReadDirArgs, node: NamespaceNodeId) -> ResOp {
        let node = match self.namespace.node(node) {
            Ok(node) => node,
            Err(error) => return ResOp::ReadDir(NfsResult::Err(map_namespace_error(error))),
        };
        let verifier = pseudo_directory_verifier(self.handles.logical_instance_id(), node);
        if arguments.cookie != 0 && arguments.cookie_verifier != verifier {
            return ResOp::ReadDir(NfsResult::Err(NfsStatus::NotSame));
        }
        let resume_name = if arguments.cookie == 0 {
            None
        } else {
            match self.namespace.resume_child(node.id(), arguments.cookie) {
                Ok(child) => Some(child.name()),
                Err(error) => return ResOp::ReadDir(NfsResult::Err(map_namespace_error(error))),
            }
        };
        let mut children: Box<dyn Iterator<Item = (&[u8], NamespaceNodeId)> + Send + '_> = match resume_name {
            Some(name) => Box::new(node.children_after(name)),
            None => Box::new(node.children()),
        };
        let mut next_child = children.next();
        let mut result = ReadDirOk {
            cookie_verifier: verifier,
            entries: Vec::new(),
            eof: next_child.is_none(),
        };
        let mut result_size = read_dir_result_size(&result);
        if result_size > arguments.max_count as usize {
            return ResOp::ReadDir(NfsResult::Err(NfsStatus::TooSmall));
        }
        let mut directory_bytes = 0usize;
        while let Some((name, child)) = next_child {
            next_child = children.next();
            let handle = match self.enter_overlay_node(child, OpNum::ReadDir.code()).await {
                Ok(handle) => handle,
                Err(status) => return ResOp::ReadDir(NfsResult::Err(status)),
            };
            let attributes = if self.handle_security_status(&handle) == NfsStatus::Ok {
                match self
                    .attributes_for_current(&Some(handle), &arguments.requested_attributes, OpNum::ReadDir.code())
                    .await
                {
                    Ok(attributes) => attributes,
                    Err(status) => match rdattr_error(&arguments.requested_attributes, status) {
                        Some(attributes) => attributes,
                        None => return ResOp::ReadDir(NfsResult::Err(status)),
                    },
                }
            } else {
                match rdattr_error(&arguments.requested_attributes, NfsStatus::WrongSecurity) {
                    Some(attributes) => attributes,
                    None => return ResOp::ReadDir(NfsResult::Err(NfsStatus::WrongSecurity)),
                }
            };
            let entry = DirectoryEntry {
                cookie: match self.namespace.child_cookie(child) {
                    Ok(cookie) => cookie,
                    Err(error) => return ResOp::ReadDir(NfsResult::Err(map_namespace_error(error))),
                },
                name: name.to_vec(),
                attributes,
            };
            let next_directory_bytes = directory_bytes.saturating_add(directory_entry_name_size(&entry));
            let candidate_size = result_size.saturating_add(directory_entry_wire_size(&entry));
            let over_dir_hint = arguments.directory_count != 0
                && !result.entries.is_empty()
                && next_directory_bytes > arguments.directory_count as usize;
            if over_dir_hint || candidate_size > arguments.max_count as usize {
                if result.entries.is_empty() {
                    return ResOp::ReadDir(NfsResult::Err(NfsStatus::TooSmall));
                }
                result.eof = false;
                break;
            }
            directory_bytes = next_directory_bytes;
            result_size = candidate_size;
            result.entries.push(entry);
            result.eof = next_child.is_none();
        }
        ResOp::ReadDir(NfsResult::Ok(result))
    }

    async fn read_backend_directory(
        &self,
        arguments: &ReadDirArgs,
        export_id: crate::vfs::ExportId,
        object: ObjectKey,
        namespace_node: Option<NamespaceNodeId>,
    ) -> ResOp {
        let Some(export) = self.export(export_id) else {
            return ResOp::ReadDir(NfsResult::Err(NfsStatus::Stale));
        };
        match self.backend_file_type(export_id, object, OpNum::ReadDir.code()).await {
            Ok(file_type) if file_type.is_directory() => {},
            Ok(FileType::Symlink) => return ResOp::ReadDir(NfsResult::Err(NfsStatus::Symlink)),
            Ok(_) => return ResOp::ReadDir(NfsResult::Err(NfsStatus::NotDirectory)),
            Err(status) => return ResOp::ReadDir(NfsResult::Err(status)),
        }
        let context = self.context_for(export_id);
        let hint = ((arguments.max_count as usize) / 64).clamp(1, 4096);
        let page = match export
            .vfs
            .readdir(&context, object, arguments.cookie, arguments.cookie_verifier, hint)
            .await
        {
            Ok(page) => page,
            Err(error) => {
                return ResOp::ReadDir(NfsResult::Err(map_vfs_error_for_operation(OpNum::ReadDir.code(), error)))
            },
        };
        if arguments.cookie != 0 && page.verifier != arguments.cookie_verifier {
            return ResOp::ReadDir(NfsResult::Err(NfsStatus::NotSame));
        }
        let mut result = ReadDirOk {
            cookie_verifier: page.verifier,
            entries: Vec::new(),
            eof: page.entries.is_empty() && page.eof,
        };
        if page.entries.is_empty() && !page.eof {
            return ResOp::ReadDir(NfsResult::Err(NfsStatus::ServerFault));
        }
        let mut result_size = read_dir_result_size(&result);
        if result_size > arguments.max_count as usize {
            return ResOp::ReadDir(NfsResult::Err(NfsStatus::TooSmall));
        }
        let mut directory_bytes = 0usize;
        let mut previous_cookie = arguments.cookie;
        for (index, entry) in page.entries.iter().enumerate() {
            if matches!(entry.name.as_bytes(), b"." | b"..") || entry.cookie <= 2 || entry.cookie <= previous_cookie {
                return ResOp::ReadDir(NfsResult::Err(NfsStatus::ServerFault));
            }
            previous_cookie = entry.cookie;
            let handle = self.backend_handle(export_id, entry.object, namespace_node);
            let attributes = self
                .attributes_for_current(&Some(handle), &arguments.requested_attributes, OpNum::ReadDir.code())
                .await;
            let attributes = match attributes {
                Ok(attributes) => attributes,
                Err(status) => match rdattr_error(&arguments.requested_attributes, status) {
                    Some(attributes) => attributes,
                    None => return ResOp::ReadDir(NfsResult::Err(status)),
                },
            };
            let wire_entry = DirectoryEntry {
                cookie: entry.cookie,
                name: entry.name.as_bytes().to_vec(),
                attributes,
            };
            let next_directory_bytes = directory_bytes.saturating_add(directory_entry_name_size(&wire_entry));
            let candidate_size = result_size.saturating_add(directory_entry_wire_size(&wire_entry));
            let over_dir_hint = arguments.directory_count != 0
                && !result.entries.is_empty()
                && next_directory_bytes > arguments.directory_count as usize;
            if over_dir_hint || candidate_size > arguments.max_count as usize {
                if result.entries.is_empty() {
                    return ResOp::ReadDir(NfsResult::Err(NfsStatus::TooSmall));
                }
                result.eof = false;
                break;
            }
            directory_bytes = next_directory_bytes;
            result_size = candidate_size;
            result.entries.push(wire_entry);
            result.eof = index + 1 == page.entries.len() && page.eof;
        }
        ResOp::ReadDir(NfsResult::Ok(result))
    }

    async fn read_overlay_directory(
        &self,
        arguments: &ReadDirArgs,
        export_id: crate::vfs::ExportId,
        object: ObjectKey,
        route: NamespaceNodeId,
    ) -> ResOp {
        let Some(export) = self.export(export_id) else {
            return ResOp::ReadDir(NfsResult::Err(NfsStatus::Stale));
        };
        let route_node = match self.namespace.node(route) {
            Ok(node) => node,
            Err(error) => return ResOp::ReadDir(NfsResult::Err(map_namespace_error(error))),
        };
        let mut result = ReadDirOk {
            cookie_verifier: [0; 8],
            entries: Vec::new(),
            eof: false,
        };
        let mut result_size = read_dir_result_size(&result);
        if result_size > arguments.max_count as usize {
            return ResOp::ReadDir(NfsResult::Err(NfsStatus::TooSmall));
        }

        let context = self.context_for(export_id);
        let hint = ((arguments.max_count as usize) / 64).clamp(1, 4096);
        // A zero-cookie read gives us the backend's current verifier. Mixing
        // it reversibly with the immutable overlay topology lets a later
        // request reconstruct and validate both halves without server-side
        // cookie state.
        let first_page = match export.vfs.readdir(&context, object, 0, [0; 8], hint).await {
            Ok(page) => page,
            Err(error) => {
                return ResOp::ReadDir(NfsResult::Err(map_vfs_error_for_operation(OpNum::ReadDir.code(), error)))
            },
        };
        if let Err(status) = validate_overlay_backend_page(&first_page, 0, hint) {
            return ResOp::ReadDir(NfsResult::Err(status));
        }
        let backend_verifier = first_page.verifier;
        let topology_verifier = pseudo_directory_verifier(self.handles.logical_instance_id(), route_node);
        let verifier = xor_verifier(backend_verifier, topology_verifier);
        result.cookie_verifier = verifier;
        if arguments.cookie != 0 && arguments.cookie_verifier != verifier {
            return ResOp::ReadDir(NfsResult::Err(NfsStatus::NotSame));
        }

        let (resume_name, mut backend_cookie) = if arguments.cookie == 0 {
            (None, 0)
        } else if arguments.cookie & BACKEND_COOKIE_FLAG != 0 {
            let backend_cookie = arguments.cookie & !BACKEND_COOKIE_FLAG;
            if backend_cookie <= 2 {
                return ResOp::ReadDir(NfsResult::Err(NfsStatus::BadCookie));
            }
            (None, backend_cookie)
        } else {
            let child = match self.namespace.resume_child(route, arguments.cookie) {
                Ok(child) => child,
                Err(error) => return ResOp::ReadDir(NfsResult::Err(map_namespace_error(error))),
            };
            (Some(child.name()), 0)
        };
        let backend_phase = arguments.cookie & BACKEND_COOKIE_FLAG != 0;
        let mut directory_bytes = 0usize;

        if !backend_phase {
            let mut children: Box<dyn Iterator<Item = (&[u8], NamespaceNodeId)> + Send + '_> = match resume_name {
                Some(name) => Box::new(route_node.children_after(name)),
                None => Box::new(route_node.children()),
            };
            let mut next_child = children.next();
            while let Some((name, child)) = next_child {
                next_child = children.next();
                let handle = match self.lookup_overlay_child(export_id, object, child, OpNum::ReadDir.code()).await {
                    Ok(handle) => handle,
                    Err(status) => return ResOp::ReadDir(NfsResult::Err(status)),
                };
                let attributes = if self.handle_security_status(&handle) == NfsStatus::Ok {
                    match self
                        .attributes_for_current(&Some(handle), &arguments.requested_attributes, OpNum::ReadDir.code())
                        .await
                    {
                        Ok(attributes) => attributes,
                        Err(status) => match rdattr_error(&arguments.requested_attributes, status) {
                            Some(attributes) => attributes,
                            None => return ResOp::ReadDir(NfsResult::Err(status)),
                        },
                    }
                } else {
                    match rdattr_error(&arguments.requested_attributes, NfsStatus::WrongSecurity) {
                        Some(attributes) => attributes,
                        None => return ResOp::ReadDir(NfsResult::Err(NfsStatus::WrongSecurity)),
                    }
                };
                let entry = DirectoryEntry {
                    cookie: match self.namespace.child_cookie(child) {
                        Ok(cookie) => cookie,
                        Err(error) => return ResOp::ReadDir(NfsResult::Err(map_namespace_error(error))),
                    },
                    name: name.to_vec(),
                    attributes,
                };
                let next_directory_bytes = directory_bytes.saturating_add(directory_entry_name_size(&entry));
                let candidate_size = result_size.saturating_add(directory_entry_wire_size(&entry));
                let over_dir_hint = arguments.directory_count != 0
                    && !result.entries.is_empty()
                    && next_directory_bytes > arguments.directory_count as usize;
                if over_dir_hint || candidate_size > arguments.max_count as usize {
                    if result.entries.is_empty() {
                        return ResOp::ReadDir(NfsResult::Err(NfsStatus::TooSmall));
                    }
                    result.eof = false;
                    return ResOp::ReadDir(NfsResult::Ok(result));
                }
                directory_bytes = next_directory_bytes;
                result_size = candidate_size;
                result.entries.push(entry);
                result.eof = false;
            }
        }

        let mut page_count = 1usize;
        let mut page = if backend_cookie == 0 {
            first_page
        } else {
            page_count += 1;
            match export
                .vfs
                .readdir(&context, object, backend_cookie, backend_verifier, hint)
                .await
            {
                Ok(page) => page,
                Err(NfsError::BadCookie) => return ResOp::ReadDir(NfsResult::Err(NfsStatus::NotSame)),
                Err(error) => {
                    return ResOp::ReadDir(NfsResult::Err(map_vfs_error_for_operation(OpNum::ReadDir.code(), error)))
                },
            }
        };
        let mut scanned_entries = 0usize;
        loop {
            if page.verifier != backend_verifier {
                return ResOp::ReadDir(NfsResult::Err(NfsStatus::NotSame));
            }
            let page_last_cookie = match validate_overlay_backend_page(&page, backend_cookie, hint) {
                Ok(cookie) => cookie,
                Err(status) => return ResOp::ReadDir(NfsResult::Err(status)),
            };
            for entry in &page.entries {
                scanned_entries = match scanned_entries.checked_add(1) {
                    Some(scanned) if scanned <= MAX_OVERLAY_READDIR_SCANNED_ENTRIES => scanned,
                    _ => return ResOp::ReadDir(NfsResult::Err(NfsStatus::Resource)),
                };
                match self.namespace.lookup(route, entry.name.as_bytes()) {
                    // Every synthetic child, and especially an export root,
                    // shadows an identically named backend entry on all
                    // backend pages.
                    Ok(_) => continue,
                    Err(NamespaceError::NotFound) => {},
                    Err(error) => return ResOp::ReadDir(NfsResult::Err(map_namespace_error(error))),
                }
                let handle = self.backend_handle(export_id, entry.object, Some(route));
                let attributes = match self
                    .attributes_for_current(&Some(handle), &arguments.requested_attributes, OpNum::ReadDir.code())
                    .await
                {
                    Ok(attributes) => attributes,
                    Err(status) => match rdattr_error(&arguments.requested_attributes, status) {
                        Some(attributes) => attributes,
                        None => return ResOp::ReadDir(NfsResult::Err(status)),
                    },
                };
                let wire_entry = DirectoryEntry {
                    cookie: match encode_overlay_backend_cookie(entry.cookie) {
                        Ok(cookie) => cookie,
                        Err(status) => return ResOp::ReadDir(NfsResult::Err(status)),
                    },
                    name: entry.name.as_bytes().to_vec(),
                    attributes,
                };
                let next_directory_bytes = directory_bytes.saturating_add(directory_entry_name_size(&wire_entry));
                let candidate_size = result_size.saturating_add(directory_entry_wire_size(&wire_entry));
                let over_dir_hint = arguments.directory_count != 0
                    && !result.entries.is_empty()
                    && next_directory_bytes > arguments.directory_count as usize;
                if over_dir_hint || candidate_size > arguments.max_count as usize {
                    if result.entries.is_empty() {
                        return ResOp::ReadDir(NfsResult::Err(NfsStatus::TooSmall));
                    }
                    result.eof = false;
                    return ResOp::ReadDir(NfsResult::Ok(result));
                }
                directory_bytes = next_directory_bytes;
                result_size = candidate_size;
                result.entries.push(wire_entry);
                result.eof = false;
            }
            backend_cookie = page_last_cookie;
            if page.eof {
                result.eof = true;
                return ResOp::ReadDir(NfsResult::Ok(result));
            }
            page_count = match page_count.checked_add(1) {
                Some(pages) if pages <= MAX_OVERLAY_READDIR_PAGES => pages,
                _ => return ResOp::ReadDir(NfsResult::Err(NfsStatus::Resource)),
            };
            page = match export
                .vfs
                .readdir(&context, object, backend_cookie, backend_verifier, hint)
                .await
            {
                Ok(page) => page,
                Err(NfsError::BadCookie) => return ResOp::ReadDir(NfsResult::Err(NfsStatus::NotSame)),
                Err(error) => {
                    return ResOp::ReadDir(NfsResult::Err(map_vfs_error_for_operation(OpNum::ReadDir.code(), error)))
                },
            };
        }
    }

    async fn read_link(&self, current: &Option<ResolvedFileHandle>) -> ResOp {
        let Some(current) = current else {
            return ResOp::ReadLink(NfsResult::Err(NfsStatus::NoFileHandle));
        };
        let ResolvedTarget::Backend { export_id, object, .. } = current.target else {
            return ResOp::ReadLink(NfsResult::Err(NfsStatus::Invalid));
        };
        let Some(export) = self.export(export_id) else {
            return ResOp::ReadLink(NfsResult::Err(NfsStatus::Stale));
        };
        let context = self.context_for(export_id);
        match export.vfs.readlink(&context, object).await {
            Ok(link) => ResOp::ReadLink(NfsResult::Ok(ReadLinkOk { link })),
            Err(error) => ResOp::ReadLink(NfsResult::Err(map_vfs_error_for_operation(OpNum::ReadLink.code(), error))),
        }
    }

    async fn commit(&self, arguments: &CommitArgs, current: &Option<ResolvedFileHandle>) -> ResOp {
        let Some(current) = current else {
            return ResOp::Commit(NfsResult::Err(NfsStatus::NoFileHandle));
        };
        let ResolvedTarget::Backend { export_id, object, .. } = current.target else {
            return ResOp::Commit(NfsResult::Err(NfsStatus::IsDirectory));
        };
        let Some(export) = self.export(export_id) else {
            return ResOp::Commit(NfsResult::Err(NfsStatus::Stale));
        };
        match self.backend_file_type(export_id, object, OpNum::Commit.code()).await {
            Ok(file_type) if file_type.is_regular() => {},
            Ok(file_type) if file_type.is_directory() => return ResOp::Commit(NfsResult::Err(NfsStatus::IsDirectory)),
            Ok(_) => return ResOp::Commit(NfsResult::Err(NfsStatus::Invalid)),
            Err(status) => return ResOp::Commit(NfsResult::Err(status)),
        }
        let context = self.context_for(export_id);
        match export.vfs.commit(&context, object, arguments.offset, arguments.count).await {
            Ok(_) => ResOp::Commit(NfsResult::Ok(CommitOk {
                write_verifier: self.runtime.write_verifier(),
            })),
            Err(error) => ResOp::Commit(NfsResult::Err(map_vfs_error_for_operation(OpNum::Commit.code(), error))),
        }
    }

    async fn write(&self, arguments: &WriteArgs, current: &Option<ResolvedFileHandle>) -> ResOp {
        let Some(current) = current else {
            return ResOp::Write(NfsResult::Err(NfsStatus::NoFileHandle));
        };
        let ResolvedTarget::Backend { export_id, object, .. } = current.target else {
            return ResOp::Write(NfsResult::Err(NfsStatus::IsDirectory));
        };
        let Some(export) = self.export(export_id) else {
            return ResOp::Write(NfsResult::Err(NfsStatus::Stale));
        };
        match self.backend_file_type(export_id, object, OpNum::Write.code()).await {
            Ok(file_type) if file_type.is_regular() => {},
            Ok(file_type) if file_type.is_directory() => return ResOp::Write(NfsResult::Err(NfsStatus::IsDirectory)),
            Ok(_) => return ResOp::Write(NfsResult::Err(NfsStatus::Invalid)),
            Err(status) => return ResOp::Write(NfsResult::Err(status)),
        }
        let requested = arguments.data.len().min(self.max_write_size as usize);
        let permit = match self
            .validate_io_stateid(
                arguments.state_id,
                RuntimeFile { export_id, object },
                IoAccess::Write,
                arguments.offset,
                requested as u64,
            )
            .await
        {
            Ok(permit) => permit,
            Err(status) => return ResOp::Write(NfsResult::Err(status)),
        };
        let mut context = self.context_for(export_id);
        context.client_id = permit.client_id;
        if requested == 0 {
            let requested_stability = map_write_stability(arguments.stability);
            return match export
                .vfs
                .nfs4_check_zero_length_write(&context, object, arguments.offset, requested_stability)
                .await
            {
                Ok(()) => ResOp::Write(NfsResult::Ok(WriteOk {
                    count: 0,
                    committed: arguments.stability,
                    write_verifier: self.runtime.write_verifier(),
                })),
                Err(error) => ResOp::Write(NfsResult::Err(map_vfs_error_for_operation(OpNum::Write.code(), error))),
            };
        }
        if let Err(status) = self
            .recall_conflicting_delegations(export_id, object, permit.client_id, DelegationKind::Write, false)
            .await
        {
            return ResOp::Write(NfsResult::Err(status));
        }
        let requested_stability = map_write_stability(arguments.stability);
        match export
            .vfs
            .write(&context, object, arguments.offset, &arguments.data[..requested], requested_stability)
            .await
        {
            Ok(result)
                if result.value.count as usize <= requested
                    && (requested == 0 || result.value.count != 0)
                    && result.value.committed.satisfies(requested_stability) =>
            {
                ResOp::Write(NfsResult::Ok(WriteOk {
                    count: result.value.count,
                    committed: map_vfs_write_stability(result.value.committed),
                    write_verifier: self.runtime.write_verifier(),
                }))
            },
            Ok(_) => ResOp::Write(NfsResult::Err(NfsStatus::ServerFault)),
            Err(error) => ResOp::Write(NfsResult::Err(map_vfs_error_for_operation(OpNum::Write.code(), error))),
        }
    }

    async fn set_attributes(&self, arguments: &SetAttrArgs, current: &Option<ResolvedFileHandle>) -> ResOp {
        let Some(current) = current else {
            return setattr_error(NfsStatus::NoFileHandle);
        };
        let ResolvedTarget::Backend { export_id, object, .. } = current.target else {
            return setattr_error(NfsStatus::ReadOnly);
        };
        let Some(export) = self.export(export_id) else {
            return setattr_error(NfsStatus::Stale);
        };
        let engine = match self.attribute_engine_for_export(export) {
            Ok(engine) => engine,
            Err(status) => return setattr_error(status),
        };
        let mut decoded = match decode_set_attributes(&engine, &arguments.attributes) {
            Ok(decoded) => decoded,
            Err(status) => return setattr_error(status),
        };
        if let Err(status) = self.map_set_identities(&mut decoded).await {
            return setattr_error(status);
        }
        let mut context = self.context_for(export_id);
        let _io_permit = if decoded.vfs.size.is_some() {
            let permit = match self
                .validate_io_stateid(
                    arguments.state_id,
                    RuntimeFile { export_id, object },
                    IoAccess::SetSize,
                    0,
                    u64::MAX,
                )
                .await
            {
                Ok(permit) => permit,
                Err(status) => return setattr_error(status),
            };
            context.client_id = permit.client_id;
            Some(permit)
        } else {
            context.client_id = match self
                .validate_non_size_setattr_stateid(arguments.state_id, RuntimeFile { export_id, object })
                .await
            {
                Ok(client_id) => client_id,
                Err(status) => return setattr_error(status),
            };
            None
        };
        let _delegation_access = if decoded.vfs.size.is_none() {
            match self.runtime.begin_delegation_access(
                RuntimeFile { export_id, object },
                context.client_id,
                DelegationKind::Write,
                false,
            ) {
                Ok(reservation) => Some(reservation),
                Err(status) => return setattr_error(status),
            }
        } else {
            None
        };
        if let Err(status) = self
            .recall_conflicting_delegations(
                export_id,
                object,
                context.client_id,
                DelegationKind::Write,
                decoded.vfs.size.is_some(),
            )
            .await
        {
            return setattr_error(status);
        }
        let requested = decoded.requested.clone();
        let result = if let Some(acl) = decoded.acl {
            if decoded.vfs.size.is_some()
                || decoded.vfs.uid.is_some()
                || decoded.vfs.gid.is_some()
                || decoded.vfs.access_time.is_some()
                || decoded.vfs.modify_time.is_some()
            {
                return setattr_error(NfsStatus::Invalid);
            }
            let acl = match vfs_acl(acl) {
                Ok(acl) => acl,
                Err(status) => return setattr_error(status),
            };
            export.vfs.nfs4_set_acl_and_mode(&context, object, acl, decoded.vfs.mode).await
        } else {
            export.vfs.setattr(&context, object, decoded.vfs, None).await
        };
        match result {
            Ok(_) => ResOp::SetAttr(SetAttrResult {
                status: NfsStatus::Ok,
                attributes_set: requested,
            }),
            Err(error) => setattr_error(map_vfs_error_for_operation(OpNum::SetAttr.code(), error)),
        }
    }

    async fn lock(
        &self,
        arguments: &LockArgs,
        current: &Option<ResolvedFileHandle>,
        digest: OwnerRequestDigest,
    ) -> ResOp {
        let file = match current_runtime_file(current) {
            Ok(file) => file,
            Err(status) => return ResOp::Lock(super::types::LockResult::Err(status)),
        };
        let fences = self.delegation_renewal_fences().await;
        if let Err(status) = self.revoke_expired_delegations_while_fenced(&fences).await {
            return ResOp::Lock(super::types::LockResult::Err(status));
        }
        let client_id = match self
            .runtime
            .preflight_lock(arguments, file, digest, &self.request_context.principal)
            .await
        {
            LockPreflight::Replay { client_id, result } => {
                if let Err(status) = self
                    .renew_delegations_while_fenced(&fences, client_id, ClientLeaseRenewal::StateId)
                    .await
                {
                    return ResOp::Lock(super::types::LockResult::Err(status));
                }
                return result;
            },
            LockPreflight::Error { status, client_id } => {
                if let Some(client_id) = client_id {
                    if let Err(renewal_status) = self
                        .renew_delegations_while_fenced(&fences, client_id, ClientLeaseRenewal::StateId)
                        .await
                    {
                        return ResOp::Lock(super::types::LockResult::Err(renewal_status));
                    }
                }
                return ResOp::Lock(super::types::LockResult::Err(status));
            },
            LockPreflight::Execute { client_id } => client_id,
        };
        if let Err(status) = self
            .renew_delegations_while_fenced(&fences, client_id, ClientLeaseRenewal::StateId)
            .await
        {
            return ResOp::Lock(super::types::LockResult::Err(status));
        }
        drop(fences);
        let kind = match arguments.lock_type {
            LockType::Read | LockType::BlockingRead => DelegationKind::Read,
            LockType::Write | LockType::BlockingWrite => DelegationKind::Write,
        };
        let delegation_access = match self
            .begin_delegation_access_and_recall(file.export_id, file.object, Some(client_id), kind, false)
            .await
        {
            Ok(reservation) => reservation,
            Err(status) => return ResOp::Lock(super::types::LockResult::Err(status)),
        };
        ResOp::Lock(
            self.runtime
                .lock_with_delegation_access(
                    arguments,
                    file,
                    digest,
                    &self.request_context.principal,
                    delegation_access,
                )
                .await,
        )
    }

    async fn lock_test(&self, arguments: &LockTestArgs, current: &Option<ResolvedFileHandle>) -> ResOp {
        let file = match current_runtime_file(current) {
            Ok(file) => file,
            Err(status) => return ResOp::LockTest(super::types::LockTestResult::Err(status)),
        };
        match self
            .backend_file_type(file.export_id, file.object, OpNum::LockTest.code())
            .await
        {
            Ok(file_type) if file_type.is_regular() => {},
            Ok(file_type) if file_type.is_directory() => {
                return ResOp::LockTest(super::types::LockTestResult::Err(NfsStatus::IsDirectory))
            },
            Ok(_) => return ResOp::LockTest(super::types::LockTestResult::Err(NfsStatus::Invalid)),
            Err(status) => return ResOp::LockTest(super::types::LockTestResult::Err(status)),
        }
        let fences = self.delegation_renewal_fences().await;
        if let Err(status) = self.revoke_expired_delegations_while_fenced(&fences).await {
            return ResOp::LockTest(super::types::LockTestResult::Err(status));
        }
        let LockTestDecision { result, client_id } = self
            .runtime
            .lock_test_with_identity(arguments, file, &self.request_context.principal)
            .await;
        if let Some(client_id) = client_id {
            if let Err(status) = self
                .renew_delegations_while_fenced(&fences, client_id, ClientLeaseRenewal::ClientId)
                .await
            {
                return ResOp::LockTest(super::types::LockTestResult::Err(status));
            }
        }
        ResOp::LockTest(result)
    }

    async fn unlock(
        &self,
        arguments: &LockUnlockArgs,
        current: &Option<ResolvedFileHandle>,
        digest: OwnerRequestDigest,
    ) -> ResOp {
        let file = match current_runtime_file(current) {
            Ok(file) => file,
            Err(status) => return ResOp::LockUnlock(NfsResult::Err(status)),
        };
        let fences = self.delegation_renewal_fences().await;
        if let Err(status) = self.revoke_expired_delegations_while_fenced(&fences).await {
            return ResOp::LockUnlock(NfsResult::Err(status));
        }
        let client_id = match self
            .runtime
            .preflight_unlock(arguments, file, digest, &self.request_context.principal)
            .await
        {
            LockPreflight::Replay { client_id, result } => {
                if let Err(status) = self
                    .renew_delegations_while_fenced(&fences, client_id, ClientLeaseRenewal::StateId)
                    .await
                {
                    return ResOp::LockUnlock(NfsResult::Err(status));
                }
                return result;
            },
            LockPreflight::Error { status, client_id } => {
                if let Some(client_id) = client_id {
                    if let Err(renewal_status) = self
                        .renew_delegations_while_fenced(&fences, client_id, ClientLeaseRenewal::StateId)
                        .await
                    {
                        return ResOp::LockUnlock(NfsResult::Err(renewal_status));
                    }
                }
                return ResOp::LockUnlock(NfsResult::Err(status));
            },
            LockPreflight::Execute { client_id } => client_id,
        };
        if let Err(status) = self
            .renew_delegations_while_fenced(&fences, client_id, ClientLeaseRenewal::StateId)
            .await
        {
            return ResOp::LockUnlock(NfsResult::Err(status));
        }
        drop(fences);
        self.runtime
            .unlock(arguments, file, digest, &self.request_context.principal)
            .await
    }

    async fn open_confirm(
        &self,
        arguments: &OpenConfirmArgs,
        current: &Option<ResolvedFileHandle>,
        digest: OwnerRequestDigest,
    ) -> ResOp {
        let file = match current_runtime_file(current) {
            Ok(file) => file,
            Err(status) => return ResOp::OpenConfirm(NfsResult::Err(status)),
        };
        let fences = self.delegation_renewal_fences().await;
        if let Err(status) = self.revoke_expired_delegations_while_fenced(&fences).await {
            return ResOp::OpenConfirm(NfsResult::Err(status));
        }
        match self
            .runtime
            .begin_open_state_operation_with_identity(
                arguments.open_state_id,
                file,
                arguments.sequence_id,
                digest,
                &self.request_context.principal,
                true,
            )
            .await
        {
            OpenStateDecision::Replay { result, client_id, .. } => {
                if let Err(status) = self
                    .renew_delegations_while_fenced(&fences, client_id, ClientLeaseRenewal::StateId)
                    .await
                {
                    return ResOp::OpenConfirm(NfsResult::Err(status));
                }
                result
            },
            OpenStateDecision::Error { status, client_id } => {
                if let Some(client_id) = client_id {
                    if let Err(renewal_status) = self
                        .renew_delegations_while_fenced(&fences, client_id, ClientLeaseRenewal::StateId)
                        .await
                    {
                        return ResOp::OpenConfirm(NfsResult::Err(renewal_status));
                    }
                }
                ResOp::OpenConfirm(NfsResult::Err(status))
            },
            OpenStateDecision::Execute(reservation) => {
                let client_id = reservation.client_id();
                if let Err(status) = self
                    .renew_delegations_while_fenced(&fences, client_id, ClientLeaseRenewal::StateId)
                    .await
                {
                    drop(fences);
                    return self
                        .runtime
                        .complete_open_state_error(reservation, status, ResOp::OpenConfirm(NfsResult::Err(status)))
                        .await;
                }
                drop(fences);
                match self.runtime.confirm_open(reservation).await {
                    Ok(result) => result,
                    Err(status) => ResOp::OpenConfirm(NfsResult::Err(status)),
                }
            },
        }
    }

    async fn open_downgrade(
        &self,
        arguments: &OpenDowngradeArgs,
        current: &Option<ResolvedFileHandle>,
        digest: OwnerRequestDigest,
    ) -> ResOp {
        let file = match current_runtime_file(current) {
            Ok(file) => file,
            Err(status) => return ResOp::OpenDowngrade(NfsResult::Err(status)),
        };
        let fences = self.delegation_renewal_fences().await;
        if let Err(status) = self.revoke_expired_delegations_while_fenced(&fences).await {
            return ResOp::OpenDowngrade(NfsResult::Err(status));
        }
        match self
            .runtime
            .begin_open_state_operation_with_identity(
                arguments.open_state_id,
                file,
                arguments.sequence_id,
                digest,
                &self.request_context.principal,
                false,
            )
            .await
        {
            OpenStateDecision::Replay { result, client_id, .. } => {
                if let Err(status) = self
                    .renew_delegations_while_fenced(&fences, client_id, ClientLeaseRenewal::StateId)
                    .await
                {
                    return ResOp::OpenDowngrade(NfsResult::Err(status));
                }
                result
            },
            OpenStateDecision::Error { status, client_id } => {
                if let Some(client_id) = client_id {
                    if let Err(renewal_status) = self
                        .renew_delegations_while_fenced(&fences, client_id, ClientLeaseRenewal::StateId)
                        .await
                    {
                        return ResOp::OpenDowngrade(NfsResult::Err(renewal_status));
                    }
                }
                ResOp::OpenDowngrade(NfsResult::Err(status))
            },
            OpenStateDecision::Execute(reservation) => {
                let client_id = reservation.client_id();
                if let Err(status) = self
                    .renew_delegations_while_fenced(&fences, client_id, ClientLeaseRenewal::StateId)
                    .await
                {
                    drop(fences);
                    return self
                        .runtime
                        .complete_open_state_error(reservation, status, ResOp::OpenDowngrade(NfsResult::Err(status)))
                        .await;
                }
                drop(fences);
                match self
                    .runtime
                    .downgrade_open(reservation, arguments.share_access, arguments.share_deny)
                    .await
                {
                    Ok(result) => result,
                    Err(status) => ResOp::OpenDowngrade(NfsResult::Err(status)),
                }
            },
        }
    }

    async fn close(
        &self,
        arguments: &CloseArgs,
        current: &Option<ResolvedFileHandle>,
        digest: OwnerRequestDigest,
    ) -> ResOp {
        let file = match current_runtime_file(current) {
            Ok(file) => file,
            Err(status) => return ResOp::Close(NfsResult::Err(status)),
        };
        let fences = self.delegation_renewal_fences().await;
        if let Err(status) = self.revoke_expired_delegations_while_fenced(&fences).await {
            return ResOp::Close(NfsResult::Err(status));
        }
        let reservation = match self
            .runtime
            .begin_open_state_operation_with_identity(
                arguments.open_state_id,
                file,
                arguments.sequence_id,
                digest,
                &self.request_context.principal,
                false,
            )
            .await
        {
            OpenStateDecision::Replay { result, client_id, .. } => {
                if let Err(status) = self
                    .renew_delegations_while_fenced(&fences, client_id, ClientLeaseRenewal::StateId)
                    .await
                {
                    return ResOp::Close(NfsResult::Err(status));
                }
                return result;
            },
            OpenStateDecision::Error { status, client_id } => {
                if let Some(client_id) = client_id {
                    if let Err(renewal_status) = self
                        .renew_delegations_while_fenced(&fences, client_id, ClientLeaseRenewal::StateId)
                        .await
                    {
                        return ResOp::Close(NfsResult::Err(renewal_status));
                    }
                }
                return ResOp::Close(NfsResult::Err(status));
            },
            OpenStateDecision::Execute(reservation) => reservation,
        };
        let client_id = reservation.client_id();
        if let Err(status) = self
            .renew_delegations_while_fenced(&fences, client_id, ClientLeaseRenewal::StateId)
            .await
        {
            drop(fences);
            return self
                .runtime
                .complete_open_state_error(reservation, status, ResOp::Close(NfsResult::Err(status)))
                .await;
        }
        drop(fences);
        if self.export(file.export_id).is_none() {
            return self
                .runtime
                .complete_open_state_error(
                    reservation,
                    NfsStatus::Stale,
                    ResOp::Close(NfsResult::Err(NfsStatus::Stale)),
                )
                .await;
        }
        let prepared = match self.runtime.prepare_close(reservation).await {
            Ok(prepared) => prepared,
            Err(result) => return result,
        };
        match self.runtime.close_open(prepared).await {
            Ok(completion) => {
                self.open_pins.accept_runtime_releases(self.runtime);
                self.open_pins.maintain(self.runtime).await;
                completion.result
            },
            Err(status) => ResOp::Close(NfsResult::Err(status)),
        }
    }

    async fn delegation_purge(&self, client_id: u64) -> ResOp {
        let fences = self.delegation_renewal_fences().await;
        if let Err(status) = self.revoke_expired_delegations_while_fenced(&fences).await {
            return ResOp::DelegPurge(status);
        }
        let renewal = match self
            .renew_client_across_delegations_while_fenced(&fences, client_id, ClientLeaseRenewal::ClientId)
            .await
        {
            Ok(renewal) => renewal,
            Err(status) => return ResOp::DelegPurge(status),
        };
        if renewal.runtime_status != NfsStatus::Ok {
            return ResOp::DelegPurge(renewal.runtime_status);
        }
        let managers = fences.managers.clone();
        drop(fences);
        let previous_client_ids = match self
            .runtime
            .previous_client_ids(client_id, &self.request_context.principal)
            .await
        {
            Ok(previous_client_ids) => previous_client_ids,
            Err(status) => return ResOp::DelegPurge(status),
        };
        for (export_id, manager) in managers {
            let mut context = self.context_for(export_id);
            context.client_id = Some(client_id);
            if let Err(error) = manager
                .delegpurge_with_recovered_client_ids(&context, client_id, &previous_client_ids)
                .await
            {
                return ResOp::DelegPurge(error.status());
            }
        }
        ResOp::DelegPurge(NfsStatus::Ok)
    }

    async fn release_lock_owner(&self, owner: &super::types::LockOwner) -> ResOp {
        let fences = self.delegation_renewal_fences().await;
        if let Err(status) = self.revoke_expired_delegations_while_fenced(&fences).await {
            return ResOp::ReleaseLockOwner(status);
        }
        match self
            .runtime
            .prepare_release_lock_owner(owner, &self.request_context.principal)
            .await
        {
            ReleaseLockOwnerDecision::Error { status, client_id } => {
                if let Some(client_id) = client_id {
                    if let Err(renewal_status) = self
                        .renew_delegations_while_fenced(&fences, client_id, ClientLeaseRenewal::ClientId)
                        .await
                    {
                        return ResOp::ReleaseLockOwner(renewal_status);
                    }
                }
                ResOp::ReleaseLockOwner(status)
            },
            ReleaseLockOwnerDecision::Execute { client_id } => {
                if let Err(status) = self
                    .renew_delegations_while_fenced(&fences, client_id, ClientLeaseRenewal::ClientId)
                    .await
                {
                    return ResOp::ReleaseLockOwner(status);
                }
                // Stable replay cleanup may block.  The renewal evidence is
                // already recorded, so release all export fences before it.
                drop(fences);
                ResOp::ReleaseLockOwner(self.runtime.release_lock_owner_after_auth(owner).await)
            },
        }
    }

    async fn renew_client(&self, client_id: u64) -> ResOp {
        let fences = self.delegation_renewal_fences().await;
        if let Err(status) = self.revoke_expired_delegations_while_fenced(&fences).await {
            return ResOp::Renew(status);
        }
        let renewal = match self
            .renew_client_across_delegations_while_fenced(&fences, client_id, ClientLeaseRenewal::Explicit)
            .await
        {
            Ok(renewal) => renewal,
            Err(status) => return ResOp::Renew(status),
        };
        ResOp::Renew(if renewal.runtime_status == NfsStatus::LeaseMoved {
            // RFC 7530 requires LEASE_MOVED to take precedence when both
            // callback-path and migrated-lease obligations are present.
            NfsStatus::LeaseMoved
        } else if renewal.callback_path_down {
            NfsStatus::CallbackPathDown
        } else {
            NfsStatus::Ok
        })
    }

    async fn delegation_renewal_fences(&self) -> DelegationRenewalFences<'_> {
        let mut managers = self
            .delegations
            .iter()
            .map(|(export_id, manager)| (*export_id, manager))
            .collect::<Vec<_>>();
        managers.sort_by_key(|(export_id, _)| export_id.0);
        let mut guards = Vec::with_capacity(managers.len());
        for (_, manager) in &managers {
            guards.push(manager.renewal_fence().await);
        }
        DelegationRenewalFences {
            managers,
            _guards: guards,
        }
    }

    async fn revoke_expired_delegations_while_fenced(
        &self,
        fences: &DelegationRenewalFences<'_>,
    ) -> Result<(), NfsStatus> {
        for (_, manager) in &fences.managers {
            manager.revoke_expired_while_fenced().await.map_err(|error| error.status())?;
        }
        Ok(())
    }

    /// Makes an expired delegation's durable tombstone visible before an
    /// operation can perform conflicting backend work.  Callers invoke this
    /// only after releasing every renewal fence: stable storage may block,
    /// but an undurable revocation must not be treated as a completed one.
    async fn finalize_detached_delegation_removals(&self) -> Result<(), NfsStatus> {
        for manager in self.delegations.values() {
            manager.finalize_detached_removals().await.map_err(|error| error.status())?;
        }
        Ok(())
    }

    /// Renews the runtime client lease and every live delegation held by that
    /// client while all manager renewal fences are held.
    async fn renew_client_across_delegations_while_fenced(
        &self,
        fences: &DelegationRenewalFences<'_>,
        client_id: u64,
        kind: ClientLeaseRenewal,
    ) -> Result<ClientLeaseRenewalOutcome, NfsStatus> {
        let runtime_status = match kind {
            ClientLeaseRenewal::Explicit => self.runtime.renew(client_id, &self.request_context.principal).await,
            ClientLeaseRenewal::ClientId | ClientLeaseRenewal::StateId => {
                self.runtime.validate_client(client_id, &self.request_context.principal).await
            },
        };
        if !matches!(runtime_status, NfsStatus::Ok | NfsStatus::LeaseMoved) {
            return Err(runtime_status);
        }
        let callback_path_down = self.renew_delegations_while_fenced(fences, client_id, kind).await?;
        Ok(ClientLeaseRenewalOutcome {
            runtime_status,
            callback_path_down,
        })
    }

    /// Extends delegation leases after the surrounding operation has already
    /// authenticated and renewed its runtime client lease.
    ///
    /// The caller keeps every manager fence held from before that runtime
    /// validation through this update.  This makes expiry and all-export
    /// lease extension one ordered action, without a second runtime touch.
    async fn renew_delegations_while_fenced(
        &self,
        fences: &DelegationRenewalFences<'_>,
        client_id: u64,
        kind: ClientLeaseRenewal,
    ) -> Result<bool, NfsStatus> {
        let mut callback_path_down = false;
        for (export_id, manager) in &fences.managers {
            let mut context = self.context_for(*export_id);
            context.client_id = Some(client_id);
            match kind {
                ClientLeaseRenewal::Explicit => match manager.renew_client(&context, client_id).await {
                    Ok(()) => {},
                    Err(NfsStatus::CallbackPathDown) => callback_path_down = true,
                    // RFC 7530 section 10.4.6 requires every known lease to
                    // be extended before reporting callback-path failure.
                    Err(status) => return Err(status),
                },
                ClientLeaseRenewal::ClientId => {
                    manager.renew_client_from_clientid_while_fenced(&context, client_id).await?;
                },
                ClientLeaseRenewal::StateId => {
                    manager.renew_client_from_stateid_while_fenced(&context, client_id).await?;
                },
            }
        }
        Ok(callback_path_down)
    }

    async fn delegation_return(&self, state_id: super::types::StateId, current: &Option<ResolvedFileHandle>) -> ResOp {
        let file = match current_runtime_file(current) {
            Ok(file) => file,
            Err(status) => return ResOp::DelegReturn(status),
        };
        let Some(manager) = self.delegations.get(&file.export_id) else {
            return ResOp::DelegReturn(NfsStatus::BadStateId);
        };
        // Keep recall-expiry revocation from interleaving between validation,
        // shared-runtime lease renewal across every export, and delegation
        // removal. RFC 7530 section 9.5 makes a valid DELEGRETURN an
        // implicit renewal of every lease owned by this client.
        let fences = self.delegation_renewal_fences().await;
        if let Err(status) = self.revoke_expired_delegations_while_fenced(&fences).await {
            return ResOp::DelegReturn(status);
        }
        let context = self.context_for(file.export_id);
        let client_id = match manager.validate_delegreturn(&context, file.object, state_id).await {
            Ok(client_id) => client_id,
            Err(error) => return ResOp::DelegReturn(error.status()),
        };
        let renewal = match self
            .renew_client_across_delegations_while_fenced(&fences, client_id, ClientLeaseRenewal::StateId)
            .await
        {
            Ok(renewal) => renewal,
            Err(status) => return ResOp::DelegReturn(status),
        };
        if renewal.runtime_status != NfsStatus::Ok {
            return ResOp::DelegReturn(renewal.runtime_status);
        }
        drop(fences);
        let mut context = context;
        context.client_id = Some(client_id);
        match manager.delegreturn(&context, file.object, state_id).await {
            Ok(()) => ResOp::DelegReturn(NfsStatus::Ok),
            Err(error) => ResOp::DelegReturn(error.status()),
        }
    }

    async fn open_attr(&self, arguments: &OpenAttrArgs, current: &mut Option<ResolvedFileHandle>) -> ResOp {
        let Some(previous) = current.as_ref().cloned() else {
            return ResOp::OpenAttr(NfsStatus::NoFileHandle);
        };
        let ResolvedTarget::Backend { export_id, object, .. } = previous.target else {
            return ResOp::OpenAttr(NfsStatus::NotSupported);
        };
        let Some(export) = self.export(export_id) else {
            return ResOp::OpenAttr(NfsStatus::Stale);
        };
        match self.backend_file_type(export_id, object, OpNum::OpenAttr.code()).await {
            Ok(file_type) if file_type.is_named_attribute() => return ResOp::OpenAttr(NfsStatus::NotSupported),
            Ok(_) => {},
            Err(status) => return ResOp::OpenAttr(status),
        }
        if !export
            .vfs
            .nfs4_capabilities()
            .is_some_and(|capabilities| capabilities.named_attributes)
        {
            return ResOp::OpenAttr(NfsStatus::NotSupported);
        }
        let _gate = self.runtime.operation_gate(RuntimeFile { export_id, object }).await;
        let context = self.context_for(export_id);
        let _delegation_access = if arguments.create_directory {
            match self
                .begin_delegation_access_and_recall(export_id, object, None, DelegationKind::Write, false)
                .await
            {
                Ok(reservation) => Some(reservation),
                Err(status) => return ResOp::OpenAttr(status),
            }
        } else {
            None
        };
        match export
            .vfs
            .nfs4_named_attribute_directory(&context, object, arguments.create_directory)
            .await
        {
            Ok(directory) => {
                *current = Some(self.backend_handle(export_id, directory.object, None));
                ResOp::OpenAttr(NfsStatus::Ok)
            },
            Err(error) => ResOp::OpenAttr(map_vfs_error_for_operation(OpNum::OpenAttr.code(), error)),
        }
    }

    async fn security_info(&self, arguments: &SecInfoArgs, current: &Option<ResolvedFileHandle>) -> ResOp {
        let name = match validate_component_name(&arguments.name) {
            Ok(name) => name,
            Err(status) => return ResOp::SecInfo(NfsResult::Err(status)),
        };
        let Some(current) = current else {
            return ResOp::SecInfo(NfsResult::Err(NfsStatus::NoFileHandle));
        };
        let target_export = match current.target {
            ResolvedTarget::Pseudo(node) => {
                let child = match self.namespace.lookup(node, name.as_bytes()) {
                    Ok(child) => child,
                    Err(error) => return ResOp::SecInfo(NfsResult::Err(map_namespace_error(error))),
                };
                match self.namespace.node(child) {
                    Ok(child) => child.export(),
                    Err(error) => return ResOp::SecInfo(NfsResult::Err(map_namespace_error(error))),
                }
            },
            ResolvedTarget::Backend {
                export_id,
                object,
                namespace_node,
            } => {
                if let Some(route) = namespace_node {
                    let at_anchor = match self.is_overlay_anchor(export_id, object, route, OpNum::SecInfo.code()).await
                    {
                        Ok(at_anchor) => at_anchor,
                        Err(status) => return ResOp::SecInfo(NfsResult::Err(status)),
                    };
                    if at_anchor {
                        match self.namespace.lookup(route, name.as_bytes()) {
                            Ok(child) => {
                                match self.lookup_overlay_child(export_id, object, child, OpNum::SecInfo.code()).await {
                                    Ok(handle) => handle.export_id(),
                                    Err(status) => return ResOp::SecInfo(NfsResult::Err(status)),
                                }
                            },
                            Err(NamespaceError::NotFound) => {
                                let Some(export) = self.export(export_id) else {
                                    return ResOp::SecInfo(NfsResult::Err(NfsStatus::Stale));
                                };
                                let context = self.context_for(export_id);
                                if let Err(error) = export.vfs.lookup(&context, object, &name).await {
                                    return ResOp::SecInfo(NfsResult::Err(map_vfs_error_for_operation(
                                        OpNum::SecInfo.code(),
                                        error,
                                    )));
                                }
                                Some(export_id)
                            },
                            Err(error) => return ResOp::SecInfo(NfsResult::Err(map_namespace_error(error))),
                        }
                    } else {
                        let Some(export) = self.export(export_id) else {
                            return ResOp::SecInfo(NfsResult::Err(NfsStatus::Stale));
                        };
                        let context = self.context_for(export_id);
                        if let Err(error) = export.vfs.lookup(&context, object, &name).await {
                            return ResOp::SecInfo(NfsResult::Err(map_vfs_error_for_operation(
                                OpNum::SecInfo.code(),
                                error,
                            )));
                        }
                        Some(export_id)
                    }
                } else {
                    let Some(export) = self.export(export_id) else {
                        return ResOp::SecInfo(NfsResult::Err(NfsStatus::Stale));
                    };
                    let context = self.context_for(export_id);
                    if let Err(error) = export.vfs.lookup(&context, object, &name).await {
                        return ResOp::SecInfo(NfsResult::Err(map_vfs_error_for_operation(
                            OpNum::SecInfo.code(),
                            error,
                        )));
                    }
                    Some(export_id)
                }
            },
        };
        let values = match target_export {
            Some(export_id) => {
                let Some(export) = self.export(export_id) else {
                    return ResOp::SecInfo(NfsResult::Err(NfsStatus::Stale));
                };
                security_info_for_policy(&export.security_policy)
            },
            None => security_info_for_exports(self.exports),
        };
        ResOp::SecInfo(NfsResult::Ok(values))
    }

    async fn open(
        &self,
        arguments: &OpenArgs,
        current: &mut Option<ResolvedFileHandle>,
        digest: OwnerRequestDigest,
    ) -> ResOp {
        let reclaim = matches!(arguments.claim, OpenClaim::Previous(_) | OpenClaim::DelegatePrevious(_));
        // The OPEN owner clientid is independent RFC 7530 §9.5 evidence for
        // every OPEN, including CLAIM_DELEGATE_CUR.  Separately, the claim's
        // delegation stateid selects RFC 7530 §10.4.6's stateid callback-path
        // rule for *all* renewal caused by that request.  Do not conflate the
        // identity that authenticated the request with its callback mode.
        let renewal_kind = if matches!(arguments.claim, OpenClaim::DelegateCurrent { .. }) {
            ClientLeaseRenewal::StateId
        } else {
            ClientLeaseRenewal::ClientId
        };
        let fences = self.delegation_renewal_fences().await;
        if let Err(status) = self.revoke_expired_delegations_while_fenced(&fences).await {
            return ResOp::Open(NfsResult::Err(status));
        }
        let reservation = match self
            .runtime
            .begin_open_with_identity(
                &arguments.owner,
                arguments.sequence_id,
                arguments.share_access,
                arguments.share_deny,
                reclaim,
                true,
                digest,
                &self.request_context.principal,
            )
            .await
        {
            OpenDecision::Replay {
                result,
                effect,
                client_id,
            } => {
                if let Some(client_id) = client_id {
                    if let Err(status) = self.renew_delegations_while_fenced(&fences, client_id, renewal_kind).await {
                        return ResOp::Open(NfsResult::Err(status));
                    }
                } else if let Some(client_id) = effect.stateid_renewal_client {
                    if let Err(status) = self
                        .renew_delegations_while_fenced(&fences, client_id, ClientLeaseRenewal::StateId)
                        .await
                    {
                        return ResOp::Open(NfsResult::Err(status));
                    }
                }
                if let Err(status) = self.apply_replay_effect(effect, current) {
                    return ResOp::Open(NfsResult::Err(status));
                }
                return result;
            },
            OpenDecision::Error { status, client_id } => {
                if let Some(client_id) = client_id {
                    if let Err(renewal_status) =
                        self.renew_delegations_while_fenced(&fences, client_id, renewal_kind).await
                    {
                        return ResOp::Open(NfsResult::Err(renewal_status));
                    }
                }
                return ResOp::Open(NfsResult::Err(status));
            },
            OpenDecision::Execute(reservation) => reservation,
        };
        // The owner clientid was authenticated before the OPEN reservation
        // was returned.  This must happen before CLAIM_DELEGATE_CUR validates
        // its delegation stateid, so a later BAD_STATEID or OPENMODE result
        // cannot discard valid owner-client lease evidence.
        if let Err(status) = self
            .renew_delegations_while_fenced(&fences, arguments.owner.client_id, renewal_kind)
            .await
        {
            drop(fences);
            return self.runtime.complete_open_error(reservation, status).await;
        }
        drop(fences);
        if let Err(status) = self.finalize_detached_delegation_removals().await {
            return self.runtime.complete_open_error(reservation, status).await;
        }

        match &arguments.claim {
            OpenClaim::Null(component) => {
                let Some(parent_handle) = current.as_ref().cloned() else {
                    return self.runtime.complete_open_error(reservation, NfsStatus::NoFileHandle).await;
                };
                let ResolvedTarget::Backend {
                    export_id,
                    object: parent,
                    ..
                } = parent_handle.target
                else {
                    return self.runtime.complete_open_error(reservation, NfsStatus::ReadOnly).await;
                };
                let Some(export) = self.export(export_id) else {
                    return self.runtime.complete_open_error(reservation, NfsStatus::Stale).await;
                };
                let name = match validate_component_name(component) {
                    Ok(name) => name,
                    Err(status) => return self.runtime.complete_open_error(reservation, status).await,
                };
                let (request, attributes_set) =
                    match self.open_request(export, &arguments.how, arguments.share_access).await {
                        Ok(request) => request,
                        Err(status) => return self.runtime.complete_open_error(reservation, status).await,
                    };
                let parent_file_type = match self.backend_file_type(export_id, parent, OpNum::Open.code()).await {
                    Ok(file_type) if file_type.is_directory() => file_type,
                    Ok(_) => return self.runtime.complete_open_error(reservation, NfsStatus::NotDirectory).await,
                    Err(status) => return self.runtime.complete_open_error(reservation, status).await,
                };
                if parent_file_type == FileType::AttributeDirectory
                    && matches!(arguments.how, OpenHow::Create(CreateHow::Exclusive(_)))
                {
                    return self.runtime.complete_open_error(reservation, NfsStatus::Invalid).await;
                }
                let name_gate = self.runtime.operation_gate((export_id, parent, name.as_bytes())).await;
                let mut context = self.context_for(export_id);
                context.client_id = Some(arguments.owner.client_id);

                let preflight = match export.vfs.nfs4_open_preflight(&context, parent, &name, &request).await {
                    Ok(preflight) => preflight,
                    Err(error) => {
                        return self
                            .runtime
                            .complete_open_error(reservation, map_vfs_error_for_operation(OpNum::Open.code(), error))
                            .await
                    },
                };
                // Validate every backend preflight output before reserving
                // share state or initiating a delegation recall.
                if validate_open_preflight_change(preflight.change_info).is_err() {
                    return self.runtime.complete_open_error(reservation, NfsStatus::ServerFault).await;
                }

                match preflight.target {
                    Nfs4OpenTarget::Existing(existing) => {
                        // Preserve the RFC-mandated GUARDED error precedence
                        // even if a backend accidentally reports the target
                        // instead of returning EXISTS from preflight.
                        if request
                            .create
                            .as_ref()
                            .is_some_and(|create| matches!(create.mode, VfsCreateMode::Guarded))
                        {
                            return self.runtime.complete_open_error(reservation, NfsStatus::Exists).await;
                        }
                        let object = existing.object;
                        let file_type = match existing.attributes {
                            Some(attributes) => attributes.file_type,
                            None => match self.backend_file_type(export_id, object, OpNum::Open.code()).await {
                                Ok(file_type) => file_type,
                                Err(status) => return self.runtime.complete_open_error(reservation, status).await,
                            },
                        };
                        match open_file_type_status(file_type) {
                            NfsStatus::Ok => {},
                            status => return self.runtime.complete_open_error(reservation, status).await,
                        }

                        // A pending share reservation is established before a
                        // recall so a concurrent conflicting OPEN cannot pass
                        // while callbacks are in flight. Any recall/backend
                        // failure below completes the target with an error and
                        // rolls this pending reservation back.
                        let operation_id = reservation.operation_id();
                        let target =
                            match self.runtime.reserve_open_target(reservation, RuntimeFile { export_id, object }) {
                                Ok(target) => target,
                                Err((reservation, status)) => {
                                    return self.runtime.complete_open_error(reservation, status).await
                                },
                            };
                        let delegation_kind = delegation_kind_for_share(arguments.share_access);
                        let _delegation_access = match self.runtime.begin_delegation_access(
                            RuntimeFile { export_id, object },
                            Some(arguments.owner.client_id),
                            delegation_kind,
                            request.truncate_existing,
                        ) {
                            Ok(reservation) => reservation,
                            Err(status) => return self.runtime.complete_open_target_error(target, status).await,
                        };
                        if let Err(status) = self
                            .recall_conflicting_delegations(
                                export_id,
                                object,
                                Some(arguments.owner.client_id),
                                delegation_kind,
                                request.truncate_existing,
                            )
                            .await
                        {
                            return self.runtime.complete_open_target_error(target, status).await;
                        }
                        let transaction = Nfs4OpenTransaction {
                            operation_id,
                            expected: Nfs4OpenExpectation::Existing(object),
                            pin_id: target.pin(),
                            acquire_pin: target.needs_retain(),
                        };
                        let mut attempt = match self.open_pins.begin(
                            export.vfs.clone(),
                            context.clone(),
                            parent,
                            name.clone(),
                            request.clone(),
                            transaction,
                        ) {
                            Ok(attempt) => attempt,
                            Err(status) => return self.runtime.complete_open_target_error(target, status).await,
                        };
                        let opened = match export.vfs.nfs4_open(&context, parent, &name, request, transaction).await {
                            Ok(opened) if opened.value.object == object => {
                                attempt.record_success(&opened);
                                opened
                            },
                            Ok(_) => {
                                let result =
                                    self.runtime.complete_open_target_error(target, NfsStatus::ServerFault).await;
                                attempt.cleanup();
                                return result;
                            },
                            Err(error) => {
                                let status = map_vfs_error_for_operation(OpNum::Open.code(), error);
                                let result = self.runtime.complete_open_target_error(target, status).await;
                                attempt.backend_failed();
                                return result;
                            },
                        };
                        let change = match required_change_info(Some(opened.change_info)) {
                            Ok(change) => change,
                            Err(status) => {
                                let result = self.runtime.complete_open_target_error(target, status).await;
                                attempt.cleanup();
                                return result;
                            },
                        };
                        // The backend name transaction is complete. Release
                        // the striped name gate before delegation preparation
                        // performs callbacks and durable state work.
                        drop(name_gate);
                        self.finish_open(
                            target,
                            export_id,
                            object,
                            change,
                            attributes_set,
                            current,
                            &context,
                            transaction.acquire_pin,
                            Some(attempt.into()),
                            OpenDelegationRequest::Optional(delegation_kind),
                        )
                        .await
                    },
                    Nfs4OpenTarget::Missing => {
                        if matches!(arguments.how, OpenHow::NoCreate) {
                            return self.runtime.complete_open_error(reservation, NfsStatus::NotFound).await;
                        }
                        let transaction = Nfs4OpenTransaction {
                            operation_id: reservation.operation_id(),
                            expected: Nfs4OpenExpectation::Missing,
                            pin_id: reservation.provisional_pin(),
                            acquire_pin: true,
                        };
                        let mut attempt = match self.open_pins.begin(
                            export.vfs.clone(),
                            context.clone(),
                            parent,
                            name.clone(),
                            request.clone(),
                            transaction,
                        ) {
                            Ok(attempt) => attempt,
                            Err(status) => return self.runtime.complete_open_error(reservation, status).await,
                        };
                        let opened = match export.vfs.nfs4_open(&context, parent, &name, request, transaction).await {
                            Ok(opened) => {
                                attempt.record_success(&opened);
                                opened
                            },
                            Err(error) => {
                                let status = map_vfs_error_for_operation(OpNum::Open.code(), error);
                                let result = self.runtime.complete_open_error(reservation, status).await;
                                attempt.backend_failed();
                                return result;
                            },
                        };
                        let object = opened.value.object;
                        let change = match required_change_info(Some(opened.change_info)) {
                            Ok(change) => change,
                            Err(status) => {
                                let result = self.runtime.complete_open_error(reservation, status).await;
                                attempt.cleanup();
                                return result;
                            },
                        };
                        let file_type = match opened.value.attributes {
                            Some(attributes) => attributes.file_type,
                            None => match self.backend_file_type(export_id, object, OpNum::Open.code()).await {
                                Ok(file_type) => file_type,
                                Err(status) => {
                                    let result = self.runtime.complete_open_error(reservation, status).await;
                                    attempt.cleanup();
                                    return result;
                                },
                            },
                        };
                        match open_file_type_status(file_type) {
                            NfsStatus::Ok => {},
                            status => {
                                let result = self.runtime.complete_open_error(reservation, status).await;
                                attempt.cleanup();
                                return result;
                            },
                        }
                        let target =
                            match self.runtime.reserve_open_target(reservation, RuntimeFile { export_id, object }) {
                                Ok(target) => target,
                                Err((reservation, status)) => {
                                    let result = self.runtime.complete_open_error(reservation, status).await;
                                    attempt.cleanup();
                                    return result;
                                },
                            };
                        if !target.needs_retain() || target.pin() != transaction.pin_id {
                            let result = self.runtime.complete_open_target_error(target, NfsStatus::ServerFault).await;
                            attempt.cleanup();
                            return result;
                        }
                        let delegation_kind = delegation_kind_for_share(arguments.share_access);
                        let _delegation_access = match self.runtime.begin_delegation_access(
                            RuntimeFile { export_id, object },
                            Some(arguments.owner.client_id),
                            delegation_kind,
                            false,
                        ) {
                            Ok(reservation) => reservation,
                            Err(status) => {
                                let result = self.runtime.complete_open_target_error(target, status).await;
                                attempt.cleanup();
                                return result;
                            },
                        };
                        // See the existing-target branch above: delegation
                        // preparation must not retain the striped name gate.
                        drop(name_gate);
                        self.finish_open(
                            target,
                            export_id,
                            object,
                            change,
                            attributes_set,
                            current,
                            &context,
                            true,
                            Some(attempt.into()),
                            OpenDelegationRequest::Optional(delegation_kind),
                        )
                        .await
                    },
                }
            },
            OpenClaim::Previous(delegation_type) => {
                if !matches!(arguments.how, OpenHow::NoCreate) {
                    return self.runtime.complete_open_error(reservation, NfsStatus::Invalid).await;
                }
                let file = match current_runtime_file(current) {
                    Ok(file) => file,
                    Err(status) => return self.runtime.complete_open_error(reservation, status).await,
                };
                let Some(export) = self.export(file.export_id) else {
                    return self.runtime.complete_open_error(reservation, NfsStatus::Stale).await;
                };
                match self.backend_file_type(file.export_id, file.object, OpNum::Open.code()).await {
                    Ok(file_type) => match open_file_type_status(file_type) {
                        NfsStatus::Ok => {},
                        status => return self.runtime.complete_open_error(reservation, status).await,
                    },
                    Err(status) => return self.runtime.complete_open_error(reservation, status).await,
                }
                let _gate = self.runtime.operation_gate(file).await;
                let target = match self.runtime.reserve_open_target(reservation, file) {
                    Ok(target) => target,
                    Err((reservation, status)) => return self.runtime.complete_open_error(reservation, status).await,
                };
                let _delegation_access = match self.runtime.begin_delegation_access(
                    file,
                    Some(arguments.owner.client_id),
                    delegation_kind_for_share(arguments.share_access),
                    false,
                ) {
                    Ok(reservation) => reservation,
                    Err(status) => return self.runtime.complete_open_target_error(target, status).await,
                };
                let retained = target.needs_retain();
                let mut context = self.context_for(file.export_id);
                context.client_id = Some(arguments.owner.client_id);
                // Register even when this OPEN upgrades an already-retained
                // pin: a reclaimed delegation still needs a cancellation-safe
                // owner until the runtime replay record is durable.
                let attempt =
                    match self
                        .open_pins
                        .begin_retain(export.vfs.clone(), context.clone(), file, target.pin(), retained)
                    {
                        Ok(attempt) => attempt,
                        Err(status) => return self.runtime.complete_open_target_error(target, status).await,
                    };
                if retained {
                    if let Err(error) = export.vfs.retain_open_object(&context, file.object, target.pin()).await {
                        let status = map_vfs_error_for_operation(OpNum::Open.code(), error);
                        let result = self.runtime.complete_open_target_error(target, status).await;
                        attempt.backend_failed();
                        return result;
                    }
                }
                let pin_attempt = Some(attempt.into());
                self.finish_open(
                    target,
                    file.export_id,
                    file.object,
                    empty_change_info(),
                    Vec::new(),
                    current,
                    &context,
                    retained,
                    pin_attempt,
                    match delegation_type {
                        OpenDelegationType::None => OpenDelegationRequest::None,
                        OpenDelegationType::Read => OpenDelegationRequest::RequiredReclaim(DelegationKind::Read),
                        OpenDelegationType::Write => OpenDelegationRequest::RequiredReclaim(DelegationKind::Write),
                    },
                )
                .await
            },
            OpenClaim::DelegateCurrent {
                delegate_state_id,
                file,
            } => {
                self.open_delegation_claim(reservation, arguments, file, Some(*delegate_state_id), false, current)
                    .await
            },
            OpenClaim::DelegatePrevious(file) => {
                self.open_delegation_claim(reservation, arguments, file, None, true, current)
                    .await
            },
        }
    }

    async fn open_delegation_claim(
        &self,
        mut reservation: super::runtime::OpenReservation,
        arguments: &OpenArgs,
        component: &[u8],
        current_delegation: Option<super::types::StateId>,
        reclaim_previous: bool,
        current: &mut Option<ResolvedFileHandle>,
    ) -> ResOp {
        if !matches!(arguments.how, OpenHow::NoCreate) {
            return self.runtime.complete_open_error(reservation, NfsStatus::Invalid).await;
        }
        let Some(parent_handle) = current.as_ref().cloned() else {
            return self.runtime.complete_open_error(reservation, NfsStatus::NoFileHandle).await;
        };
        let ResolvedTarget::Backend {
            export_id,
            object: parent,
            ..
        } = parent_handle.target
        else {
            return self.runtime.complete_open_error(reservation, NfsStatus::ReadOnly).await;
        };
        let Some(export) = self.export(export_id) else {
            return self.runtime.complete_open_error(reservation, NfsStatus::Stale).await;
        };
        let name = match validate_component_name(component) {
            Ok(name) => name,
            Err(status) => return self.runtime.complete_open_error(reservation, status).await,
        };
        match self.backend_file_type(export_id, parent, OpNum::Open.code()).await {
            Ok(file_type) if file_type.is_directory() => {},
            Ok(_) => return self.runtime.complete_open_error(reservation, NfsStatus::NotDirectory).await,
            Err(status) => return self.runtime.complete_open_error(reservation, status).await,
        }
        let name_gate = self.runtime.operation_gate((export_id, parent, name.as_bytes())).await;
        let mut context = self.context_for(export_id);
        context.client_id = Some(arguments.owner.client_id);
        let access = match vfs_open_access(arguments.share_access) {
            Ok(access) => access,
            Err(status) => return self.runtime.complete_open_error(reservation, status).await,
        };
        let request = Nfs4OpenRequest {
            access,
            create: None,
            truncate_existing: false,
        };
        let preflight = match export.vfs.nfs4_open_preflight(&context, parent, &name, &request).await {
            Ok(preflight) => preflight,
            Err(error) => {
                return self
                    .runtime
                    .complete_open_error(reservation, map_vfs_error_for_operation(OpNum::Open.code(), error))
                    .await
            },
        };
        if validate_open_preflight_change(preflight.change_info).is_err() {
            return self.runtime.complete_open_error(reservation, NfsStatus::ServerFault).await;
        }
        let object = match preflight.target {
            Nfs4OpenTarget::Existing(object) => {
                let file_type = match object.attributes {
                    Some(attributes) => attributes.file_type,
                    None => match self.backend_file_type(export_id, object.object, OpNum::Open.code()).await {
                        Ok(file_type) => file_type,
                        Err(status) => return self.runtime.complete_open_error(reservation, status).await,
                    },
                };
                match open_file_type_status(file_type) {
                    NfsStatus::Ok => object.object,
                    status => return self.runtime.complete_open_error(reservation, status).await,
                }
            },
            Nfs4OpenTarget::Missing => return self.runtime.complete_open_error(reservation, NfsStatus::NotFound).await,
        };
        let delegation_request = if reclaim_previous {
            match self
                .recovered_delegation_kind(export_id, object, arguments.owner.client_id, &context)
                .await
            {
                Ok(kind) => OpenDelegationRequest::RequiredReclaim(kind),
                Err(status) => return self.runtime.complete_open_error(reservation, status).await,
            }
        } else {
            let Some(state_id) = current_delegation else {
                return self.runtime.complete_open_error(reservation, NfsStatus::BadStateId).await;
            };
            let Some(manager) = self.delegations.get(&export_id) else {
                return self.runtime.complete_open_error(reservation, NfsStatus::BadStateId).await;
            };
            // CLAIM_DELEGATE_CUR is an OPEN carrying a delegation stateid.
            // Authenticate it and renew under the stateid callback-down rule,
            // without holding manager fences across the preceding preflight.
            let fences = self.delegation_renewal_fences().await;
            if let Err(status) = self.revoke_expired_delegations_while_fenced(&fences).await {
                drop(fences);
                return self.runtime.complete_open_error(reservation, status).await;
            }
            let grant = match manager.claim_delegate_current_while_fenced(&context, object, state_id).await {
                Ok(grant) => grant,
                Err(status) => {
                    drop(fences);
                    return self.runtime.complete_open_error(reservation, status).await;
                },
            };
            // Persist this authenticated delegation source with the OPEN
            // owner replay before any later share-mode or backend error can
            // consume the owner sequence.  An exact CLAIM_DELEGATE_CUR retry
            // must renew by stateid, not by ordinary OPEN clientid semantics.
            reservation.set_stateid_renewal_client(grant.client_id);
            let renewal = match self
                .renew_client_across_delegations_while_fenced(&fences, grant.client_id, ClientLeaseRenewal::StateId)
                .await
            {
                Ok(renewal) => renewal,
                Err(status) => {
                    drop(fences);
                    return self.runtime.complete_open_error(reservation, status).await;
                },
            };
            if renewal.runtime_status != NfsStatus::Ok {
                drop(fences);
                return self.runtime.complete_open_error(reservation, renewal.runtime_status).await;
            }
            if delegation_kind_for_share(arguments.share_access) == DelegationKind::Write
                && grant.kind != DelegationKind::Write
            {
                drop(fences);
                return self.runtime.complete_open_error(reservation, NfsStatus::OpenMode).await;
            }
            drop(fences);
            OpenDelegationRequest::None
        };
        let operation_id = reservation.operation_id();
        let target = match self.runtime.reserve_open_target(reservation, RuntimeFile { export_id, object }) {
            Ok(target) => target,
            Err((reservation, status)) => return self.runtime.complete_open_error(reservation, status).await,
        };
        let _delegation_access = match self.runtime.begin_delegation_access(
            RuntimeFile { export_id, object },
            Some(arguments.owner.client_id),
            delegation_kind_for_share(arguments.share_access),
            false,
        ) {
            Ok(reservation) => reservation,
            Err(status) => return self.runtime.complete_open_target_error(target, status).await,
        };
        let transaction = Nfs4OpenTransaction {
            operation_id,
            expected: Nfs4OpenExpectation::Existing(object),
            pin_id: target.pin(),
            acquire_pin: target.needs_retain(),
        };
        let mut attempt = match self.open_pins.begin(
            export.vfs.clone(),
            context.clone(),
            parent,
            name.clone(),
            request.clone(),
            transaction,
        ) {
            Ok(attempt) => attempt,
            Err(status) => return self.runtime.complete_open_target_error(target, status).await,
        };
        let opened = match export.vfs.nfs4_open(&context, parent, &name, request, transaction).await {
            Ok(opened) if opened.value.object == object => {
                attempt.record_success(&opened);
                opened
            },
            Ok(_) => {
                let result = self.runtime.complete_open_target_error(target, NfsStatus::ServerFault).await;
                attempt.cleanup();
                return result;
            },
            Err(error) => {
                let status = map_vfs_error_for_operation(OpNum::Open.code(), error);
                let result = self.runtime.complete_open_target_error(target, status).await;
                attempt.backend_failed();
                return result;
            },
        };
        let change = match required_change_info(Some(opened.change_info)) {
            Ok(change) => change,
            Err(status) => {
                let result = self.runtime.complete_open_target_error(target, status).await;
                attempt.cleanup();
                return result;
            },
        };
        drop(name_gate);
        self.finish_open(
            target,
            export_id,
            object,
            change,
            Vec::new(),
            current,
            &context,
            transaction.acquire_pin,
            Some(attempt.into()),
            delegation_request,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn finish_open(
        &self,
        mut target: super::runtime::OpenTargetReservation,
        export_id: crate::vfs::ExportId,
        object: ObjectKey,
        change: ChangeInfo,
        attributes_set: Bitmap,
        current: &mut Option<ResolvedFileHandle>,
        context: &RequestContext,
        retained: bool,
        mut pin_attempt: Option<ManagedOpenPin>,
        mut delegation_request: OpenDelegationRequest,
    ) -> ResOp {
        debug_assert!(!retained || pin_attempt.is_some(), "every newly acquired OPEN pin has a manager guard");
        let delegation_attachment = pin_attempt.as_ref().map(ManagedOpenPin::delegation_attachment);
        if let OpenDelegationRequest::Optional(kind) | OpenDelegationRequest::RequiredReclaim(kind) = delegation_request
        {
            let eligibility = match context.client_id {
                Some(client_id) => self.runtime.reserve_delegation_eligibility(&mut target, client_id, kind),
                None => Err(NfsStatus::StaleClientId),
            };
            match eligibility {
                Ok(eligibility) => pin_attempt
                    .as_ref()
                    .expect("delegation-capable OPEN has a manager guard")
                    .attach_delegation_eligibility(eligibility),
                Err(_) if matches!(delegation_request, OpenDelegationRequest::Optional(_)) => {
                    delegation_request = OpenDelegationRequest::None;
                },
                Err(status) => {
                    let result = self.runtime.complete_open_target_error(target, status).await;
                    if let Some(attempt) = pin_attempt.take() {
                        attempt.cleanup();
                    }
                    return result;
                },
            }
        }
        let delegation = match delegation_request {
            OpenDelegationRequest::None => Ok(OpenDelegation::None),
            OpenDelegationRequest::Optional(kind) => Ok(self
                .try_grant_delegation(
                    export_id,
                    object,
                    kind,
                    context,
                    delegation_attachment
                        .clone()
                        .expect("delegation-capable OPEN has a manager guard"),
                )
                .await),
            OpenDelegationRequest::RequiredReclaim(kind) => {
                self.reclaim_delegation(
                    export_id,
                    object,
                    kind,
                    context,
                    delegation_attachment.expect("delegation reclaim OPEN has a manager guard"),
                )
                .await
            },
        };
        let delegation = match delegation {
            Ok(delegation) => delegation,
            Err(status) => {
                let result = self.runtime.complete_open_target_error(target, status).await;
                if let Some(attempt) = pin_attempt.take() {
                    attempt.cleanup();
                }
                return result;
            },
        };
        if let Some(attempt) = pin_attempt.as_mut() {
            attempt.mark_committing(RuntimeFile { export_id, object });
        }
        match self.runtime.complete_open(target, change, attributes_set, delegation).await {
            Ok(completion) => {
                if let Some(attempt) = pin_attempt.take() {
                    attempt.adopt();
                }
                debug_assert_eq!(completion.newly_retained, retained);
                debug_assert_eq!(completion.effect.current_file, Some(RuntimeFile { export_id, object }));
                self.apply_replay_effect(completion.effect, current)
                    .expect("successful OPEN replay effect references its registered export");
                completion.result
            },
            Err(status) => {
                if let Some(attempt) = pin_attempt.take() {
                    attempt.cleanup();
                }
                ResOp::Open(NfsResult::Err(status))
            },
        }
    }

    async fn try_grant_delegation(
        &self,
        export_id: crate::vfs::ExportId,
        object: ObjectKey,
        kind: DelegationKind,
        context: &RequestContext,
        attachment: DelegationAttachment,
    ) -> OpenDelegation {
        let Some(manager) = self.delegations.get(&export_id).cloned() else {
            return OpenDelegation::None;
        };
        let Some(client_id) = context.client_id else {
            return OpenDelegation::None;
        };
        let callback = match self.callback_client(client_id).await {
            Ok(callback) => callback,
            Err(status) => {
                tracing::debug!(?status, client_id, "NFSv4 delegation callback is unavailable");
                return OpenDelegation::None;
            },
        };
        let file_handle = self.backend_handle(export_id, object, None).wire;
        let requested_space = if kind == DelegationKind::Write {
            u64::from(self.max_write_size)
        } else {
            0
        };
        let request = DelegationGrantRequest {
            context: context.clone(),
            object,
            file_handle,
            kind,
            requested_space,
            callback,
        };
        match self.open_pins.grant_delegation(attachment, manager, request).await {
            Ok(GrantOutcome::Granted(grant)) => wire_delegation(&grant, requested_space),
            Ok(GrantOutcome::NotGranted(_)) | Ok(GrantOutcome::Delay) => OpenDelegation::None,
            Err(error) => {
                tracing::warn!(
                    export_id = export_id.0,
                    client_id,
                    error = %error,
                    "NFSv4 delegation grant failed"
                );
                OpenDelegation::None
            },
        }
    }

    async fn reclaim_delegation(
        &self,
        export_id: crate::vfs::ExportId,
        object: ObjectKey,
        kind: DelegationKind,
        context: &RequestContext,
        attachment: DelegationAttachment,
    ) -> Result<OpenDelegation, NfsStatus> {
        let manager = self.delegations.get(&export_id).cloned().ok_or(NfsStatus::ReclaimBad)?;
        let client_id = context.client_id.ok_or(NfsStatus::StaleClientId)?;
        let callback = self.callback_client(client_id).await.map_err(|_| NfsStatus::ReclaimBad)?;
        let export = self.export(export_id).ok_or(NfsStatus::Stale)?;
        let persistent_object_id = export
            .vfs
            .nfs4_persistent_object_id(context, object)
            .await
            .map_err(|error| map_vfs_error_for_operation(OpNum::Open.code(), error))?;
        let previous_client_ids = self
            .runtime
            .previous_client_ids(client_id, &self.request_context.principal)
            .await?;
        let mut recovered = None;
        for previous_client_id in previous_client_ids {
            if let Some(candidate) = manager
                .recovered_delegation(previous_client_id, &persistent_object_id, kind)
                .await
            {
                if recovered.replace(candidate).is_some() {
                    return Err(NfsStatus::ServerFault);
                }
            }
        }
        let recovered = recovered.ok_or(NfsStatus::ReclaimBad)?;
        let requested_space = if kind == DelegationKind::Write {
            recovered.requested_space
        } else {
            0
        };
        let request = DelegationGrantRequest {
            context: context.clone(),
            object,
            file_handle: self.backend_handle(export_id, object, None).wire,
            kind,
            requested_space,
            callback,
        };
        match self
            .open_pins
            .prepare_delegation_reclaim(attachment, manager, request, recovered)
            .await
            .map_err(|error| error.status())?
        {
            GrantOutcome::Granted(grant) => Ok(wire_delegation(&grant, requested_space)),
            GrantOutcome::Delay => Err(NfsStatus::Delay),
            GrantOutcome::NotGranted(denial) => {
                tracing::debug!(
                    export_id = export_id.0,
                    object = object.file_id,
                    ?denial,
                    "NFSv4 persistent delegation reclaim was denied"
                );
                Err(NfsStatus::ReclaimBad)
            },
        }
    }

    async fn recovered_delegation_kind(
        &self,
        export_id: crate::vfs::ExportId,
        object: ObjectKey,
        client_id: u64,
        context: &RequestContext,
    ) -> Result<DelegationKind, NfsStatus> {
        let manager = self.delegations.get(&export_id).ok_or(NfsStatus::ReclaimBad)?;
        let export = self.export(export_id).ok_or(NfsStatus::Stale)?;
        let persistent_object_id = export
            .vfs
            .nfs4_persistent_object_id(context, object)
            .await
            .map_err(|error| map_vfs_error_for_operation(OpNum::Open.code(), error))?;
        let previous_client_ids = self
            .runtime
            .previous_client_ids(client_id, &self.request_context.principal)
            .await?;
        let mut found = None;
        for previous_client_id in previous_client_ids {
            for kind in [DelegationKind::Read, DelegationKind::Write] {
                if manager
                    .recovered_delegation(previous_client_id, &persistent_object_id, kind)
                    .await
                    .is_some()
                    && found.replace(kind).is_some()
                {
                    return Err(NfsStatus::ServerFault);
                }
            }
        }
        found.ok_or(NfsStatus::ReclaimBad)
    }

    async fn callback_client(&self, client_id: u64) -> Result<Arc<CallbackRpcClient>, NfsStatus> {
        let connector = self.callback_connector.cloned().ok_or(NfsStatus::NotSupported)?;
        let confirmed = self
            .runtime
            .confirmed_client_callback(client_id, &self.request_context.principal)
            .await?;
        let network_id = std::str::from_utf8(&confirmed.callback.location.netid)
            .map_err(|_| NfsStatus::Invalid)?
            .to_owned();
        let universal_address = std::str::from_utf8(&confirmed.callback.location.address)
            .map_err(|_| NfsStatus::Invalid)?
            .to_owned();
        let auth =
            auth_for_setclientid_principal(&confirmed.setclientid_principal, self.callback_gss_initiator.cloned())
                .map_err(|_| NfsStatus::NotSupported)?;
        CallbackRpcClient::with_system_clock(
            connector,
            CallbackTarget {
                network_id,
                universal_address,
            },
            confirmed.callback.program,
            confirmed.callback_identifier,
            auth,
            CallbackClientConfig {
                attempt_timeout: self.callback_attempt_timeout,
                ..CallbackClientConfig::default()
            },
        )
        .map(Arc::new)
        .map_err(|_| NfsStatus::NotSupported)
    }

    async fn recall_conflicting_delegations(
        &self,
        export_id: crate::vfs::ExportId,
        object: ObjectKey,
        requesting_client: Option<u64>,
        access: DelegationKind,
        truncate: bool,
    ) -> Result<(), NfsStatus> {
        // A prior expiry may have removed a conflicting delegation from the
        // live map while its durable deletion is still pending.  Do not start
        // callbacks or backend mutation under the assumption that conflict
        // disappeared until that tombstone is committed.
        self.finalize_detached_delegation_removals().await?;
        let Some(manager) = self.delegations.get(&export_id).cloned() else {
            return Ok(());
        };
        let conflict = manager
            .begin_conflict(object, requesting_client.unwrap_or(0), access, truncate)
            .await
            .map_err(|error| error.status())?;
        if !conflict.recalls.is_empty() {
            let tracker = self.executions.upgrade().ok_or(NfsStatus::ServerFault)?;
            for recall in conflict.recalls {
                let manager = manager.clone();
                tracker
                    .spawn(async move {
                        match manager.execute_recall(recall).await {
                            Ok(RecallOutcome::Delivered | RecallOutcome::AlreadyReturned) => {},
                            Ok(RecallOutcome::Revoked {
                                callback_error,
                                revoked,
                            }) => {
                                tracing::warn!(
                                    error = %callback_error,
                                    state_id = ?revoked.map(|record| record.state_id),
                                    "NFSv4 delegation recall expired and was revoked"
                                );
                            },
                            Err(error) => {
                                tracing::warn!(error = %error, "NFSv4 delegation recall failed");
                            },
                        }
                    })
                    .await
                    .map_err(|_| NfsStatus::Delay)?;
            }
        }
        match conflict.status {
            NfsStatus::Ok => Ok(()),
            status => Err(status),
        }
    }

    async fn begin_delegation_access_and_recall(
        &self,
        export_id: crate::vfs::ExportId,
        object: ObjectKey,
        requesting_client: Option<u64>,
        access: DelegationKind,
        truncate: bool,
    ) -> Result<super::runtime::DelegationAccessReservation, NfsStatus> {
        self.finalize_detached_delegation_removals().await?;
        let reservation = self.runtime.begin_delegation_access(
            RuntimeFile { export_id, object },
            requesting_client,
            access,
            truncate,
        )?;
        self.recall_conflicting_delegations(export_id, object, requesting_client, access, truncate)
            .await?;
        Ok(reservation)
    }

    fn apply_replay_effect(
        &self,
        effect: ReplayEffect,
        current: &mut Option<ResolvedFileHandle>,
    ) -> Result<(), NfsStatus> {
        if let Some(file) = effect.current_file {
            self.export(file.export_id).ok_or(NfsStatus::Stale)?;
            *current = Some(self.backend_handle(file.export_id, file.object, None));
        }
        Ok(())
    }

    async fn create(&self, arguments: &CreateArgs, current: &mut Option<ResolvedFileHandle>) -> ResOp {
        let (export_id, parent) = match current_backend(current) {
            Ok(value) => value,
            Err(status) => return ResOp::Create(NfsResult::Err(status)),
        };
        let namespace_node = match current.as_ref().map(|handle| handle.target) {
            Some(ResolvedTarget::Backend { namespace_node, .. }) => namespace_node,
            _ => None,
        };
        let Some(export) = self.export(export_id) else {
            return ResOp::Create(NfsResult::Err(NfsStatus::Stale));
        };
        match self.backend_file_type(export_id, parent, OpNum::Create.code()).await {
            // RFC 7530 section 5.3 forbids CREATE in an NF4ATTRDIR.  OPEN
            // is the sole creation path for named attributes.
            Ok(FileType::AttributeDirectory) => return ResOp::Create(NfsResult::Err(NfsStatus::Invalid)),
            Ok(file_type) if file_type.is_directory() => {},
            Ok(FileType::Symlink) => return ResOp::Create(NfsResult::Err(NfsStatus::Symlink)),
            Ok(_) => return ResOp::Create(NfsResult::Err(NfsStatus::NotDirectory)),
            Err(status) => return ResOp::Create(NfsResult::Err(status)),
        }
        let name = match validate_component_name(&arguments.name) {
            Ok(name) => name,
            Err(status) => return ResOp::Create(NfsResult::Err(status)),
        };
        let engine = match self.attribute_engine_for_export(export) {
            Ok(engine) => engine,
            Err(status) => return ResOp::Create(NfsResult::Err(status)),
        };
        let mut decoded = match decode_set_attributes(&engine, &arguments.attributes) {
            Ok(decoded) => decoded,
            Err(status) => return ResOp::Create(NfsResult::Err(status)),
        };
        if let Err(status) = self.map_set_identities(&mut decoded).await {
            return ResOp::Create(NfsResult::Err(status));
        }
        if let Some(acl) = decoded.acl.take() {
            decoded.vfs.acl = match vfs_acl(acl) {
                Ok(acl) => Some(acl),
                Err(status) => return ResOp::Create(NfsResult::Err(status)),
            };
        }
        if decoded.vfs.size.is_some() {
            return ResOp::Create(NfsResult::Err(NfsStatus::Invalid));
        }
        let _gate = self.runtime.operation_gate((export_id, parent, name.as_bytes())).await;
        let context = self.context_for(export_id);
        let result = match &arguments.object_type {
            CreateType::Directory => export.vfs.mkdir(&context, parent, &name, decoded.vfs).await,
            CreateType::Symlink(target) => {
                if validate_symlink_target(target).is_err() {
                    return ResOp::Create(NfsResult::Err(NfsStatus::Invalid));
                }
                export.vfs.symlink(&context, parent, &name, target, decoded.vfs).await
            },
            CreateType::Block(device) => {
                export
                    .vfs
                    .mknod(
                        &context,
                        parent,
                        &name,
                        NodeType::BlockDevice {
                            major: device.major,
                            minor: device.minor,
                        },
                        decoded.vfs,
                    )
                    .await
            },
            CreateType::Character(device) => {
                export
                    .vfs
                    .mknod(
                        &context,
                        parent,
                        &name,
                        NodeType::CharacterDevice {
                            major: device.major,
                            minor: device.minor,
                        },
                        decoded.vfs,
                    )
                    .await
            },
            CreateType::Socket => export.vfs.mknod(&context, parent, &name, NodeType::Socket, decoded.vfs).await,
            CreateType::Fifo => export.vfs.mknod(&context, parent, &name, NodeType::Fifo, decoded.vfs).await,
            CreateType::Other(_) => return ResOp::Create(NfsResult::Err(NfsStatus::BadType)),
        };
        match result {
            Ok(result) => {
                let change_info = match required_change_info(result.change_info) {
                    Ok(change_info) => change_info,
                    Err(status) => return ResOp::Create(NfsResult::Err(status)),
                };
                *current = Some(self.backend_handle(export_id, result.value.object, namespace_node));
                ResOp::Create(NfsResult::Ok(CreateOk {
                    change_info,
                    attributes_set: decoded.requested,
                }))
            },
            Err(error) => ResOp::Create(NfsResult::Err(map_vfs_error_for_operation(OpNum::Create.code(), error))),
        }
    }

    async fn remove(&self, arguments: &RemoveArgs, current: &Option<ResolvedFileHandle>) -> ResOp {
        if let Err(status) = self.runtime.ensure_not_in_grace().await {
            return ResOp::Remove(NfsResult::Err(status));
        }
        let (export_id, parent) = match current_backend(current) {
            Ok(value) => value,
            Err(status) => return ResOp::Remove(NfsResult::Err(status)),
        };
        let Some(export) = self.export(export_id) else {
            return ResOp::Remove(NfsResult::Err(NfsStatus::Stale));
        };
        let name = match validate_component_name(&arguments.target) {
            Ok(name) => name,
            Err(status) => return ResOp::Remove(NfsResult::Err(status)),
        };
        let _gate = self.runtime.operation_gate((export_id, parent, name.as_bytes())).await;
        let context = self.context_for(export_id);
        let target = match export.vfs.lookup(&context, parent, &name).await {
            Ok(target) => target,
            Err(error) => {
                return ResOp::Remove(NfsResult::Err(map_vfs_error_for_operation(OpNum::Remove.code(), error)))
            },
        };
        let _delegation_access = match self
            .begin_delegation_access_and_recall(export_id, target.object, None, DelegationKind::Write, false)
            .await
        {
            Ok(reservation) => reservation,
            Err(status) => return ResOp::Remove(NfsResult::Err(status)),
        };
        let file_type = match target.attributes {
            Some(attributes) => attributes.file_type,
            None => match export.vfs.getattr(&context, target.object).await {
                Ok(attributes) => attributes.file_type,
                Err(error) => {
                    return ResOp::Remove(NfsResult::Err(map_vfs_error_for_operation(OpNum::Remove.code(), error)))
                },
            },
        };
        let result = if file_type.is_directory() {
            export.vfs.rmdir(&context, parent, &name).await
        } else {
            export.vfs.remove(&context, parent, &name).await
        };
        match result {
            Ok(result) => match required_change_info(result.change_info) {
                Ok(change_info) => ResOp::Remove(NfsResult::Ok(RemoveOk { change_info })),
                Err(status) => ResOp::Remove(NfsResult::Err(status)),
            },
            Err(error) => ResOp::Remove(NfsResult::Err(map_vfs_error_for_operation(OpNum::Remove.code(), error))),
        }
    }

    async fn link(
        &self,
        arguments: &LinkArgs,
        current: &Option<ResolvedFileHandle>,
        saved: &Option<ResolvedFileHandle>,
    ) -> ResOp {
        let (export_id, directory) = match current_backend(current) {
            Ok(value) => value,
            Err(status) => return ResOp::Link(NfsResult::Err(status)),
        };
        let (saved_export, object) = match saved_backend(saved) {
            Ok(value) => value,
            Err(status) => return ResOp::Link(NfsResult::Err(status)),
        };
        if export_id != saved_export {
            return ResOp::Link(NfsResult::Err(NfsStatus::CrossDevice));
        }
        let Some(export) = self.export(export_id) else {
            return ResOp::Link(NfsResult::Err(NfsStatus::Stale));
        };
        let context = self.context_for(export_id);
        let directory_file_type = match self.backend_file_type(export_id, directory, OpNum::Link.code()).await {
            Ok(file_type) if file_type.is_directory() => file_type,
            Ok(_) => return ResOp::Link(NfsResult::Err(NfsStatus::NotDirectory)),
            Err(status) => return ResOp::Link(NfsResult::Err(status)),
        };
        let object_file_type = match self.backend_file_type(saved_export, object, OpNum::Link.code()).await {
            Ok(file_type) => file_type,
            Err(status) => return ResOp::Link(NfsResult::Err(status)),
        };
        if directory_file_type == FileType::AttributeDirectory {
            if object_file_type != FileType::NamedAttribute {
                return ResOp::Link(NfsResult::Err(NfsStatus::CrossDevice));
            }
            return match export.vfs.nfs4_named_attribute_parent(&context, object).await {
                Ok(parent) if parent == directory => ResOp::Link(NfsResult::Err(NfsStatus::NotSupported)),
                Ok(_) => ResOp::Link(NfsResult::Err(NfsStatus::CrossDevice)),
                Err(error) => ResOp::Link(NfsResult::Err(map_vfs_error_for_operation(OpNum::Link.code(), error))),
            };
        }
        if object_file_type.is_named_attribute() {
            return ResOp::Link(NfsResult::Err(NfsStatus::CrossDevice));
        }
        if object_file_type.is_directory() {
            return ResOp::Link(NfsResult::Err(NfsStatus::IsDirectory));
        }
        let name = match validate_component_name(&arguments.new_name) {
            Ok(name) => name,
            Err(status) => return ResOp::Link(NfsResult::Err(status)),
        };
        let _gate = self.runtime.operation_gate((export_id, directory, name.as_bytes())).await;
        let _delegation_access = match self
            .begin_delegation_access_and_recall(export_id, object, None, DelegationKind::Write, false)
            .await
        {
            Ok(reservation) => reservation,
            Err(status) => return ResOp::Link(NfsResult::Err(status)),
        };
        match export.vfs.link(&context, object, directory, &name).await {
            Ok(result) => match required_change_info(result.change_info) {
                Ok(change_info) => ResOp::Link(NfsResult::Ok(LinkOk { change_info })),
                Err(status) => ResOp::Link(NfsResult::Err(status)),
            },
            Err(error) => ResOp::Link(NfsResult::Err(map_vfs_error_for_operation(OpNum::Link.code(), error))),
        }
    }

    async fn rename(
        &self,
        arguments: &RenameArgs,
        current: &Option<ResolvedFileHandle>,
        saved: &Option<ResolvedFileHandle>,
    ) -> ResOp {
        if let Err(status) = self.runtime.ensure_not_in_grace().await {
            return ResOp::Rename(NfsResult::Err(status));
        }
        let (target_export, target_parent) = match current_backend(current) {
            Ok(value) => value,
            Err(status) => return ResOp::Rename(NfsResult::Err(status)),
        };
        let (source_export, source_parent) = match saved_backend(saved) {
            Ok(value) => value,
            Err(status) => return ResOp::Rename(NfsResult::Err(status)),
        };
        if source_export != target_export {
            return ResOp::Rename(NfsResult::Err(NfsStatus::CrossDevice));
        }
        let Some(export) = self.export(source_export) else {
            return ResOp::Rename(NfsResult::Err(NfsStatus::Stale));
        };
        let source_file_type = match self.backend_file_type(source_export, source_parent, OpNum::Rename.code()).await {
            Ok(file_type) if file_type.is_directory() => file_type,
            Ok(_) => return ResOp::Rename(NfsResult::Err(NfsStatus::NotDirectory)),
            Err(status) => return ResOp::Rename(NfsResult::Err(status)),
        };
        let target_file_type = match self.backend_file_type(target_export, target_parent, OpNum::Rename.code()).await {
            Ok(file_type) if file_type.is_directory() => file_type,
            Ok(_) => return ResOp::Rename(NfsResult::Err(NfsStatus::NotDirectory)),
            Err(status) => return ResOp::Rename(NfsResult::Err(status)),
        };
        if (source_file_type == FileType::AttributeDirectory || target_file_type == FileType::AttributeDirectory)
            && (source_file_type != FileType::AttributeDirectory
                || target_file_type != FileType::AttributeDirectory
                || source_parent != target_parent)
        {
            return ResOp::Rename(NfsResult::Err(NfsStatus::CrossDevice));
        }
        let old_name = match validate_component_name(&arguments.old_name) {
            Ok(name) => name,
            Err(status) => return ResOp::Rename(NfsResult::Err(status)),
        };
        let new_name = match validate_component_name(&arguments.new_name) {
            Ok(name) => name,
            Err(status) => return ResOp::Rename(NfsResult::Err(status)),
        };
        let (_first, _second) = self
            .runtime
            .operation_gates(
                (source_export, source_parent, old_name.as_bytes()),
                (target_export, target_parent, new_name.as_bytes()),
            )
            .await;
        let context = self.context_for(source_export);
        let source_object = match export.vfs.lookup(&context, source_parent, &old_name).await {
            Ok(source) => source.object,
            Err(error) => {
                return ResOp::Rename(NfsResult::Err(map_vfs_error_for_operation(OpNum::Rename.code(), error)))
            },
        };
        let _source_delegation_access = match self
            .begin_delegation_access_and_recall(source_export, source_object, None, DelegationKind::Write, false)
            .await
        {
            Ok(reservation) => reservation,
            Err(status) => return ResOp::Rename(NfsResult::Err(status)),
        };
        let mut target_delegation_access = None;
        match export.vfs.lookup(&context, target_parent, &new_name).await {
            Ok(target) => {
                target_delegation_access = match self
                    .begin_delegation_access_and_recall(
                        target_export,
                        target.object,
                        None,
                        DelegationKind::Write,
                        false,
                    )
                    .await
                {
                    Ok(reservation) => Some(reservation),
                    Err(status) => return ResOp::Rename(NfsResult::Err(status)),
                };
            },
            Err(NfsError::NotFound) => {},
            Err(error) => {
                return ResOp::Rename(NfsResult::Err(map_vfs_error_for_operation(OpNum::Rename.code(), error)))
            },
        }
        let _target_delegation_access = target_delegation_access;
        match export
            .vfs
            .rename(&context, source_parent, &old_name, target_parent, &new_name)
            .await
        {
            Ok((source, target)) => {
                let source_change_info = match required_change_info(source.change_info) {
                    Ok(change_info) => change_info,
                    Err(status) => return ResOp::Rename(NfsResult::Err(status)),
                };
                let target_change_info = match required_change_info(target.change_info) {
                    Ok(change_info) => change_info,
                    Err(status) => return ResOp::Rename(NfsResult::Err(status)),
                };
                ResOp::Rename(NfsResult::Ok(RenameOk {
                    source_change_info,
                    target_change_info,
                }))
            },
            Err(error) => ResOp::Rename(NfsResult::Err(map_vfs_error_for_operation(OpNum::Rename.code(), error))),
        }
    }

    fn lookup_namespace_child(&self, parent: NamespaceNodeId, name: &[u8]) -> Result<NamespaceNodeId, NfsStatus> {
        self.namespace.lookup(parent, name).map_err(map_namespace_error)
    }

    async fn lookup_backend(
        &self,
        export_id: crate::vfs::ExportId,
        parent: ObjectKey,
        name: &NfsName,
        namespace_node: Option<NamespaceNodeId>,
    ) -> Result<ResolvedFileHandle, NfsStatus> {
        let export = self.export(export_id).ok_or(NfsStatus::Stale)?;
        let context = self.context_for(export_id);
        let object = export
            .vfs
            .lookup(&context, parent, name)
            .await
            .map_err(|error| map_vfs_error_for_operation(OpNum::Lookup.code(), error))?;
        Ok(self.backend_handle(export_id, object.object, namespace_node))
    }

    async fn lookup_overlay_child(
        &self,
        export_id: crate::vfs::ExportId,
        parent: ObjectKey,
        child: NamespaceNodeId,
        opcode: u32,
    ) -> Result<ResolvedFileHandle, NfsStatus> {
        let child_node = self.namespace.node(child).map_err(map_namespace_error)?;
        if child_node.export().is_some() {
            // A nested export mountpoint always shadows an identically named
            // object in the containing backend.
            return self.enter_namespace_node(child);
        }
        let export = self.export(export_id).ok_or(NfsStatus::Stale)?;
        let name =
            NfsName::new(child_node.name().to_vec()).map_err(|error| map_vfs_error_for_operation(opcode, error))?;
        let context = self.context_for(export_id);
        let created = match export.vfs.lookup(&context, parent, &name).await {
            Ok(created) => created,
            Err(NfsError::NotFound | NfsError::NotDirectory) => return Ok(self.pseudo_handle(child)),
            Err(error) => return Err(map_vfs_error_for_operation(opcode, error)),
        };
        let attributes = match created.attributes {
            Some(attributes) => attributes,
            None => export
                .vfs
                .getattr(&context, created.object)
                .await
                .map_err(|error| map_vfs_error_for_operation(opcode, error))?,
        };
        if !attributes.file_type.is_directory() {
            return Ok(self.pseudo_handle(child));
        }
        Ok(self.backend_handle(export_id, created.object, Some(child)))
    }

    async fn enter_overlay_node(&self, node: NamespaceNodeId, opcode: u32) -> Result<ResolvedFileHandle, NfsStatus> {
        let namespace_node = self.namespace.node(node).map_err(map_namespace_error)?;
        if namespace_node.export().is_some() {
            return self.enter_namespace_node(node);
        }
        let Some((export_id, _)) = self.namespace.backing_export(node).map_err(map_namespace_error)? else {
            return Ok(self.pseudo_handle(node));
        };
        match self.resolve_overlay_anchor(export_id, node, opcode).await? {
            Some(object) => Ok(self.backend_handle(export_id, object, Some(node))),
            None => Ok(self.pseudo_handle(node)),
        }
    }

    async fn is_overlay_anchor(
        &self,
        export_id: crate::vfs::ExportId,
        object: ObjectKey,
        route: NamespaceNodeId,
        opcode: u32,
    ) -> Result<bool, NfsStatus> {
        Ok(self.resolve_overlay_anchor(export_id, route, opcode).await? == Some(object))
    }

    async fn resolve_overlay_anchor(
        &self,
        export_id: crate::vfs::ExportId,
        route: NamespaceNodeId,
        opcode: u32,
    ) -> Result<Option<ObjectKey>, NfsStatus> {
        let Some((route_export, mountpoint)) = self.namespace.backing_export(route).map_err(map_namespace_error)?
        else {
            return Err(NfsStatus::BadHandle);
        };
        if route_export != export_id {
            return Err(NfsStatus::BadHandle);
        }
        let export = self.export(export_id).ok_or(NfsStatus::Stale)?;
        let context = self.context_for(export_id);
        let mut object = export.vfs.root();
        for component in self
            .namespace
            .relative_components(mountpoint, route)
            .map_err(map_namespace_error)?
        {
            let name = NfsName::new(component.to_vec()).map_err(|error| map_vfs_error_for_operation(opcode, error))?;
            let created = match export.vfs.lookup(&context, object, &name).await {
                Ok(created) => created,
                Err(NfsError::NotFound | NfsError::NotDirectory) => return Ok(None),
                Err(error) => return Err(map_vfs_error_for_operation(opcode, error)),
            };
            let attributes = match created.attributes {
                Some(attributes) => attributes,
                None => export
                    .vfs
                    .getattr(&context, created.object)
                    .await
                    .map_err(|error| map_vfs_error_for_operation(opcode, error))?,
            };
            if !attributes.file_type.is_directory() {
                return Ok(None);
            }
            object = created.object;
        }
        Ok(Some(object))
    }

    async fn attributes_for_current(
        &self,
        current: &Option<ResolvedFileHandle>,
        requested: &[u32],
        opcode: u32,
    ) -> Result<FileAttributes, NfsStatus> {
        if let Some(ResolvedFileHandle {
            target:
                ResolvedTarget::Backend {
                    export_id,
                    object,
                    namespace_node,
                },
            ..
        }) = current
        {
            if self.migration_status(*export_id) == MigrationGateStatus::Moved {
                if let Some(locations) = self.namespace_locations_for(*export_id) {
                    return self.encode_absent_attributes(
                        current.as_ref().expect("matched current filehandle"),
                        *export_id,
                        *object,
                        *namespace_node,
                        requested,
                        &locations,
                    );
                }
                return Err(NfsStatus::Moved);
            }
            if let Some(state) = self.filesystem_location_state(*export_id, *object, opcode).await? {
                match state {
                    Nfs4LocationState::Present(_) => {},
                    Nfs4LocationState::Absent(locations) | Nfs4LocationState::Moved(locations) => {
                        return self.encode_absent_attributes(
                            current.as_ref().expect("matched current filehandle"),
                            *export_id,
                            *object,
                            *namespace_node,
                            requested,
                            &locations,
                        );
                    },
                }
            }
        }
        let (engine, values) = self.attribute_view_for_current(current, requested, opcode).await?;
        engine.encode_getattr(requested, &values).map_err(|error| error.status())
    }

    async fn attribute_view_for_current(
        &self,
        current: &Option<ResolvedFileHandle>,
        requested: &[u32],
        opcode: u32,
    ) -> Result<(AttributeEngine, AttributeValues), NfsStatus> {
        let current = current.as_ref().ok_or(NfsStatus::NoFileHandle)?;
        match current.target {
            ResolvedTarget::Pseudo(node) => {
                let node = self.namespace.node(node).map_err(map_namespace_error)?;
                let links = u32::try_from(node.children().len()).unwrap_or(u32::MAX).saturating_add(2);
                let attributes = VfsFileAttributes {
                    file_type: FileType::Directory,
                    mode: 0o555,
                    links,
                    uid: 0,
                    gid: 0,
                    size: 0,
                    used: 0,
                    device: None,
                    fs_id: 0,
                    file_id: node.id().get(),
                    change_id: crate::vfs::ChangeId(node.id().get()),
                    access_time: crate::vfs::NfsTime {
                        seconds: 0,
                        nanoseconds: 0,
                    },
                    modify_time: crate::vfs::NfsTime {
                        seconds: 0,
                        nanoseconds: 0,
                    },
                    change_time: crate::vfs::NfsTime {
                        seconds: 0,
                        nanoseconds: 0,
                    },
                };
                let mut values = AttributeValues::from_vfs(
                    &attributes,
                    current.wire.clone(),
                    FsId { major: 0, minor: 0 },
                    VfsCapabilities::READ_ONLY,
                    self.lease_seconds,
                )
                .map_err(|error| error.status())?;
                values
                    .insert(FATTR4_FH_EXPIRE_TYPE, AttributeValue::U32(FH4_VOLATILE_ANY))
                    .map_err(|error| error.status())?;
                let engine =
                    AttributeEngine::from_attributes(pseudo_supported_attributes()).map_err(|error| error.status())?;
                Ok((engine, values))
            },
            ResolvedTarget::Backend {
                export_id,
                object,
                namespace_node,
            } => {
                let export = self.export(export_id).ok_or(NfsStatus::Stale)?;
                let context = self.context_for(export_id);
                let attributes = export
                    .vfs
                    .getattr(&context, object)
                    .await
                    .map_err(|error| map_vfs_error_for_operation(opcode, error))?;
                let capabilities = export.vfs.capabilities();
                let nfs4_capabilities = export.vfs.nfs4_capabilities().unwrap_or_default();
                let mounted_on_file_id = match namespace_node {
                    Some(route) if self.is_overlay_anchor(export_id, object, route, opcode).await? => route.get(),
                    _ => attributes.file_id,
                };
                let mut values = AttributeValues::from_vfs(
                    &attributes,
                    current.wire.clone(),
                    FsId {
                        major: export.fsid.major,
                        minor: export.fsid.minor,
                    },
                    capabilities,
                    self.lease_seconds,
                )
                .and_then(|mut values| {
                    values.insert(
                        FATTR4_FH_EXPIRE_TYPE,
                        AttributeValue::U32(match export.filehandle_policy {
                            FileHandlePolicy::Persistent => FH4_PERSISTENT,
                            FileHandlePolicy::Volatile => FH4_VOLATILE_ANY,
                        }),
                    )?;
                    values.insert(FATTR4_NAMED_ATTR, AttributeValue::Boolean(nfs4_capabilities.named_attributes))?;
                    values.insert(FATTR4_MOUNTED_ON_FILEID, AttributeValue::U64(mounted_on_file_id))?;
                    Ok(values)
                })
                .map_err(|error| error.status())?;

                let wants_supported = bitmap_contains(requested, FATTR4_SUPPORTED_ATTRS);
                if wants_any(requested, &[FATTR4_CHANGE, FATTR4_SIZE]) {
                    if let Some(manager) = self.delegations.get(&export_id) {
                        let delegated_requested =
                            bitmap_from_attributes([FATTR4_CHANGE, FATTR4_SIZE]).map_err(|_| NfsStatus::ServerFault)?;
                        if let Some((delegated, client_id)) =
                            manager.delegated_getattr(object, delegated_requested).await?
                        {
                            let client_status =
                                self.runtime.validate_client(client_id, &self.request_context.principal).await;
                            if client_status != NfsStatus::Ok {
                                return Err(client_status);
                            }
                            let (change, size) = decode_delegated_change_and_size(&delegated)?;
                            values
                                .insert(FATTR4_CHANGE, AttributeValue::U64(change))
                                .and_then(|_| values.insert(FATTR4_SIZE, AttributeValue::U64(size)))
                                .map_err(|error| error.status())?;
                        }
                    }
                }
                if wants_supported
                    || wants_any(
                        requested,
                        &[
                            FATTR4_FILES_AVAIL,
                            FATTR4_FILES_FREE,
                            FATTR4_FILES_TOTAL,
                            FATTR4_SPACE_AVAIL,
                            FATTR4_SPACE_FREE,
                            FATTR4_SPACE_TOTAL,
                        ],
                    )
                {
                    match export.vfs.fsstat(&context, object).await {
                        Ok(stat) => values.apply_fs_stat(&stat).map_err(|error| error.status())?,
                        Err(NfsError::NotSupported) => {},
                        Err(error) => return Err(map_vfs_error_for_operation(opcode, error)),
                    }
                }
                if wants_supported
                    || wants_any(requested, &[FATTR4_MAXFILESIZE, FATTR4_MAXREAD, FATTR4_MAXWRITE, FATTR4_TIME_DELTA])
                {
                    match export.vfs.fsinfo(&context, object).await {
                        Ok(info) => values.apply_fs_info(&info).map_err(|error| error.status())?,
                        Err(NfsError::NotSupported) => {},
                        Err(error) => return Err(map_vfs_error_for_operation(opcode, error)),
                    }
                }
                if wants_supported
                    || wants_any(
                        requested,
                        &[
                            FATTR4_CASE_INSENSITIVE,
                            FATTR4_CASE_PRESERVING,
                            FATTR4_CHOWN_RESTRICTED,
                            FATTR4_MAXLINK,
                            FATTR4_MAXNAME,
                            FATTR4_NO_TRUNC,
                        ],
                    )
                {
                    match export.vfs.pathconf(&context, object).await {
                        Ok(path_conf) => values.apply_path_conf(&path_conf).map_err(|error| error.status())?,
                        Err(NfsError::NotSupported) => {},
                        Err(error) => return Err(map_vfs_error_for_operation(opcode, error)),
                    }
                }
                if nfs4_capabilities.quotas
                    && (wants_supported
                        || wants_any(requested, &[FATTR4_QUOTA_AVAIL_HARD, FATTR4_QUOTA_AVAIL_SOFT, FATTR4_QUOTA_USED]))
                {
                    match export.vfs.nfs4_quota(&context, object).await {
                        Ok(quota) => {
                            values
                                .insert(FATTR4_QUOTA_USED, AttributeValue::U64(quota.used_bytes))
                                .map_err(|error| error.status())?;
                            if let Some(hard) = quota.hard_bytes {
                                values
                                    .insert(
                                        FATTR4_QUOTA_AVAIL_HARD,
                                        AttributeValue::U64(hard.saturating_sub(quota.used_bytes)),
                                    )
                                    .map_err(|error| error.status())?;
                            }
                            if let Some(soft) = quota.soft_bytes {
                                values
                                    .insert(
                                        FATTR4_QUOTA_AVAIL_SOFT,
                                        AttributeValue::U64(soft.saturating_sub(quota.used_bytes)),
                                    )
                                    .map_err(|error| error.status())?;
                            }
                        },
                        Err(NfsError::NotSupported) => {},
                        Err(error) => return Err(map_vfs_error_for_operation(opcode, error)),
                    }
                }
                if nfs4_capabilities.acls && (wants_supported || wants_any(requested, &[FATTR4_ACL, FATTR4_ACLSUPPORT]))
                {
                    values
                        .insert(FATTR4_ACLSUPPORT, AttributeValue::U32(0x0f))
                        .map_err(|error| error.status())?;
                    match export.vfs.nfs4_get_acl(&context, object).await {
                        Ok(acl) => {
                            values
                                .insert(FATTR4_ACL, AttributeValue::Acl(wire_acl(acl)))
                                .map_err(|error| error.status())?;
                        },
                        Err(NfsError::NotSupported) => {
                            values.remove(FATTR4_ACLSUPPORT);
                        },
                        Err(error) => return Err(map_vfs_error_for_operation(opcode, error)),
                    }
                }
                if let Some(mapper) = self.identity_mapper {
                    if wants_supported || wants_any(requested, &[FATTR4_OWNER, FATTR4_OWNER_GROUP]) {
                        if let Ok(owner) = mapper.uid_to_owner(attributes.uid).await {
                            values
                                .insert(FATTR4_OWNER, AttributeValue::String(owner.into_bytes()))
                                .map_err(|error| error.status())?;
                        }
                        if let Ok(group) = mapper.gid_to_group(attributes.gid).await {
                            values
                                .insert(FATTR4_OWNER_GROUP, AttributeValue::String(group.into_bytes()))
                                .map_err(|error| error.status())?;
                        }
                    }
                }
                let configured_locations = self.namespace_locations_for(export_id);
                if (nfs4_capabilities.fs_locations || configured_locations.is_some())
                    && (wants_supported || bitmap_contains(requested, FATTR4_FS_LOCATIONS))
                {
                    let dynamic = if nfs4_capabilities.fs_locations {
                        match self.filesystem_location_state(export_id, object, opcode).await? {
                            Some(Nfs4LocationState::Present(locations))
                            | Some(Nfs4LocationState::Absent(locations))
                            | Some(Nfs4LocationState::Moved(locations)) => Some(locations),
                            None => None,
                        }
                    } else {
                        None
                    };
                    if let Some(locations) = dynamic.as_ref().or(configured_locations.as_ref()) {
                        values.apply_fs_locations(locations).map_err(|error| error.status())?;
                    }
                }

                let engine = AttributeEngine::from_attributes(backend_supported_attributes(
                    capabilities,
                    nfs4_capabilities,
                    self.identity_mapper.is_some(),
                    configured_locations.is_some(),
                ))
                .map_err(|error| error.status())?;
                Ok((engine, values))
            },
        }
    }

    async fn compare_attributes(
        &self,
        current: &Option<ResolvedFileHandle>,
        expected: &FileAttributes,
        opcode: u32,
    ) -> Result<bool, NfsStatus> {
        if let Some(file) = current.as_ref().and_then(ResolvedFileHandle::runtime_file) {
            let absent = self.migration_status(file.export_id) == MigrationGateStatus::Moved
                || matches!(
                    self.filesystem_location_state(file.export_id, file.object, opcode).await?,
                    Some(Nfs4LocationState::Absent(_) | Nfs4LocationState::Moved(_))
                );
            if absent {
                let actual = self.attributes_for_current(current, &expected.mask, opcode).await?;
                return Ok(bitmaps_equal(&actual.mask, &expected.mask) && actual.values == expected.values);
            }
        }
        let (engine, values) = self.attribute_view_for_current(current, &expected.mask, opcode).await?;
        engine.compare(expected, &values).map_err(|error| error.status())
    }

    fn resolve_wire_handle(&self, wire: &NfsFileHandle) -> Result<ResolvedFileHandle, NfsStatus> {
        let (target, imported) = match self.handles.decode_target(wire.as_bytes()) {
            Ok(target) => (target, false),
            Err(primary_error) => match self
                .migration
                .and_then(|migration| migration.imported_handles().decode_any(wire.as_bytes()))
            {
                Some(Ok(target)) => (target, true),
                Some(Err(imported_error)) => {
                    return Err(map_handle_error(prefer_handle_error(primary_error, imported_error)));
                },
                None => return Err(map_handle_error(primary_error)),
            },
        };
        let resolved = match target {
            HandleTarget::Pseudo { namespace_node } => {
                let node = self.namespace_node_by_raw(namespace_node).ok_or(NfsStatus::BadHandle)?;
                ResolvedTarget::Pseudo(node)
            },
            HandleTarget::Backend {
                export_id,
                object,
                namespace_node,
            } => {
                let export = self.export(export_id).ok_or(NfsStatus::Stale)?;
                if imported && export.filehandle_policy != FileHandlePolicy::Persistent {
                    return Err(NfsStatus::BadHandle);
                }
                let namespace_node = namespace_node
                    .map(|raw| self.namespace_node_by_raw(raw).ok_or(NfsStatus::BadHandle))
                    .transpose()?;
                if let Some(node) = namespace_node {
                    let route_export = self
                        .namespace
                        .backing_export(node)
                        .map_err(map_namespace_error)?
                        .map(|(route_export, _)| route_export);
                    if route_export != Some(export_id) {
                        return Err(NfsStatus::BadHandle);
                    }
                }
                ResolvedTarget::Backend {
                    export_id,
                    object,
                    namespace_node,
                }
            },
        };
        Ok(ResolvedFileHandle {
            wire: wire.clone(),
            target: resolved,
        })
    }

    fn enter_namespace_node(&self, node: NamespaceNodeId) -> Result<ResolvedFileHandle, NfsStatus> {
        let namespace_node = self.namespace.node(node).map_err(map_namespace_error)?;
        if let Some(export_id) = namespace_node.export() {
            let export = self.export(export_id).ok_or(NfsStatus::Stale)?;
            Ok(self.backend_handle(export_id, export.vfs.root(), Some(node)))
        } else {
            Ok(self.pseudo_handle(node))
        }
    }

    fn pseudo_handle(&self, node: NamespaceNodeId) -> ResolvedFileHandle {
        ResolvedFileHandle {
            wire: NfsFileHandle(
                self.handles
                    .encode_target(HandleTarget::Pseudo {
                        namespace_node: node.get(),
                    })
                    .expect("pseudo handles always use the logical-server codec")
                    .to_vec(),
            ),
            target: ResolvedTarget::Pseudo(node),
        }
    }

    fn backend_handle(
        &self,
        export_id: crate::vfs::ExportId,
        object: ObjectKey,
        namespace_node: Option<NamespaceNodeId>,
    ) -> ResolvedFileHandle {
        ResolvedFileHandle {
            wire: NfsFileHandle(
                self.handles
                    .encode_target(HandleTarget::Backend {
                        export_id,
                        object,
                        namespace_node: namespace_node.map(NamespaceNodeId::get),
                    })
                    .expect("backend export has a configured filehandle lifetime")
                    .to_vec(),
            ),
            target: ResolvedTarget::Backend {
                export_id,
                object,
                namespace_node,
            },
        }
    }

    fn namespace_node_by_raw(&self, raw: u64) -> Option<NamespaceNodeId> {
        self.walk_namespace().find(|node| node.get() == raw)
    }

    fn namespace_node_for_export(&self, export_id: crate::vfs::ExportId) -> Option<NamespaceNodeId> {
        self.walk_namespace()
            .find(|node| self.namespace.node(*node).is_ok_and(|node| node.export() == Some(export_id)))
    }

    fn walk_namespace(&self) -> impl Iterator<Item = NamespaceNodeId> + '_ {
        let mut pending = vec![NamespaceNodeId::ROOT];
        std::iter::from_fn(move || {
            let node = pending.pop()?;
            if let Ok(node) = self.namespace.node(node) {
                pending.extend(node.children().map(|(_, child)| child));
            }
            Some(node)
        })
    }

    fn export(&self, export_id: crate::vfs::ExportId) -> Option<&ExportState> {
        self.exports.iter().find(|export| export.id == export_id)
    }

    async fn backend_file_type(
        &self,
        export_id: crate::vfs::ExportId,
        object: ObjectKey,
        opcode: u32,
    ) -> Result<FileType, NfsStatus> {
        let export = self.export(export_id).ok_or(NfsStatus::Stale)?;
        export
            .vfs
            .getattr(&self.context_for(export_id), object)
            .await
            .map(|attributes| attributes.file_type)
            .map_err(|error| map_vfs_error_for_operation(opcode, error))
    }

    fn handle_security_status(&self, handle: &ResolvedFileHandle) -> NfsStatus {
        let ResolvedTarget::Backend { export_id, .. } = handle.target else {
            return NfsStatus::Ok;
        };
        match self.export(export_id) {
            Some(export) if policy_allows(&export.security_policy, &self.request_context.principal) => NfsStatus::Ok,
            Some(_) => NfsStatus::WrongSecurity,
            None => NfsStatus::Stale,
        }
    }

    fn attribute_engine_for_export(&self, export: &ExportState) -> Result<AttributeEngine, NfsStatus> {
        AttributeEngine::from_attributes(backend_supported_attributes(
            export.vfs.capabilities(),
            export.vfs.nfs4_capabilities().unwrap_or_default(),
            self.identity_mapper.is_some(),
            self.has_namespace_locations(export.id),
        ))
        .map_err(|error| error.status())
    }

    async fn map_set_identities(&self, decoded: &mut DecodedSetAttributes) -> Result<(), NfsStatus> {
        if decoded.owner.is_none() && decoded.owner_group.is_none() {
            return Ok(());
        }
        if decoded.owner.as_ref().is_some_and(Vec::is_empty) || decoded.owner_group.as_ref().is_some_and(Vec::is_empty)
        {
            return Err(NfsStatus::Invalid);
        }
        let mapper = self.identity_mapper.ok_or(NfsStatus::AttributeNotSupported)?;
        if let Some(owner) = decoded.owner.take() {
            let owner = std::str::from_utf8(&owner).map_err(|_| NfsStatus::BadOwner)?;
            decoded.vfs.uid = Some(mapper.owner_to_uid(owner).await.map_err(map_identity_error)?);
        }
        if let Some(group) = decoded.owner_group.take() {
            let group = std::str::from_utf8(&group).map_err(|_| NfsStatus::BadOwner)?;
            decoded.vfs.gid = Some(mapper.group_to_gid(group).await.map_err(map_identity_error)?);
        }
        Ok(())
    }

    async fn open_request(
        &self,
        export: &ExportState,
        how: &OpenHow,
        share_access: u32,
    ) -> Result<(Nfs4OpenRequest, Bitmap), NfsStatus> {
        let engine = self.attribute_engine_for_export(export)?;
        let access = vfs_open_access(share_access)?;
        match how {
            OpenHow::NoCreate => Ok((
                Nfs4OpenRequest {
                    access,
                    create: None,
                    truncate_existing: false,
                },
                Vec::new(),
            )),
            OpenHow::Create(CreateHow::Unchecked(attributes)) => {
                let mut decoded = decode_set_attributes(&engine, attributes)?;
                self.map_set_identities(&mut decoded).await?;
                if let Some(acl) = decoded.acl.take() {
                    decoded.vfs.acl = Some(vfs_acl(acl)?);
                }
                let truncate_existing = decoded.vfs.size == Some(0);
                Ok((
                    Nfs4OpenRequest {
                        access,
                        create: Some(Nfs4OpenCreate {
                            attributes: decoded.vfs,
                            mode: VfsCreateMode::Unchecked,
                        }),
                        truncate_existing,
                    },
                    decoded.requested,
                ))
            },
            OpenHow::Create(CreateHow::Guarded(attributes)) => {
                let mut decoded = decode_set_attributes(&engine, attributes)?;
                self.map_set_identities(&mut decoded).await?;
                if let Some(acl) = decoded.acl.take() {
                    decoded.vfs.acl = Some(vfs_acl(acl)?);
                }
                Ok((
                    Nfs4OpenRequest {
                        access,
                        create: Some(Nfs4OpenCreate {
                            attributes: decoded.vfs,
                            mode: VfsCreateMode::Guarded,
                        }),
                        truncate_existing: false,
                    },
                    decoded.requested,
                ))
            },
            OpenHow::Create(CreateHow::Exclusive(verifier)) => Ok((
                Nfs4OpenRequest {
                    access,
                    create: Some(Nfs4OpenCreate {
                        attributes: VfsSetAttributes::default(),
                        mode: VfsCreateMode::Exclusive { verifier: *verifier },
                    }),
                    truncate_existing: false,
                },
                Vec::new(),
            )),
        }
    }

    fn context_for(&self, export_id: crate::vfs::ExportId) -> RequestContext {
        let mut context = self.request_context.clone();
        context.export_id = export_id;
        context
    }

    fn migration_status(&self, export_id: crate::vfs::ExportId) -> MigrationGateStatus {
        self.migration
            .map(MigrationControl::gate)
            .map_or(MigrationGateStatus::Active, |gate| gate.status(export_id))
    }

    fn namespace_locations_for(&self, export_id: crate::vfs::ExportId) -> Option<Nfs4FsLocations> {
        self.migration
            .and_then(|migration| migration.locations(export_id))
            .or_else(|| self.namespace_locations.get(&export_id).cloned())
    }

    fn has_namespace_locations(&self, export_id: crate::vfs::ExportId) -> bool {
        self.namespace_locations_for(export_id).is_some()
    }

    async fn filesystem_location_state(
        &self,
        export_id: crate::vfs::ExportId,
        object: ObjectKey,
        opcode: u32,
    ) -> Result<Option<Nfs4LocationState>, NfsStatus> {
        let export = self.export(export_id).ok_or(NfsStatus::Stale)?;
        if !export
            .vfs
            .nfs4_capabilities()
            .is_some_and(|capabilities| capabilities.fs_locations)
        {
            return Ok(None);
        }
        let context = self.context_for(export_id);
        match export.vfs.nfs4_location_state(&context, object).await {
            Ok(state) => validate_location_state(export_id, state).map(Some),
            Err(NfsError::NotSupported) => Ok(None),
            Err(error) => Err(map_vfs_error_for_operation(opcode, error)),
        }
    }

    async fn location_status_for_operation(
        &self,
        operation: &ArgOp,
        current: &Option<ResolvedFileHandle>,
    ) -> Result<(), NfsStatus> {
        if !operation_uses_current_handle(operation) {
            return Ok(());
        }
        let Some(RuntimeFile { export_id, object }) = current.as_ref().and_then(ResolvedFileHandle::runtime_file)
        else {
            return Ok(());
        };
        let Some(state) = self.filesystem_location_state(export_id, object, operation.opcode()).await? else {
            return Ok(());
        };
        if matches!(state, Nfs4LocationState::Present(_)) || operation_allows_absent_attributes(operation) {
            Ok(())
        } else {
            Err(NfsStatus::Moved)
        }
    }

    async fn moved_notification_status(&self, operation: &ArgOp, current: &Option<ResolvedFileHandle>) -> NfsStatus {
        let Some(export_id) = current.as_ref().and_then(ResolvedFileHandle::export_id) else {
            return NfsStatus::Moved;
        };
        let Some(client_id) = self.operation_client_id(operation, current).await else {
            return NfsStatus::Moved;
        };
        match self
            .runtime
            .note_moved_export(client_id, export_id, &self.request_context.principal)
            .await
        {
            Ok(()) => NfsStatus::Moved,
            // A stale/invalid state reference must not supersede the
            // start-of-operation absent-filesystem check.
            Err(NfsStatus::Resource) => NfsStatus::Resource,
            Err(_) => NfsStatus::Moved,
        }
    }

    async fn operation_client_id(&self, operation: &ArgOp, current: &Option<ResolvedFileHandle>) -> Option<u64> {
        let direct = match operation {
            ArgOp::DelegPurge(arguments) => Some(arguments.client_id),
            ArgOp::LockTest(arguments) => Some(arguments.owner.client_id),
            ArgOp::Open(arguments) => Some(arguments.owner.client_id),
            ArgOp::ReleaseLockOwner(arguments) => Some(arguments.lock_owner.client_id),
            ArgOp::Renew(arguments) => Some(arguments.client_id),
            _ => None,
        };
        if direct.is_some() {
            return direct;
        }

        let state_id = match operation {
            ArgOp::Close(arguments) => Some(arguments.open_state_id),
            ArgOp::DelegReturn(arguments) => Some(arguments.delegation_state_id),
            ArgOp::Lock(arguments) => Some(match &arguments.locker {
                Locker::New(locker) => locker.open_state_id,
                Locker::Existing(locker) => locker.lock_state_id,
            }),
            ArgOp::LockUnlock(arguments) => Some(arguments.lock_state_id),
            ArgOp::OpenConfirm(arguments) => Some(arguments.open_state_id),
            ArgOp::OpenDowngrade(arguments) => Some(arguments.open_state_id),
            ArgOp::Read(arguments) => Some(arguments.state_id),
            ArgOp::SetAttr(arguments) => Some(arguments.state_id),
            ArgOp::Write(arguments) => Some(arguments.state_id),
            _ => None,
        }?;
        let file = current.as_ref().and_then(ResolvedFileHandle::runtime_file)?;
        self.runtime
            .identify_stateid_client(state_id, file, &self.request_context.principal)
            .await
            .ok()
            .flatten()
    }

    fn encode_absent_attributes(
        &self,
        handle: &ResolvedFileHandle,
        export_id: crate::vfs::ExportId,
        object: ObjectKey,
        namespace_node: Option<NamespaceNodeId>,
        requested: &[u32],
        locations: &Nfs4FsLocations,
    ) -> Result<FileAttributes, NfsStatus> {
        if !bitmap_contains(requested, FATTR4_FS_LOCATIONS) {
            return Err(NfsStatus::Moved);
        }
        let export = self.export(export_id).ok_or(NfsStatus::Stale)?;
        let restricted = bitmap_from_attributes(
            [FATTR4_FSID, FATTR4_FS_LOCATIONS, FATTR4_MOUNTED_ON_FILEID]
                .into_iter()
                .filter(|attribute| bitmap_contains(requested, *attribute)),
        )
        .map_err(|_| NfsStatus::ServerFault)?;
        let placeholder = VfsFileAttributes {
            file_type: FileType::Directory,
            mode: 0,
            links: 1,
            uid: 0,
            gid: 0,
            size: 0,
            used: 0,
            device: None,
            fs_id: export.fsid.minor,
            file_id: object.file_id,
            change_id: crate::vfs::ChangeId(0),
            access_time: crate::vfs::NfsTime::default(),
            modify_time: crate::vfs::NfsTime::default(),
            change_time: crate::vfs::NfsTime::default(),
        };
        let mut values = AttributeValues::from_vfs(
            &placeholder,
            handle.wire.clone(),
            FsId {
                major: export.fsid.major,
                minor: export.fsid.minor,
            },
            VfsCapabilities::READ_ONLY,
            self.lease_seconds,
        )
        .map_err(|error| error.status())?;
        values
            .insert(
                FATTR4_MOUNTED_ON_FILEID,
                AttributeValue::U64(namespace_node.map(NamespaceNodeId::get).unwrap_or(object.file_id)),
            )
            .and_then(|_| values.apply_fs_locations(locations))
            .map_err(|error| error.status())?;
        let engine = AttributeEngine::from_attributes(backend_supported_attributes(
            VfsCapabilities::READ_ONLY,
            crate::vfs::Nfs4Capabilities {
                fs_locations: true,
                ..crate::vfs::Nfs4Capabilities::READ_ONLY
            },
            false,
            true,
        ))
        .map_err(|error| error.status())?;
        engine.encode_getattr(&restricted, &values).map_err(|error| error.status())
    }

    async fn stabilize_unstable_writes(
        &self,
        writes: &HashSet<(RuntimeFile, Option<u64>)>,
        next_operation: u32,
    ) -> Result<(), NfsStatus> {
        for (file, client_id) in writes {
            let export = self.export(file.export_id).ok_or(NfsStatus::Stale)?;
            let mut context = self.context_for(file.export_id);
            context.client_id = *client_id;
            export
                .vfs
                .nfs4_stabilize_mutation(&context, file.object)
                .await
                .map_err(|error| map_vfs_error_for_operation(next_operation, error))?;
        }
        Ok(())
    }

    async fn validate_io_stateid(
        &self,
        state_id: super::types::StateId,
        file: RuntimeFile,
        access: IoAccess,
        offset: u64,
        length: u64,
    ) -> Result<super::runtime::IoPermit, NfsStatus> {
        if matches!(state_id, super::types::ANONYMOUS_STATE_ID | super::types::READ_BYPASS_STATE_ID) {
            return self
                .runtime
                .validate_io(state_id, file, access, offset, length, &self.request_context.principal)
                .await;
        }
        // Keep delegation expiry from interleaving with successful non-special
        // stateid validation and RFC 7530 section 9.5's all-export renewal.
        let fences = self.delegation_renewal_fences().await;
        self.revoke_expired_delegations_while_fenced(&fences).await?;
        let result = match self
            .runtime
            .validate_io_with_identity(state_id, file, access, offset, length, &self.request_context.principal)
            .await
        {
            Ok(permit) => {
                if let Some(client_id) = permit.client_id {
                    self.renew_delegations_while_fenced(&fences, client_id, ClientLeaseRenewal::StateId)
                        .await?;
                }
                Ok(permit)
            },
            Err(error) if error.client_id.is_some() => {
                self.renew_delegations_while_fenced(
                    &fences,
                    error.client_id.expect("authenticated I/O error carries a client"),
                    ClientLeaseRenewal::StateId,
                )
                .await?;
                Err(error.status)
            },
            Err(
                error @ super::runtime::IoValidationError {
                    status: NfsStatus::BadStateId | NfsStatus::StaleStateId,
                    client_id: None,
                },
            ) => {
                let status = error.status;
                let Some(manager) = self.delegations.get(&file.export_id) else {
                    return Err(status);
                };
                if !manager.owns_stateid_namespace(state_id) {
                    return Err(status);
                }
                let context = self.context_for(file.export_id);
                let kind = match access {
                    IoAccess::Read => DelegationKind::Read,
                    IoAccess::Write | IoAccess::SetSize => DelegationKind::Write,
                };
                let client_id = manager
                    .validate_io_delegation_while_fenced(&context, file.object, state_id, kind)
                    .await?;
                let renewal = self
                    .renew_client_across_delegations_while_fenced(&fences, client_id, ClientLeaseRenewal::StateId)
                    .await?;
                if renewal.runtime_status != NfsStatus::Ok {
                    return Err(renewal.runtime_status);
                }
                self.runtime.reserve_delegation_io(file, client_id, access).await
            },
            Err(error) => Err(error.status),
        };
        if result.is_ok() {
            drop(fences);
            self.finalize_detached_delegation_removals().await?;
        }
        result
    }

    /// Validates the optional stateid on a SETATTR that does not change file
    /// size.  Special stateids retain their RFC-defined bypass meaning.  RFC
    /// 7530 sections 9.1.4.4 and 9.1.4.6 otherwise allow only delegation
    /// stateids here: open and lock stateids must be rejected.
    async fn validate_non_size_setattr_stateid(
        &self,
        state_id: super::types::StateId,
        file: RuntimeFile,
    ) -> Result<Option<u64>, NfsStatus> {
        match self
            .runtime
            .identify_stateid_client(state_id, file, &self.request_context.principal)
            .await
        {
            Ok(Some(_)) => Err(NfsStatus::BadStateId),
            Ok(None) => Ok(None),
            Err(_) if self.runtime.owns_open_or_lock_stateid_namespace(state_id) => Err(NfsStatus::BadStateId),
            Err(status @ (NfsStatus::BadStateId | NfsStatus::StaleStateId)) => {
                let Some(manager) = self.delegations.get(&file.export_id) else {
                    return Err(status);
                };
                if !manager.owns_stateid_namespace(state_id) {
                    return Err(status);
                }
                // A valid delegation stateid is a lease-renewing operation.
                // Lock every manager in a stable order so revocation cannot
                // race the RFC 7530 section 9.5 all-export renewal.
                let fences = self.delegation_renewal_fences().await;
                self.revoke_expired_delegations_while_fenced(&fences).await?;
                let context = self.context_for(file.export_id);
                let client_id = manager
                    .validate_setattr_delegation_while_fenced(&context, file.object, state_id)
                    .await?;
                let renewal = self
                    .renew_client_across_delegations_while_fenced(&fences, client_id, ClientLeaseRenewal::StateId)
                    .await?;
                let result = if renewal.runtime_status != NfsStatus::Ok {
                    Err(renewal.runtime_status)
                } else {
                    Ok(Some(client_id))
                };
                if result.is_ok() {
                    drop(fences);
                    self.finalize_detached_delegation_removals().await?;
                }
                result
            },
            Err(status) => Err(status),
        }
    }
}

fn operation_digest(operation: &ArgOp) -> OwnerRequestDigest {
    let encoded = encode_compound_args(&CompoundArgs {
        tag: Vec::new(),
        minor_version: 0,
        operations: vec![operation.clone()],
    })
    .unwrap_or_else(|_| format!("{operation:?}").into_bytes());
    OwnerRequestDigest(Sha256::digest(encoded).into())
}

fn vfs_open_access(share_access: u32) -> Result<Nfs4OpenAccess, NfsStatus> {
    match share_access {
        OPEN4_SHARE_ACCESS_READ => Ok(Nfs4OpenAccess::Read),
        OPEN4_SHARE_ACCESS_WRITE => Ok(Nfs4OpenAccess::Write),
        OPEN4_SHARE_ACCESS_BOTH => Ok(Nfs4OpenAccess::ReadWrite),
        _ => Err(NfsStatus::Invalid),
    }
}

fn delegation_kind_for_share(share_access: u32) -> DelegationKind {
    if share_access & OPEN4_SHARE_ACCESS_WRITE != 0 {
        DelegationKind::Write
    } else {
        DelegationKind::Read
    }
}

fn wire_delegation(grant: &DelegationGrant, requested_space: u64) -> OpenDelegation {
    const ACE4_ACCESS_ALLOWED_ACE_TYPE: u32 = 0;
    const GENERIC_READ: u32 = 0x0012_0081;
    const GENERIC_WRITE: u32 = 0x0016_0106;
    let permissions = NfsAce {
        ace_type: ACE4_ACCESS_ALLOWED_ACE_TYPE,
        flags: 0,
        access_mask: match grant.kind {
            DelegationKind::Read => GENERIC_READ,
            DelegationKind::Write => GENERIC_READ | GENERIC_WRITE,
        },
        who: b"OWNER@".to_vec(),
    };
    match grant.kind {
        DelegationKind::Read => OpenDelegation::Read(OpenReadDelegation {
            state_id: grant.state_id,
            recall: false,
            permissions,
        }),
        DelegationKind::Write => OpenDelegation::Write(OpenWriteDelegation {
            state_id: grant.state_id,
            recall: false,
            space_limit: SpaceLimit::Size(requested_space),
            permissions,
        }),
    }
}

fn operation_uses_current_handle(operation: &ArgOp) -> bool {
    !matches!(
        operation,
        ArgOp::DelegPurge(_)
            | ArgOp::Illegal { .. }
            | ArgOp::PutFh(_)
            | ArgOp::PutPublicFh
            | ArgOp::PutRootFh
            | ArgOp::ReleaseLockOwner(_)
            | ArgOp::Renew(_)
            | ArgOp::RestoreFh
            | ArgOp::SetClientId(_)
            | ArgOp::SetClientIdConfirm(_)
    )
}

fn operation_mutates_export(operation: &ArgOp) -> bool {
    matches!(
        operation,
        ArgOp::Close(_)
            | ArgOp::Commit(_)
            | ArgOp::Create(_)
            | ArgOp::DelegReturn(_)
            | ArgOp::Link(_)
            | ArgOp::Lock(_)
            | ArgOp::LockUnlock(_)
            | ArgOp::Open(_)
            | ArgOp::OpenConfirm(_)
            | ArgOp::OpenDowngrade(_)
            | ArgOp::Remove(_)
            | ArgOp::Rename(_)
            | ArgOp::SetAttr(_)
            | ArgOp::Write(_)
    ) || matches!(operation, ArgOp::OpenAttr(OpenAttrArgs { create_directory: true }))
}

fn operation_has_side_effects(operation: &ArgOp) -> bool {
    operation_mutates_export(operation)
        || matches!(
            operation,
            ArgOp::DelegPurge(_)
                | ArgOp::ReleaseLockOwner(_)
                | ArgOp::Renew(_)
                | ArgOp::SetClientId(_)
                | ArgOp::SetClientIdConfirm(_)
        )
}

fn operation_allows_absent_attributes(operation: &ArgOp) -> bool {
    const ALLOWED: [u32; 3] = [FATTR4_FSID, FATTR4_FS_LOCATIONS, FATTR4_MOUNTED_ON_FILEID];
    match operation {
        ArgOp::GetAttr(arguments) => bitmap_contains(&arguments.requested_attributes, FATTR4_FS_LOCATIONS),
        ArgOp::Verify(arguments) => {
            bitmap_contains(&arguments.attributes.mask, FATTR4_FS_LOCATIONS)
                && bitmap_subset_of(&arguments.attributes.mask, &ALLOWED)
        },
        ArgOp::NotVerify(arguments) => {
            bitmap_contains(&arguments.attributes.mask, FATTR4_FS_LOCATIONS)
                && bitmap_subset_of(&arguments.attributes.mask, &ALLOWED)
        },
        _ => false,
    }
}

fn bitmap_subset_of(bitmap: &[u32], allowed: &[u32]) -> bool {
    attribute_numbers(bitmap).all(|attribute| allowed.contains(&attribute))
}

fn operation_requires_prior_stability(operation: &ArgOp) -> bool {
    match operation {
        ArgOp::Commit(_)
        | ArgOp::Create(_)
        | ArgOp::Link(_)
        | ArgOp::Open(_)
        | ArgOp::Remove(_)
        | ArgOp::Rename(_)
        | ArgOp::SetAttr(_) => true,
        ArgOp::OpenAttr(arguments) => arguments.create_directory,
        ArgOp::Write(arguments) => arguments.stability != StableHow::Unstable,
        _ => false,
    }
}

fn operation_error(operation: &ArgOp, status: NfsStatus) -> ResOp {
    match operation {
        ArgOp::Access(_) => ResOp::Access(NfsResult::Err(status)),
        ArgOp::Close(_) => ResOp::Close(NfsResult::Err(status)),
        ArgOp::Commit(_) => ResOp::Commit(NfsResult::Err(status)),
        ArgOp::Create(_) => ResOp::Create(NfsResult::Err(status)),
        ArgOp::DelegPurge(_) => ResOp::DelegPurge(status),
        ArgOp::DelegReturn(_) => ResOp::DelegReturn(status),
        ArgOp::GetAttr(_) => ResOp::GetAttr(NfsResult::Err(status)),
        ArgOp::GetFh => ResOp::GetFh(NfsResult::Err(status)),
        ArgOp::Link(_) => ResOp::Link(NfsResult::Err(status)),
        ArgOp::Lock(_) => ResOp::Lock(super::types::LockResult::Err(status)),
        ArgOp::LockTest(_) => ResOp::LockTest(super::types::LockTestResult::Err(status)),
        ArgOp::LockUnlock(_) => ResOp::LockUnlock(NfsResult::Err(status)),
        ArgOp::Lookup(_) => ResOp::Lookup(status),
        ArgOp::LookupParent => ResOp::LookupParent(status),
        ArgOp::NotVerify(_) => ResOp::NotVerify(status),
        ArgOp::Open(_) => ResOp::Open(NfsResult::Err(status)),
        ArgOp::OpenAttr(_) => ResOp::OpenAttr(status),
        ArgOp::OpenConfirm(_) => ResOp::OpenConfirm(NfsResult::Err(status)),
        ArgOp::OpenDowngrade(_) => ResOp::OpenDowngrade(NfsResult::Err(status)),
        ArgOp::PutFh(_) => ResOp::PutFh(status),
        ArgOp::PutPublicFh => ResOp::PutPublicFh(status),
        ArgOp::PutRootFh => ResOp::PutRootFh(status),
        ArgOp::Read(_) => ResOp::Read(NfsResult::Err(status)),
        ArgOp::ReadDir(_) => ResOp::ReadDir(NfsResult::Err(status)),
        ArgOp::ReadLink => ResOp::ReadLink(NfsResult::Err(status)),
        ArgOp::Remove(_) => ResOp::Remove(NfsResult::Err(status)),
        ArgOp::Rename(_) => ResOp::Rename(NfsResult::Err(status)),
        ArgOp::Renew(_) => ResOp::Renew(status),
        ArgOp::RestoreFh => ResOp::RestoreFh(status),
        ArgOp::SaveFh => ResOp::SaveFh(status),
        ArgOp::SecInfo(_) => ResOp::SecInfo(NfsResult::Err(status)),
        ArgOp::SetAttr(_) => setattr_error(status),
        ArgOp::SetClientId(_) => ResOp::SetClientId(super::types::SetClientIdResult::Err(status)),
        ArgOp::SetClientIdConfirm(_) => ResOp::SetClientIdConfirm(status),
        ArgOp::Verify(_) => ResOp::Verify(status),
        ArgOp::Write(_) => ResOp::Write(NfsResult::Err(status)),
        ArgOp::ReleaseLockOwner(_) => ResOp::ReleaseLockOwner(status),
        ArgOp::Illegal { .. } => ResOp::Illegal(status),
    }
}

fn normalize_operation_result(operation: &ArgOp, result: ResOp) -> ResOp {
    if is_legal_operation_status(operation.opcode(), result.status()) {
        return result;
    }
    let fallback = if is_legal_operation_status(operation.opcode(), NfsStatus::ServerFault) {
        NfsStatus::ServerFault
    } else {
        NfsStatus::OperationIllegal
    };
    operation_error(operation, fallback)
}

fn decode_set_attributes(
    engine: &AttributeEngine,
    attributes: &FileAttributes,
) -> Result<DecodedSetAttributes, NfsStatus> {
    engine.decode_setattr(attributes).map_err(|error| error.status())
}

fn current_backend(current: &Option<ResolvedFileHandle>) -> Result<(crate::vfs::ExportId, ObjectKey), NfsStatus> {
    let current = current.as_ref().ok_or(NfsStatus::NoFileHandle)?;
    match current.target {
        ResolvedTarget::Backend { export_id, object, .. } => Ok((export_id, object)),
        ResolvedTarget::Pseudo(_) => Err(NfsStatus::ReadOnly),
    }
}

fn saved_backend(saved: &Option<ResolvedFileHandle>) -> Result<(crate::vfs::ExportId, ObjectKey), NfsStatus> {
    let saved = saved.as_ref().ok_or(NfsStatus::NoFileHandle)?;
    match saved.target {
        ResolvedTarget::Backend { export_id, object, .. } => Ok((export_id, object)),
        ResolvedTarget::Pseudo(_) => Err(NfsStatus::ReadOnly),
    }
}

fn current_runtime_file(current: &Option<ResolvedFileHandle>) -> Result<RuntimeFile, NfsStatus> {
    let (export_id, object) = current_backend(current)?;
    Ok(RuntimeFile { export_id, object })
}

fn required_change_info(info: Option<crate::vfs::ChangeInfo>) -> Result<ChangeInfo, NfsStatus> {
    info.map(|info| ChangeInfo {
        atomic: info.atomic,
        before: info.before.0,
        after: info.after.0,
    })
    .ok_or(NfsStatus::ServerFault)
}

fn validate_open_preflight_change(info: crate::vfs::ChangeInfo) -> Result<(), NfsStatus> {
    if info.atomic && info.before == info.after {
        Ok(())
    } else {
        Err(NfsStatus::ServerFault)
    }
}

fn empty_change_info() -> ChangeInfo {
    ChangeInfo {
        atomic: false,
        before: 0,
        after: 0,
    }
}

fn setattr_error(status: NfsStatus) -> ResOp {
    ResOp::SetAttr(SetAttrResult {
        status,
        attributes_set: Vec::new(),
    })
}

const fn map_write_stability(stability: StableHow) -> VfsWriteStability {
    match stability {
        StableHow::Unstable => VfsWriteStability::Unstable,
        StableHow::DataSync => VfsWriteStability::DataSync,
        StableHow::FileSync => VfsWriteStability::FileSync,
    }
}

const fn map_vfs_write_stability(stability: VfsWriteStability) -> StableHow {
    match stability {
        VfsWriteStability::Unstable => StableHow::Unstable,
        VfsWriteStability::DataSync => StableHow::DataSync,
        VfsWriteStability::FileSync => StableHow::FileSync,
    }
}

fn policy_allows(policy: &crate::server::SecurityPolicy, principal: &crate::vfs::Principal) -> bool {
    policy.flavors().iter().any(|flavor| match (flavor, principal) {
        (RpcSecurityFlavor::AuthNone, crate::vfs::Principal::Anonymous)
        | (RpcSecurityFlavor::AuthSys, crate::vfs::Principal::AuthSys { .. }) => true,
        (
            RpcSecurityFlavor::RpcSecGss {
                mechanism,
                qop,
                service,
            },
            crate::vfs::Principal::Gss {
                mechanism: principal_mechanism,
                service: principal_service,
                ..
            },
        ) => {
            let expected = match principal_service {
                crate::vfs::GssService::Authentication => ConfigGssService::None,
                crate::vfs::GssService::Integrity => ConfigGssService::Integrity,
                crate::vfs::GssService::Privacy => ConfigGssService::Privacy,
                crate::vfs::GssService::ChannelProtection => ConfigGssService::ChannelProtection,
            };
            *qop == 0 && mechanism == principal_mechanism && *service == expected
        },
        _ => false,
    })
}

fn security_info_for_exports(exports: &[ExportState]) -> Vec<SecurityInfo> {
    let mut result = Vec::new();
    for export in exports {
        for value in security_info_for_policy(&export.security_policy) {
            if !result.contains(&value) {
                result.push(value);
            }
        }
    }
    result
}

fn security_info_for_policy(policy: &crate::server::SecurityPolicy) -> Vec<SecurityInfo> {
    policy
        .flavors()
        .iter()
        .map(|flavor| match flavor {
            RpcSecurityFlavor::AuthNone => SecurityInfo::Other(0),
            RpcSecurityFlavor::AuthSys => SecurityInfo::Other(1),
            RpcSecurityFlavor::RpcSecGss {
                mechanism,
                qop,
                service,
            } => SecurityInfo::RpcSecGss(RpcSecGssInfo {
                oid: mechanism.clone(),
                qop: *qop,
                service: match service {
                    ConfigGssService::None => RpcGssService::None,
                    ConfigGssService::Integrity => RpcGssService::Integrity,
                    ConfigGssService::Privacy => RpcGssService::Privacy,
                    ConfigGssService::ChannelProtection => RpcGssService::ChannelProtection,
                },
            }),
        })
        .collect()
}

fn pseudo_directory_verifier(instance_id: [u8; 8], node: &super::namespace::NamespaceNode) -> [u8; 8] {
    let mut hash = Sha256::new();
    hash.update(b"nfsembed/nfs4/pseudo-readdir");
    hash.update(instance_id);
    hash.update(node.id().get().to_be_bytes());
    for (name, child) in node.children() {
        hash.update((name.len() as u64).to_be_bytes());
        hash.update(name);
        hash.update(child.get().to_be_bytes());
    }
    hash.finalize()[..8].try_into().expect("SHA-256 has eight bytes")
}

fn xor_verifier(left: [u8; 8], right: [u8; 8]) -> [u8; 8] {
    std::array::from_fn(|index| left[index] ^ right[index])
}

fn encode_overlay_backend_cookie(cookie: u64) -> Result<u64, NfsStatus> {
    if cookie <= 2 {
        return Err(NfsStatus::ServerFault);
    }
    if cookie & BACKEND_COOKIE_FLAG != 0 {
        return Err(NfsStatus::Resource);
    }
    Ok(BACKEND_COOKIE_FLAG | cookie)
}

fn validate_overlay_backend_page(
    page: &crate::vfs::ReadDirectoryPage,
    requested_cookie: u64,
    hint: usize,
) -> Result<u64, NfsStatus> {
    if page.entries.len() > hint {
        return Err(NfsStatus::Resource);
    }
    if page.entries.is_empty() {
        return if page.eof {
            Ok(requested_cookie)
        } else {
            Err(NfsStatus::ServerFault)
        };
    }
    let mut previous_cookie = requested_cookie;
    for entry in &page.entries {
        if matches!(entry.name.as_bytes(), b"." | b"..") || entry.cookie <= 2 || entry.cookie <= previous_cookie {
            return Err(NfsStatus::ServerFault);
        }
        if entry.cookie & BACKEND_COOKIE_FLAG != 0 {
            return Err(NfsStatus::Resource);
        }
        previous_cookie = entry.cookie;
    }
    Ok(previous_cookie)
}

fn rdattr_error(requested: &[u32], status: NfsStatus) -> Option<FileAttributes> {
    if !bitmap_contains(requested, FATTR4_RDATTR_ERROR) {
        return None;
    }
    let mut encoder = AttributeEncoder::new();
    encoder.push_status(FATTR4_RDATTR_ERROR, status).ok()?;
    Some(encoder.finish())
}

fn decode_delegated_change_and_size(attributes: &FileAttributes) -> Result<(u64, u64), NfsStatus> {
    if !bitmap_contains(&attributes.mask, FATTR4_CHANGE) || !bitmap_contains(&attributes.mask, FATTR4_SIZE) {
        return Err(NfsStatus::ServerFault);
    }
    let mut decoder = crate::rpc::codec::Decoder::new(&attributes.values);
    let mut change = None;
    let mut size = None;
    for attribute in attribute_numbers(&attributes.mask) {
        match attribute {
            FATTR4_CHANGE => change = Some(decoder.read_u64().map_err(|_| NfsStatus::ServerFault)?),
            FATTR4_SIZE => size = Some(decoder.read_u64().map_err(|_| NfsStatus::ServerFault)?),
            _ => return Err(NfsStatus::ServerFault),
        }
    }
    decoder.finish().map_err(|_| NfsStatus::ServerFault)?;
    Ok((change.ok_or(NfsStatus::ServerFault)?, size.ok_or(NfsStatus::ServerFault)?))
}

fn directory_entry_name_size(entry: &DirectoryEntry) -> usize {
    8 + 4 + xdr_padded_size(entry.name.len())
}

fn directory_entry_wire_size(entry: &DirectoryEntry) -> usize {
    [
        4, // linked-list entry-present boolean
        8, // cookie
        4,
        xdr_padded_size(entry.name.len()),
        4,
        entry.attributes.mask.len().saturating_mul(4),
        4,
        xdr_padded_size(entry.attributes.values.len()),
    ]
    .into_iter()
    .try_fold(0usize, usize::checked_add)
    .unwrap_or(usize::MAX)
}

fn xdr_padded_size(length: usize) -> usize {
    length.saturating_add(3) & !3
}

fn read_dir_result_size(value: &ReadDirOk) -> usize {
    encode_compound_res(&CompoundRes::from_operations(Vec::new(), vec![ResOp::ReadDir(NfsResult::Ok(value.clone()))]))
        // Strip COMPOUND status/tag/opcount (12 bytes), opcode (4), and
        // READDIR status (4). maxcount covers READDIR4resok itself.
        .map(|encoded| encoded.len().saturating_sub(20))
        .unwrap_or(usize::MAX)
}

#[derive(Clone, Debug)]
struct ResolvedFileHandle {
    wire: NfsFileHandle,
    target: ResolvedTarget,
}

impl ResolvedFileHandle {
    fn export_id(&self) -> Option<crate::vfs::ExportId> {
        match self.target {
            ResolvedTarget::Pseudo(_) => None,
            ResolvedTarget::Backend { export_id, .. } => Some(export_id),
        }
    }

    fn runtime_file(&self) -> Option<RuntimeFile> {
        match self.target {
            ResolvedTarget::Pseudo(_) => None,
            ResolvedTarget::Backend { export_id, object, .. } => Some(RuntimeFile { export_id, object }),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum ResolvedTarget {
    Pseudo(NamespaceNodeId),
    Backend {
        export_id: crate::vfs::ExportId,
        object: ObjectKey,
        namespace_node: Option<NamespaceNodeId>,
    },
}

fn pseudo_supported_attributes() -> Vec<u32> {
    let mut supported: Vec<_> = attribute_numbers(&required_attribute_bitmap()).collect();
    supported.extend([
        FATTR4_FILEID,
        FATTR4_MODE,
        FATTR4_NUMLINKS,
        FATTR4_RAWDEV,
        FATTR4_SPACE_USED,
        FATTR4_TIME_ACCESS,
        FATTR4_TIME_METADATA,
        FATTR4_TIME_MODIFY,
        FATTR4_MOUNTED_ON_FILEID,
    ]);
    supported
}

fn backend_supported_attributes(
    capabilities: VfsCapabilities,
    nfs4_capabilities: crate::vfs::Nfs4Capabilities,
    has_identity_mapper: bool,
    has_configured_locations: bool,
) -> Vec<u32> {
    let mut supported = pseudo_supported_attributes();
    supported.extend([
        FATTR4_CASE_INSENSITIVE,
        FATTR4_CASE_PRESERVING,
        FATTR4_CHOWN_RESTRICTED,
        FATTR4_FILES_AVAIL,
        FATTR4_FILES_FREE,
        FATTR4_FILES_TOTAL,
        FATTR4_HOMOGENEOUS,
        FATTR4_MAXFILESIZE,
        FATTR4_MAXLINK,
        FATTR4_MAXNAME,
        FATTR4_MAXREAD,
        FATTR4_MAXWRITE,
        FATTR4_NO_TRUNC,
        FATTR4_SPACE_AVAIL,
        FATTR4_SPACE_FREE,
        FATTR4_SPACE_TOTAL,
        FATTR4_TIME_DELTA,
    ]);
    if capabilities.can_set_time {
        supported.extend([FATTR4_CANSETTIME, FATTR4_TIME_ACCESS_SET, FATTR4_TIME_MODIFY_SET]);
    }
    if has_identity_mapper {
        supported.extend([FATTR4_OWNER, FATTR4_OWNER_GROUP]);
    }
    if nfs4_capabilities.acls {
        supported.extend([FATTR4_ACL, FATTR4_ACLSUPPORT]);
    }
    if nfs4_capabilities.quotas {
        supported.extend([FATTR4_QUOTA_AVAIL_HARD, FATTR4_QUOTA_AVAIL_SOFT, FATTR4_QUOTA_USED]);
    }
    if nfs4_capabilities.fs_locations || has_configured_locations {
        supported.push(FATTR4_FS_LOCATIONS);
    }
    supported.sort_unstable();
    supported.dedup();
    supported
}

fn wants_any(requested: &[u32], attributes: &[u32]) -> bool {
    attributes.iter().any(|attribute| bitmap_contains(requested, *attribute))
}

fn validate_location_state(
    export_id: crate::vfs::ExportId,
    state: Nfs4LocationState,
) -> Result<Nfs4LocationState, NfsStatus> {
    let (locations, purpose) = match &state {
        Nfs4LocationState::Present(locations) => (locations, LocationPurpose::Replica),
        Nfs4LocationState::Absent(locations) => (locations, LocationPurpose::ReferralTarget),
        Nfs4LocationState::Moved(locations) => (locations, LocationPurpose::MigrationTarget),
    };
    let purposes = vec![purpose; locations.locations.len()];
    let mut registry = LocationRegistry::new(LocationRegistryLimits::default()).map_err(map_location_registry_error)?;
    registry
        .insert(export_id, FileSystemLocationRecord::new(state.clone(), purposes, PlacementMigrationStatus::None))
        .map_err(map_location_registry_error)?;
    Ok(state)
}

fn map_location_registry_error(error: LocationRegistryError) -> NfsStatus {
    match error {
        LocationRegistryError::InvalidLimits
        | LocationRegistryError::DuplicateExport(_)
        | LocationRegistryError::UnknownExport(_)
        | LocationRegistryError::PurposeCount
        | LocationRegistryError::AbsentWithoutLocations
        | LocationRegistryError::LocationWithoutServers
        | LocationRegistryError::InvalidServerName
        | LocationRegistryError::InvalidPathComponent
        | LocationRegistryError::LocationOrdering
        | LocationRegistryError::PurposeInconsistentWithPresence
        | LocationRegistryError::MigrationInconsistentWithPresence
        | LocationRegistryError::InvalidMigrationTransition { .. } => NfsStatus::ServerFault,
        LocationRegistryError::FilesystemCapacity
        | LocationRegistryError::AdvertisedBytesCapacity
        | LocationRegistryError::AdvertisedBytesPerFilesystem
        | LocationRegistryError::TooManyLocations
        | LocationRegistryError::TooManyServers
        | LocationRegistryError::ServerNameTooLong
        | LocationRegistryError::TooManyPathComponents => NfsStatus::Resource,
    }
}

fn wire_acl(acl: VfsNfs4Acl) -> Vec<super::types::NfsAce> {
    acl.entries
        .into_iter()
        .map(|entry| super::types::NfsAce {
            ace_type: match entry.ace_type {
                VfsNfs4AceType::Allow => 0,
                VfsNfs4AceType::Deny => 1,
                VfsNfs4AceType::Audit => 2,
                VfsNfs4AceType::Alarm => 3,
            },
            flags: entry.flags,
            access_mask: entry.mask,
            who: entry.who.into_bytes(),
        })
        .collect()
}

fn vfs_acl(acl: Vec<super::types::NfsAce>) -> Result<VfsNfs4Acl, NfsStatus> {
    acl.into_iter()
        .map(|entry| {
            Ok(VfsNfs4Ace {
                ace_type: match entry.ace_type {
                    0 => VfsNfs4AceType::Allow,
                    1 => VfsNfs4AceType::Deny,
                    2 => VfsNfs4AceType::Audit,
                    3 => VfsNfs4AceType::Alarm,
                    _ => return Err(NfsStatus::Invalid),
                },
                flags: entry.flags,
                mask: entry.access_mask,
                who: String::from_utf8(entry.who).map_err(|_| NfsStatus::BadCharacter)?,
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|entries| VfsNfs4Acl { entries })
}

fn validate_component_name(value: &[u8]) -> Result<NfsName, NfsStatus> {
    if value.len() > NfsName::MAX_LEN {
        return Err(NfsStatus::NameTooLong);
    }
    if value.is_empty() {
        return Err(NfsStatus::Invalid);
    }
    if std::str::from_utf8(value).is_err() {
        return Err(NfsStatus::Invalid);
    }
    if matches!(value, b"." | b"..") || value.contains(&b'/') {
        return Err(NfsStatus::BadName);
    }
    if value.contains(&0) {
        return Err(NfsStatus::BadCharacter);
    }
    NfsName::new(value.to_vec()).map_err(map_vfs_error)
}

fn validate_lookup_name(value: &[u8]) -> Result<NfsName, NfsStatus> {
    validate_component_name(value)
}

fn validate_symlink_target(value: &[u8]) -> Result<(), NfsStatus> {
    if value.is_empty() || value.contains(&0) || std::str::from_utf8(value).is_err() {
        return Err(NfsStatus::Invalid);
    }
    Ok(())
}

const fn meaningful_access_mask(file_type: FileType, requested: u32) -> u32 {
    if file_type.is_directory() {
        requested & !ACCESS4_EXECUTE
    } else {
        requested & !(ACCESS4_LOOKUP | ACCESS4_DELETE)
    }
}

const fn open_file_type_status(file_type: FileType) -> NfsStatus {
    if file_type.is_regular() {
        NfsStatus::Ok
    } else if file_type.is_directory() {
        NfsStatus::IsDirectory
    } else {
        NfsStatus::Symlink
    }
}

fn map_handle_error(error: HandleError) -> NfsStatus {
    match error {
        HandleError::StaleInstance => NfsStatus::Stale,
        _ => NfsStatus::BadHandle,
    }
}

fn prefer_handle_error(left: HandleError, right: HandleError) -> HandleError {
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

fn map_namespace_error(error: NamespaceError) -> NfsStatus {
    match error {
        NamespaceError::NotFound | NamespaceError::RootParent => NfsStatus::NotFound,
        NamespaceError::InvalidCookie => NfsStatus::BadCookie,
        NamespaceError::CookieOverflow => NfsStatus::Resource,
        NamespaceError::InvalidComponent | NamespaceError::InvalidPath => NfsStatus::BadName,
        NamespaceError::UnknownNode => NfsStatus::BadHandle,
        NamespaceError::InvalidLimit
        | NamespaceError::Capacity
        | NamespaceError::DuplicateExportPath
        | NamespaceError::NotDescendant
        | NamespaceError::PathTooLong => NfsStatus::ServerFault,
    }
}

fn map_identity_error(error: IdentityMappingError) -> NfsStatus {
    match error {
        IdentityMappingError::Unmapped | IdentityMappingError::Invalid => NfsStatus::BadOwner,
        IdentityMappingError::Unavailable(_) | IdentityMappingError::Other(_) => NfsStatus::ServerFault,
    }
}

fn map_vfs_error(error: NfsError) -> NfsStatus {
    match error {
        NfsError::Permission => NfsStatus::Permission,
        NfsError::NotFound => NfsStatus::NotFound,
        NfsError::Io => NfsStatus::Io,
        NfsError::NoDeviceOrAddress | NfsError::NoDevice => NfsStatus::NoDeviceOrAddress,
        NfsError::Access => NfsStatus::Access,
        NfsError::Exists => NfsStatus::Exists,
        NfsError::CrossDevice => NfsStatus::CrossDevice,
        NfsError::NotDirectory => NfsStatus::NotDirectory,
        NfsError::IsDirectory => NfsStatus::IsDirectory,
        NfsError::Invalid => NfsStatus::Invalid,
        NfsError::FileTooLarge => NfsStatus::FileTooLarge,
        NfsError::NoSpace => NfsStatus::NoSpace,
        NfsError::ReadOnly => NfsStatus::ReadOnly,
        NfsError::TooManyLinks => NfsStatus::TooManyLinks,
        NfsError::NameTooLong => NfsStatus::NameTooLong,
        NfsError::NotEmpty => NfsStatus::NotEmpty,
        NfsError::Quota => NfsStatus::Quota,
        NfsError::Stale => NfsStatus::Stale,
        NfsError::Remote => NfsStatus::Moved,
        NfsError::NotSynchronized => NfsStatus::Io,
        NfsError::BadCookie => NfsStatus::BadCookie,
        NfsError::NotSupported => NfsStatus::NotSupported,
        NfsError::TooSmall => NfsStatus::TooSmall,
        NfsError::ServerFault => NfsStatus::ServerFault,
        NfsError::BadType => NfsStatus::BadType,
        NfsError::Jukebox => NfsStatus::Delay,
    }
}

/// Maps a protocol-neutral backend error to the closest semantic status that
/// RFC 7530 permits for the operation. Backends should not need to know that,
/// for example, WRITE permits ACCESS but not PERM, or that READLINK expresses
/// a wrong object type as INVAL rather than BADTYPE.
fn map_vfs_error_for_operation(opcode: u32, error: NfsError) -> NfsStatus {
    // A protocol-neutral backend reports the target's actual type. RENAME's
    // RFC 7530 error union does not include NFS4ERR_ISDIR for replacing a
    // directory with a non-directory, but it does permit NFS4ERR_EXIST.
    if opcode == OpNum::Rename.code() && error == NfsError::IsDirectory {
        return NfsStatus::Exists;
    }
    // RFC 7530 Section 16.16 requires OPEN to report every existing
    // non-regular, non-directory target as NFS4ERR_SYMLINK.  BADTYPE and
    // INVAL are explicitly inappropriate for this case, even for sockets,
    // FIFOs, and device nodes.
    if opcode == OpNum::Open.code() && error == NfsError::BadType {
        return NfsStatus::Symlink;
    }
    let canonical = map_vfs_error(error);
    let alternatives: &[NfsStatus] = match error {
        NfsError::Permission | NfsError::Access => &[NfsStatus::Access, NfsStatus::Permission],
        NfsError::NoDeviceOrAddress | NfsError::NoDevice => {
            &[NfsStatus::NoDeviceOrAddress, NfsStatus::Invalid, NfsStatus::Io]
        },
        NfsError::NotDirectory => &[NfsStatus::NotDirectory, NfsStatus::Invalid],
        NfsError::IsDirectory => &[NfsStatus::IsDirectory, NfsStatus::Invalid],
        NfsError::BadType => &[
            NfsStatus::BadType,
            NfsStatus::Invalid,
            NfsStatus::IsDirectory,
            NfsStatus::NotDirectory,
        ],
        NfsError::NotSynchronized => &[NfsStatus::Io, NfsStatus::NotSame, NfsStatus::Invalid],
        NfsError::BadCookie => &[NfsStatus::BadCookie, NfsStatus::NotSame, NfsStatus::Invalid],
        NfsError::NotSupported => &[
            NfsStatus::NotSupported,
            NfsStatus::AttributeNotSupported,
            NfsStatus::Invalid,
        ],
        NfsError::TooSmall => &[NfsStatus::TooSmall, NfsStatus::Resource],
        _ => &[],
    };
    std::iter::once(canonical)
        .chain(alternatives.iter().copied())
        .find(|status| is_legal_operation_status(opcode, *status))
        .unwrap_or(NfsStatus::ServerFault)
}

fn attribute_numbers(bitmap: &[u32]) -> impl Iterator<Item = u32> + '_ {
    bitmap.iter().enumerate().flat_map(|(word_index, word)| {
        let mut remaining = *word;
        std::iter::from_fn(move || {
            if remaining == 0 {
                return None;
            }
            let bit = remaining.trailing_zeros();
            remaining &= !(1 << bit);
            let base = u32::try_from(word_index).ok()?.checked_mul(32)?;
            base.checked_add(bit)
        })
    })
}

fn bitmaps_equal(left: &[u32], right: &[u32]) -> bool {
    let left_len = left.iter().rposition(|word| *word != 0).map_or(0, |index| index + 1);
    let right_len = right.iter().rposition(|word| *word != 0).map_or(0, |index| index + 1);
    left[..left_len] == right[..right_len]
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;

    use super::*;
    use crate::handles::{HandleCodec, HandleLifetime};
    use crate::nfs4::callback::CallbackClock;
    use crate::nfs4::runtime::RuntimeConfig;
    use crate::nfs4::stable::{BootRecord, PreviousShutdown, RecoveredStableState};
    use crate::nfs4::state::lease::ManualLeaseClock;
    use crate::nfs4::types::{FATTR4_FILEHANDLE, FATTR4_SIZE, FATTR4_TYPE, OPEN4_SHARE_DENY_WRITE};
    use crate::nfs4::ANONYMOUS_STATE_ID;
    use crate::server::{FileHandlePolicy, FileSystemId, Nfs4Limits, SecurityPolicy};
    use crate::vfs::{
        CreatedObject, DelegationEligibility, DelegationRequest, DelegationReservation,
        DirectoryEntry as VfsDirectoryEntry, ExportId, MutationResult, Nfs4Capabilities, Nfs4FsLocation,
        Nfs4OpenPreflight, NfsTime, Principal, ProtocolVersion, ReadDirectoryPage, ReadResult, SetAttributes,
        VfsCapabilities, VirtualFileSystem, WriteResult, WriteStability,
    };

    const ROOT: ObjectKey = ObjectKey {
        file_id: 10,
        generation: 1,
    };
    const FILE: ObjectKey = ObjectKey {
        file_id: 2,
        generation: 1,
    };
    const LINK: ObjectKey = ObjectKey {
        file_id: 3,
        generation: 1,
    };
    const CREATED_DIRECTORY: ObjectKey = ObjectKey {
        file_id: 4,
        generation: 1,
    };
    const ATTRIBUTE_DIRECTORY: ObjectKey = ObjectKey {
        file_id: 5,
        generation: 1,
    };
    const NAMED_ATTRIBUTE: ObjectKey = ObjectKey {
        file_id: 6,
        generation: 1,
    };

    #[derive(Default)]
    struct ManualCallbackClock {
        seconds: AtomicU64,
    }

    impl ManualCallbackClock {
        fn advance(&self, duration: Duration) {
            self.seconds.fetch_add(duration.as_secs(), Ordering::Relaxed);
        }
    }

    #[async_trait]
    impl CallbackClock for ManualCallbackClock {
        fn now(&self) -> Duration {
            Duration::from_secs(self.seconds.load(Ordering::Relaxed))
        }

        async fn sleep(&self, duration: Duration) {
            self.advance(duration);
        }
    }

    struct TestVfs {
        getattr_calls: AtomicUsize,
        commit_calls: AtomicUsize,
        setattr_calls: AtomicUsize,
        open_preflight_calls: AtomicUsize,
        open_calls: AtomicUsize,
        open_error: AtomicU8,
        file_generation: AtomicU64,
        replace_after_preflight: AtomicU8,
        truncate_calls: AtomicUsize,
        release_calls: AtomicUsize,
        delegation_release_calls: AtomicUsize,
        delegation_release_failures: AtomicUsize,
        delegation_release_block: AtomicU8,
        delegation_release_started: tokio::sync::Notify,
        delegation_release_continue: tokio::sync::Notify,
        remove_calls: AtomicUsize,
        rename_calls: AtomicUsize,
        location_state: AtomicU8,
        change_info_enabled: AtomicU8,
        write_committed: AtomicU8,
        write_count: AtomicUsize,
        write_calls: AtomicUsize,
        zero_length_write_checks: AtomicUsize,
        zero_length_write_error: AtomicU8,
        root_change: AtomicU64,
        stabilized_client_id: AtomicU64,
        named_attributes: AtomicU8,
    }

    impl TestVfs {
        fn new() -> Self {
            Self {
                getattr_calls: AtomicUsize::new(0),
                commit_calls: AtomicUsize::new(0),
                setattr_calls: AtomicUsize::new(0),
                open_preflight_calls: AtomicUsize::new(0),
                open_calls: AtomicUsize::new(0),
                open_error: AtomicU8::new(0),
                file_generation: AtomicU64::new(FILE.generation),
                replace_after_preflight: AtomicU8::new(0),
                truncate_calls: AtomicUsize::new(0),
                release_calls: AtomicUsize::new(0),
                delegation_release_calls: AtomicUsize::new(0),
                delegation_release_failures: AtomicUsize::new(0),
                delegation_release_block: AtomicU8::new(0),
                delegation_release_started: tokio::sync::Notify::new(),
                delegation_release_continue: tokio::sync::Notify::new(),
                remove_calls: AtomicUsize::new(0),
                rename_calls: AtomicUsize::new(0),
                location_state: AtomicU8::new(0),
                change_info_enabled: AtomicU8::new(1),
                write_committed: AtomicU8::new(0),
                write_count: AtomicUsize::new(usize::MAX),
                write_calls: AtomicUsize::new(0),
                zero_length_write_checks: AtomicUsize::new(0),
                zero_length_write_error: AtomicU8::new(0),
                root_change: AtomicU64::new(100),
                stabilized_client_id: AtomicU64::new(u64::MAX),
                named_attributes: AtomicU8::new(0),
            }
        }

        fn attributes(&self, object: ObjectKey) -> Result<VfsFileAttributes, NfsError> {
            let (file_type, mode, size) = match object.file_id {
                10 => (FileType::Directory, 0o755, 0),
                2 => (FileType::Regular, 0o640, 6),
                3 => (FileType::Symlink, 0o777, 6),
                4 => (FileType::Directory, 0o755, 0),
                5 => (FileType::AttributeDirectory, 0o755, 0),
                6 => (FileType::NamedAttribute, 0o600, 6),
                _ => return Err(NfsError::Stale),
            };
            Ok(VfsFileAttributes {
                file_type,
                mode,
                links: if object.file_id == ROOT.file_id { 2 } else { 1 },
                uid: 1000,
                gid: 100,
                size,
                used: size,
                device: None,
                fs_id: 77,
                file_id: object.file_id,
                change_id: if object.file_id == ROOT.file_id {
                    self.root_change.load(Ordering::Relaxed).into()
                } else {
                    (object.file_id * 10).into()
                },
                access_time: NfsTime {
                    seconds: 100,
                    nanoseconds: 1,
                },
                modify_time: NfsTime {
                    seconds: 200,
                    nanoseconds: 2,
                },
                change_time: NfsTime {
                    seconds: 300,
                    nanoseconds: 3,
                },
            })
        }

        fn change_info(&self, before: u64, after: u64) -> Option<crate::vfs::ChangeInfo> {
            (self.change_info_enabled.load(Ordering::Relaxed) != 0).then_some(crate::vfs::ChangeInfo {
                atomic: true,
                before: before.into(),
                after: after.into(),
            })
        }

        fn open_change_info(&self, before: u64, after: u64) -> crate::vfs::ChangeInfo {
            self.change_info(before, after).unwrap_or(crate::vfs::ChangeInfo {
                atomic: false,
                before: before.into(),
                after: after.into(),
            })
        }
    }

    #[async_trait]
    impl VirtualFileSystem for TestVfs {
        fn capabilities(&self) -> VfsCapabilities {
            VfsCapabilities::READ_WRITE
        }

        fn nfs4_capabilities(&self) -> Option<Nfs4Capabilities> {
            let mut capabilities = Nfs4Capabilities::READ_WRITE;
            capabilities.fs_locations = self.location_state.load(Ordering::Relaxed) != 0;
            capabilities.delegations = true;
            capabilities.named_attributes = self.named_attributes.load(Ordering::Relaxed) != 0;
            Some(capabilities)
        }

        fn root(&self) -> ObjectKey {
            ROOT
        }

        async fn getattr(&self, _context: &RequestContext, object: ObjectKey) -> Result<VfsFileAttributes, NfsError> {
            self.getattr_calls.fetch_add(1, Ordering::Relaxed);
            self.attributes(object)
        }

        async fn lookup(
            &self,
            _context: &RequestContext,
            parent: ObjectKey,
            name: &NfsName,
        ) -> Result<CreatedObject, NfsError> {
            let object = match parent {
                ROOT => match name.as_bytes() {
                    b"file" => ObjectKey {
                        file_id: FILE.file_id,
                        generation: self.file_generation.load(Ordering::Relaxed),
                    },
                    b"link" => LINK,
                    b"created" => CREATED_DIRECTORY,
                    _ => return Err(NfsError::NotFound),
                },
                ATTRIBUTE_DIRECTORY if self.named_attributes.load(Ordering::Relaxed) != 0 => match name.as_bytes() {
                    b"user.test" => NAMED_ATTRIBUTE,
                    _ => return Err(NfsError::NotFound),
                },
                _ => return Err(NfsError::NotDirectory),
            };
            Ok(CreatedObject {
                object,
                attributes: Some(self.attributes(object)?),
            })
        }

        async fn lookup_parent(
            &self,
            _context: &RequestContext,
            directory: ObjectKey,
        ) -> Result<CreatedObject, NfsError> {
            if directory == ROOT {
                return Err(NfsError::NotFound);
            }
            let parent = if directory == ATTRIBUTE_DIRECTORY { FILE } else { ROOT };
            Ok(CreatedObject {
                object: parent,
                attributes: Some(self.attributes(parent)?),
            })
        }

        async fn nfs4_named_attribute_directory(
            &self,
            _context: &RequestContext,
            object: ObjectKey,
            _create: bool,
        ) -> Result<CreatedObject, NfsError> {
            if self.named_attributes.load(Ordering::Relaxed) == 0 || object != FILE {
                return Err(NfsError::NotSupported);
            }
            Ok(CreatedObject {
                object: ATTRIBUTE_DIRECTORY,
                attributes: Some(self.attributes(ATTRIBUTE_DIRECTORY)?),
            })
        }

        async fn nfs4_named_attribute_parent(
            &self,
            _context: &RequestContext,
            object: ObjectKey,
        ) -> Result<ObjectKey, NfsError> {
            if self.named_attributes.load(Ordering::Relaxed) != 0 && object == NAMED_ATTRIBUTE {
                Ok(ATTRIBUTE_DIRECTORY)
            } else {
                Err(NfsError::NotFound)
            }
        }

        async fn nfs4_open_preflight(
            &self,
            context: &RequestContext,
            parent: ObjectKey,
            name: &NfsName,
            request: &Nfs4OpenRequest,
        ) -> Result<Nfs4OpenPreflight, NfsError> {
            self.open_preflight_calls.fetch_add(1, Ordering::Relaxed);
            if self.open_error.load(Ordering::Relaxed) != 0 {
                return Err(NfsError::Access);
            }
            let opened = self.lookup(context, parent, name).await?;
            if request
                .create
                .as_ref()
                .is_some_and(|create| matches!(create.mode, VfsCreateMode::Guarded))
            {
                return Err(NfsError::Exists);
            }
            let change = self.root_change.load(Ordering::Relaxed);
            if self.replace_after_preflight.swap(0, Ordering::Relaxed) != 0 {
                self.file_generation.fetch_add(1, Ordering::Relaxed);
            }
            Ok(Nfs4OpenPreflight {
                target: Nfs4OpenTarget::Existing(opened),
                change_info: self.open_change_info(change, change),
            })
        }

        async fn nfs4_open(
            &self,
            context: &RequestContext,
            parent: ObjectKey,
            name: &NfsName,
            request: Nfs4OpenRequest,
            transaction: Nfs4OpenTransaction,
        ) -> Result<crate::vfs::Nfs4OpenResult, NfsError> {
            self.open_calls.fetch_add(1, Ordering::Relaxed);
            if self.open_error.load(Ordering::Relaxed) != 0 {
                return Err(NfsError::Access);
            }
            let opened = self.lookup(context, parent, name).await?;
            if request
                .create
                .as_ref()
                .is_some_and(|create| matches!(create.mode, VfsCreateMode::Guarded))
            {
                return Err(NfsError::Exists);
            }
            if transaction.expected != Nfs4OpenExpectation::Existing(opened.object) {
                return Err(NfsError::Jukebox);
            }
            if request.truncate_existing {
                self.truncate_calls.fetch_add(1, Ordering::Relaxed);
            }
            let change = self.root_change.load(Ordering::Relaxed);
            Ok(crate::vfs::Nfs4OpenResult {
                value: opened,
                change_info: self.open_change_info(change, change),
            })
        }

        async fn nfs4_finish_open_operation(
            &self,
            _context: &RequestContext,
            _operation_id: u64,
        ) -> Result<(), NfsError> {
            Ok(())
        }

        async fn retain_open_object(
            &self,
            _context: &RequestContext,
            _object: ObjectKey,
            _open_instance: [u8; 16],
        ) -> Result<(), NfsError> {
            Ok(())
        }

        async fn release_open_object(
            &self,
            _context: &RequestContext,
            _object: ObjectKey,
            _open_instance: [u8; 16],
        ) -> Result<(), NfsError> {
            self.release_calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        async fn nfs4_delegation_eligibility(
            &self,
            _context: &RequestContext,
            _object: ObjectKey,
            _request: DelegationRequest,
        ) -> Result<DelegationEligibility, NfsError> {
            Ok(DelegationEligibility::Eligible)
        }

        async fn nfs4_reserve_delegated_space(
            &self,
            _context: &RequestContext,
            _object: ObjectKey,
            bytes: u64,
            _scope: &crate::vfs::StableFenceToken,
        ) -> Result<DelegationReservation, NfsError> {
            Ok(DelegationReservation {
                token: bytes::Bytes::from_static(b"compound-cleanup-test"),
                reserved_bytes: bytes,
            })
        }

        async fn nfs4_release_delegated_space(
            &self,
            _context: &RequestContext,
            _reservation: DelegationReservation,
        ) -> Result<(), NfsError> {
            self.delegation_release_calls.fetch_add(1, Ordering::SeqCst);
            if self.delegation_release_block.load(Ordering::SeqCst) != 0 {
                self.delegation_release_started.notify_one();
                self.delegation_release_continue.notified().await;
            }
            if self
                .delegation_release_failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| remaining.checked_sub(1))
                .is_ok()
            {
                Err(NfsError::Io)
            } else {
                Ok(())
            }
        }

        async fn remove(
            &self,
            _context: &RequestContext,
            parent: ObjectKey,
            name: &NfsName,
        ) -> Result<MutationResult<()>, NfsError> {
            if parent != ROOT {
                return Err(NfsError::NotDirectory);
            }
            if name.as_bytes() != b"file" {
                return Err(NfsError::NotFound);
            }
            self.remove_calls.fetch_add(1, Ordering::Relaxed);
            let before = self.root_change.fetch_add(1, Ordering::Relaxed);
            Ok(MutationResult {
                value: (),
                change_info: self.change_info(before, before + 1),
                before: None,
                after: None,
            })
        }

        async fn rename(
            &self,
            _context: &RequestContext,
            from_parent: ObjectKey,
            from_name: &NfsName,
            to_parent: ObjectKey,
            to_name: &NfsName,
        ) -> Result<(MutationResult<()>, MutationResult<()>), NfsError> {
            if from_parent != ROOT || to_parent != ROOT {
                return Err(NfsError::NotDirectory);
            }
            if from_name.as_bytes() != b"file" || to_name.as_bytes() != b"renamed" {
                return Err(NfsError::NotFound);
            }
            self.rename_calls.fetch_add(1, Ordering::Relaxed);
            let before = self.root_change.fetch_add(1, Ordering::Relaxed);
            let result = || MutationResult {
                value: (),
                change_info: self.change_info(before, before + 1),
                before: None,
                after: None,
            };
            Ok((result(), result()))
        }

        async fn nfs4_location_state(
            &self,
            _context: &RequestContext,
            _object: ObjectKey,
        ) -> Result<Nfs4LocationState, NfsError> {
            if self.location_state.load(Ordering::Relaxed) == 1 {
                Ok(Nfs4LocationState::Moved(Nfs4FsLocations {
                    fs_root: vec!["export".to_owned()],
                    locations: vec![Nfs4FsLocation {
                        servers: vec!["destination.example.test".to_owned()],
                        root_path: vec!["srv".to_owned(), "export".to_owned()],
                    }],
                }))
            } else {
                Err(NfsError::NotSupported)
            }
        }

        async fn access(&self, _context: &RequestContext, _object: ObjectKey, requested: u32) -> Result<u32, NfsError> {
            Ok(requested & !ACCESS4_MODIFY)
        }

        async fn read(
            &self,
            _context: &RequestContext,
            object: ObjectKey,
            _offset: u64,
            _count: u32,
        ) -> Result<ReadResult, NfsError> {
            if !matches!(object, FILE | NAMED_ATTRIBUTE) {
                return Err(NfsError::Invalid);
            }
            // Deliberately return more than requested to verify the executor's
            // transport bound remains authoritative.
            Ok(ReadResult {
                data: b"abcdef".to_vec(),
                eof: true,
                attributes: None,
            })
        }

        async fn readlink(&self, _context: &RequestContext, object: ObjectKey) -> Result<Vec<u8>, NfsError> {
            if object == LINK {
                Ok(b"target".to_vec())
            } else {
                Err(NfsError::Invalid)
            }
        }

        async fn nfs4_check_zero_length_write(
            &self,
            _context: &RequestContext,
            object: ObjectKey,
            _offset: u64,
            _requested: WriteStability,
        ) -> Result<(), NfsError> {
            if !matches!(object, FILE | NAMED_ATTRIBUTE) {
                return Err(NfsError::Invalid);
            }
            self.zero_length_write_checks.fetch_add(1, Ordering::Relaxed);
            match self.zero_length_write_error.load(Ordering::Relaxed) {
                0 => Ok(()),
                1 => Err(NfsError::Access),
                2 => Err(NfsError::ReadOnly),
                _ => Err(NfsError::ServerFault),
            }
        }

        async fn write(
            &self,
            _context: &RequestContext,
            object: ObjectKey,
            _offset: u64,
            data: &[u8],
            _requested: WriteStability,
        ) -> Result<MutationResult<WriteResult>, NfsError> {
            if !matches!(object, FILE | NAMED_ATTRIBUTE) {
                return Err(NfsError::Invalid);
            }
            self.write_calls.fetch_add(1, Ordering::Relaxed);
            Ok(MutationResult {
                value: WriteResult {
                    count: u32::try_from(self.write_count.load(Ordering::Relaxed).min(data.len()))
                        .map_err(|_| NfsError::FileTooLarge)?,
                    committed: match self.write_committed.load(Ordering::Relaxed) {
                        0 => WriteStability::Unstable,
                        1 => WriteStability::DataSync,
                        _ => WriteStability::FileSync,
                    },
                },
                change_info: None,
                before: None,
                after: None,
            })
        }

        async fn mkdir(
            &self,
            _context: &RequestContext,
            parent: ObjectKey,
            _name: &NfsName,
            _attributes: SetAttributes,
        ) -> Result<MutationResult<CreatedObject>, NfsError> {
            if parent != ROOT {
                return Err(NfsError::NotDirectory);
            }
            let before = self.root_change.fetch_add(1, Ordering::Relaxed);
            let after = before + 1;
            Ok(MutationResult {
                value: CreatedObject {
                    object: CREATED_DIRECTORY,
                    attributes: Some(self.attributes(CREATED_DIRECTORY)?),
                },
                change_info: self.change_info(before, after),
                before: None,
                after: None,
            })
        }

        async fn setattr(
            &self,
            _context: &RequestContext,
            object: ObjectKey,
            _attributes: SetAttributes,
            _guard: Option<NfsTime>,
        ) -> Result<MutationResult<()>, NfsError> {
            if object != FILE {
                return Err(NfsError::Invalid);
            }
            self.setattr_calls.fetch_add(1, Ordering::Relaxed);
            Ok(MutationResult {
                value: (),
                change_info: None,
                before: None,
                after: None,
            })
        }

        async fn commit(
            &self,
            _context: &RequestContext,
            object: ObjectKey,
            _offset: u64,
            _count: u32,
        ) -> Result<MutationResult<()>, NfsError> {
            if object != FILE {
                return Err(NfsError::Invalid);
            }
            self.commit_calls.fetch_add(1, Ordering::Relaxed);
            Ok(MutationResult {
                value: (),
                change_info: None,
                before: None,
                after: None,
            })
        }

        async fn nfs4_stabilize_mutation(&self, context: &RequestContext, object: ObjectKey) -> Result<(), NfsError> {
            self.stabilized_client_id
                .store(context.client_id.unwrap_or(u64::MAX), Ordering::Relaxed);
            self.commit(context, object, 0, 0).await.map(|_| ())
        }
    }

    struct Fixture {
        vfs: Arc<TestVfs>,
        exports: Vec<ExportState>,
        handles: HandleCodecSet,
        namespace: PseudoNamespace,
        runtime: Nfs4Runtime,
        open_pins: OpenPinManager,
        delegations: HashMap<ExportId, Arc<DelegationManager>>,
        locations: BTreeMap<ExportId, Nfs4FsLocations>,
        context: RequestContext,
    }

    struct UnusedCallbackConnector;

    #[async_trait]
    impl CallbackConnector for UnusedCallbackConnector {
        async fn connect(
            &self,
            _target: &CallbackTarget,
        ) -> Result<Arc<dyn crate::server::CallbackTransport>, crate::server::CallbackError> {
            Err(crate::server::CallbackError::Unavailable("unused test connector".to_owned()))
        }
    }

    struct SuccessfulCallbackConnector;

    struct SuccessfulCallbackTransport;

    #[async_trait]
    impl CallbackConnector for SuccessfulCallbackConnector {
        async fn connect(
            &self,
            _target: &CallbackTarget,
        ) -> Result<Arc<dyn crate::server::CallbackTransport>, crate::server::CallbackError> {
            Ok(Arc::new(SuccessfulCallbackTransport))
        }
    }

    #[async_trait]
    impl crate::server::CallbackTransport for SuccessfulCallbackTransport {
        async fn call(
            &self,
            call: bytes::Bytes,
            _timeout: Duration,
        ) -> Result<bytes::Bytes, crate::server::CallbackError> {
            let xid = call
                .get(..4)
                .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                .map(u32::from_be_bytes)
                .ok_or_else(|| crate::server::CallbackError::Protocol("short callback RPC call".to_owned()))?;
            let mut reply = Vec::with_capacity(24);
            for word in [xid, 1, 0, 0, 0, 0] {
                reply.extend_from_slice(&word.to_be_bytes());
            }
            Ok(bytes::Bytes::from(reply))
        }
    }

    struct UnusedGssInitiator;

    #[async_trait]
    impl GssInitiatorProvider for UnusedGssInitiator {
        async fn initiate_security_context(
            &self,
            _continuation: Option<crate::rpc::gss::InitiateContext>,
            _version: crate::rpc::gss::Version,
            _target_name: &str,
            _input_token: bytes::Bytes,
        ) -> Result<crate::rpc::gss::InitiateOutcome, crate::rpc::gss::ProviderError> {
            Err(crate::rpc::gss::ProviderError::UnknownContext)
        }

        async fn verify_mic(
            &self,
            _context: crate::rpc::gss::ProviderContextId,
            _message: bytes::Bytes,
            _mic: bytes::Bytes,
        ) -> Result<(), crate::rpc::gss::ProviderError> {
            Err(crate::rpc::gss::ProviderError::UnknownContext)
        }

        async fn get_mic(
            &self,
            _context: crate::rpc::gss::ProviderContextId,
            _message: bytes::Bytes,
        ) -> Result<bytes::Bytes, crate::rpc::gss::ProviderError> {
            Err(crate::rpc::gss::ProviderError::UnknownContext)
        }

        async fn unwrap(
            &self,
            _context: crate::rpc::gss::ProviderContextId,
            _token: bytes::Bytes,
        ) -> Result<bytes::Bytes, crate::rpc::gss::ProviderError> {
            Err(crate::rpc::gss::ProviderError::UnknownContext)
        }

        async fn wrap(
            &self,
            _context: crate::rpc::gss::ProviderContextId,
            _message: bytes::Bytes,
            _confidentiality: bool,
        ) -> Result<bytes::Bytes, crate::rpc::gss::ProviderError> {
            Err(crate::rpc::gss::ProviderError::UnknownContext)
        }

        async fn delete_security_context(
            &self,
            _context: crate::rpc::gss::ProviderContextId,
        ) -> Result<(), crate::rpc::gss::ProviderError> {
            Err(crate::rpc::gss::ProviderError::UnknownContext)
        }
    }

    impl Fixture {
        fn new() -> Self {
            let vfs = Arc::new(TestVfs::new());
            let export_id = ExportId(7);
            let exports = vec![ExportState {
                vfs: vfs.clone(),
                id: export_id,
                path: "/export".to_owned(),
                fsid: FileSystemId::new(0, 1),
                security_policy: SecurityPolicy::anonymous(),
                filehandle_policy: FileHandlePolicy::Volatile,
            }];
            let mut namespace = PseudoNamespace::new(16).unwrap();
            namespace.add_export("/export", export_id).unwrap();
            let open_pins = OpenPinManager::new(&exports, 1024).unwrap();
            Self {
                vfs,
                exports,
                handles: HandleCodecSet::new(
                    HandleCodec::from_key([0x11; 8], [0x22; 32]),
                    HandleCodec::from_key([0x33; 8], [0x44; 32]),
                    [(export_id, HandleLifetime::Volatile)],
                ),
                namespace,
                runtime: Nfs4Runtime::new(RuntimeConfig {
                    lease_duration: Duration::from_secs(90),
                    grace_duration: Duration::from_secs(90),
                    limits: Nfs4Limits::default(),
                    boot_tag: 0x1122_3344,
                    write_verifier: [0x11; 8],
                    stable_journal: None,
                    recovered: None,
                })
                .unwrap(),
                open_pins,
                delegations: HashMap::new(),
                locations: BTreeMap::new(),
                context: RequestContext {
                    principal: Principal::Anonymous,
                    client_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 2049)),
                    export_id,
                    protocol: ProtocolVersion::V4,
                    client_id: None,
                },
            }
        }

        fn executor(&self) -> CompoundExecutor<'_> {
            self.executor_with_public_filehandle_node(NamespaceNodeId::ROOT)
        }

        fn executor_with_limits(&self, max_read_size: u32, max_response_body_size: usize) -> CompoundExecutor<'_> {
            self.executor_with_public_filehandle_node_and_limits(
                NamespaceNodeId::ROOT,
                max_read_size,
                max_response_body_size,
            )
        }

        fn executor_with_public_filehandle_node(
            &self,
            public_filehandle_node: NamespaceNodeId,
        ) -> CompoundExecutor<'_> {
            self.executor_with_public_filehandle_node_and_limits(public_filehandle_node, 4, usize::MAX)
        }

        fn executor_with_public_filehandle_node_and_limits(
            &self,
            public_filehandle_node: NamespaceNodeId,
            max_read_size: u32,
            max_response_body_size: usize,
        ) -> CompoundExecutor<'_> {
            CompoundExecutor::new(
                &self.exports,
                &self.handles,
                &self.namespace,
                public_filehandle_node,
                &self.runtime,
                &self.open_pins,
                &self.delegations,
                None,
                None,
                &self.locations,
                &self.context,
                max_read_size,
                4,
                90,
                max_response_body_size,
                None,
                Duration::from_secs(5),
                None,
                Weak::new(),
            )
        }

        fn executor_with_identity_mapper<'a>(&'a self, mapper: &'a Arc<dyn IdentityMapper>) -> CompoundExecutor<'a> {
            CompoundExecutor::new(
                &self.exports,
                &self.handles,
                &self.namespace,
                NamespaceNodeId::ROOT,
                &self.runtime,
                &self.open_pins,
                &self.delegations,
                None,
                Some(mapper),
                &self.locations,
                &self.context,
                4,
                4,
                90,
                usize::MAX,
                None,
                Duration::from_secs(5),
                None,
                Weak::new(),
            )
        }
    }

    const OVERLAY_PARENT_ROOT: ObjectKey = ObjectKey {
        file_id: 100,
        generation: 1,
    };
    const OVERLAY_PROJECTS: ObjectKey = ObjectKey {
        file_id: 101,
        generation: 1,
    };
    const OVERLAY_ALPHA: ObjectKey = ObjectKey {
        file_id: 102,
        generation: 1,
    };
    const OVERLAY_BACKEND_DATA: ObjectKey = ObjectKey {
        file_id: 103,
        generation: 1,
    };
    const OVERLAY_BETA: ObjectKey = ObjectKey {
        file_id: 104,
        generation: 1,
    };
    const OVERLAY_NESTED_ROOT: ObjectKey = ObjectKey {
        file_id: 200,
        generation: 1,
    };

    #[derive(Clone, Copy)]
    enum OverlayVfsRole {
        Parent { projects_present: bool },
        Nested,
    }

    struct OverlayVfs {
        role: OverlayVfsRole,
        verifier: AtomicU8,
        page_size: usize,
    }

    impl OverlayVfs {
        fn parent(projects_present: bool) -> Self {
            Self {
                role: OverlayVfsRole::Parent { projects_present },
                verifier: AtomicU8::new(7),
                // A one-entry backend page forces the merge path to suppress
                // a shadowed name across page boundaries.
                page_size: 1,
            }
        }

        fn nested() -> Self {
            Self {
                role: OverlayVfsRole::Nested,
                verifier: AtomicU8::new(3),
                page_size: 1,
            }
        }

        fn set_verifier(&self, verifier: u8) {
            self.verifier.store(verifier, Ordering::Relaxed);
        }

        fn attributes(object: ObjectKey) -> Result<VfsFileAttributes, NfsError> {
            let file_type = match object {
                OVERLAY_PARENT_ROOT | OVERLAY_PROJECTS | OVERLAY_BACKEND_DATA | OVERLAY_NESTED_ROOT => {
                    FileType::Directory
                },
                OVERLAY_ALPHA | OVERLAY_BETA => FileType::Regular,
                _ => return Err(NfsError::Stale),
            };
            Ok(VfsFileAttributes {
                file_type,
                mode: if file_type == FileType::Directory { 0o755 } else { 0o644 },
                links: if file_type == FileType::Directory { 2 } else { 1 },
                uid: 1000,
                gid: 1000,
                size: 0,
                used: 0,
                device: None,
                fs_id: if object == OVERLAY_NESTED_ROOT { 2 } else { 1 },
                file_id: object.file_id,
                change_id: object.file_id.into(),
                access_time: NfsTime::default(),
                modify_time: NfsTime::default(),
                change_time: NfsTime::default(),
            })
        }
    }

    #[async_trait]
    impl VirtualFileSystem for OverlayVfs {
        fn capabilities(&self) -> VfsCapabilities {
            VfsCapabilities::READ_ONLY
        }

        fn nfs4_capabilities(&self) -> Option<Nfs4Capabilities> {
            Some(Nfs4Capabilities::READ_ONLY)
        }

        fn root(&self) -> ObjectKey {
            match self.role {
                OverlayVfsRole::Parent { .. } => OVERLAY_PARENT_ROOT,
                OverlayVfsRole::Nested => OVERLAY_NESTED_ROOT,
            }
        }

        async fn getattr(&self, _context: &RequestContext, object: ObjectKey) -> Result<VfsFileAttributes, NfsError> {
            Self::attributes(object)
        }

        async fn lookup(
            &self,
            _context: &RequestContext,
            parent: ObjectKey,
            name: &NfsName,
        ) -> Result<CreatedObject, NfsError> {
            let object = match self.role {
                OverlayVfsRole::Nested => return Err(NfsError::NotFound),
                OverlayVfsRole::Parent {
                    projects_present: false,
                } if parent == OVERLAY_PARENT_ROOT && name.as_bytes() == b"projects" => {
                    return Err(NfsError::NotFound);
                },
                OverlayVfsRole::Parent { .. } if parent == OVERLAY_PARENT_ROOT => match name.as_bytes() {
                    b"projects" => OVERLAY_PROJECTS,
                    _ => return Err(NfsError::NotFound),
                },
                OverlayVfsRole::Parent { .. } if parent == OVERLAY_PROJECTS => match name.as_bytes() {
                    b"alpha" => OVERLAY_ALPHA,
                    b"data" => OVERLAY_BACKEND_DATA,
                    b"beta" => OVERLAY_BETA,
                    _ => return Err(NfsError::NotFound),
                },
                OverlayVfsRole::Parent { .. } => return Err(NfsError::NotDirectory),
            };
            Ok(CreatedObject {
                object,
                attributes: Some(Self::attributes(object)?),
            })
        }

        async fn lookup_parent(
            &self,
            _context: &RequestContext,
            directory: ObjectKey,
        ) -> Result<CreatedObject, NfsError> {
            let parent = match self.role {
                OverlayVfsRole::Parent { projects_present } if directory == OVERLAY_PROJECTS && projects_present => {
                    OVERLAY_PARENT_ROOT
                },
                OverlayVfsRole::Parent { projects_present } if projects_present => match directory {
                    OVERLAY_ALPHA | OVERLAY_BACKEND_DATA | OVERLAY_BETA => OVERLAY_PROJECTS,
                    _ => return Err(NfsError::NotFound),
                },
                _ => return Err(NfsError::NotFound),
            };
            Ok(CreatedObject {
                object: parent,
                attributes: Some(Self::attributes(parent)?),
            })
        }

        async fn readdir(
            &self,
            _context: &RequestContext,
            directory: ObjectKey,
            cookie: u64,
            verifier: [u8; 8],
            backend_hint: usize,
        ) -> Result<ReadDirectoryPage, NfsError> {
            if !matches!(self.role, OverlayVfsRole::Parent { projects_present: true }) || directory != OVERLAY_PROJECTS
            {
                return Err(NfsError::NotDirectory);
            }
            let current = [self.verifier.load(Ordering::Relaxed); 8];
            if verifier != [0; 8] && verifier != current {
                return Err(NfsError::BadCookie);
            }
            let remaining: Vec<_> = [
                (OVERLAY_ALPHA, b"alpha".as_slice(), 10_u64),
                (OVERLAY_BACKEND_DATA, b"data".as_slice(), 20_u64),
                (OVERLAY_BETA, b"beta".as_slice(), 30_u64),
            ]
            .into_iter()
            .filter(|(_, _, entry_cookie)| *entry_cookie > cookie)
            .collect();
            let take = backend_hint.min(self.page_size);
            let entries = remaining
                .iter()
                .take(take)
                .map(|(object, name, entry_cookie)| VfsDirectoryEntry {
                    object: *object,
                    file_id: object.file_id,
                    name: NfsName::new(name.to_vec()).unwrap(),
                    cookie: *entry_cookie,
                    attributes: Some(Self::attributes(*object).unwrap()),
                })
                .collect::<Vec<_>>();
            Ok(ReadDirectoryPage {
                verifier: current,
                eof: entries.len() == remaining.len(),
                entries,
            })
        }
    }

    struct OverlayFixture {
        parent: Arc<OverlayVfs>,
        exports: Vec<ExportState>,
        handles: HandleCodecSet,
        namespace: PseudoNamespace,
        runtime: Nfs4Runtime,
        open_pins: OpenPinManager,
        delegations: HashMap<ExportId, Arc<DelegationManager>>,
        locations: BTreeMap<ExportId, Nfs4FsLocations>,
        context: RequestContext,
    }

    impl OverlayFixture {
        fn new(projects_present: bool) -> Self {
            let parent = Arc::new(OverlayVfs::parent(projects_present));
            let nested = Arc::new(OverlayVfs::nested());
            let parent_export = ExportId(41);
            let nested_export = ExportId(42);
            let exports = vec![
                ExportState {
                    vfs: parent.clone(),
                    id: parent_export,
                    path: "/srv".to_owned(),
                    fsid: FileSystemId::new(1, 1),
                    security_policy: SecurityPolicy::anonymous(),
                    filehandle_policy: FileHandlePolicy::Volatile,
                },
                ExportState {
                    vfs: nested,
                    id: nested_export,
                    path: "/srv/projects/data".to_owned(),
                    fsid: FileSystemId::new(2, 2),
                    security_policy: SecurityPolicy::auth_sys_or_anonymous(),
                    filehandle_policy: FileHandlePolicy::Volatile,
                },
            ];
            let mut namespace = PseudoNamespace::new(32).unwrap();
            namespace.add_export("/srv", parent_export).unwrap();
            namespace.add_export("/srv/projects/data", nested_export).unwrap();
            let open_pins = OpenPinManager::new(&exports, 1024).unwrap();
            Self {
                parent,
                exports,
                handles: HandleCodecSet::new(
                    HandleCodec::from_key([0x31; 8], [0x42; 32]),
                    HandleCodec::from_key([0x53; 8], [0x64; 32]),
                    [
                        (parent_export, HandleLifetime::Volatile),
                        (nested_export, HandleLifetime::Volatile),
                    ],
                ),
                namespace,
                runtime: Nfs4Runtime::new(RuntimeConfig {
                    lease_duration: Duration::from_secs(90),
                    grace_duration: Duration::from_secs(90),
                    limits: Nfs4Limits::default(),
                    boot_tag: 0x5566_7788,
                    write_verifier: [0x23; 8],
                    stable_journal: None,
                    recovered: None,
                })
                .unwrap(),
                open_pins,
                delegations: HashMap::new(),
                locations: BTreeMap::new(),
                context: RequestContext {
                    principal: Principal::Anonymous,
                    client_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 2049)),
                    export_id: parent_export,
                    protocol: ProtocolVersion::V4,
                    client_id: None,
                },
            }
        }

        fn executor(&self) -> CompoundExecutor<'_> {
            CompoundExecutor::new(
                &self.exports,
                &self.handles,
                &self.namespace,
                NamespaceNodeId::ROOT,
                &self.runtime,
                &self.open_pins,
                &self.delegations,
                None,
                None,
                &self.locations,
                &self.context,
                4096,
                4096,
                90,
                usize::MAX,
                None,
                Duration::from_secs(5),
                None,
                Weak::new(),
            )
        }

        fn projects_node(&self) -> NamespaceNodeId {
            self.namespace.resolve_absolute_path("/srv/projects").unwrap()
        }

        fn data_node(&self) -> NamespaceNodeId {
            self.namespace.resolve_absolute_path("/srv/projects/data").unwrap()
        }
    }

    fn request(operations: Vec<ArgOp>) -> CompoundArgs {
        CompoundArgs {
            tag: b"tag".to_vec(),
            minor_version: 0,
            operations,
        }
    }

    fn enter_export() -> Vec<ArgOp> {
        vec![
            ArgOp::PutRootFh,
            ArgOp::Lookup(super::super::types::LookupArgs {
                name: b"export".to_vec(),
            }),
        ]
    }

    async fn confirmed_fixture_client(fixture: &Fixture, owner: &[u8]) -> u64 {
        let arguments = super::super::types::SetClientIdArgs {
            client: super::super::types::NfsClientId {
                verifier: [0x61; 8],
                id: owner.to_vec(),
            },
            callback: super::super::types::CallbackClient {
                program: 0x4000_0000,
                location: super::super::types::ClientAddress {
                    netid: b"tcp".to_vec(),
                    address: b"127.0.0.1.8.1".to_vec(),
                },
            },
            callback_identifier: 9,
        };
        let super::super::types::SetClientIdResult::Ok(set) =
            fixture.runtime.set_client_id(&arguments, &Principal::Anonymous).await.result
        else {
            panic!("SETCLIENTID did not succeed");
        };
        assert_eq!(
            fixture
                .runtime
                .confirm_client(set.client_id, set.confirmation, &Principal::Anonymous)
                .await
                .result,
            NfsStatus::Ok
        );
        set.client_id
    }

    fn leased_fixture() -> (Fixture, Arc<ManualLeaseClock>) {
        let mut fixture = Fixture::new();
        let clock = Arc::new(ManualLeaseClock::default());
        fixture.runtime = Nfs4Runtime::with_clock(
            RuntimeConfig {
                lease_duration: Duration::from_secs(10),
                grace_duration: Duration::from_secs(10),
                limits: Nfs4Limits::default(),
                boot_tag: 0x1122_3344,
                write_verifier: [0x11; 8],
                stable_journal: None,
                recovered: None,
            },
            clock.clone(),
        )
        .unwrap();
        (fixture, clock)
    }

    async fn grant_fixture_write_delegation(
        fixture: &mut Fixture,
        client_id: u64,
        export_id: ExportId,
        clock: Arc<dyn CallbackClock>,
        boot_tag: u32,
    ) -> DelegationGrant {
        let manager = Arc::new(
            DelegationManager::with_boot_tag(
                fixture.vfs.clone(),
                crate::server::DelegationPolicy::Conservative {
                    max_read_delegations: 1,
                    max_write_delegations: 1,
                    persistent: false,
                },
                Duration::from_secs(10),
                clock,
                boot_tag,
            )
            .unwrap(),
        );
        fixture.delegations.insert(export_id, manager.clone());
        let callback = Arc::new(
            CallbackRpcClient::with_system_clock(
                Arc::new(SuccessfulCallbackConnector),
                CallbackTarget {
                    network_id: "tcp".to_owned(),
                    universal_address: "127.0.0.1.8.1".to_owned(),
                },
                0x4000_0001,
                1,
                crate::nfs4::callback::CallbackAuth::AuthNone,
                CallbackClientConfig::default(),
            )
            .unwrap(),
        );
        let mut context = fixture.context.clone();
        context.client_id = Some(client_id);
        let GrantOutcome::Granted(grant) = manager
            .grant(DelegationGrantRequest {
                context,
                object: FILE,
                file_handle: NfsFileHandle(vec![2]),
                kind: DelegationKind::Write,
                requested_space: 4096,
                callback,
            })
            .await
            .unwrap()
        else {
            panic!("write delegation was not granted");
        };
        grant
    }

    /// Opens and confirms `file`, returning both stateid and filehandle for
    /// follow-up stateful-operation tests.
    async fn open_fixture_file_state(
        fixture: &Fixture,
        client_id: u64,
        owner: &[u8],
    ) -> (super::super::types::StateId, NfsFileHandle) {
        let mut operations = enter_export();
        operations.extend([
            ArgOp::Open(OpenArgs {
                sequence_id: 1,
                share_access: OPEN4_SHARE_ACCESS_READ,
                share_deny: 0,
                owner: super::super::types::OpenOwner {
                    client_id,
                    owner: owner.to_vec(),
                },
                how: OpenHow::NoCreate,
                claim: OpenClaim::Null(b"file".to_vec()),
            }),
            ArgOp::GetFh,
        ]);
        let opened = fixture.executor().execute(request(operations)).await;
        let unconfirmed = match &opened.operations[2] {
            ResOp::Open(NfsResult::Ok(open)) => open.state_id,
            operation => panic!("unexpected OPEN response: {operation:?}"),
        };
        let file_handle = match &opened.operations[3] {
            ResOp::GetFh(NfsResult::Ok(file_handle)) => file_handle.clone(),
            operation => panic!("unexpected GETFH response: {operation:?}"),
        };
        let confirmed = fixture
            .executor()
            .execute(request(vec![
                ArgOp::PutFh(PutFhArgs {
                    object: file_handle.clone(),
                }),
                ArgOp::OpenConfirm(OpenConfirmArgs {
                    open_state_id: unconfirmed,
                    sequence_id: 2,
                }),
            ]))
            .await;
        let state_id = match &confirmed.operations[1] {
            ResOp::OpenConfirm(NfsResult::Ok(state_id)) => *state_id,
            operation => panic!("unexpected OPEN_CONFIRM response: {operation:?}"),
        };
        (state_id, file_handle)
    }

    #[tokio::test]
    async fn failed_delegation_release_maintenance_does_not_fail_unrelated_compounds() {
        let mut fixture = Fixture::new();
        let export_id = ExportId(7);
        let manager = Arc::new(
            DelegationManager::with_boot_tag(
                fixture.vfs.clone(),
                crate::server::DelegationPolicy::Conservative {
                    max_read_delegations: 1,
                    max_write_delegations: 1,
                    persistent: false,
                },
                Duration::from_secs(30),
                Arc::new(crate::nfs4::callback::SystemCallbackClock::default()),
                9,
            )
            .unwrap(),
        );
        fixture.delegations.insert(export_id, manager.clone());
        let callback = Arc::new(
            CallbackRpcClient::with_system_clock(
                Arc::new(SuccessfulCallbackConnector),
                CallbackTarget {
                    network_id: "tcp".to_owned(),
                    universal_address: "127.0.0.1.8.1".to_owned(),
                },
                0x4000_0001,
                1,
                crate::nfs4::callback::CallbackAuth::AuthNone,
                CallbackClientConfig::default(),
            )
            .unwrap(),
        );
        let mut delegation_context = fixture.context.clone();
        delegation_context.client_id = Some(1);
        let GrantOutcome::Granted(grant) = manager
            .grant(DelegationGrantRequest {
                context: delegation_context.clone(),
                object: FILE,
                file_handle: NfsFileHandle(vec![2]),
                kind: DelegationKind::Write,
                requested_space: 4096,
                callback,
            })
            .await
            .unwrap()
        else {
            panic!("write delegation was not granted");
        };

        // DELEGRETURN performs the first release attempt and the next
        // request's single explicit maintenance pass performs the second.
        // Both fail while the exact release token remains queued.
        fixture.vfs.delegation_release_failures.store(2, Ordering::SeqCst);
        manager.delegreturn(&delegation_context, FILE, grant.state_id).await.unwrap();
        assert_eq!(manager.pending_cleanup(), 1);
        assert_eq!(fixture.vfs.delegation_release_calls.load(Ordering::SeqCst), 1);

        let unrelated = fixture.executor().execute(request(vec![ArgOp::PutRootFh])).await;
        assert_eq!(unrelated.status, NfsStatus::Ok);
        assert_eq!(unrelated.operations, vec![ResOp::PutRootFh(NfsStatus::Ok)]);
        assert_eq!(manager.pending_cleanup(), 1);
        assert_eq!(fixture.vfs.delegation_release_calls.load(Ordering::SeqCst), 2);

        let retried = fixture.executor().execute(request(vec![ArgOp::PutRootFh])).await;
        assert_eq!(retried.status, NfsStatus::Ok);
        assert_eq!(manager.pending_cleanup(), 0);
        assert_eq!(fixture.vfs.delegation_release_calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn slow_delegation_release_does_not_block_another_exports_renewal() {
        let (mut fixture, _) = leased_fixture();
        let delegation_clock = Arc::new(ManualCallbackClock::default());
        let client_id = confirmed_fixture_client(&fixture, b"slow-release-client").await;
        let _expiring =
            grant_fixture_write_delegation(&mut fixture, client_id, ExportId(7), delegation_clock.clone(), 20).await;
        let _retained =
            grant_fixture_write_delegation(&mut fixture, client_id, ExportId(8), delegation_clock.clone(), 21).await;
        let expiring_manager = fixture.delegations.get(&ExportId(7)).unwrap().clone();
        let retained_manager = fixture.delegations.get(&ExportId(8)).unwrap().clone();
        let mut context = fixture.context.clone();
        context.client_id = Some(client_id);

        // Keep export 8 live while export 7 reaches expiry. The release from
        // export 7 will be held in the VFS after it has been detached from
        // live state and after its renewal fence has been released.
        delegation_clock.advance(Duration::from_secs(9));
        retained_manager.renew_client(&context, client_id).await.unwrap();
        delegation_clock.advance(Duration::from_secs(1));
        fixture.vfs.delegation_release_block.store(1, Ordering::SeqCst);
        let started = fixture.vfs.delegation_release_started.notified();
        tokio::pin!(started);
        let expiration = tokio::spawn(async move { expiring_manager.revoke_expired().await });
        started.await;

        // This would deadlock behind the all-manager fence if the expiry path
        // still awaited VFS release while fencing protocol lease decisions.
        let renewal =
            tokio::time::timeout(Duration::from_millis(250), retained_manager.renew_client(&context, client_id))
                .await
                .expect("another export's renewal must not wait for a slow release");
        assert_eq!(renewal, Ok(()));

        fixture.vfs.delegation_release_block.store(0, Ordering::SeqCst);
        fixture.vfs.delegation_release_continue.notify_one();
        assert_eq!(expiration.await.unwrap().unwrap().len(), 1);
        assert_eq!(retained_manager.active_counts().await, (0, 1));
    }

    #[tokio::test]
    async fn fenced_expiry_check_prevents_a_just_expired_delegation_from_being_renewed() {
        let (mut fixture, _) = leased_fixture();
        let delegation_clock = Arc::new(ManualCallbackClock::default());
        let client_id = confirmed_fixture_client(&fixture, b"fenced-expiry-client").await;
        let _delegation =
            grant_fixture_write_delegation(&mut fixture, client_id, ExportId(7), delegation_clock.clone(), 22).await;
        let manager = fixture.delegations.get(&ExportId(7)).unwrap().clone();
        let mut context = fixture.context.clone();
        context.client_id = Some(client_id);

        // Model the window after the request-start cleanup but before a
        // stateid renewal acquires its all-manager fences.
        delegation_clock.advance(Duration::from_secs(9));
        assert!(manager.revoke_expired().await.unwrap().is_empty());
        delegation_clock.advance(Duration::from_secs(1));

        let fence = manager.renewal_fence().await;
        assert_eq!(manager.revoke_expired_while_fenced().await.unwrap().len(), 1);
        manager
            .renew_client_from_stateid_while_fenced(&context, client_id)
            .await
            .unwrap();
        drop(fence);
        assert_eq!(manager.active_counts().await, (0, 0));
        manager.finalize_detached_removals().await.unwrap();
    }

    #[test]
    fn stable_reconciliation_health_blocks_grace_but_release_retry_does_not() {
        let release_retry = DelegationCleanupProgress {
            pending_releases: 1,
            pending: 1,
            ..DelegationCleanupProgress::default()
        };
        assert!(!delegation_cleanup_blocks_grace(&release_retry));

        let reconciliation = DelegationCleanupProgress {
            pending_reconciliation: 1,
            pending: 1,
            ..DelegationCleanupProgress::default()
        };
        assert!(delegation_cleanup_blocks_grace(&reconciliation));

        let durable_deletion = DelegationCleanupProgress {
            pending_detached_removals: 1,
            pending: 1,
            ..DelegationCleanupProgress::default()
        };
        assert!(delegation_cleanup_blocks_grace(&durable_deletion));
    }

    #[tokio::test]
    async fn backend_open_errors_take_priority_over_share_conflicts() {
        let fixture = Fixture::new();
        let first_client = confirmed_fixture_client(&fixture, b"open-priority-first").await;
        let second_client = confirmed_fixture_client(&fixture, b"open-priority-second").await;
        let first_owner = super::super::types::OpenOwner {
            client_id: first_client,
            owner: b"open-priority-owner".to_vec(),
        };

        let mut first = enter_export();
        first.push(ArgOp::Open(OpenArgs {
            sequence_id: 1,
            share_access: OPEN4_SHARE_ACCESS_BOTH,
            share_deny: OPEN4_SHARE_DENY_WRITE,
            owner: first_owner.clone(),
            how: OpenHow::NoCreate,
            claim: OpenClaim::Null(b"file".to_vec()),
        }));
        assert_eq!(fixture.executor().execute(request(first)).await.status, NfsStatus::Ok);

        fixture.vfs.open_error.store(1, Ordering::Relaxed);
        let mut unauthorized = enter_export();
        unauthorized.push(ArgOp::Open(OpenArgs {
            sequence_id: 1,
            share_access: OPEN4_SHARE_ACCESS_READ,
            share_deny: OPEN4_SHARE_DENY_WRITE,
            owner: super::super::types::OpenOwner {
                client_id: second_client,
                owner: b"open-priority-other-owner".to_vec(),
            },
            how: OpenHow::NoCreate,
            claim: OpenClaim::Null(b"file".to_vec()),
        }));
        assert_eq!(fixture.executor().execute(request(unauthorized)).await.status, NfsStatus::Access);

        fixture.vfs.open_error.store(0, Ordering::Relaxed);
        let mut guarded = enter_export();
        guarded.push(ArgOp::Open(OpenArgs {
            sequence_id: 2,
            share_access: OPEN4_SHARE_ACCESS_BOTH,
            share_deny: OPEN4_SHARE_DENY_WRITE,
            owner: first_owner,
            how: OpenHow::Create(CreateHow::Guarded(FileAttributes {
                mask: Vec::new(),
                values: Vec::new(),
            })),
            claim: OpenClaim::Null(b"file".to_vec()),
        }));
        assert_eq!(fixture.executor().execute(request(guarded)).await.status, NfsStatus::Exists);
        assert_eq!(fixture.vfs.open_preflight_calls.load(Ordering::Relaxed), 3);
        assert_eq!(fixture.vfs.open_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn open_expected_object_cas_rejects_replacement_before_truncate_and_rolls_back_share() {
        let fixture = Fixture::new();
        let client_id = confirmed_fixture_client(&fixture, b"open-cas-client").await;
        let owner = super::super::types::OpenOwner {
            client_id,
            owner: b"open-cas-owner".to_vec(),
        };
        let open = |sequence_id| {
            let mut operations = enter_export();
            operations.push(ArgOp::Open(OpenArgs {
                sequence_id,
                share_access: OPEN4_SHARE_ACCESS_BOTH,
                share_deny: 0,
                owner: owner.clone(),
                how: OpenHow::Create(CreateHow::Unchecked(FileAttributes {
                    mask: bitmap_from_attributes([FATTR4_SIZE]).unwrap(),
                    values: 0_u64.to_be_bytes().to_vec(),
                })),
                claim: OpenClaim::Null(b"file".to_vec()),
            }));
            operations
        };

        fixture.vfs.replace_after_preflight.store(1, Ordering::Relaxed);
        assert_eq!(fixture.executor().execute(request(open(1))).await.status, NfsStatus::Delay);
        assert_eq!(fixture.vfs.truncate_calls.load(Ordering::Relaxed), 0);
        // The backend rejects the expected-object CAS before the atomic
        // transaction acquires a pin, so there is nothing to release.
        assert_eq!(fixture.vfs.release_calls.load(Ordering::Relaxed), 0);

        // A fresh owner sequence can reserve the replacement, proving the
        // failed CAS did not leave a pending share reservation behind.
        assert_eq!(fixture.executor().execute(request(open(2))).await.status, NfsStatus::Ok);
        assert_eq!(fixture.vfs.truncate_calls.load(Ordering::Relaxed), 1);
    }

    fn recovering_fixture() -> (Fixture, Arc<ManualLeaseClock>) {
        let mut fixture = Fixture::new();
        let clock = Arc::new(ManualLeaseClock::default());
        fixture.runtime = Nfs4Runtime::with_clock(
            RuntimeConfig {
                lease_duration: Duration::from_secs(90),
                grace_duration: Duration::from_secs(90),
                limits: Nfs4Limits::default(),
                boot_tag: 0x1122_3344,
                write_verifier: [0x11; 8],
                stable_journal: None,
                recovered: Some(RecoveredStableState {
                    previous_shutdown: PreviousShutdown::Unclean,
                    previous_boot: Some(BootRecord {
                        verifier: [0x77; 8],
                        boot_tag: 0x5566_7788,
                        started_at_unix_seconds: 1,
                        clean_shutdown: false,
                    }),
                    records: Vec::new(),
                }),
            },
            clock.clone(),
        )
        .unwrap();
        (fixture, clock)
    }

    #[tokio::test]
    async fn close_with_locks_held_does_not_release_the_backend_pin() {
        let fixture = Fixture::new();
        let client_id = confirmed_fixture_client(&fixture, b"compound-close-locks").await;
        let mut open_operations = enter_export();
        open_operations.extend([
            ArgOp::Open(OpenArgs {
                sequence_id: 1,
                share_access: super::super::types::OPEN4_SHARE_ACCESS_READ,
                share_deny: 0,
                owner: super::super::types::OpenOwner {
                    client_id,
                    owner: b"compound-close-owner".to_vec(),
                },
                how: OpenHow::NoCreate,
                claim: OpenClaim::Null(b"file".to_vec()),
            }),
            ArgOp::GetFh,
        ]);
        let opened = fixture.executor().execute(request(open_operations)).await;
        let open_state_id = match &opened.operations[2] {
            ResOp::Open(NfsResult::Ok(open)) => open.state_id,
            result => panic!("unexpected OPEN result: {result:?}"),
        };
        let filehandle = match &opened.operations[3] {
            ResOp::GetFh(NfsResult::Ok(filehandle)) => filehandle.clone(),
            result => panic!("unexpected GETFH result: {result:?}"),
        };

        let confirmed = fixture
            .executor()
            .execute(request(vec![
                ArgOp::PutFh(PutFhArgs {
                    object: filehandle.clone(),
                }),
                ArgOp::OpenConfirm(OpenConfirmArgs {
                    open_state_id,
                    sequence_id: 2,
                }),
            ]))
            .await;
        let open_state_id = match &confirmed.operations[1] {
            ResOp::OpenConfirm(NfsResult::Ok(state_id)) => *state_id,
            result => panic!("unexpected OPEN_CONFIRM result: {result:?}"),
        };
        // Exercise the compound integration seam: access is admitted before
        // delegation recall and the same RAII token is handed into the
        // runtime LOCK transition.
        let locked = fixture
            .executor()
            .execute(request(vec![
                ArgOp::PutFh(PutFhArgs {
                    object: filehandle.clone(),
                }),
                ArgOp::Lock(LockArgs {
                    lock_type: LockType::Read,
                    reclaim: false,
                    offset: 0,
                    length: 16,
                    locker: Locker::New(super::super::types::OpenToLockOwner {
                        open_sequence_id: 3,
                        open_state_id,
                        lock_sequence_id: 1,
                        lock_owner: super::super::types::LockOwner {
                            client_id,
                            owner: b"compound-close-lock-owner".to_vec(),
                        },
                    }),
                }),
            ]))
            .await;
        assert_eq!(locked.status, NfsStatus::Ok);
        assert!(matches!(locked.operations[1], ResOp::Lock(super::super::types::LockResult::Ok(_))));

        let closed = fixture
            .executor()
            .execute(request(vec![
                ArgOp::PutFh(PutFhArgs { object: filehandle }),
                ArgOp::Close(CloseArgs {
                    sequence_id: 4,
                    open_state_id,
                }),
            ]))
            .await;
        assert_eq!(closed.status, NfsStatus::LocksHeld);
        assert!(matches!(closed.operations[1], ResOp::Close(NfsResult::Err(NfsStatus::LocksHeld))));
        assert_eq!(fixture.vfs.release_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn remove_and_rename_have_no_backend_side_effects_during_grace() {
        let (fixture, clock) = recovering_fixture();

        let mut remove_operations = enter_export();
        remove_operations.push(ArgOp::Remove(RemoveArgs {
            target: b"file".to_vec(),
        }));
        let remove_during_grace = fixture.executor().execute(request(remove_operations.clone())).await;
        assert_eq!(remove_during_grace.status, NfsStatus::Grace);

        let mut rename_operations = enter_export();
        rename_operations.extend([
            ArgOp::SaveFh,
            ArgOp::Rename(RenameArgs {
                old_name: b"file".to_vec(),
                new_name: b"renamed".to_vec(),
            }),
        ]);
        let rename_during_grace = fixture.executor().execute(request(rename_operations.clone())).await;
        assert_eq!(rename_during_grace.status, NfsStatus::Grace);
        assert_eq!(fixture.vfs.remove_calls.load(Ordering::Relaxed), 0);
        assert_eq!(fixture.vfs.rename_calls.load(Ordering::Relaxed), 0);

        clock.advance(Duration::from_secs(90));
        assert!(fixture.runtime.finish_grace_if_due().await.unwrap());

        let remove_after_grace = fixture.executor().execute(request(remove_operations)).await;
        let rename_after_grace = fixture.executor().execute(request(rename_operations)).await;
        assert_eq!(remove_after_grace.status, NfsStatus::Ok);
        assert_eq!(rename_after_grace.status, NfsStatus::Ok);
        assert_eq!(fixture.vfs.remove_calls.load(Ordering::Relaxed), 1);
        assert_eq!(fixture.vfs.rename_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn callback_auth_uses_setclientid_gss_flavor_not_current_compound_flavor() {
        const KERBEROS_MECHANISM: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

        let fixture = Fixture::new();
        let setclientid_principal = Principal::Gss {
            canonical_name: "nfs/callback@example.test".to_owned(),
            mechanism: KERBEROS_MECHANISM.to_vec(),
            version: crate::vfs::GssVersion::V1,
            service: crate::vfs::GssService::Privacy,
        };
        let current_principal = Principal::Gss {
            canonical_name: "nfs/callback@example.test".to_owned(),
            mechanism: KERBEROS_MECHANISM.to_vec(),
            version: crate::vfs::GssVersion::V2,
            service: crate::vfs::GssService::Integrity,
        };
        let arguments = super::super::types::SetClientIdArgs {
            client: super::super::types::NfsClientId {
                verifier: [0x71; 8],
                id: b"callback-flavor-client".to_vec(),
            },
            callback: super::super::types::CallbackClient {
                program: 0x4000_0000,
                location: super::super::types::ClientAddress {
                    netid: b"tcp".to_vec(),
                    address: b"127.0.0.1.8.1".to_vec(),
                },
            },
            callback_identifier: 17,
        };
        let super::super::types::SetClientIdResult::Ok(set) =
            fixture.runtime.set_client_id(&arguments, &setclientid_principal).await.result
        else {
            panic!("GSS SETCLIENTID did not succeed");
        };
        assert_eq!(
            fixture
                .runtime
                .confirm_client(set.client_id, set.confirmation, &current_principal)
                .await
                .result,
            NfsStatus::Ok
        );

        let mut context = fixture.context.clone();
        context.principal = current_principal;
        let connector: Arc<dyn CallbackConnector> = Arc::new(UnusedCallbackConnector);
        let initiator: Arc<dyn GssInitiatorProvider> = Arc::new(UnusedGssInitiator);
        let executor = CompoundExecutor::new(
            &fixture.exports,
            &fixture.handles,
            &fixture.namespace,
            NamespaceNodeId::ROOT,
            &fixture.runtime,
            &fixture.open_pins,
            &fixture.delegations,
            None,
            None,
            &fixture.locations,
            &context,
            4,
            4,
            90,
            usize::MAX,
            Some(&connector),
            Duration::from_secs(5),
            Some(&initiator),
            Weak::new(),
        );
        let callback = executor.callback_client(set.client_id).await.unwrap();
        let callback_debug = format!("{callback:?}");
        assert!(callback_debug.contains("version: V1"), "{callback_debug}");
        assert!(callback_debug.contains("service: Privacy"), "{callback_debug}");
        assert!(!callback_debug.contains("service: Integrity"), "{callback_debug}");
    }

    fn enter_overlay_projects() -> Vec<ArgOp> {
        vec![
            ArgOp::PutRootFh,
            ArgOp::Lookup(super::super::types::LookupArgs { name: b"srv".to_vec() }),
            ArgOp::Lookup(super::super::types::LookupArgs {
                name: b"projects".to_vec(),
            }),
        ]
    }

    #[tokio::test]
    async fn minor_version_mismatch_echoes_tag_without_executing() {
        let fixture = Fixture::new();
        let response = fixture
            .executor()
            .execute(CompoundArgs {
                tag: b"minor".to_vec(),
                minor_version: 1,
                operations: vec![
                    ArgOp::PutRootFh,
                    ArgOp::GetAttr(GetAttrArgs {
                        requested_attributes: vec![1],
                    }),
                ],
            })
            .await;

        assert_eq!(response.status, NfsStatus::MinorVersionMismatch);
        assert_eq!(response.tag, b"minor");
        assert!(response.operations.is_empty());
        assert_eq!(fixture.vfs.getattr_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn current_and_saved_filehandles_cross_the_pseudo_export_junction() {
        let fixture = Fixture::new();
        let response = fixture
            .executor()
            .execute(request(vec![
                ArgOp::PutRootFh,
                ArgOp::SaveFh,
                ArgOp::Lookup(super::super::types::LookupArgs {
                    name: b"export".to_vec(),
                }),
                ArgOp::GetFh,
                ArgOp::RestoreFh,
                ArgOp::GetFh,
            ]))
            .await;

        assert_eq!(response.status, NfsStatus::Ok);
        let backend = match &response.operations[3] {
            ResOp::GetFh(NfsResult::Ok(handle)) => fixture.handles.decode_target(handle.as_bytes()).unwrap(),
            other => panic!("unexpected result: {other:?}"),
        };
        assert_eq!(
            backend,
            HandleTarget::Backend {
                export_id: ExportId(7),
                object: ROOT,
                namespace_node: Some(1),
            }
        );
        let restored = match &response.operations[5] {
            ResOp::GetFh(NfsResult::Ok(handle)) => fixture.handles.decode_target(handle.as_bytes()).unwrap(),
            other => panic!("unexpected result: {other:?}"),
        };
        assert_eq!(restored, HandleTarget::Pseudo { namespace_node: 0 });
    }

    #[tokio::test]
    async fn putpubfh_uses_the_configured_namespace_path() {
        let fixture = Fixture::new();
        let public_node = fixture.namespace.resolve_absolute_path("/export").unwrap();
        let response = fixture
            .executor_with_public_filehandle_node(public_node)
            .execute(request(vec![ArgOp::PutPublicFh, ArgOp::GetFh]))
            .await;

        assert_eq!(response.status, NfsStatus::Ok);
        let target = match &response.operations[1] {
            ResOp::GetFh(NfsResult::Ok(handle)) => fixture.handles.decode_target(handle.as_bytes()).unwrap(),
            other => panic!("unexpected result: {other:?}"),
        };
        assert_eq!(
            target,
            HandleTarget::Backend {
                export_id: ExportId(7),
                object: ROOT,
                namespace_node: Some(public_node.get()),
            }
        );
    }

    #[tokio::test]
    async fn stops_after_first_error_and_does_not_apply_later_fh_changes() {
        let fixture = Fixture::new();
        let response = fixture.executor().execute(request(vec![ArgOp::GetFh, ArgOp::PutRootFh])).await;

        assert_eq!(response.status, NfsStatus::NoFileHandle);
        assert_eq!(response.operations, vec![ResOp::GetFh(NfsResult::Err(NfsStatus::NoFileHandle))]);
    }

    #[tokio::test]
    async fn getattr_verify_nverify_access_read_and_commit_execute_sequentially() {
        let fixture = Fixture::new();
        let requested_attributes =
            bitmap_from_attributes([FATTR4_TYPE, FATTR4_SIZE, FATTR4_FILEHANDLE, FATTR4_MODE]).unwrap();
        let mut first = enter_export();
        first.push(ArgOp::Lookup(super::super::types::LookupArgs { name: b"file".to_vec() }));
        first.push(ArgOp::GetAttr(GetAttrArgs {
            requested_attributes: requested_attributes.clone(),
        }));
        let first_response = fixture.executor().execute(request(first)).await;
        let mut expected = match &first_response.operations[3] {
            ResOp::GetAttr(NfsResult::Ok(attributes)) => attributes.clone(),
            other => panic!("unexpected result: {other:?}"),
        };
        // A bitmap4 may contain trailing zero words; they do not alter the
        // selected attribute set and therefore must not make VERIFY fail.
        expected.mask.push(0);
        let mut different = expected.clone();
        *different.values.last_mut().expect("MODE value is present") ^= 1;

        let mut operations = enter_export();
        operations.extend([
            ArgOp::Lookup(super::super::types::LookupArgs { name: b"file".to_vec() }),
            ArgOp::Access(AccessArgs {
                access: ACCESS4_READ | ACCESS4_MODIFY,
            }),
            ArgOp::Verify(VerifyArgs { attributes: expected }),
            ArgOp::NotVerify(NotVerifyArgs { attributes: different }),
            ArgOp::Read(ReadArgs {
                state_id: ANONYMOUS_STATE_ID,
                offset: 0,
                count: 64,
            }),
            ArgOp::Commit(CommitArgs { offset: 0, count: 0 }),
        ]);
        let response = fixture.executor().execute(request(operations)).await;

        assert_eq!(response.status, NfsStatus::Ok);
        assert_eq!(
            response.operations[3],
            ResOp::Access(NfsResult::Ok(AccessOk {
                supported: ACCESS4_READ | ACCESS4_MODIFY,
                access: ACCESS4_READ,
            }))
        );
        assert_eq!(response.operations[4], ResOp::Verify(NfsStatus::Ok));
        assert_eq!(response.operations[5], ResOp::NotVerify(NfsStatus::Ok));
        assert_eq!(
            response.operations[6],
            ResOp::Read(NfsResult::Ok(ReadOk {
                eof: false,
                data: b"abcd".to_vec(),
            }))
        );
        assert_eq!(
            response.operations[7],
            ResOp::Commit(NfsResult::Ok(CommitOk {
                write_verifier: [0x11; 8],
            }))
        );
        assert_eq!(fixture.vfs.commit_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn object_type_rules_are_enforced_before_backend_io_or_state_checks() {
        let fixture = Fixture::new();

        let mut lookup_through_symlink = enter_export();
        lookup_through_symlink.extend([
            ArgOp::Lookup(super::super::types::LookupArgs { name: b"link".to_vec() }),
            ArgOp::Lookup(super::super::types::LookupArgs {
                name: b"child".to_vec(),
            }),
        ]);
        assert_eq!(fixture.executor().execute(request(lookup_through_symlink)).await.status, NfsStatus::Symlink);

        let mut read_directory = enter_export();
        read_directory.push(ArgOp::Read(ReadArgs {
            state_id: ANONYMOUS_STATE_ID,
            offset: 0,
            count: 1,
        }));
        assert_eq!(fixture.executor().execute(request(read_directory)).await.status, NfsStatus::IsDirectory);

        for (name, expected) in [
            (b"link".as_slice(), NfsStatus::Invalid),
            (b"created", NfsStatus::IsDirectory),
        ] {
            let mut commit = enter_export();
            commit.extend([
                ArgOp::Lookup(super::super::types::LookupArgs { name: name.to_vec() }),
                ArgOp::Commit(CommitArgs { offset: 0, count: 0 }),
            ]);
            assert_eq!(fixture.executor().execute(request(commit)).await.status, expected);

            let mut lock_test = enter_export();
            lock_test.extend([
                ArgOp::Lookup(super::super::types::LookupArgs { name: name.to_vec() }),
                ArgOp::LockTest(LockTestArgs {
                    lock_type: LockType::Read,
                    offset: 0,
                    length: 1,
                    owner: super::super::types::LockOwner {
                        client_id: 0,
                        owner: b"type-check".to_vec(),
                    },
                }),
            ]);
            assert_eq!(fixture.executor().execute(request(lock_test)).await.status, expected);
        }
        assert_eq!(fixture.vfs.commit_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn access_reports_only_rights_meaningful_for_the_object_type() {
        let fixture = Fixture::new();

        let mut directory = enter_export();
        directory.push(ArgOp::Access(AccessArgs {
            access: VALID_ACCESS_MASK,
        }));
        let directory = fixture.executor().execute(request(directory)).await;
        assert_eq!(
            directory.operations.last(),
            Some(&ResOp::Access(NfsResult::Ok(AccessOk {
                supported: VALID_ACCESS_MASK & !ACCESS4_EXECUTE,
                access: (VALID_ACCESS_MASK & !ACCESS4_EXECUTE) & !ACCESS4_MODIFY,
            })))
        );

        let mut regular = enter_export();
        regular.extend([
            ArgOp::Lookup(super::super::types::LookupArgs { name: b"file".to_vec() }),
            ArgOp::Access(AccessArgs {
                access: VALID_ACCESS_MASK,
            }),
        ]);
        let regular = fixture.executor().execute(request(regular)).await;
        assert_eq!(
            regular.operations.last(),
            Some(&ResOp::Access(NfsResult::Ok(AccessOk {
                supported: VALID_ACCESS_MASK & !(ACCESS4_LOOKUP | ACCESS4_DELETE),
                access: (VALID_ACCESS_MASK & !(ACCESS4_LOOKUP | ACCESS4_DELETE)) & !ACCESS4_MODIFY,
            })))
        );
    }

    #[tokio::test]
    async fn open_and_link_enforce_source_and_target_object_types() {
        let fixture = Fixture::new();
        let client_id = confirmed_fixture_client(&fixture, b"open-type-client").await;
        let open = |sequence_id, component: &[u8]| {
            ArgOp::Open(OpenArgs {
                sequence_id,
                share_access: 1,
                share_deny: 0,
                owner: super::super::types::OpenOwner {
                    client_id,
                    owner: b"open-type-owner".to_vec(),
                },
                how: OpenHow::NoCreate,
                claim: OpenClaim::Null(component.to_vec()),
            })
        };

        let mut symlink = enter_export();
        symlink.push(open(1, b"link"));
        assert_eq!(fixture.executor().execute(request(symlink)).await.status, NfsStatus::Symlink);

        let mut directory = enter_export();
        directory.push(open(2, b"created"));
        assert_eq!(fixture.executor().execute(request(directory)).await.status, NfsStatus::IsDirectory);
        assert_eq!(fixture.vfs.open_preflight_calls.load(Ordering::Relaxed), 2);
        assert_eq!(fixture.vfs.open_calls.load(Ordering::Relaxed), 0);

        let mut directory_source = enter_export();
        directory_source.extend([
            ArgOp::SaveFh,
            ArgOp::Link(LinkArgs {
                new_name: b"hardlink".to_vec(),
            }),
        ]);
        assert_eq!(fixture.executor().execute(request(directory_source)).await.status, NfsStatus::IsDirectory);

        let mut non_directory_target = enter_export();
        non_directory_target.extend([
            ArgOp::Lookup(super::super::types::LookupArgs { name: b"file".to_vec() }),
            ArgOp::SaveFh,
            ArgOp::Link(LinkArgs {
                new_name: b"hardlink".to_vec(),
            }),
        ]);
        assert_eq!(fixture.executor().execute(request(non_directory_target)).await.status, NfsStatus::NotDirectory);
    }

    #[tokio::test]
    async fn protocol_components_and_empty_identity_strings_are_rejected_precisely() {
        for value in [b".".as_slice(), b"..", b"a/b"] {
            assert_eq!(validate_component_name(value), Err(NfsStatus::BadName));
        }
        assert_eq!(validate_component_name(b""), Err(NfsStatus::Invalid));
        assert_eq!(validate_component_name(&[0xff]), Err(NfsStatus::Invalid));
        assert_eq!(validate_symlink_target(b""), Err(NfsStatus::Invalid));

        let fixture = Fixture::new();
        let mapper: Arc<dyn IdentityMapper> = Arc::new(crate::vfs::NumericIdentityMapper::new(""));
        for attribute in [FATTR4_OWNER, FATTR4_OWNER_GROUP] {
            let mut encoded = AttributeEncoder::new();
            encoded.push_opaque(attribute, b"").unwrap();
            let mut operations = enter_export();
            operations.extend([
                ArgOp::Lookup(super::super::types::LookupArgs { name: b"file".to_vec() }),
                ArgOp::SetAttr(SetAttrArgs {
                    state_id: ANONYMOUS_STATE_ID,
                    attributes: encoded.finish(),
                }),
            ]);
            assert_eq!(
                fixture
                    .executor_with_identity_mapper(&mapper)
                    .execute(request(operations))
                    .await
                    .status,
                NfsStatus::Invalid
            );
        }

        let mut create_empty_symlink = enter_export();
        create_empty_symlink.push(ArgOp::Create(CreateArgs {
            object_type: CreateType::Symlink(Vec::new()),
            name: b"empty-target".to_vec(),
            attributes: FileAttributes {
                mask: Vec::new(),
                values: Vec::new(),
            },
        }));
        assert_eq!(fixture.executor().execute(request(create_empty_symlink)).await.status, NfsStatus::Invalid);
    }

    #[tokio::test]
    async fn configured_fsid_expiration_and_mountpoint_identity_are_reported() {
        let fixture = Fixture::new();
        let mut operations = enter_export();
        operations.push(ArgOp::GetAttr(GetAttrArgs {
            requested_attributes: bitmap_from_attributes([
                FATTR4_FH_EXPIRE_TYPE,
                FATTR4_FSID,
                FATTR4_MOUNTED_ON_FILEID,
            ])
            .unwrap(),
        }));
        let response = fixture.executor().execute(request(operations)).await;

        let attributes = match &response.operations[2] {
            ResOp::GetAttr(NfsResult::Ok(attributes)) => attributes,
            other => panic!("unexpected result: {other:?}"),
        };
        let mut expected = Vec::new();
        expected.extend_from_slice(&FH4_VOLATILE_ANY.to_be_bytes());
        expected.extend_from_slice(&0_u64.to_be_bytes());
        expected.extend_from_slice(&1_u64.to_be_bytes());
        expected.extend_from_slice(&1_u64.to_be_bytes());
        assert_eq!(attributes.values, expected);
    }

    #[tokio::test]
    async fn unsupported_recommended_getattr_values_are_omitted() {
        let fixture = Fixture::new();
        let mut operations = enter_export();
        operations.push(ArgOp::GetAttr(GetAttrArgs {
            requested_attributes: bitmap_from_attributes([FATTR4_QUOTA_USED]).unwrap(),
        }));
        let response = fixture.executor().execute(request(operations)).await;

        assert_eq!(response.status, NfsStatus::Ok);
        let attributes = match &response.operations[2] {
            ResOp::GetAttr(NfsResult::Ok(attributes)) => attributes,
            other => panic!("unexpected result: {other:?}"),
        };
        assert!(attributes.mask.is_empty());
        assert!(attributes.values.is_empty());
    }

    #[tokio::test]
    async fn configured_replication_locations_are_exposed_by_getattr() {
        let mut fixture = Fixture::new();
        fixture.locations.insert(
            ExportId(7),
            Nfs4FsLocations {
                fs_root: vec!["export".to_owned()],
                locations: vec![Nfs4FsLocation {
                    servers: vec!["replica.example.test".to_owned()],
                    root_path: vec!["srv".to_owned(), "export".to_owned()],
                }],
            },
        );
        let mut operations = enter_export();
        operations.push(ArgOp::GetAttr(GetAttrArgs {
            requested_attributes: bitmap_from_attributes([FATTR4_FS_LOCATIONS]).unwrap(),
        }));
        let response = fixture.executor().execute(request(operations)).await;

        assert_eq!(response.status, NfsStatus::Ok);
        let attributes = match &response.operations[2] {
            ResOp::GetAttr(NfsResult::Ok(attributes)) => attributes,
            other => panic!("unexpected result: {other:?}"),
        };
        assert!(bitmap_contains(&attributes.mask, FATTR4_FS_LOCATIONS));
        assert!(!attributes.values.is_empty());
    }

    #[tokio::test]
    async fn moved_response_records_client_obligation_and_getattr_probe_with_renew_clears_it() {
        let fixture = Fixture::new();
        let client_id = confirmed_fixture_client(&fixture, b"migration-client").await;
        fixture.vfs.location_state.store(1, Ordering::Relaxed);

        let mut moved_operations = enter_export();
        moved_operations.push(ArgOp::Open(OpenArgs {
            sequence_id: 1,
            share_access: 1,
            share_deny: 0,
            owner: super::super::types::OpenOwner {
                client_id,
                owner: b"migration-open-owner".to_vec(),
            },
            how: OpenHow::NoCreate,
            claim: OpenClaim::Null(b"file".to_vec()),
        }));
        let moved = fixture.executor().execute(request(moved_operations)).await;
        assert_eq!(moved.status, NfsStatus::Moved);
        assert!(matches!(moved.operations.last(), Some(ResOp::Open(NfsResult::Err(NfsStatus::Moved)))));
        assert_eq!(fixture.runtime.renew(client_id, &Principal::Anonymous).await, NfsStatus::LeaseMoved);

        let mut probe_operations = enter_export();
        probe_operations.extend([
            ArgOp::GetAttr(GetAttrArgs {
                requested_attributes: bitmap_from_attributes([FATTR4_FS_LOCATIONS]).unwrap(),
            }),
            ArgOp::Renew(super::super::types::RenewArgs { client_id }),
        ]);
        let probe = fixture.executor().execute(request(probe_operations)).await;
        assert_eq!(probe.status, NfsStatus::Ok);
        assert!(matches!(probe.operations.last(), Some(ResOp::Renew(NfsStatus::Ok))));
        assert_eq!(fixture.runtime.renew(client_id, &Principal::Anonymous).await, NfsStatus::Ok);
    }

    #[test]
    fn backend_location_data_is_validated_before_encoding() {
        let malformed = Nfs4LocationState::Absent(Nfs4FsLocations {
            fs_root: vec!["export".to_owned()],
            locations: vec![Nfs4FsLocation {
                servers: Vec::new(),
                root_path: vec!["export".to_owned()],
            }],
        });
        assert_eq!(validate_location_state(ExportId(7), malformed), Err(NfsStatus::ServerFault));

        let excessive = Nfs4LocationState::Present(Nfs4FsLocations {
            fs_root: Vec::new(),
            locations: (0..65)
                .map(|index| Nfs4FsLocation {
                    servers: vec![format!("replica-{index}.example.test")],
                    root_path: vec!["export".to_owned()],
                })
                .collect(),
        });
        assert_eq!(validate_location_state(ExportId(7), excessive), Err(NfsStatus::Resource));
    }

    #[tokio::test]
    async fn compound_reply_budget_preserves_multiple_reads_at_the_exact_boundary() {
        let operations = {
            let mut operations = enter_export();
            operations.extend([
                ArgOp::Lookup(super::super::types::LookupArgs { name: b"file".to_vec() }),
                ArgOp::Read(ReadArgs {
                    state_id: ANONYMOUS_STATE_ID,
                    offset: 0,
                    count: 4,
                }),
                ArgOp::Read(ReadArgs {
                    state_id: ANONYMOUS_STATE_ID,
                    offset: 4,
                    count: 4,
                }),
            ]);
            operations
        };
        let baseline_fixture = Fixture::new();
        let baseline = baseline_fixture.executor().execute(request(operations.clone())).await;
        let exact_limit = encode_compound_res(&baseline).unwrap().len();

        let bounded_fixture = Fixture::new();
        let bounded = bounded_fixture
            .executor_with_limits(4, exact_limit)
            .execute(request(operations))
            .await;

        assert_eq!(bounded, baseline);
        assert_eq!(encode_compound_res(&bounded).unwrap().len(), exact_limit);
    }

    #[tokio::test]
    async fn read_is_capped_to_reserve_a_later_mutation_result() {
        let fixture = Fixture::new();
        let mut prefix = enter_export();
        prefix.push(ArgOp::Lookup(super::super::types::LookupArgs { name: b"file".to_vec() }));
        let prefix_response = fixture.executor().execute(request(prefix.clone())).await;
        let prefix_size = encode_compound_res(&prefix_response).unwrap().len();

        let mut set_attributes = AttributeEncoder::new();
        set_attributes.push_u32(FATTR4_MODE, 0o600).unwrap();
        let mut operations = prefix;
        operations.extend([
            ArgOp::Read(ReadArgs {
                state_id: ANONYMOUS_STATE_ID,
                offset: 0,
                count: u32::MAX,
            }),
            ArgOp::SetAttr(SetAttrArgs {
                state_id: ANONYMOUS_STATE_ID,
                attributes: set_attributes.finish(),
            }),
        ]);
        let exact_read_and_reserve = prefix_size + 20 + SIDE_EFFECT_RESULT_RESERVE;
        let response = fixture
            .executor_with_limits(u32::MAX, exact_read_and_reserve)
            .execute(request(operations))
            .await;

        match &response.operations[3] {
            ResOp::Read(NfsResult::Ok(read)) => assert_eq!(read.data, b"abcd"),
            other => panic!("unexpected READ result: {other:?}"),
        }
        assert_eq!(response.operations[4].status(), NfsStatus::Ok);
        assert_eq!(fixture.vfs.setattr_calls.load(Ordering::Relaxed), 1);
        assert!(encode_compound_res(&response).unwrap().len() <= exact_read_and_reserve);
    }

    #[tokio::test]
    async fn insufficient_mutation_reserve_stops_before_backend_side_effects() {
        let fixture = Fixture::new();
        let mut prefix = enter_export();
        prefix.push(ArgOp::Lookup(super::super::types::LookupArgs { name: b"file".to_vec() }));
        let prefix_response = fixture.executor().execute(request(prefix.clone())).await;
        let prefix_size = encode_compound_res(&prefix_response).unwrap().len();

        let mut set_attributes = AttributeEncoder::new();
        set_attributes.push_u32(FATTR4_MODE, 0o600).unwrap();
        let mut operations = prefix;
        operations.extend([
            ArgOp::Read(ReadArgs {
                state_id: ANONYMOUS_STATE_ID,
                offset: 0,
                count: u32::MAX,
            }),
            ArgOp::SetAttr(SetAttrArgs {
                state_id: ANONYMOUS_STATE_ID,
                attributes: set_attributes.finish(),
            }),
        ]);
        let response = fixture
            .executor_with_limits(u32::MAX, prefix_size + SIDE_EFFECT_RESULT_RESERVE + 7)
            .execute(request(operations))
            .await;

        assert!(matches!(response.operations.last(), Some(ResOp::Read(NfsResult::Err(NfsStatus::Resource)))));
        assert_eq!(fixture.vfs.setattr_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn mutation_reply_reserve_never_hides_an_executed_first_mutation() {
        let fixture = Fixture::new();
        let mut prefix = enter_export();
        prefix.push(ArgOp::Lookup(super::super::types::LookupArgs { name: b"file".to_vec() }));
        let prefix_response = fixture.executor().execute(request(prefix.clone())).await;
        let prefix_size = encode_compound_res(&prefix_response).unwrap().len();

        let mut attributes = AttributeEncoder::new();
        attributes.push_u32(FATTR4_MODE, 0o600).unwrap();
        let arguments = SetAttrArgs {
            state_id: ANONYMOUS_STATE_ID,
            attributes: attributes.finish(),
        };
        let mut operations = prefix;
        operations.extend([ArgOp::SetAttr(arguments.clone()), ArgOp::SetAttr(arguments)]);
        let limit = prefix_size + SIDE_EFFECT_RESULT_RESERVE + SIMPLE_ERROR_RESULT_BYTES;
        let response = fixture.executor_with_limits(u32::MAX, limit).execute(request(operations)).await;

        assert_eq!(response.operations[3].status(), NfsStatus::Ok);
        assert_eq!(response.operations[4].status(), NfsStatus::Resource);
        assert_eq!(fixture.vfs.setattr_calls.load(Ordering::Relaxed), 1);
        assert!(encode_compound_res(&response).unwrap().len() <= limit);
    }

    #[tokio::test]
    async fn read_directory_honors_the_remaining_compound_budget() {
        let fixture = Fixture::new();
        let prefix = fixture.executor().execute(request(vec![ArgOp::PutRootFh])).await;
        let prefix_size = encode_compound_res(&prefix).unwrap().len();
        let empty_resok = read_dir_result_size(&ReadDirOk {
            cookie_verifier: [0; 8],
            entries: Vec::new(),
            eof: false,
        });
        let limit = prefix_size + 8 + empty_resok;
        let response = fixture
            .executor_with_limits(u32::MAX, limit)
            .execute(request(vec![
                ArgOp::PutRootFh,
                ArgOp::ReadDir(ReadDirArgs {
                    cookie: 0,
                    cookie_verifier: [0; 8],
                    directory_count: 0,
                    max_count: u32::MAX,
                    requested_attributes: Vec::new(),
                }),
            ]))
            .await;

        assert!(matches!(response.operations.last(), Some(ResOp::ReadDir(NfsResult::Err(NfsStatus::TooSmall)))));
        assert!(encode_compound_res(&response).unwrap().len() <= limit);
    }

    #[tokio::test]
    async fn unstable_write_is_stabilized_before_later_synchronous_mutation() {
        let fixture = Fixture::new();
        let mut set_attributes = AttributeEncoder::new();
        set_attributes.push_u32(FATTR4_MODE, 0o600).unwrap();
        let mut operations = enter_export();
        operations.extend([
            ArgOp::Lookup(super::super::types::LookupArgs { name: b"file".to_vec() }),
            ArgOp::Write(WriteArgs {
                state_id: ANONYMOUS_STATE_ID,
                offset: 0,
                stability: StableHow::Unstable,
                data: b"data".to_vec(),
            }),
            ArgOp::SetAttr(SetAttrArgs {
                state_id: ANONYMOUS_STATE_ID,
                attributes: set_attributes.finish(),
            }),
        ]);
        let response = fixture.executor().execute(request(operations)).await;

        assert_eq!(response.status, NfsStatus::Ok);
        assert_eq!(fixture.vfs.commit_calls.load(Ordering::Relaxed), 1);
        assert_eq!(fixture.vfs.setattr_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn write_rejects_less_stability_than_requested_and_zero_progress() {
        let fixture = Fixture::new();
        let write = |stability| {
            let mut operations = enter_export();
            operations.extend([
                ArgOp::Lookup(super::super::types::LookupArgs { name: b"file".to_vec() }),
                ArgOp::Write(WriteArgs {
                    state_id: ANONYMOUS_STATE_ID,
                    offset: 0,
                    stability,
                    data: b"data".to_vec(),
                }),
            ]);
            request(operations)
        };

        let under_stable = fixture.executor().execute(write(StableHow::FileSync)).await;
        assert_eq!(under_stable.status, NfsStatus::ServerFault);
        assert!(matches!(under_stable.operations.last(), Some(ResOp::Write(NfsResult::Err(NfsStatus::ServerFault)))));

        fixture.vfs.write_count.store(0, Ordering::Relaxed);
        let zero_progress = fixture.executor().execute(write(StableHow::Unstable)).await;
        assert_eq!(zero_progress.status, NfsStatus::ServerFault);
    }

    #[tokio::test]
    async fn zero_length_write_authorizes_without_mutating_data_or_times() {
        let fixture = Fixture::new();
        let before = fixture.vfs.attributes(FILE).unwrap();
        let mut operations = enter_export();
        operations.extend([
            ArgOp::Lookup(super::super::types::LookupArgs { name: b"file".to_vec() }),
            ArgOp::Write(WriteArgs {
                state_id: ANONYMOUS_STATE_ID,
                offset: u64::MAX,
                stability: StableHow::FileSync,
                data: Vec::new(),
            }),
        ]);

        let response = fixture.executor().execute(request(operations)).await;

        assert_eq!(response.status, NfsStatus::Ok);
        assert_eq!(fixture.vfs.zero_length_write_checks.load(Ordering::Relaxed), 1);
        assert_eq!(fixture.vfs.write_calls.load(Ordering::Relaxed), 0);
        assert_eq!(fixture.vfs.attributes(FILE).unwrap(), before);
        assert!(matches!(
            response.operations.last(),
            Some(ResOp::Write(NfsResult::Ok(WriteOk {
                count: 0,
                committed: StableHow::FileSync,
                ..
            })))
        ));
    }

    #[tokio::test]
    async fn zero_length_write_returns_backend_access_and_read_only_errors() {
        let fixture = Fixture::new();
        for (backend_error, expected) in [(1, NfsStatus::Access), (2, NfsStatus::ReadOnly)] {
            fixture.vfs.zero_length_write_error.store(backend_error, Ordering::Relaxed);
            let mut operations = enter_export();
            operations.extend([
                ArgOp::Lookup(super::super::types::LookupArgs { name: b"file".to_vec() }),
                ArgOp::Write(WriteArgs {
                    state_id: ANONYMOUS_STATE_ID,
                    offset: 0,
                    stability: StableHow::FileSync,
                    data: Vec::new(),
                }),
            ]);
            let response = fixture.executor().execute(request(operations)).await;
            assert_eq!(response.status, expected, "{response:?}");
        }
        assert_eq!(fixture.vfs.zero_length_write_checks.load(Ordering::Relaxed), 2);
        assert_eq!(fixture.vfs.write_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn zero_length_write_rejects_non_regular_objects_before_state_validation() {
        let fixture = Fixture::new();
        for (name, expected) in [
            (b"created".as_slice(), NfsStatus::IsDirectory),
            (b"link", NfsStatus::Invalid),
        ] {
            let mut operations = enter_export();
            operations.extend([
                ArgOp::Lookup(super::super::types::LookupArgs { name: name.to_vec() }),
                ArgOp::Write(WriteArgs {
                    state_id: ANONYMOUS_STATE_ID,
                    offset: 0,
                    stability: StableHow::FileSync,
                    data: Vec::new(),
                }),
            ]);
            assert_eq!(fixture.executor().execute(request(operations)).await.status, expected);
        }
        assert_eq!(fixture.vfs.zero_length_write_checks.load(Ordering::Relaxed), 0);
        assert_eq!(fixture.vfs.write_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn metadata_setattr_accepts_a_delegation_stateid_and_renews_its_client() {
        let (mut fixture, clock) = leased_fixture();
        let client_id = confirmed_fixture_client(&fixture, b"setattr-delegation-client").await;
        assert_eq!(fixture.runtime.renew(client_id, &Principal::Anonymous).await, NfsStatus::Ok);
        let delegation_clock = Arc::new(ManualCallbackClock::default());
        let delegation =
            grant_fixture_write_delegation(&mut fixture, client_id, ExportId(7), delegation_clock.clone(), 9).await;
        clock.advance(Duration::from_secs(9));

        let mut attributes = AttributeEncoder::new();
        attributes.push_u32(FATTR4_MODE, 0o600).unwrap();
        let mut operations = enter_export();
        operations.extend([
            ArgOp::Lookup(super::super::types::LookupArgs { name: b"file".to_vec() }),
            ArgOp::SetAttr(SetAttrArgs {
                state_id: delegation.state_id,
                attributes: attributes.finish(),
            }),
        ]);
        let response = fixture.executor().execute(request(operations)).await;
        assert_eq!(response.status, NfsStatus::Ok, "{response:?}");
        assert_eq!(fixture.vfs.setattr_calls.load(Ordering::Relaxed), 1);

        // Without the stateid-based renewal this client would have expired at
        // t=10.  RFC 7530 sections 9.1.4.6 and 9.5 require it to remain live.
        clock.advance(Duration::from_secs(9));
        let _ = fixture.runtime.expire_due().await;
        assert_eq!(fixture.runtime.validate_client(client_id, &Principal::Anonymous).await, NfsStatus::Ok);
    }

    #[tokio::test]
    async fn delegreturn_renews_the_owning_client_before_removing_the_delegation() {
        let (mut fixture, clock) = leased_fixture();
        let client_id = confirmed_fixture_client(&fixture, b"delegreturn-lease-client").await;
        assert_eq!(fixture.runtime.renew(client_id, &Principal::Anonymous).await, NfsStatus::Ok);
        let delegation_clock = Arc::new(ManualCallbackClock::default());
        let delegation =
            grant_fixture_write_delegation(&mut fixture, client_id, ExportId(7), delegation_clock.clone(), 9).await;
        clock.advance(Duration::from_secs(9));

        let mut operations = enter_export();
        operations.extend([
            ArgOp::Lookup(super::super::types::LookupArgs { name: b"file".to_vec() }),
            ArgOp::DelegReturn(super::super::types::DelegReturnArgs {
                delegation_state_id: delegation.state_id,
            }),
        ]);
        assert_eq!(fixture.executor().execute(request(operations)).await.status, NfsStatus::Ok);

        // A successful DELEGRETURN is an implicit lease renewal under RFC
        // 7530 section 9.5, even though it removes the delegation itself.
        clock.advance(Duration::from_secs(9));
        let _ = fixture.runtime.expire_due().await;
        assert_eq!(fixture.runtime.validate_client(client_id, &Principal::Anonymous).await, NfsStatus::Ok);
    }

    #[tokio::test]
    async fn delegreturn_renews_delegations_held_on_every_export() {
        let (mut fixture, runtime_clock) = leased_fixture();
        let delegation_clock = Arc::new(ManualCallbackClock::default());
        let client_id = confirmed_fixture_client(&fixture, b"delegreturn-all-exports-client").await;
        assert_eq!(fixture.runtime.renew(client_id, &Principal::Anonymous).await, NfsStatus::Ok);
        let returned =
            grant_fixture_write_delegation(&mut fixture, client_id, ExportId(7), delegation_clock.clone(), 9).await;
        let _retained =
            grant_fixture_write_delegation(&mut fixture, client_id, ExportId(8), delegation_clock.clone(), 10).await;
        let retained_manager = fixture.delegations.get(&ExportId(8)).unwrap().clone();

        runtime_clock.advance(Duration::from_secs(9));
        delegation_clock.advance(Duration::from_secs(9));
        let mut operations = enter_export();
        operations.extend([
            ArgOp::Lookup(super::super::types::LookupArgs { name: b"file".to_vec() }),
            ArgOp::DelegReturn(super::super::types::DelegReturnArgs {
                delegation_state_id: returned.state_id,
            }),
        ]);
        assert_eq!(fixture.executor().execute(request(operations)).await.status, NfsStatus::Ok);

        // The retained delegation was granted by a different manager.  It
        // would expire at t=10 without the §9.5 all-export renewal.
        runtime_clock.advance(Duration::from_secs(9));
        delegation_clock.advance(Duration::from_secs(9));
        assert!(retained_manager.revoke_expired().await.unwrap().is_empty());
        assert_eq!(retained_manager.active_counts().await, (0, 1));
        assert_eq!(fixture.runtime.validate_client(client_id, &Principal::Anonymous).await, NfsStatus::Ok);
    }

    #[tokio::test]
    async fn non_size_setattr_renews_delegations_held_on_every_export() {
        let (mut fixture, runtime_clock) = leased_fixture();
        let delegation_clock = Arc::new(ManualCallbackClock::default());
        let client_id = confirmed_fixture_client(&fixture, b"setattr-all-exports-client").await;
        assert_eq!(fixture.runtime.renew(client_id, &Principal::Anonymous).await, NfsStatus::Ok);
        let delegation =
            grant_fixture_write_delegation(&mut fixture, client_id, ExportId(7), delegation_clock.clone(), 9).await;
        let _retained =
            grant_fixture_write_delegation(&mut fixture, client_id, ExportId(8), delegation_clock.clone(), 10).await;
        let retained_manager = fixture.delegations.get(&ExportId(8)).unwrap().clone();

        runtime_clock.advance(Duration::from_secs(9));
        delegation_clock.advance(Duration::from_secs(9));
        let mut attributes = AttributeEncoder::new();
        attributes.push_u32(FATTR4_MODE, 0o600).unwrap();
        let mut operations = enter_export();
        operations.extend([
            ArgOp::Lookup(super::super::types::LookupArgs { name: b"file".to_vec() }),
            ArgOp::SetAttr(SetAttrArgs {
                state_id: delegation.state_id,
                attributes: attributes.finish(),
            }),
        ]);
        assert_eq!(fixture.executor().execute(request(operations)).await.status, NfsStatus::Ok);

        runtime_clock.advance(Duration::from_secs(9));
        delegation_clock.advance(Duration::from_secs(9));
        assert!(retained_manager.revoke_expired().await.unwrap().is_empty());
        assert_eq!(retained_manager.active_counts().await, (0, 1));
        assert_eq!(fixture.runtime.validate_client(client_id, &Principal::Anonymous).await, NfsStatus::Ok);
    }

    #[tokio::test]
    async fn read_with_open_stateid_renews_delegations_held_on_every_export() {
        let (mut fixture, runtime_clock) = leased_fixture();
        let delegation_clock = Arc::new(ManualCallbackClock::default());
        let client_id = confirmed_fixture_client(&fixture, b"read-all-exports-client").await;
        assert_eq!(fixture.runtime.renew(client_id, &Principal::Anonymous).await, NfsStatus::Ok);
        let (open_state_id, _) = open_fixture_file_state(&fixture, client_id, b"read-open-owner").await;
        let _retained =
            grant_fixture_write_delegation(&mut fixture, client_id, ExportId(8), delegation_clock.clone(), 11).await;
        let retained_manager = fixture.delegations.get(&ExportId(8)).unwrap().clone();

        runtime_clock.advance(Duration::from_secs(9));
        delegation_clock.advance(Duration::from_secs(9));
        let mut operations = enter_export();
        operations.extend([
            ArgOp::Lookup(super::super::types::LookupArgs { name: b"file".to_vec() }),
            ArgOp::Read(ReadArgs {
                state_id: open_state_id,
                offset: 0,
                count: 1,
            }),
        ]);
        assert_eq!(fixture.executor().execute(request(operations)).await.status, NfsStatus::Ok);

        // The I/O used state in export 7 while the retained delegation is
        // managed by export 8.  RFC 7530 section 9.5 renews both leases.
        runtime_clock.advance(Duration::from_secs(9));
        delegation_clock.advance(Duration::from_secs(9));
        assert!(retained_manager.revoke_expired().await.unwrap().is_empty());
        assert_eq!(retained_manager.active_counts().await, (0, 1));
        assert_eq!(fixture.runtime.validate_client(client_id, &Principal::Anonymous).await, NfsStatus::Ok);
    }

    #[tokio::test]
    async fn ordinary_open_renews_delegations_held_on_every_export() {
        let (mut fixture, runtime_clock) = leased_fixture();
        let delegation_clock = Arc::new(ManualCallbackClock::default());
        let client_id = confirmed_fixture_client(&fixture, b"open-all-exports-client").await;
        assert_eq!(fixture.runtime.renew(client_id, &Principal::Anonymous).await, NfsStatus::Ok);
        let _retained =
            grant_fixture_write_delegation(&mut fixture, client_id, ExportId(8), delegation_clock.clone(), 12).await;
        let retained_manager = fixture.delegations.get(&ExportId(8)).unwrap().clone();

        runtime_clock.advance(Duration::from_secs(9));
        delegation_clock.advance(Duration::from_secs(9));
        let _ = open_fixture_file_state(&fixture, client_id, b"renewing-open-owner").await;

        runtime_clock.advance(Duration::from_secs(9));
        delegation_clock.advance(Duration::from_secs(9));
        assert!(retained_manager.revoke_expired().await.unwrap().is_empty());
        assert_eq!(retained_manager.active_counts().await, (0, 1));
        assert_eq!(fixture.runtime.validate_client(client_id, &Principal::Anonymous).await, NfsStatus::Ok);
    }

    #[tokio::test]
    async fn ordinary_open_bad_seqid_renews_delegations_on_every_export() {
        let (mut fixture, runtime_clock) = leased_fixture();
        let delegation_clock = Arc::new(ManualCallbackClock::default());
        let client_id = confirmed_fixture_client(&fixture, b"ordinary-open-error-client").await;
        let _retained =
            grant_fixture_write_delegation(&mut fixture, client_id, ExportId(8), delegation_clock.clone(), 20).await;
        let retained_manager = fixture.delegations.get(&ExportId(8)).unwrap().clone();
        let owner = super::super::types::OpenOwner {
            client_id,
            owner: b"ordinary-open-error-owner".to_vec(),
        };
        let open = |sequence_id| OpenArgs {
            sequence_id,
            share_access: OPEN4_SHARE_ACCESS_READ,
            share_deny: 0,
            owner: owner.clone(),
            how: OpenHow::NoCreate,
            claim: OpenClaim::Null(b"file".to_vec()),
        };

        let mut initial = enter_export();
        initial.push(ArgOp::Open(open(1)));
        assert_eq!(fixture.executor().execute(request(initial)).await.status, NfsStatus::Ok);

        runtime_clock.advance(Duration::from_secs(9));
        delegation_clock.advance(Duration::from_secs(9));
        let mut invalid_sequence = enter_export();
        invalid_sequence.push(ArgOp::Open(open(99)));
        let response = fixture.executor().execute(request(invalid_sequence)).await;
        assert_eq!(response.status, NfsStatus::BadSequenceId, "{response:?}");

        runtime_clock.advance(Duration::from_secs(9));
        delegation_clock.advance(Duration::from_secs(9));
        assert!(retained_manager.revoke_expired().await.unwrap().is_empty());
        assert_eq!(retained_manager.active_counts().await, (0, 1));
        assert_eq!(fixture.runtime.validate_client(client_id, &Principal::Anonymous).await, NfsStatus::Ok);
    }

    #[tokio::test]
    async fn reclaim_open_no_grace_renews_delegations_while_preserving_status() {
        let (mut fixture, runtime_clock) = leased_fixture();
        let delegation_clock = Arc::new(ManualCallbackClock::default());
        let client_id = confirmed_fixture_client(&fixture, b"reclaim-open-no-grace-client").await;
        let (_, file_handle) = open_fixture_file_state(&fixture, client_id, b"reclaim-open-source-owner").await;
        let _retained =
            grant_fixture_write_delegation(&mut fixture, client_id, ExportId(8), delegation_clock.clone(), 24).await;
        let retained_manager = fixture.delegations.get(&ExportId(8)).unwrap().clone();

        runtime_clock.advance(Duration::from_secs(9));
        delegation_clock.advance(Duration::from_secs(9));
        let response = fixture
            .executor()
            .execute(request(vec![
                ArgOp::PutFh(PutFhArgs { object: file_handle }),
                ArgOp::Open(OpenArgs {
                    sequence_id: 1,
                    share_access: OPEN4_SHARE_ACCESS_READ,
                    share_deny: 0,
                    owner: super::super::types::OpenOwner {
                        client_id,
                        owner: b"reclaim-open-no-grace-owner".to_vec(),
                    },
                    how: OpenHow::NoCreate,
                    claim: OpenClaim::Previous(OpenDelegationType::None),
                }),
            ]))
            .await;
        assert_eq!(response.status, NfsStatus::NoGrace, "{response:?}");

        // The recovery gate's NO_GRACE result keeps the confirmed client
        // evidence, so RFC 7530 section 9.5 still renews export 8.
        delegation_clock.advance(Duration::from_secs(9));
        assert!(retained_manager.revoke_expired().await.unwrap().is_empty());
        assert_eq!(retained_manager.active_counts().await, (0, 1));
    }

    #[tokio::test]
    async fn lock_with_open_stateid_renews_delegations_held_on_every_export() {
        let (mut fixture, runtime_clock) = leased_fixture();
        let delegation_clock = Arc::new(ManualCallbackClock::default());
        let client_id = confirmed_fixture_client(&fixture, b"lock-all-exports-client").await;
        assert_eq!(fixture.runtime.renew(client_id, &Principal::Anonymous).await, NfsStatus::Ok);
        let (open_state_id, file_handle) = open_fixture_file_state(&fixture, client_id, b"lock-open-owner").await;
        let _retained =
            grant_fixture_write_delegation(&mut fixture, client_id, ExportId(8), delegation_clock.clone(), 13).await;
        let retained_manager = fixture.delegations.get(&ExportId(8)).unwrap().clone();

        runtime_clock.advance(Duration::from_secs(9));
        delegation_clock.advance(Duration::from_secs(9));
        let response = fixture
            .executor()
            .execute(request(vec![
                ArgOp::PutFh(PutFhArgs { object: file_handle }),
                ArgOp::Lock(LockArgs {
                    lock_type: LockType::Read,
                    reclaim: false,
                    offset: 0,
                    length: 1,
                    locker: Locker::New(super::super::types::OpenToLockOwner {
                        open_sequence_id: 3,
                        open_state_id,
                        lock_sequence_id: 1,
                        lock_owner: super::super::types::LockOwner {
                            client_id,
                            owner: b"renewing-lock-owner".to_vec(),
                        },
                    }),
                }),
            ]))
            .await;
        assert_eq!(response.status, NfsStatus::Ok, "{response:?}");

        runtime_clock.advance(Duration::from_secs(9));
        delegation_clock.advance(Duration::from_secs(9));
        assert!(retained_manager.revoke_expired().await.unwrap().is_empty());
        assert_eq!(retained_manager.active_counts().await, (0, 1));
        assert_eq!(fixture.runtime.validate_client(client_id, &Principal::Anonymous).await, NfsStatus::Ok);
    }

    #[tokio::test]
    async fn existing_lock_and_locku_exact_replays_accept_the_prior_stateid() {
        let fixture = Fixture::new();
        let client_id = confirmed_fixture_client(&fixture, b"lock-replay-client").await;
        let (open_state_id, file_handle) = open_fixture_file_state(&fixture, client_id, b"lock-replay-open").await;
        let lock_owner = super::super::types::LockOwner {
            client_id,
            owner: b"lock-replay-owner".to_vec(),
        };

        let initial = fixture
            .executor()
            .execute(request(vec![
                ArgOp::PutFh(PutFhArgs {
                    object: file_handle.clone(),
                }),
                ArgOp::Lock(LockArgs {
                    lock_type: LockType::Read,
                    reclaim: false,
                    offset: 0,
                    length: 8,
                    locker: Locker::New(super::super::types::OpenToLockOwner {
                        open_sequence_id: 3,
                        open_state_id,
                        lock_sequence_id: 1,
                        lock_owner,
                    }),
                }),
            ]))
            .await;
        let initial_state_id = match initial.operations[1] {
            ResOp::Lock(super::super::types::LockResult::Ok(state_id)) => state_id,
            ref operation => panic!("unexpected initial LOCK response: {operation:?}"),
        };

        let lock = LockArgs {
            lock_type: LockType::Read,
            reclaim: false,
            offset: 8,
            length: 8,
            locker: Locker::Existing(super::super::types::ExistingLockOwner {
                lock_state_id: initial_state_id,
                lock_sequence_id: 2,
            }),
        };
        let first_lock = fixture
            .executor()
            .execute(request(vec![
                ArgOp::PutFh(PutFhArgs {
                    object: file_handle.clone(),
                }),
                ArgOp::Lock(lock.clone()),
            ]))
            .await;
        let advanced_state_id = match first_lock.operations[1] {
            ResOp::Lock(super::super::types::LockResult::Ok(state_id)) => state_id,
            ref operation => panic!("unexpected existing LOCK response: {operation:?}"),
        };
        let replayed_lock = fixture
            .executor()
            .execute(request(vec![
                ArgOp::PutFh(PutFhArgs {
                    object: file_handle.clone(),
                }),
                ArgOp::Lock(lock),
            ]))
            .await;
        assert_eq!(replayed_lock, first_lock);

        let unlock = LockUnlockArgs {
            lock_state_id: advanced_state_id,
            sequence_id: 3,
            lock_type: LockType::Read,
            offset: 8,
            length: 8,
        };
        let first_unlock = fixture
            .executor()
            .execute(request(vec![
                ArgOp::PutFh(PutFhArgs {
                    object: file_handle.clone(),
                }),
                ArgOp::LockUnlock(unlock),
            ]))
            .await;
        let replayed_unlock = fixture
            .executor()
            .execute(request(vec![
                ArgOp::PutFh(PutFhArgs { object: file_handle }),
                ArgOp::LockUnlock(unlock),
            ]))
            .await;
        assert_eq!(replayed_unlock, first_unlock);
    }

    #[tokio::test]
    async fn lock_and_locku_bad_seqid_precede_old_or_bad_stateid() {
        let fixture = Fixture::new();
        let client_id = confirmed_fixture_client(&fixture, b"lock-sequence-priority-client").await;
        let (open_state_id, file_handle) =
            open_fixture_file_state(&fixture, client_id, b"lock-sequence-priority-open").await;
        let lock_owner = super::super::types::LockOwner {
            client_id,
            owner: b"lock-sequence-priority-owner".to_vec(),
        };
        let initial = fixture
            .executor()
            .execute(request(vec![
                ArgOp::PutFh(PutFhArgs {
                    object: file_handle.clone(),
                }),
                ArgOp::Lock(LockArgs {
                    lock_type: LockType::Read,
                    reclaim: false,
                    offset: 0,
                    length: 8,
                    locker: Locker::New(super::super::types::OpenToLockOwner {
                        open_sequence_id: 3,
                        open_state_id,
                        lock_sequence_id: 1,
                        lock_owner,
                    }),
                }),
            ]))
            .await;
        let initial_state_id = match initial.operations[1] {
            ResOp::Lock(super::super::types::LockResult::Ok(state_id)) => state_id,
            ref operation => panic!("unexpected initial LOCK response: {operation:?}"),
        };
        let advanced = fixture
            .executor()
            .execute(request(vec![
                ArgOp::PutFh(PutFhArgs {
                    object: file_handle.clone(),
                }),
                ArgOp::Lock(LockArgs {
                    lock_type: LockType::Read,
                    reclaim: false,
                    offset: 8,
                    length: 8,
                    locker: Locker::Existing(super::super::types::ExistingLockOwner {
                        lock_state_id: initial_state_id,
                        lock_sequence_id: 2,
                    }),
                }),
            ]))
            .await;
        let advanced_state_id = match advanced.operations[1] {
            ResOp::Lock(super::super::types::LockResult::Ok(state_id)) => state_id,
            ref operation => panic!("unexpected advancing LOCK response: {operation:?}"),
        };

        let bad_lock_state_id = super::super::types::StateId {
            sequence_id: advanced_state_id.sequence_id.saturating_add(1),
            other: advanced_state_id.other,
        };
        for lock_state_id in [initial_state_id, bad_lock_state_id] {
            let response = fixture
                .executor()
                .execute(request(vec![
                    ArgOp::PutFh(PutFhArgs {
                        object: file_handle.clone(),
                    }),
                    ArgOp::Lock(LockArgs {
                        lock_type: LockType::Read,
                        reclaim: false,
                        offset: 16,
                        length: 8,
                        locker: Locker::Existing(super::super::types::ExistingLockOwner {
                            lock_state_id,
                            lock_sequence_id: 99,
                        }),
                    }),
                ]))
                .await;
            assert_eq!(response.status, NfsStatus::BadSequenceId, "{response:?}");
        }

        let unlocked = fixture
            .executor()
            .execute(request(vec![
                ArgOp::PutFh(PutFhArgs {
                    object: file_handle.clone(),
                }),
                ArgOp::LockUnlock(LockUnlockArgs {
                    lock_state_id: advanced_state_id,
                    sequence_id: 3,
                    lock_type: LockType::Read,
                    offset: 8,
                    length: 8,
                }),
            ]))
            .await;
        let unlocked_state_id = match unlocked.operations[1] {
            ResOp::LockUnlock(NfsResult::Ok(state_id)) => state_id,
            ref operation => panic!("unexpected LOCKU response: {operation:?}"),
        };
        let bad_unlock_state_id = super::super::types::StateId {
            sequence_id: unlocked_state_id.sequence_id.saturating_add(1),
            other: unlocked_state_id.other,
        };
        for lock_state_id in [advanced_state_id, bad_unlock_state_id] {
            let response = fixture
                .executor()
                .execute(request(vec![
                    ArgOp::PutFh(PutFhArgs {
                        object: file_handle.clone(),
                    }),
                    ArgOp::LockUnlock(LockUnlockArgs {
                        lock_state_id,
                        sequence_id: 99,
                        lock_type: LockType::Read,
                        offset: 0,
                        length: 8,
                    }),
                ]))
                .await;
            assert_eq!(response.status, NfsStatus::BadSequenceId, "{response:?}");
        }
    }

    #[tokio::test]
    async fn post_auth_open_bad_seqid_renews_delegations_on_every_export() {
        let (mut fixture, runtime_clock) = leased_fixture();
        let delegation_clock = Arc::new(ManualCallbackClock::default());
        let client_id = confirmed_fixture_client(&fixture, b"post-auth-open-error-client").await;
        let (open_state_id, file_handle) =
            open_fixture_file_state(&fixture, client_id, b"post-auth-open-error-owner").await;
        let _retained =
            grant_fixture_write_delegation(&mut fixture, client_id, ExportId(8), delegation_clock.clone(), 16).await;
        let retained_manager = fixture.delegations.get(&ExportId(8)).unwrap().clone();

        runtime_clock.advance(Duration::from_secs(9));
        delegation_clock.advance(Duration::from_secs(9));
        let response = fixture
            .executor()
            .execute(request(vec![
                ArgOp::PutFh(PutFhArgs { object: file_handle }),
                ArgOp::OpenDowngrade(OpenDowngradeArgs {
                    open_state_id,
                    sequence_id: 99,
                    share_access: OPEN4_SHARE_ACCESS_READ,
                    share_deny: 0,
                }),
            ]))
            .await;
        assert_eq!(response.status, NfsStatus::BadSequenceId, "{response:?}");

        // The error happens after a valid stateid identified this client. Per
        // RFC 7530 §9.5, it renews the client lease and every delegation lease.
        runtime_clock.advance(Duration::from_secs(9));
        delegation_clock.advance(Duration::from_secs(9));
        assert!(retained_manager.revoke_expired().await.unwrap().is_empty());
        assert_eq!(retained_manager.active_counts().await, (0, 1));
        assert_eq!(fixture.runtime.validate_client(client_id, &Principal::Anonymous).await, NfsStatus::Ok);
    }

    #[tokio::test]
    async fn post_auth_io_openmode_renews_delegations_on_every_export() {
        let (mut fixture, runtime_clock) = leased_fixture();
        let delegation_clock = Arc::new(ManualCallbackClock::default());
        let client_id = confirmed_fixture_client(&fixture, b"post-auth-io-error-client").await;
        let (open_state_id, file_handle) =
            open_fixture_file_state(&fixture, client_id, b"post-auth-io-error-owner").await;
        let _retained =
            grant_fixture_write_delegation(&mut fixture, client_id, ExportId(8), delegation_clock.clone(), 17).await;
        let retained_manager = fixture.delegations.get(&ExportId(8)).unwrap().clone();

        runtime_clock.advance(Duration::from_secs(9));
        delegation_clock.advance(Duration::from_secs(9));
        let response = fixture
            .executor()
            .execute(request(vec![
                ArgOp::PutFh(PutFhArgs { object: file_handle }),
                ArgOp::Write(WriteArgs {
                    state_id: open_state_id,
                    offset: 0,
                    stability: StableHow::Unstable,
                    data: b"x".to_vec(),
                }),
            ]))
            .await;
        assert_eq!(response.status, NfsStatus::OpenMode, "{response:?}");

        runtime_clock.advance(Duration::from_secs(9));
        delegation_clock.advance(Duration::from_secs(9));
        assert!(retained_manager.revoke_expired().await.unwrap().is_empty());
        assert_eq!(retained_manager.active_counts().await, (0, 1));
        assert_eq!(fixture.runtime.validate_client(client_id, &Principal::Anonymous).await, NfsStatus::Ok);
    }

    #[tokio::test]
    async fn stateid_lease_moved_renews_delegations_while_preserving_status() {
        let (mut fixture, runtime_clock) = leased_fixture();
        let delegation_clock = Arc::new(ManualCallbackClock::default());
        let client_id = confirmed_fixture_client(&fixture, b"stateid-moved-client").await;
        let (open_state_id, file_handle) = open_fixture_file_state(&fixture, client_id, b"stateid-moved-owner").await;
        let _retained =
            grant_fixture_write_delegation(&mut fixture, client_id, ExportId(8), delegation_clock.clone(), 21).await;
        let retained_manager = fixture.delegations.get(&ExportId(8)).unwrap().clone();

        runtime_clock.advance(Duration::from_secs(9));
        delegation_clock.advance(Duration::from_secs(9));
        fixture
            .runtime
            .note_moved_export(client_id, ExportId(7), &Principal::Anonymous)
            .await
            .unwrap();
        let response = fixture
            .executor()
            .execute(request(vec![
                ArgOp::PutFh(PutFhArgs { object: file_handle }),
                ArgOp::Read(ReadArgs {
                    state_id: open_state_id,
                    offset: 0,
                    count: 1,
                }),
            ]))
            .await;
        assert_eq!(response.status, NfsStatus::LeaseMoved, "{response:?}");

        delegation_clock.advance(Duration::from_secs(9));
        assert!(retained_manager.revoke_expired().await.unwrap().is_empty());
        assert_eq!(retained_manager.active_counts().await, (0, 1));
    }

    #[tokio::test]
    async fn claim_delegate_current_exact_replay_renews_its_cached_stateid_source() {
        let (mut fixture, runtime_clock) = leased_fixture();
        let delegation_clock = Arc::new(ManualCallbackClock::default());
        let client_id = confirmed_fixture_client(&fixture, b"delegate-current-replay-client").await;
        let delegation =
            grant_fixture_write_delegation(&mut fixture, client_id, ExportId(7), delegation_clock.clone(), 18).await;
        let _retained =
            grant_fixture_write_delegation(&mut fixture, client_id, ExportId(8), delegation_clock.clone(), 19).await;
        let retained_manager = fixture.delegations.get(&ExportId(8)).unwrap().clone();
        let claim = OpenArgs {
            sequence_id: 1,
            share_access: OPEN4_SHARE_ACCESS_READ,
            share_deny: 0,
            owner: super::super::types::OpenOwner {
                client_id,
                owner: b"delegate-current-replay-open-owner".to_vec(),
            },
            how: OpenHow::NoCreate,
            claim: OpenClaim::DelegateCurrent {
                delegate_state_id: delegation.state_id,
                file: b"file".to_vec(),
            },
        };
        let mut operations = enter_export();
        operations.push(ArgOp::Open(claim));

        runtime_clock.advance(Duration::from_secs(9));
        delegation_clock.advance(Duration::from_secs(9));
        let initial = fixture.executor().execute(request(operations.clone())).await;
        assert_eq!(initial.status, NfsStatus::Ok, "{initial:?}");

        // The exact owner replay must not fall back to the ordinary OPEN
        // clientid renewal rule; it must retain the authenticated delegation
        // source recorded with the original response.
        runtime_clock.advance(Duration::from_secs(9));
        delegation_clock.advance(Duration::from_secs(9));
        let replay = fixture.executor().execute(request(operations)).await;
        assert_eq!(replay, initial);

        runtime_clock.advance(Duration::from_secs(9));
        delegation_clock.advance(Duration::from_secs(9));
        assert!(retained_manager.revoke_expired().await.unwrap().is_empty());
        assert_eq!(retained_manager.active_counts().await, (0, 1));
        assert_eq!(fixture.runtime.validate_client(client_id, &Principal::Anonymous).await, NfsStatus::Ok);
    }

    #[tokio::test]
    async fn claim_delegate_current_invalid_stateid_renews_from_the_authenticated_owner() {
        let (mut fixture, runtime_clock) = leased_fixture();
        let delegation_clock = Arc::new(ManualCallbackClock::default());
        let client_id = confirmed_fixture_client(&fixture, b"delegate-current-invalid-stateid-client").await;
        let source =
            grant_fixture_write_delegation(&mut fixture, client_id, ExportId(7), delegation_clock.clone(), 25).await;
        let _retained =
            grant_fixture_write_delegation(&mut fixture, client_id, ExportId(8), delegation_clock.clone(), 26).await;
        let source_manager = fixture.delegations.get(&ExportId(7)).unwrap().clone();
        let retained_manager = fixture.delegations.get(&ExportId(8)).unwrap().clone();
        let invalid_state_id = super::super::types::StateId {
            sequence_id: source.state_id.sequence_id.saturating_add(1),
            other: source.state_id.other,
        };

        runtime_clock.advance(Duration::from_secs(9));
        delegation_clock.advance(Duration::from_secs(9));
        let mut operations = enter_export();
        operations.push(ArgOp::Open(OpenArgs {
            sequence_id: 1,
            share_access: OPEN4_SHARE_ACCESS_READ,
            share_deny: 0,
            owner: super::super::types::OpenOwner {
                client_id,
                owner: b"delegate-current-invalid-stateid-owner".to_vec(),
            },
            how: OpenHow::NoCreate,
            claim: OpenClaim::DelegateCurrent {
                delegate_state_id: invalid_state_id,
                file: b"file".to_vec(),
            },
        }));
        let response = fixture.executor().execute(request(operations)).await;
        assert_eq!(response.status, NfsStatus::BadStateId, "{response:?}");

        // CLAIM_DELEGATE_CUR takes a stateid, but its independently
        // authenticated OPEN owner still renews every manager before that
        // later BAD_STATEID is selected.
        runtime_clock.advance(Duration::from_secs(9));
        delegation_clock.advance(Duration::from_secs(9));
        assert!(source_manager.revoke_expired().await.unwrap().is_empty());
        assert!(retained_manager.revoke_expired().await.unwrap().is_empty());
        assert_eq!(source_manager.active_counts().await, (0, 1));
        assert_eq!(retained_manager.active_counts().await, (0, 1));
        assert_eq!(fixture.runtime.validate_client(client_id, &Principal::Anonymous).await, NfsStatus::Ok);
    }

    #[tokio::test]
    async fn claim_delegate_current_gate_error_uses_stateid_callback_path_rules() {
        let (mut fixture, runtime_clock) = leased_fixture();
        let delegation_clock = Arc::new(ManualCallbackClock::default());
        let client_id = confirmed_fixture_client(&fixture, b"delegate-current-callback-down-client").await;
        let source =
            grant_fixture_write_delegation(&mut fixture, client_id, ExportId(7), delegation_clock.clone(), 27).await;
        let _retained =
            grant_fixture_write_delegation(&mut fixture, client_id, ExportId(8), delegation_clock.clone(), 28).await;
        let source_manager = fixture.delegations.get(&ExportId(7)).unwrap().clone();
        let retained_manager = fixture.delegations.get(&ExportId(8)).unwrap().clone();
        source_manager.mark_callback_path_down_for_test(client_id);
        retained_manager.mark_callback_path_down_for_test(client_id);

        runtime_clock.advance(Duration::from_secs(9));
        delegation_clock.advance(Duration::from_secs(9));
        fixture
            .runtime
            .note_moved_export(client_id, ExportId(7), &Principal::Anonymous)
            .await
            .unwrap();
        let mut operations = enter_export();
        operations.push(ArgOp::Open(OpenArgs {
            sequence_id: 1,
            share_access: OPEN4_SHARE_ACCESS_READ,
            share_deny: 0,
            owner: super::super::types::OpenOwner {
                client_id,
                owner: b"delegate-current-callback-down-owner".to_vec(),
            },
            how: OpenHow::NoCreate,
            claim: OpenClaim::DelegateCurrent {
                delegate_state_id: source.state_id,
                file: b"file".to_vec(),
            },
        }));
        let response = fixture.executor().execute(request(operations)).await;
        assert_eq!(response.status, NfsStatus::LeaseMoved, "{response:?}");

        // Owner authentication renewed the common runtime lease, but this
        // stateid-taking claim must not extend delegation leases once the
        // callback path is down (RFC 7530 §10.4.6).
        runtime_clock.advance(Duration::from_secs(2));
        delegation_clock.advance(Duration::from_secs(2));
        assert_eq!(source_manager.revoke_expired().await.unwrap().len(), 1);
        assert_eq!(retained_manager.revoke_expired().await.unwrap().len(), 1);
        assert_eq!(source_manager.active_counts().await, (0, 0));
        assert_eq!(retained_manager.active_counts().await, (0, 0));
        assert_eq!(fixture.runtime.validate_client(client_id, &Principal::Anonymous).await, NfsStatus::LeaseMoved);
    }

    #[tokio::test]
    async fn claim_delegate_current_expired_owner_does_not_renew_delegations() {
        let (mut fixture, runtime_clock) = leased_fixture();
        let delegation_clock = Arc::new(ManualCallbackClock::default());
        let client_id = confirmed_fixture_client(&fixture, b"delegate-current-expired-owner-client").await;
        // SETCLIENTID_CONFIRM does not itself begin a lease.  Establish the
        // client's first live runtime lease before allowing it to expire.
        assert_eq!(fixture.runtime.validate_client(client_id, &Principal::Anonymous).await, NfsStatus::Ok);
        let source =
            grant_fixture_write_delegation(&mut fixture, client_id, ExportId(7), delegation_clock.clone(), 29).await;
        let _retained =
            grant_fixture_write_delegation(&mut fixture, client_id, ExportId(8), delegation_clock.clone(), 30).await;
        let source_manager = fixture.delegations.get(&ExportId(7)).unwrap().clone();
        let retained_manager = fixture.delegations.get(&ExportId(8)).unwrap().clone();

        // Let the runtime lease expire while both delegation leases remain
        // live.  The subsequent OPEN has a real owner clientid and a real
        // delegation stateid, so it would expose either source renewing a
        // manager despite the prior NFS4ERR_EXPIRED gate.
        runtime_clock.advance(Duration::from_secs(11));
        delegation_clock.advance(Duration::from_secs(9));
        let mut operations = enter_export();
        operations.push(ArgOp::Open(OpenArgs {
            sequence_id: 1,
            share_access: OPEN4_SHARE_ACCESS_READ,
            share_deny: 0,
            owner: super::super::types::OpenOwner {
                client_id,
                owner: b"delegate-current-expired-owner".to_vec(),
            },
            how: OpenHow::NoCreate,
            claim: OpenClaim::DelegateCurrent {
                delegate_state_id: source.state_id,
                file: b"file".to_vec(),
            },
        }));
        let response = fixture.executor().execute(request(operations)).await;
        assert_eq!(response.status, NfsStatus::Expired, "{response:?}");

        // An expired owner is not renewal evidence.  The valid claim stateid
        // cannot override that gate either, so both records retain their
        // original expiry at callback time 10.
        delegation_clock.advance(Duration::from_secs(1));
        assert_eq!(source_manager.revoke_expired().await.unwrap().len(), 1);
        assert_eq!(retained_manager.revoke_expired().await.unwrap().len(), 1);
        assert_eq!(source_manager.active_counts().await, (0, 0));
        assert_eq!(retained_manager.active_counts().await, (0, 0));
    }

    #[tokio::test]
    async fn anonymous_and_invalid_stateids_do_not_renew_delegation_leases() {
        let (mut fixture, _) = leased_fixture();
        let delegation_clock = Arc::new(ManualCallbackClock::default());
        let client_id = confirmed_fixture_client(&fixture, b"non-renewing-stateid-client").await;
        let _anonymous =
            grant_fixture_write_delegation(&mut fixture, client_id, ExportId(8), delegation_clock.clone(), 14).await;
        let _invalid =
            grant_fixture_write_delegation(&mut fixture, client_id, ExportId(9), delegation_clock.clone(), 15).await;
        let anonymous_manager = fixture.delegations.get(&ExportId(8)).unwrap().clone();
        let invalid_manager = fixture.delegations.get(&ExportId(9)).unwrap().clone();

        delegation_clock.advance(Duration::from_secs(9));
        let mut anonymous_operations = enter_export();
        anonymous_operations.extend([
            ArgOp::Lookup(super::super::types::LookupArgs { name: b"file".to_vec() }),
            ArgOp::Read(ReadArgs {
                state_id: ANONYMOUS_STATE_ID,
                offset: 0,
                count: 1,
            }),
        ]);
        assert_eq!(fixture.executor().execute(request(anonymous_operations)).await.status, NfsStatus::Ok);

        let invalid_state_id = super::super::types::StateId {
            sequence_id: 1,
            other: [0x42; 12],
        };
        let mut invalid_operations = enter_export();
        invalid_operations.extend([
            ArgOp::Lookup(super::super::types::LookupArgs { name: b"file".to_vec() }),
            ArgOp::Read(ReadArgs {
                state_id: invalid_state_id,
                offset: 0,
                count: 1,
            }),
        ]);
        let invalid_response = fixture.executor().execute(request(invalid_operations)).await;
        assert!(
            matches!(invalid_response.status, NfsStatus::BadStateId | NfsStatus::StaleStateId),
            "{invalid_response:?}"
        );

        delegation_clock.advance(Duration::from_secs(2));
        assert_eq!(anonymous_manager.revoke_expired().await.unwrap().len(), 1);
        assert_eq!(invalid_manager.revoke_expired().await.unwrap().len(), 1);
        assert_eq!(anonymous_manager.active_counts().await, (0, 0));
        assert_eq!(invalid_manager.active_counts().await, (0, 0));
    }

    #[tokio::test]
    async fn known_bad_stateid_sequence_does_not_renew_delegation_leases() {
        let (mut fixture, _) = leased_fixture();
        let delegation_clock = Arc::new(ManualCallbackClock::default());
        let client_id = confirmed_fixture_client(&fixture, b"known-bad-stateid-client").await;
        let (open_state_id, _) = open_fixture_file_state(&fixture, client_id, b"known-bad-stateid-open").await;
        let _delegation =
            grant_fixture_write_delegation(&mut fixture, client_id, ExportId(8), delegation_clock.clone(), 23).await;
        let manager = fixture.delegations.get(&ExportId(8)).unwrap().clone();

        delegation_clock.advance(Duration::from_secs(9));
        let bad_state_id = super::super::types::StateId {
            sequence_id: open_state_id.sequence_id.saturating_add(1),
            other: open_state_id.other,
        };
        let mut operations = enter_export();
        operations.extend([
            ArgOp::Lookup(super::super::types::LookupArgs { name: b"file".to_vec() }),
            ArgOp::Read(ReadArgs {
                state_id: bad_state_id,
                offset: 0,
                count: 1,
            }),
        ]);
        let response = fixture.executor().execute(request(operations)).await;
        assert_eq!(response.status, NfsStatus::BadStateId, "{response:?}");

        delegation_clock.advance(Duration::from_secs(2));
        assert_eq!(manager.revoke_expired().await.unwrap().len(), 1);
        assert_eq!(manager.active_counts().await, (0, 0));
    }

    #[tokio::test]
    async fn non_size_setattr_rejects_open_and_lock_stateids() {
        let fixture = Fixture::new();
        let client_id = confirmed_fixture_client(&fixture, b"setattr-runtime-stateids-client").await;
        let mut open_operations = enter_export();
        open_operations.extend([
            ArgOp::Open(OpenArgs {
                sequence_id: 1,
                share_access: OPEN4_SHARE_ACCESS_READ,
                share_deny: 0,
                owner: super::super::types::OpenOwner {
                    client_id,
                    owner: b"setattr-runtime-open-owner".to_vec(),
                },
                how: OpenHow::NoCreate,
                claim: OpenClaim::Null(b"file".to_vec()),
            }),
            ArgOp::GetFh,
        ]);
        let opened = fixture.executor().execute(request(open_operations)).await;
        let unconfirmed_open = match &opened.operations[2] {
            ResOp::Open(NfsResult::Ok(open)) => open.state_id,
            operation => panic!("unexpected OPEN response: {operation:?}"),
        };
        let file_handle = match &opened.operations[3] {
            ResOp::GetFh(NfsResult::Ok(file_handle)) => file_handle.clone(),
            operation => panic!("unexpected GETFH response: {operation:?}"),
        };
        let confirmed = fixture
            .executor()
            .execute(request(vec![
                ArgOp::PutFh(PutFhArgs {
                    object: file_handle.clone(),
                }),
                ArgOp::OpenConfirm(OpenConfirmArgs {
                    open_state_id: unconfirmed_open,
                    sequence_id: 2,
                }),
            ]))
            .await;
        let open_state_id = match &confirmed.operations[1] {
            ResOp::OpenConfirm(NfsResult::Ok(state_id)) => *state_id,
            operation => panic!("unexpected OPEN_CONFIRM response: {operation:?}"),
        };
        let setattr = |state_id| {
            let mut attributes = AttributeEncoder::new();
            attributes.push_u32(FATTR4_MODE, 0o600).unwrap();
            request(vec![
                ArgOp::PutFh(PutFhArgs {
                    object: file_handle.clone(),
                }),
                ArgOp::SetAttr(SetAttrArgs {
                    state_id,
                    attributes: attributes.finish(),
                }),
            ])
        };
        assert_eq!(fixture.executor().execute(setattr(unconfirmed_open)).await.status, NfsStatus::BadStateId);
        assert_eq!(fixture.executor().execute(setattr(open_state_id)).await.status, NfsStatus::BadStateId);

        let locked = fixture
            .executor()
            .execute(request(vec![
                ArgOp::PutFh(PutFhArgs {
                    object: file_handle.clone(),
                }),
                ArgOp::Lock(LockArgs {
                    lock_type: LockType::Read,
                    reclaim: false,
                    offset: 0,
                    length: 16,
                    locker: Locker::New(super::super::types::OpenToLockOwner {
                        open_sequence_id: 3,
                        open_state_id,
                        lock_sequence_id: 1,
                        lock_owner: super::super::types::LockOwner {
                            client_id,
                            owner: b"setattr-runtime-lock-owner".to_vec(),
                        },
                    }),
                }),
            ]))
            .await;
        let lock_state_id = match &locked.operations[1] {
            ResOp::Lock(super::super::types::LockResult::Ok(state_id)) => *state_id,
            operation => panic!("unexpected LOCK response: {operation:?}"),
        };
        assert_eq!(fixture.executor().execute(setattr(lock_state_id)).await.status, NfsStatus::BadStateId);
        assert_eq!(fixture.vfs.setattr_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn non_size_setattr_preserves_delegation_old_and_bad_stateid_errors() {
        let (mut fixture, _) = leased_fixture();
        let client_id = confirmed_fixture_client(&fixture, b"setattr-delegation-sequence-client").await;
        let delegation_clock = Arc::new(ManualCallbackClock::default());
        let delegation =
            grant_fixture_write_delegation(&mut fixture, client_id, ExportId(7), delegation_clock, 9).await;
        let setattr = |state_id| {
            let mut attributes = AttributeEncoder::new();
            attributes.push_u32(FATTR4_MODE, 0o600).unwrap();
            let mut operations = enter_export();
            operations.extend([
                ArgOp::Lookup(super::super::types::LookupArgs { name: b"file".to_vec() }),
                ArgOp::SetAttr(SetAttrArgs {
                    state_id,
                    attributes: attributes.finish(),
                }),
            ]);
            request(operations)
        };
        let old = super::super::types::StateId {
            // A supplied sequence value of zero has the delegation
            // validator's established wildcard meaning.  `u32::MAX` is the
            // immediately older serial value for a newly allocated sequence
            // ID of one.
            sequence_id: delegation.state_id.sequence_id.wrapping_sub(2),
            other: delegation.state_id.other,
        };
        let bad = super::super::types::StateId {
            sequence_id: delegation.state_id.sequence_id.saturating_add(1),
            other: delegation.state_id.other,
        };
        assert_eq!(fixture.executor().execute(setattr(old)).await.status, NfsStatus::OldStateId);
        assert_eq!(fixture.executor().execute(setattr(bad)).await.status, NfsStatus::BadStateId);
        assert_eq!(fixture.vfs.setattr_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn named_attribute_objects_report_rfc_types_and_use_open_for_creation() {
        let fixture = Fixture::new();
        fixture.vfs.named_attributes.store(1, Ordering::Relaxed);
        let client_id = confirmed_fixture_client(&fixture, b"named-attribute-client").await;

        let mut operations = enter_export();
        operations.extend([
            ArgOp::Lookup(super::super::types::LookupArgs { name: b"file".to_vec() }),
            ArgOp::OpenAttr(OpenAttrArgs { create_directory: true }),
            ArgOp::GetAttr(GetAttrArgs {
                requested_attributes: bitmap_from_attributes([FATTR4_TYPE]).unwrap(),
            }),
            ArgOp::Lookup(super::super::types::LookupArgs {
                name: b"user.test".to_vec(),
            }),
            ArgOp::GetAttr(GetAttrArgs {
                requested_attributes: bitmap_from_attributes([FATTR4_TYPE]).unwrap(),
            }),
        ]);
        let response = fixture.executor().execute(request(operations)).await;
        assert_eq!(response.status, NfsStatus::Ok);
        for (operation, expected) in [(4, 8_u32), (6, 9_u32)] {
            let ResOp::GetAttr(NfsResult::Ok(attributes)) = &response.operations[operation] else {
                panic!("expected GETATTR at operation {operation}");
            };
            assert_eq!(attributes.values, expected.to_be_bytes());
        }

        let mut open = enter_export();
        open.extend([
            ArgOp::Lookup(super::super::types::LookupArgs { name: b"file".to_vec() }),
            ArgOp::OpenAttr(OpenAttrArgs { create_directory: true }),
            ArgOp::Open(OpenArgs {
                sequence_id: 1,
                share_access: OPEN4_SHARE_ACCESS_READ,
                share_deny: 0,
                owner: super::super::types::OpenOwner {
                    client_id,
                    owner: b"named-attribute-open".to_vec(),
                },
                how: OpenHow::NoCreate,
                claim: OpenClaim::Null(b"user.test".to_vec()),
            }),
            ArgOp::GetAttr(GetAttrArgs {
                requested_attributes: bitmap_from_attributes([FATTR4_TYPE]).unwrap(),
            }),
        ]);
        let response = fixture.executor().execute(request(open)).await;
        assert_eq!(response.status, NfsStatus::Ok);
        let ResOp::GetAttr(NfsResult::Ok(attributes)) = &response.operations[5] else {
            panic!("expected GETATTR for opened named attribute");
        };
        assert_eq!(attributes.values, 9_u32.to_be_bytes());
    }

    #[tokio::test]
    async fn named_attribute_namespace_restrictions_are_enforced() {
        let fixture = Fixture::new();
        fixture.vfs.named_attributes.store(1, Ordering::Relaxed);
        let client_id = confirmed_fixture_client(&fixture, b"named-attribute-restrictions").await;

        let mut create = enter_export();
        create.extend([
            ArgOp::Lookup(super::super::types::LookupArgs { name: b"file".to_vec() }),
            ArgOp::OpenAttr(OpenAttrArgs { create_directory: true }),
            ArgOp::Create(CreateArgs {
                object_type: CreateType::Directory,
                name: b"forbidden".to_vec(),
                attributes: FileAttributes {
                    mask: Vec::new(),
                    values: Vec::new(),
                },
            }),
        ]);
        assert_eq!(fixture.executor().execute(request(create)).await.status, NfsStatus::Invalid);

        let mut exclusive = enter_export();
        exclusive.extend([
            ArgOp::Lookup(super::super::types::LookupArgs { name: b"file".to_vec() }),
            ArgOp::OpenAttr(OpenAttrArgs { create_directory: true }),
            ArgOp::Open(OpenArgs {
                sequence_id: 1,
                share_access: OPEN4_SHARE_ACCESS_WRITE,
                share_deny: 0,
                owner: super::super::types::OpenOwner {
                    client_id,
                    owner: b"named-attribute-exclusive".to_vec(),
                },
                how: OpenHow::Create(CreateHow::Exclusive([0x55; 8])),
                claim: OpenClaim::Null(b"user.new".to_vec()),
            }),
        ]);
        assert_eq!(fixture.executor().execute(request(exclusive)).await.status, NfsStatus::Invalid);

        let mut openattr = enter_export();
        openattr.extend([
            ArgOp::Lookup(super::super::types::LookupArgs { name: b"file".to_vec() }),
            ArgOp::OpenAttr(OpenAttrArgs { create_directory: true }),
            ArgOp::OpenAttr(OpenAttrArgs {
                create_directory: false,
            }),
        ]);
        assert_eq!(fixture.executor().execute(request(openattr)).await.status, NfsStatus::NotSupported);

        let mut cross_namespace_link = enter_export();
        cross_namespace_link.extend([
            ArgOp::Lookup(super::super::types::LookupArgs { name: b"file".to_vec() }),
            ArgOp::SaveFh,
            ArgOp::OpenAttr(OpenAttrArgs { create_directory: true }),
            ArgOp::Link(LinkArgs {
                new_name: b"forbidden-link".to_vec(),
            }),
        ]);
        assert_eq!(fixture.executor().execute(request(cross_namespace_link)).await.status, NfsStatus::CrossDevice);
    }

    #[tokio::test]
    async fn stabilization_retains_the_writing_client_context() {
        let fixture = Fixture::new();
        let writes = HashSet::from([(
            RuntimeFile {
                export_id: ExportId(7),
                object: FILE,
            },
            Some(0x1234),
        )]);

        fixture
            .executor()
            .stabilize_unstable_writes(&writes, OpNum::SetAttr.code())
            .await
            .unwrap();

        assert_eq!(fixture.vfs.stabilized_client_id.load(Ordering::Relaxed), 0x1234);
    }

    #[test]
    fn openattr_create_requires_prior_write_stability() {
        assert!(operation_requires_prior_stability(&ArgOp::OpenAttr(OpenAttrArgs { create_directory: true })));
        assert!(!operation_requires_prior_stability(&ArgOp::OpenAttr(OpenAttrArgs {
            create_directory: false,
        })));
    }

    #[tokio::test]
    async fn create_updates_current_filehandle_only_after_valid_change_info() {
        let fixture = Fixture::new();
        let create = ArgOp::Create(CreateArgs {
            object_type: CreateType::Directory,
            name: b"created".to_vec(),
            attributes: FileAttributes {
                mask: Vec::new(),
                values: Vec::new(),
            },
        });
        let mut operations = enter_export();
        operations.extend([
            create.clone(),
            ArgOp::GetFh,
            ArgOp::GetAttr(GetAttrArgs {
                requested_attributes: bitmap_from_attributes([FATTR4_TYPE]).unwrap(),
            }),
        ]);
        let response = fixture.executor().execute(request(operations)).await;

        assert_eq!(response.status, NfsStatus::Ok);
        let handle = match &response.operations[3] {
            ResOp::GetFh(NfsResult::Ok(handle)) => handle,
            other => panic!("unexpected result: {other:?}"),
        };
        assert_eq!(
            fixture.handles.decode_target(handle.as_bytes()).unwrap(),
            HandleTarget::Backend {
                export_id: ExportId(7),
                object: CREATED_DIRECTORY,
                namespace_node: Some(1),
            }
        );
        assert!(matches!(response.operations[4], ResOp::GetAttr(NfsResult::Ok(_))));

        fixture.vfs.change_info_enabled.store(0, Ordering::Relaxed);
        let mut missing = enter_export();
        missing.extend([create, ArgOp::GetFh]);
        let response = fixture.executor().execute(request(missing)).await;
        assert_eq!(response.status, NfsStatus::ServerFault);
        assert_eq!(response.operations.len(), 3);
        assert!(matches!(response.operations.last(), Some(ResOp::Create(NfsResult::Err(NfsStatus::ServerFault)))));
    }

    #[tokio::test]
    async fn open_missing_change_info_is_cached_as_a_replay_safe_error() {
        let fixture = Fixture::new();
        let client_id = confirmed_fixture_client(&fixture, b"missing-change-info").await;
        fixture.vfs.change_info_enabled.store(0, Ordering::Relaxed);
        let mut operations = enter_export();
        operations.push(ArgOp::Open(OpenArgs {
            sequence_id: 1,
            share_access: 1,
            share_deny: 0,
            owner: super::super::types::OpenOwner {
                client_id,
                owner: b"owner".to_vec(),
            },
            how: OpenHow::NoCreate,
            claim: OpenClaim::Null(b"file".to_vec()),
        }));
        let request = request(operations);

        let first = fixture.executor().execute(request.clone()).await;
        let replay = fixture.executor().execute(request).await;

        assert_eq!(first.status, NfsStatus::ServerFault);
        assert_eq!(replay, first);
        assert_eq!(fixture.vfs.open_preflight_calls.load(Ordering::Relaxed), 1);
        assert_eq!(fixture.vfs.open_calls.load(Ordering::Relaxed), 0);
        assert_eq!(fixture.vfs.release_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn operation_aware_vfs_error_mapping_always_returns_a_legal_status() {
        let operations = [
            OpNum::Access,
            OpNum::Close,
            OpNum::Commit,
            OpNum::Create,
            OpNum::GetAttr,
            OpNum::Link,
            OpNum::Lookup,
            OpNum::LookupParent,
            OpNum::NotVerify,
            OpNum::Open,
            OpNum::OpenAttr,
            OpNum::Read,
            OpNum::ReadDir,
            OpNum::ReadLink,
            OpNum::Remove,
            OpNum::Rename,
            OpNum::SecInfo,
            OpNum::SetAttr,
            OpNum::Verify,
            OpNum::Write,
        ];
        let errors = [
            NfsError::Permission,
            NfsError::NotFound,
            NfsError::Io,
            NfsError::NoDeviceOrAddress,
            NfsError::Access,
            NfsError::Exists,
            NfsError::CrossDevice,
            NfsError::NoDevice,
            NfsError::NotDirectory,
            NfsError::IsDirectory,
            NfsError::Invalid,
            NfsError::FileTooLarge,
            NfsError::NoSpace,
            NfsError::ReadOnly,
            NfsError::TooManyLinks,
            NfsError::NameTooLong,
            NfsError::NotEmpty,
            NfsError::Quota,
            NfsError::Stale,
            NfsError::Remote,
            NfsError::NotSynchronized,
            NfsError::BadCookie,
            NfsError::NotSupported,
            NfsError::TooSmall,
            NfsError::ServerFault,
            NfsError::BadType,
            NfsError::Jukebox,
        ];
        for operation in operations {
            for error in errors {
                let status = map_vfs_error_for_operation(operation.code(), error);
                assert!(
                    is_legal_operation_status(operation.code(), status),
                    "{operation:?} mapped {error:?} to {status:?}"
                );
            }
        }
        assert_eq!(map_vfs_error_for_operation(OpNum::Access.code(), NfsError::Permission), NfsStatus::Access);
        assert_eq!(map_vfs_error_for_operation(OpNum::Write.code(), NfsError::Permission), NfsStatus::Access);
        assert_eq!(map_vfs_error_for_operation(OpNum::Open.code(), NfsError::BadType), NfsStatus::Symlink);
        assert_eq!(map_vfs_error_for_operation(OpNum::ReadLink.code(), NfsError::BadType), NfsStatus::Invalid);
        assert_eq!(map_vfs_error_for_operation(OpNum::Rename.code(), NfsError::IsDirectory), NfsStatus::Exists);
    }

    #[tokio::test]
    async fn lookupp_returns_through_backend_root_to_pseudo_parent() {
        let fixture = Fixture::new();
        let mut operations = enter_export();
        operations.extend([
            ArgOp::Lookup(super::super::types::LookupArgs {
                name: b"created".to_vec(),
            }),
            ArgOp::LookupParent,
            ArgOp::LookupParent,
            ArgOp::GetFh,
        ]);
        let response = fixture.executor().execute(request(operations)).await;

        assert_eq!(response.status, NfsStatus::Ok);
        let handle = match &response.operations[5] {
            ResOp::GetFh(NfsResult::Ok(handle)) => handle,
            other => panic!("unexpected result: {other:?}"),
        };
        assert_eq!(
            fixture.handles.decode_target(handle.as_bytes()).unwrap(),
            HandleTarget::Pseudo { namespace_node: 0 }
        );
    }

    #[tokio::test]
    async fn readlink_and_stale_stateid_use_operation_specific_results() {
        let fixture = Fixture::new();
        let mut link_operations = enter_export();
        link_operations.extend([
            ArgOp::Lookup(super::super::types::LookupArgs { name: b"link".to_vec() }),
            ArgOp::ReadLink,
        ]);
        let link_response = fixture.executor().execute(request(link_operations)).await;
        assert_eq!(
            link_response.operations[3],
            ResOp::ReadLink(NfsResult::Ok(ReadLinkOk {
                link: b"target".to_vec(),
            }))
        );

        let mut read_operations = enter_export();
        read_operations.extend([
            ArgOp::Lookup(super::super::types::LookupArgs { name: b"file".to_vec() }),
            ArgOp::Read(ReadArgs {
                state_id: super::super::types::StateId {
                    sequence_id: 1,
                    other: [1; 12],
                },
                offset: 0,
                count: 1,
            }),
            ArgOp::GetFh,
        ]);
        let read_response = fixture.executor().execute(request(read_operations)).await;
        assert_eq!(read_response.status, NfsStatus::StaleStateId);
        assert_eq!(read_response.operations.len(), 4);
    }

    #[tokio::test]
    async fn stateful_errors_and_illegal_discriminants_stop_the_compound() {
        let fixture = Fixture::new();
        let placeholder = fixture
            .executor()
            .execute(request(vec![
                ArgOp::Renew(super::super::types::RenewArgs { client_id: 1 }),
                ArgOp::PutRootFh,
            ]))
            .await;
        assert_eq!(placeholder.status, NfsStatus::StaleClientId);
        assert_eq!(placeholder.operations, vec![ResOp::Renew(NfsStatus::StaleClientId)]);

        let illegal = fixture
            .executor()
            .execute(request(vec![ArgOp::Illegal { requested_opcode: 2 }, ArgOp::PutRootFh]))
            .await;
        assert_eq!(illegal.status, NfsStatus::OperationIllegal);
        assert_eq!(illegal.operations, vec![ResOp::Illegal(NfsStatus::OperationIllegal)]);
    }

    #[tokio::test]
    async fn putfh_rejects_forged_handles_without_changing_current_fh() {
        let fixture = Fixture::new();
        let response = fixture
            .executor()
            .execute(request(vec![
                ArgOp::PutRootFh,
                ArgOp::PutFh(PutFhArgs {
                    object: NfsFileHandle(vec![0; 8]),
                }),
                ArgOp::GetFh,
            ]))
            .await;

        assert_eq!(response.status, NfsStatus::BadHandle);
        assert_eq!(response.operations.len(), 2);
        assert_eq!(response.operations[1], ResOp::PutFh(NfsStatus::BadHandle));
    }

    #[tokio::test]
    async fn putfh_rejects_authentic_handle_from_wrong_lifetime_codec() {
        let fixture = Fixture::new();
        let wrongly_persistent = HandleCodec::from_key([0x11; 8], [0x22; 32]).encode_target(HandleTarget::Backend {
            export_id: ExportId(7),
            object: ROOT,
            namespace_node: None,
        });
        let response = fixture
            .executor()
            .execute(request(vec![ArgOp::PutFh(PutFhArgs {
                object: NfsFileHandle(wrongly_persistent.to_vec()),
            })]))
            .await;

        assert_eq!(response.status, NfsStatus::BadHandle);
        assert_eq!(response.operations, vec![ResOp::PutFh(NfsStatus::BadHandle)]);
    }

    #[tokio::test]
    async fn pseudo_readdir_uses_stable_cookies_verifiers_and_exact_maxcount() {
        let fixture = Fixture::new();
        let first = fixture
            .executor()
            .execute(request(vec![
                ArgOp::PutRootFh,
                ArgOp::ReadDir(ReadDirArgs {
                    cookie: 0,
                    cookie_verifier: [0; 8],
                    directory_count: 4096,
                    max_count: 4096,
                    requested_attributes: Vec::new(),
                }),
            ]))
            .await;
        let listing = match &first.operations[1] {
            ResOp::ReadDir(NfsResult::Ok(listing)) => listing,
            other => panic!("unexpected result: {other:?}"),
        };
        assert_eq!(listing.entries.len(), 1);
        assert_eq!(listing.entries[0].cookie, 3);
        assert_eq!(listing.entries[0].name, b"export");
        assert!(listing.eof);

        let continuation = fixture
            .executor()
            .execute(request(vec![
                ArgOp::PutRootFh,
                ArgOp::ReadDir(ReadDirArgs {
                    cookie: 3,
                    cookie_verifier: listing.cookie_verifier,
                    directory_count: 0,
                    // verifier + null entry pointer + eof
                    max_count: 16,
                    requested_attributes: Vec::new(),
                }),
            ]))
            .await;
        assert_eq!(
            continuation.operations[1],
            ResOp::ReadDir(NfsResult::Ok(ReadDirOk {
                cookie_verifier: listing.cookie_verifier,
                entries: Vec::new(),
                eof: true,
            }))
        );

        let stale_verifier = fixture
            .executor()
            .execute(request(vec![
                ArgOp::PutRootFh,
                ArgOp::ReadDir(ReadDirArgs {
                    cookie: 3,
                    cookie_verifier: [0xff; 8],
                    directory_count: 0,
                    max_count: 4096,
                    requested_attributes: Vec::new(),
                }),
            ]))
            .await;
        assert_eq!(stale_verifier.operations[1], ResOp::ReadDir(NfsResult::Err(NfsStatus::NotSame)));
    }

    #[tokio::test]
    async fn secinfo_preserves_policy_order_and_lookup_enforces_the_edge() {
        let mut fixture = Fixture::new();
        fixture.exports[0].security_policy = SecurityPolicy::auth_sys();

        let secinfo = fixture
            .executor()
            .execute(request(vec![
                ArgOp::PutRootFh,
                ArgOp::SecInfo(SecInfoArgs {
                    name: b"export".to_vec(),
                }),
            ]))
            .await;
        assert_eq!(secinfo.operations[1], ResOp::SecInfo(NfsResult::Ok(vec![SecurityInfo::Other(1)])));

        let lookup = fixture.executor().execute(request(enter_export())).await;
        assert_eq!(lookup.status, NfsStatus::WrongSecurity);
        assert_eq!(lookup.operations[1], ResOp::Lookup(NfsStatus::WrongSecurity));
    }

    #[tokio::test]
    async fn nested_export_overlays_real_and_missing_intermediate_directories() {
        let real = OverlayFixture::new(true);
        let mut alpha_operations = enter_overlay_projects();
        alpha_operations.extend([
            ArgOp::Lookup(super::super::types::LookupArgs {
                name: b"alpha".to_vec(),
            }),
            ArgOp::GetFh,
        ]);
        let alpha = real.executor().execute(request(alpha_operations)).await;
        let alpha_target = match &alpha.operations[4] {
            ResOp::GetFh(NfsResult::Ok(handle)) => real.handles.decode_target(handle.as_bytes()).unwrap(),
            other => panic!("unexpected result: {other:?}"),
        };
        assert_eq!(
            alpha_target,
            HandleTarget::Backend {
                export_id: ExportId(41),
                object: OVERLAY_ALPHA,
                namespace_node: Some(real.projects_node().get()),
            }
        );

        let mut data_operations = enter_overlay_projects();
        data_operations.extend([
            ArgOp::Lookup(super::super::types::LookupArgs { name: b"data".to_vec() }),
            ArgOp::GetFh,
        ]);
        let data = real.executor().execute(request(data_operations)).await;
        let data_target = match &data.operations[4] {
            ResOp::GetFh(NfsResult::Ok(handle)) => real.handles.decode_target(handle.as_bytes()).unwrap(),
            other => panic!("unexpected result: {other:?}"),
        };
        assert_eq!(
            data_target,
            HandleTarget::Backend {
                export_id: ExportId(42),
                object: OVERLAY_NESTED_ROOT,
                namespace_node: Some(real.data_node().get()),
            },
            "the nested export must shadow the parent backend's data directory"
        );

        let missing = OverlayFixture::new(false);
        let mut missing_operations = enter_overlay_projects();
        missing_operations.extend([
            ArgOp::Lookup(super::super::types::LookupArgs { name: b"data".to_vec() }),
            ArgOp::GetFh,
        ]);
        let missing_data = missing.executor().execute(request(missing_operations)).await;
        assert_eq!(missing_data.status, NfsStatus::Ok);
        let missing_target = match &missing_data.operations[4] {
            ResOp::GetFh(NfsResult::Ok(handle)) => missing.handles.decode_target(handle.as_bytes()).unwrap(),
            other => panic!("unexpected result: {other:?}"),
        };
        assert_eq!(
            missing_target,
            HandleTarget::Backend {
                export_id: ExportId(42),
                object: OVERLAY_NESTED_ROOT,
                namespace_node: Some(missing.data_node().get()),
            }
        );
    }

    #[tokio::test]
    async fn overlay_route_survives_getfh_putfh_and_arbitrary_lookupp() {
        let fixture = OverlayFixture::new(true);
        let mut acquire = enter_overlay_projects();
        acquire.extend([
            ArgOp::Lookup(super::super::types::LookupArgs { name: b"data".to_vec() }),
            ArgOp::GetFh,
        ]);
        let acquired = fixture.executor().execute(request(acquire)).await;
        let data_handle = match &acquired.operations[4] {
            ResOp::GetFh(NfsResult::Ok(handle)) => handle.clone(),
            other => panic!("unexpected result: {other:?}"),
        };

        let response = fixture
            .executor()
            .execute(request(vec![
                ArgOp::PutFh(PutFhArgs { object: data_handle }),
                ArgOp::LookupParent,
                ArgOp::Lookup(super::super::types::LookupArgs { name: b"data".to_vec() }),
                ArgOp::LookupParent,
                ArgOp::Lookup(super::super::types::LookupArgs { name: b"beta".to_vec() }),
                ArgOp::GetFh,
            ]))
            .await;

        assert_eq!(response.status, NfsStatus::Ok);
        let target = match &response.operations[5] {
            ResOp::GetFh(NfsResult::Ok(handle)) => fixture.handles.decode_target(handle.as_bytes()).unwrap(),
            other => panic!("unexpected result: {other:?}"),
        };
        assert_eq!(
            target,
            HandleTarget::Backend {
                export_id: ExportId(41),
                object: OVERLAY_BETA,
                namespace_node: Some(fixture.projects_node().get()),
            }
        );
    }

    #[tokio::test]
    async fn mismatched_and_stale_overlay_anchors_cannot_redirect_lookup() {
        let fixture = OverlayFixture::new(true);
        let mismatched = NfsFileHandle(
            fixture
                .handles
                .encode_target(HandleTarget::Backend {
                    export_id: ExportId(41),
                    object: OVERLAY_ALPHA,
                    namespace_node: Some(fixture.data_node().get()),
                })
                .expect("fixture export has a configured filehandle lifetime")
                .to_vec(),
        );
        let rejected = fixture
            .executor()
            .execute(request(vec![ArgOp::PutFh(PutFhArgs { object: mismatched })]))
            .await;
        assert_eq!(rejected.operations, vec![ResOp::PutFh(NfsStatus::BadHandle)]);

        let missing = OverlayFixture::new(false);
        let stale = NfsFileHandle(
            missing
                .handles
                .encode_target(HandleTarget::Backend {
                    export_id: ExportId(41),
                    object: OVERLAY_ALPHA,
                    namespace_node: Some(missing.projects_node().get()),
                })
                .expect("fixture export has a configured filehandle lifetime")
                .to_vec(),
        );
        let not_redirected = missing
            .executor()
            .execute(request(vec![
                ArgOp::PutFh(PutFhArgs { object: stale }),
                ArgOp::Lookup(super::super::types::LookupArgs { name: b"data".to_vec() }),
            ]))
            .await;
        assert_eq!(not_redirected.status, NfsStatus::NotDirectory);
        assert_eq!(not_redirected.operations[1], ResOp::Lookup(NfsStatus::NotDirectory));
    }

    #[tokio::test]
    async fn overlay_readdir_merges_shadowed_names_across_pages_with_reversible_cookies() {
        let fixture = OverlayFixture::new(true);
        let mut full_operations = enter_overlay_projects();
        full_operations.push(ArgOp::ReadDir(ReadDirArgs {
            cookie: 0,
            cookie_verifier: [0; 8],
            directory_count: 4096,
            max_count: 4096,
            requested_attributes: Vec::new(),
        }));
        let full = fixture.executor().execute(request(full_operations)).await;
        let full_listing = match &full.operations[3] {
            ResOp::ReadDir(NfsResult::Ok(listing)) => listing,
            other => panic!("unexpected result: {other:?}"),
        };
        assert_eq!(
            full_listing
                .entries
                .iter()
                .map(|entry| entry.name.as_slice())
                .collect::<Vec<_>>(),
            vec![b"data".as_slice(), b"alpha".as_slice(), b"beta".as_slice()]
        );
        assert_eq!(full_listing.entries.iter().filter(|entry| entry.name == b"data").count(), 1);

        let first_two_directory_bytes =
            directory_entry_name_size(&full_listing.entries[0]) + directory_entry_name_size(&full_listing.entries[1]);
        for (directory_count, expected_entries) in [
            (first_two_directory_bytes - 1, 1_usize),
            (first_two_directory_bytes, 2_usize),
        ] {
            let mut operations = enter_overlay_projects();
            operations.push(ArgOp::ReadDir(ReadDirArgs {
                cookie: 0,
                cookie_verifier: [0; 8],
                directory_count: directory_count as u32,
                max_count: 4096,
                requested_attributes: Vec::new(),
            }));
            let response = fixture.executor().execute(request(operations)).await;
            let listing = match &response.operations[3] {
                ResOp::ReadDir(NfsResult::Ok(listing)) => listing,
                other => panic!("unexpected result: {other:?}"),
            };
            assert_eq!(listing.entries.len(), expected_entries);
            assert!(!listing.eof);
        }

        let page_max_count = full_listing
            .entries
            .iter()
            .map(|entry| {
                read_dir_result_size(&ReadDirOk {
                    cookie_verifier: full_listing.cookie_verifier,
                    entries: vec![entry.clone()],
                    eof: false,
                })
            })
            .max()
            .unwrap() as u32;
        let mut cookie = 0;
        let mut verifier = [0; 8];
        let mut names = Vec::new();
        let mut cookies = Vec::new();
        for _ in 0..8 {
            let mut operations = enter_overlay_projects();
            operations.push(ArgOp::ReadDir(ReadDirArgs {
                cookie,
                cookie_verifier: verifier,
                directory_count: 4096,
                max_count: page_max_count,
                requested_attributes: Vec::new(),
            }));
            let response = fixture.executor().execute(request(operations)).await;
            let listing = match &response.operations[3] {
                ResOp::ReadDir(NfsResult::Ok(listing)) => listing,
                other => panic!("unexpected result: {other:?}"),
            };
            assert!(read_dir_result_size(listing) <= page_max_count as usize);
            assert_eq!(listing.entries.len(), 1);
            names.push(listing.entries[0].name.clone());
            cookies.push(listing.entries[0].cookie);
            cookie = listing.entries[0].cookie;
            verifier = listing.cookie_verifier;
            if listing.eof {
                break;
            }
        }
        assert_eq!(names, vec![b"data".to_vec(), b"alpha".to_vec(), b"beta".to_vec()]);
        assert!(cookies[0] < BACKEND_COOKIE_FLAG);
        assert_eq!(cookies[1], BACKEND_COOKIE_FLAG | 10);
        assert_eq!(cookies[2], BACKEND_COOKIE_FLAG | 30);
    }

    #[tokio::test]
    async fn overlay_readdir_verifier_tracks_backend_and_namespace_topology() {
        let fixture = OverlayFixture::new(true);
        let mut first_operations = enter_overlay_projects();
        first_operations.push(ArgOp::ReadDir(ReadDirArgs {
            cookie: 0,
            cookie_verifier: [0; 8],
            directory_count: 4096,
            max_count: 128,
            requested_attributes: Vec::new(),
        }));
        let first = fixture.executor().execute(request(first_operations)).await;
        let listing = match &first.operations[3] {
            ResOp::ReadDir(NfsResult::Ok(listing)) => listing,
            other => panic!("unexpected result: {other:?}"),
        };
        let cookie = listing.entries.last().unwrap().cookie;
        let old_verifier = listing.cookie_verifier;

        let identical = OverlayFixture::new(true);
        let mut identical_operations = enter_overlay_projects();
        identical_operations.push(ArgOp::ReadDir(ReadDirArgs {
            cookie: 0,
            cookie_verifier: [0; 8],
            directory_count: 4096,
            max_count: 128,
            requested_attributes: Vec::new(),
        }));
        let identical_response = identical.executor().execute(request(identical_operations)).await;
        let identical_listing = match &identical_response.operations[3] {
            ResOp::ReadDir(NfsResult::Ok(listing)) => listing,
            other => panic!("unexpected result: {other:?}"),
        };
        assert_eq!(identical_listing.cookie_verifier, old_verifier);
        assert_eq!(identical_listing.entries, listing.entries);

        let mut changed_topology = OverlayFixture::new(true);
        changed_topology
            .namespace
            .add_export("/srv/projects/zeta", ExportId(43))
            .unwrap();
        let mut topology_continuation = enter_overlay_projects();
        topology_continuation.push(ArgOp::ReadDir(ReadDirArgs {
            cookie,
            cookie_verifier: old_verifier,
            directory_count: 4096,
            max_count: 4096,
            requested_attributes: Vec::new(),
        }));
        let topology_response = changed_topology.executor().execute(request(topology_continuation)).await;
        assert_eq!(topology_response.operations[3], ResOp::ReadDir(NfsResult::Err(NfsStatus::NotSame)));

        fixture.parent.set_verifier(8);

        let mut continuation = enter_overlay_projects();
        continuation.push(ArgOp::ReadDir(ReadDirArgs {
            cookie,
            cookie_verifier: old_verifier,
            directory_count: 4096,
            max_count: 4096,
            requested_attributes: Vec::new(),
        }));
        let response = fixture.executor().execute(request(continuation)).await;
        assert_eq!(response.operations[3], ResOp::ReadDir(NfsResult::Err(NfsStatus::NotSame)));
    }

    #[tokio::test]
    async fn secinfo_reports_nested_export_policy_at_the_overlay_edge() {
        let fixture = OverlayFixture::new(true);
        let mut operations = enter_overlay_projects();
        operations.extend([
            ArgOp::SecInfo(SecInfoArgs { name: b"data".to_vec() }),
            ArgOp::SecInfo(SecInfoArgs {
                name: b"alpha".to_vec(),
            }),
        ]);
        let response = fixture.executor().execute(request(operations)).await;
        assert_eq!(
            response.operations[3],
            ResOp::SecInfo(NfsResult::Ok(vec![SecurityInfo::Other(1), SecurityInfo::Other(0),]))
        );
        assert_eq!(response.operations[4], ResOp::SecInfo(NfsResult::Ok(vec![SecurityInfo::Other(0)])));
    }

    #[test]
    fn malformed_or_unrepresentable_overlay_backend_progress_is_bounded() {
        let wire_entry = DirectoryEntry {
            cookie: 10,
            name: b"alpha".to_vec(),
            attributes: FileAttributes {
                mask: vec![1, 2],
                values: vec![3; 5],
            },
        };
        let empty_size = read_dir_result_size(&ReadDirOk {
            cookie_verifier: [0; 8],
            entries: Vec::new(),
            eof: false,
        });
        let one_size = read_dir_result_size(&ReadDirOk {
            cookie_verifier: [0; 8],
            entries: vec![wire_entry.clone()],
            eof: false,
        });
        assert_eq!(directory_entry_wire_size(&wire_entry), one_size - empty_size);

        let empty_progress = ReadDirectoryPage {
            verifier: [1; 8],
            entries: Vec::new(),
            eof: false,
        };
        assert_eq!(validate_overlay_backend_page(&empty_progress, 0, 1), Err(NfsStatus::ServerFault));

        let high_cookie = ReadDirectoryPage {
            verifier: [1; 8],
            entries: vec![VfsDirectoryEntry {
                object: OVERLAY_ALPHA,
                file_id: OVERLAY_ALPHA.file_id,
                name: NfsName::new(b"alpha".to_vec()).unwrap(),
                cookie: BACKEND_COOKIE_FLAG,
                attributes: None,
            }],
            eof: true,
        };
        assert_eq!(validate_overlay_backend_page(&high_cookie, 0, 1), Err(NfsStatus::Resource));
        assert_eq!(encode_overlay_backend_cookie(BACKEND_COOKIE_FLAG), Err(NfsStatus::Resource));
    }
}
