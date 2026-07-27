mod capabilities;
mod context;
mod nfs4;
mod types;

use async_trait::async_trait;
pub use capabilities::VfsCapabilities;
pub use context::{ExportId, GssService, GssVersion, Principal, ProtocolVersion, RequestContext, SecurityContext};
pub use nfs4::*;
pub use types::*;

/// Application-provided virtual filesystem contract for NFSv3 and NFSv4.
///
/// Unsupported optional operations have safe `NFS3ERR_NOTSUPP` defaults.
/// Once admitted, an RPC execution is tracked independently of its connection:
/// a disconnected client or elapsed reply deadline does not cancel an
/// in-progress backend mutation. A forced server shutdown after the configured
/// graceful-shutdown timeout can still cancel the future, so mutation
/// implementations must keep irreversible work cancellation-safe and must not
/// detach untracked work from the returned future. Every successful non-WRITE
/// mutation on a read-write NFSv4 export must be durable before its future
/// returns; opting into NFSv4 makes that guarantee an explicit capability
/// promise.
#[async_trait]
pub trait VirtualFileSystem: Send + Sync + 'static {
    fn capabilities(&self) -> VfsCapabilities;

    /// Explicitly opts this backend into NFSv4 and describes the semantics it
    /// can provide. The default keeps existing NFSv3 backends v3-only.
    fn nfs4_capabilities(&self) -> Option<Nfs4Capabilities> {
        None
    }

    fn root(&self) -> ObjectKey;

    #[doc(hidden)]
    fn unsupported_mutation(&self) -> NfsError {
        if self.capabilities().read_only {
            NfsError::ReadOnly
        } else {
            NfsError::NotSupported
        }
    }

    async fn getattr(&self, context: &RequestContext, object: ObjectKey) -> Result<FileAttributes, NfsError>;

    async fn lookup(
        &self,
        context: &RequestContext,
        parent: ObjectKey,
        name: &NfsName,
    ) -> Result<CreatedObject, NfsError>;

    /// Returns a directory's parent for NFSv4 LOOKUPP.
    async fn lookup_parent(&self, _context: &RequestContext, _directory: ObjectKey) -> Result<CreatedObject, NfsError> {
        Err(NfsError::NotSupported)
    }

    /// Validates the complete NFSv4 OPEN request and snapshots its target
    /// without changing backend state.
    ///
    /// This method must perform all checks that can be made at the snapshot,
    /// including requested data access, read-only policy, quota/space
    /// constraints, create attributes, ACL inheritance, and truncate
    /// eligibility. It must not create or truncate an object, update
    /// timestamps or change IDs, or reserve backend resources. When a
    /// `GUARDED` create finds an existing name, it must return
    /// [`NfsError::Exists`] before inspecting or reporting the target's file
    /// type. `NoCreate` against a missing name returns
    /// [`NfsError::NotFound`].
    ///
    /// A successful result includes authoritative [`ChangeInfo`] for the
    /// parent directory. The server uses this result only to order protocol
    /// state and error precedence; the mutating phase must repeat all
    /// authorization and validation atomically. Truncation requires
    /// write/modify authorization independently of the requested OPEN share
    /// access in both phases.
    async fn nfs4_open_preflight(
        &self,
        _context: &RequestContext,
        _parent: ObjectKey,
        _name: &NfsName,
        _request: &Nfs4OpenRequest,
    ) -> Result<Nfs4OpenPreflight, NfsError> {
        Err(self.unsupported_mutation())
    }

    /// Atomically revalidates and executes an NFSv4 OPEN after preflight.
    ///
    /// The name-to-object mapping must still satisfy `transaction.expected`
    /// in the same backend transaction that repeats full authorization and
    /// applies any create or truncate. A replacement, removal, or unexpected
    /// insertion must not be opened or modified; backends should report
    /// [`NfsError::Jukebox`] so the client retries against fresh namespace
    /// state (`GUARDED` insertion races may report [`NfsError::Exists`]).
    /// When `request.create.attributes.acl` is present, ACL inheritance and
    /// mode synchronization are part of that transaction.
    ///
    /// The complete outcome (success or error) is exactly idempotent by
    /// `transaction.operation_id`: a retry with identical authenticated
    /// identity and arguments returns the original result without
    /// reauthorizing, recreating, or retruncating. Reuse of a live operation
    /// ID with any different identity or argument must be rejected. The
    /// backend must reserve bounded outcome-cache capacity before any side
    /// effect and must not evict live or indeterminate outcomes; capacity
    /// exhaustion should return a retryable error.
    ///
    /// If `transaction.acquire_pin` is true, `transaction.pin_id` must be
    /// installed in this same transaction before an existing object is
    /// mutated or a new name becomes visible. A `Missing` expectation with
    /// `acquire_pin == false` is invalid and must be rejected before outcome
    /// capacity is reserved or any mutation begins. Pin tokens are
    /// idempotent.
    /// Neither cancellation nor a backend process failure may leave an
    /// unrecorded completed mutation: implementations must use a
    /// cancellation-safe transaction and recover each indeterminate operation
    /// to its exact committed outcome (or roll it back) before accepting a
    /// retry.
    ///
    /// Durable backends must namespace operation records by the fenced server
    /// instance and reconcile orphaned operation records and pins during
    /// instance recovery. They may retire a record only after
    /// [`VirtualFileSystem::nfs4_finish_open_operation`] is called.
    async fn nfs4_open(
        &self,
        _context: &RequestContext,
        _parent: ObjectKey,
        _name: &NfsName,
        _request: Nfs4OpenRequest,
        _transaction: Nfs4OpenTransaction,
    ) -> Result<Nfs4OpenResult, NfsError> {
        Err(self.unsupported_mutation())
    }

    /// Retires an exact OPEN outcome after the server has durably adopted it
    /// into protocol replay state or has definitively abandoned the attempt.
    ///
    /// This operation is idempotent and cancellation-safe. It releases only
    /// the outcome-cache entry; an acquired object pin remains live until
    /// [`VirtualFileSystem::release_open_object`] is called. NFSv4 backends
    /// overriding [`VirtualFileSystem::nfs4_open`] must override this method
    /// with the matching bounded-cache lifecycle.
    async fn nfs4_finish_open_operation(&self, _context: &RequestContext, _operation_id: u64) -> Result<(), NfsError> {
        Err(NfsError::NotSupported)
    }

    /// Pins an object for an NFSv4 open instance so it remains usable after
    /// unlink. The token is opaque, scoped to one running server, and
    /// idempotent. This separate method is used for pins that were not
    /// acquired by [`VirtualFileSystem::nfs4_open`].
    async fn retain_open_object(
        &self,
        _context: &RequestContext,
        _object: ObjectKey,
        _open_instance: [u8; 16],
    ) -> Result<(), NfsError> {
        Err(NfsError::NotSupported)
    }

    /// Releases a pin previously established by `retain_open_object` or an
    /// atomic OPEN transaction.
    ///
    /// Release is an idempotent server-cleanup capability: the backend uses
    /// `context` for export routing and audit identity, but must not deny
    /// cleanup because the originating user no longer has access to the
    /// object. Retrying release after the pin or unlinked object has already
    /// been collected succeeds.
    async fn release_open_object(
        &self,
        _context: &RequestContext,
        _object: ObjectKey,
        _open_instance: [u8; 16],
    ) -> Result<(), NfsError> {
        Err(NfsError::NotSupported)
    }

    /// Reads the canonical ACL used by NFSv4 `acl`.
    async fn nfs4_get_acl(&self, _context: &RequestContext, _object: ObjectKey) -> Result<Nfs4Acl, NfsError> {
        Err(NfsError::NotSupported)
    }

    /// Atomically applies ACL inheritance/mode synchronization.
    async fn nfs4_set_acl_and_mode(
        &self,
        _context: &RequestContext,
        _object: ObjectKey,
        _acl: Nfs4Acl,
        _mode: Option<u32>,
    ) -> Result<MutationResult<()>, NfsError> {
        Err(self.unsupported_mutation())
    }

    /// Opens the named-attribute directory object associated with `object`.
    ///
    /// If the backend advertises named attributes, a successful result must
    /// identify an object whose [`FileType`] is
    /// [`FileType::AttributeDirectory`]. Every entry returned by `lookup` or
    /// `readdir` for that directory must have [`FileType::NamedAttribute`].
    async fn nfs4_named_attribute_directory(
        &self,
        _context: &RequestContext,
        _object: ObjectKey,
        _create: bool,
    ) -> Result<CreatedObject, NfsError> {
        Err(NfsError::NotSupported)
    }

    /// Returns the named-attribute directory containing `object`.
    ///
    /// Backends that advertise [`Nfs4Capabilities::named_attributes`] must
    /// implement this for every object whose [`FileType`] is
    /// [`FileType::NamedAttribute`].  The NFSv4 adapter uses the association
    /// to reject hard links that would cross a named-attribute namespace.
    async fn nfs4_named_attribute_parent(
        &self,
        _context: &RequestContext,
        _object: ObjectKey,
    ) -> Result<ObjectKey, NfsError> {
        Err(NfsError::NotSupported)
    }

    async fn nfs4_quota(&self, _context: &RequestContext, _object: ObjectKey) -> Result<Nfs4Quota, NfsError> {
        Err(NfsError::NotSupported)
    }

    /// Answers delegation eligibility while performing any backend-specific
    /// authorization atomically with the answer.
    async fn nfs4_delegation_eligibility(
        &self,
        _context: &RequestContext,
        _object: ObjectKey,
        _request: DelegationRequest,
    ) -> Result<DelegationEligibility, NfsError> {
        Ok(DelegationEligibility::Ineligible)
    }

    /// Fences delegated-space reservations to one server incarnation.
    ///
    /// Before enabling delegations, the server calls this method with the
    /// exclusive stable-state fence token for durable mode, or a unique
    /// boot-scoped token for in-memory mode. The backend must atomically make
    /// `scope` current and release or invalidate every reservation created
    /// under an older scope before returning success. Repeating the call with
    /// the same token is idempotent.
    ///
    /// This is what makes delegated-space cleanup safe across process death:
    /// an opaque release token can be lost only with the old process, and the
    /// next fenced incarnation retires all such tokens before it grants or
    /// reclaims a delegation.
    async fn nfs4_fence_delegation_reservations(&self, _scope: &StableFenceToken) -> Result<(), NfsError> {
        Err(NfsError::NotSupported)
    }

    /// Reserves space before a write delegation is acknowledged.
    ///
    /// The returned token must be non-empty and no larger than
    /// [`MAX_DELEGATION_RESERVATION_TOKEN_SIZE`], and `reserved_bytes` must
    /// cover the requested byte count. The reservation must be bound to
    /// `scope`; it becomes invalid when a newer scope is installed through
    /// [`Self::nfs4_fence_delegation_reservations`]. The server may retain the
    /// reservation across a failed protocol transaction and release it
    /// asynchronously.
    async fn nfs4_reserve_delegated_space(
        &self,
        _context: &RequestContext,
        _object: ObjectKey,
        _bytes: u64,
        _scope: &StableFenceToken,
    ) -> Result<DelegationReservation, NfsError> {
        Err(NfsError::NotSupported)
    }

    /// Releases a delegated-space reservation.
    ///
    /// This is an idempotent, cancellation-safe server-cleanup capability.
    /// The backend uses `context` only for export routing and audit identity;
    /// it must not reauthorize the originating user. A retry after the
    /// reservation was already released succeeds. If the future is cancelled,
    /// the backend must either have completed the release or leave the same
    /// token valid for a later retry. The server retains its cloned token until
    /// one call confirms success.
    async fn nfs4_release_delegated_space(
        &self,
        _context: &RequestContext,
        _reservation: DelegationReservation,
    ) -> Result<(), NfsError> {
        Err(NfsError::NotSupported)
    }

    /// Reports current, replicated, absent, or moved filesystem placement.
    async fn nfs4_location_state(
        &self,
        _context: &RequestContext,
        _object: ObjectKey,
    ) -> Result<Nfs4LocationState, NfsError> {
        Err(NfsError::NotSupported)
    }

    async fn nfs4_persistent_object_id(
        &self,
        _context: &RequestContext,
        _object: ObjectKey,
    ) -> Result<PersistentObjectId, NfsError> {
        Err(NfsError::NotSupported)
    }

    async fn nfs4_resolve_persistent_object(
        &self,
        _context: &RequestContext,
        _identity: &PersistentObjectId,
    ) -> Result<CreatedObject, NfsError> {
        Err(NfsError::NotSupported)
    }

    /// Makes earlier unstable data durable before a later synchronous
    /// mutation is acknowledged in the same COMPOUND.
    async fn nfs4_stabilize_mutation(&self, context: &RequestContext, object: ObjectKey) -> Result<(), NfsError> {
        self.commit(context, object, 0, 0).await.map(|_| ())
    }

    async fn access(&self, _context: &RequestContext, _object: ObjectKey, _requested: u32) -> Result<u32, NfsError> {
        Err(NfsError::NotSupported)
    }

    async fn setattr(
        &self,
        _context: &RequestContext,
        _object: ObjectKey,
        _attributes: SetAttributes,
        _guard: Option<NfsTime>,
    ) -> Result<MutationResult<()>, NfsError> {
        Err(self.unsupported_mutation())
    }

    async fn readlink(&self, _context: &RequestContext, _object: ObjectKey) -> Result<Vec<u8>, NfsError> {
        Err(NfsError::NotSupported)
    }

    async fn read(
        &self,
        _context: &RequestContext,
        _object: ObjectKey,
        _offset: u64,
        _count: u32,
    ) -> Result<ReadResult, NfsError> {
        Err(NfsError::NotSupported)
    }

    /// Zero-copy read extension. Existing implementations only need to
    /// implement `read`; converting its `Vec` result into `Bytes` transfers
    /// ownership without copying. Backends with immutable shared storage can
    /// override this method directly.
    async fn read_bytes(
        &self,
        context: &RequestContext,
        object: ObjectKey,
        offset: u64,
        count: u32,
    ) -> Result<ReadBytesResult, NfsError> {
        self.read(context, object, offset, count).await.map(Into::into)
    }

    async fn write(
        &self,
        _context: &RequestContext,
        _object: ObjectKey,
        _offset: u64,
        _data: &[u8],
        _requested: WriteStability,
    ) -> Result<MutationResult<WriteResult>, NfsError> {
        Err(self.unsupported_mutation())
    }

    /// Performs the non-mutating authorization phase of a zero-length
    /// NFSv4 WRITE.
    ///
    /// RFC 7530 section 16.36.4 requires a zero-length WRITE to succeed
    /// subject to permission checking. Implementations that advertise NFSv4
    /// write support must override this hook to check write authorization,
    /// read-only policy, and object availability without changing data,
    /// metadata, or timestamps. The default refuses the operation rather
    /// than treating an empty `write` call as proof that this check is safe.
    async fn nfs4_check_zero_length_write(
        &self,
        _context: &RequestContext,
        _object: ObjectKey,
        _offset: u64,
        _requested: WriteStability,
    ) -> Result<(), NfsError> {
        Err(self.unsupported_mutation())
    }

    /// Creates an object. NFSv4 callers may include a canonical ACL in
    /// `attributes`; the backend must apply inheritance and mode
    /// synchronization atomically with creation.
    async fn create(
        &self,
        _context: &RequestContext,
        _parent: ObjectKey,
        _name: &NfsName,
        _attributes: SetAttributes,
        _mode: CreateMode,
    ) -> Result<MutationResult<CreatedObject>, NfsError> {
        Err(self.unsupported_mutation())
    }

    /// Creates a directory with the same NFSv4 ACL atomicity requirement as
    /// [`VirtualFileSystem::create`].
    async fn mkdir(
        &self,
        _context: &RequestContext,
        _parent: ObjectKey,
        _name: &NfsName,
        _attributes: SetAttributes,
    ) -> Result<MutationResult<CreatedObject>, NfsError> {
        Err(self.unsupported_mutation())
    }

    /// Creates a symbolic link with the same NFSv4 ACL atomicity requirement
    /// as [`VirtualFileSystem::create`].
    async fn symlink(
        &self,
        _context: &RequestContext,
        _parent: ObjectKey,
        _name: &NfsName,
        _target: &[u8],
        _attributes: SetAttributes,
    ) -> Result<MutationResult<CreatedObject>, NfsError> {
        Err(self.unsupported_mutation())
    }

    /// Creates a special node with the same NFSv4 ACL atomicity requirement
    /// as [`VirtualFileSystem::create`].
    async fn mknod(
        &self,
        _context: &RequestContext,
        _parent: ObjectKey,
        _name: &NfsName,
        _node_type: NodeType,
        _attributes: SetAttributes,
    ) -> Result<MutationResult<CreatedObject>, NfsError> {
        Err(self.unsupported_mutation())
    }

    async fn remove(
        &self,
        _context: &RequestContext,
        _parent: ObjectKey,
        _name: &NfsName,
    ) -> Result<MutationResult<()>, NfsError> {
        Err(self.unsupported_mutation())
    }

    async fn rmdir(
        &self,
        _context: &RequestContext,
        _parent: ObjectKey,
        _name: &NfsName,
    ) -> Result<MutationResult<()>, NfsError> {
        Err(self.unsupported_mutation())
    }

    async fn rename(
        &self,
        _context: &RequestContext,
        _from_parent: ObjectKey,
        _from_name: &NfsName,
        _to_parent: ObjectKey,
        _to_name: &NfsName,
    ) -> Result<(MutationResult<()>, MutationResult<()>), NfsError> {
        Err(self.unsupported_mutation())
    }

    async fn link(
        &self,
        _context: &RequestContext,
        _object: ObjectKey,
        _to_parent: ObjectKey,
        _to_name: &NfsName,
    ) -> Result<MutationResult<()>, NfsError> {
        Err(self.unsupported_mutation())
    }

    /// Returns one page after `cookie`.
    ///
    /// NFSv4 reserves cookies 1 and 2. A backend serving a
    /// [`ProtocolVersion::V4`] request must therefore return monotonically
    /// increasing entry cookies greater than 2 and accept those cookies on
    /// continuation requests. NFSv3 backends may use their native cookie
    /// space.
    async fn readdir(
        &self,
        _context: &RequestContext,
        _directory: ObjectKey,
        _cookie: u64,
        _verifier: [u8; 8],
        _backend_hint: usize,
    ) -> Result<ReadDirectoryPage, NfsError> {
        Err(NfsError::NotSupported)
    }

    async fn fsstat(&self, _context: &RequestContext, _object: ObjectKey) -> Result<FsStat, NfsError> {
        Err(NfsError::NotSupported)
    }

    async fn fsinfo(&self, _context: &RequestContext, _object: ObjectKey) -> Result<FsInfo, NfsError> {
        Err(NfsError::NotSupported)
    }

    async fn pathconf(&self, _context: &RequestContext, _object: ObjectKey) -> Result<PathConf, NfsError> {
        Err(NfsError::NotSupported)
    }

    async fn commit(
        &self,
        _context: &RequestContext,
        _object: ObjectKey,
        _offset: u64,
        _count: u32,
    ) -> Result<MutationResult<()>, NfsError> {
        Err(self.unsupported_mutation())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ReadOnlyDefaults;

    #[async_trait]
    impl VirtualFileSystem for ReadOnlyDefaults {
        fn capabilities(&self) -> VfsCapabilities {
            VfsCapabilities::READ_ONLY
        }

        fn root(&self) -> ObjectKey {
            ObjectKey {
                file_id: 1,
                generation: 1,
            }
        }

        async fn getattr(&self, _context: &RequestContext, _object: ObjectKey) -> Result<FileAttributes, NfsError> {
            Err(NfsError::NotSupported)
        }

        async fn lookup(
            &self,
            _context: &RequestContext,
            _parent: ObjectKey,
            _name: &NfsName,
        ) -> Result<CreatedObject, NfsError> {
            Err(NfsError::NotSupported)
        }
    }

    #[tokio::test]
    async fn default_access_requires_an_authoritative_backend_answer() {
        let context = RequestContext {
            principal: Principal::Anonymous,
            client_addr: "127.0.0.1:1".parse().unwrap(),
            export_id: ExportId(1),
            protocol: ProtocolVersion::V3,
            client_id: None,
        };
        assert_eq!(ReadOnlyDefaults.access(&context, ReadOnlyDefaults.root(), 0x3f).await, Err(NfsError::NotSupported));
    }
}
