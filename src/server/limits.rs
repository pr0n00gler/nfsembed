use std::time::Duration;

const MAXIMUM_MUTATION_REPLY_SIZE: usize = 304;
const MAX_VALID_RPC_CALL_PREFIX_SIZE: usize = 440;
const MAX_FILE_HANDLE_XDR_SIZE: usize = 68;
const WRITE_ARGUMENT_FIXED_SIZE: usize = MAX_FILE_HANDLE_XDR_SIZE + 8 + 4 + 4 + 4;
const WRITE_PADDING_ALLOWANCE: usize = 3;
const MAXIMUM_WRITE_RECORD_OVERHEAD: usize =
    MAX_VALID_RPC_CALL_PREFIX_SIZE + WRITE_ARGUMENT_FIXED_SIZE + WRITE_PADDING_ALLOWANCE;
const MAXIMUM_READ_REPLY_OVERHEAD: usize = 24 + 4 + 88 + 4 + 4 + 4 + 3;
const READDIR_REPLY_OVERHEAD: usize = 24 + 4;

#[derive(Clone, Debug)]
pub struct ServerLimits {
    pub max_connections: usize,
    pub max_requests_per_connection: usize,
    pub max_inflight_requests: usize,
    pub max_rpc_record_size: usize,
    pub max_rpc_fragment_size: usize,
    pub max_fragments_per_record: usize,
    pub max_buffered_request_bytes: usize,
    pub max_buffered_reply_bytes: usize,
    pub max_read_size: u32,
    pub max_write_size: u32,
    pub max_readdir_response_size: u32,
    pub request_timeout: Duration,
    pub idle_connection_timeout: Duration,
    pub replay_cache_capacity: usize,
    pub replay_cache_max_bytes: usize,
    pub replay_cache_ttl: Duration,
    pub graceful_shutdown_timeout: Duration,
    pub max_mounts: usize,
}

impl ServerLimits {
    pub fn production_defaults() -> Self {
        Self {
            max_connections: 1024,
            max_requests_per_connection: 32,
            max_inflight_requests: 2048,
            max_rpc_record_size: 2 * 1024 * 1024,
            max_rpc_fragment_size: 1024 * 1024,
            max_fragments_per_record: 16,
            max_buffered_request_bytes: 64 * 1024 * 1024,
            max_buffered_reply_bytes: 64 * 1024 * 1024,
            max_read_size: 1024 * 1024,
            max_write_size: 1024 * 1024,
            max_readdir_response_size: 1024 * 1024,
            request_timeout: Duration::from_secs(30),
            idle_connection_timeout: Duration::from_secs(120),
            replay_cache_capacity: 4096,
            replay_cache_max_bytes: 64 * 1024 * 1024,
            replay_cache_ttl: Duration::from_secs(120),
            graceful_shutdown_timeout: Duration::from_secs(10),
            max_mounts: 4096,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.max_connections == 0 {
            return Err("max_connections must be greater than zero");
        }
        if self.max_requests_per_connection == 0 || self.max_inflight_requests == 0 {
            return Err("request concurrency limits must be greater than zero");
        }
        if self.max_connections > tokio::sync::Semaphore::MAX_PERMITS
            || self.max_requests_per_connection > tokio::sync::Semaphore::MAX_PERMITS
            || self.max_inflight_requests > tokio::sync::Semaphore::MAX_PERMITS
        {
            return Err("connection and request limits exceed the runtime maximum");
        }
        if self.max_rpc_fragment_size == 0 || self.max_rpc_record_size < self.max_rpc_fragment_size {
            return Err("RPC record limit must be at least the non-zero fragment limit");
        }
        if self.max_rpc_fragment_size > 0x7fff_ffff || self.max_rpc_record_size > u32::MAX as usize {
            return Err("RPC record and fragment limits exceed wire or budgeting capacity");
        }
        if self.max_fragments_per_record == 0
            || self.replay_cache_capacity == 0
            || self.replay_cache_max_bytes == 0
            || self.max_mounts == 0
        {
            return Err("fragment, replay, and mount limits must be greater than zero");
        }
        if self.max_buffered_request_bytes < self.max_rpc_record_size
            || self.max_buffered_reply_bytes < self.max_rpc_record_size
            || self.max_buffered_request_bytes > tokio::sync::Semaphore::MAX_PERMITS
            || self.max_buffered_reply_bytes > tokio::sync::Semaphore::MAX_PERMITS
        {
            return Err("buffer byte budgets must each hold one record and fit the runtime semaphore");
        }
        // RPC envelope plus the largest mutation result (CREATE with a
        // maximum-size handle, post-op attributes, and complete WCC data).
        // Rejecting smaller transports prevents a side effect from executing
        // when its only possible reply cannot be delivered.
        if self.max_rpc_record_size < MAXIMUM_MUTATION_REPLY_SIZE
            || MAXIMUM_MUTATION_REPLY_SIZE.div_ceil(self.max_rpc_fragment_size) > self.max_fragments_per_record
        {
            return Err("RPC limits must be able to carry every mutation reply");
        }
        let transport_capacity = self.transport_record_capacity();
        let read_capacity = transport_capacity.saturating_sub(MAXIMUM_READ_REPLY_OVERHEAD);
        let write_capacity = transport_capacity.saturating_sub(MAXIMUM_WRITE_RECORD_OVERHEAD);
        let readdir_capacity = transport_capacity.saturating_sub(READDIR_REPLY_OVERHEAD);
        if self.max_read_size == 0
            || self.max_write_size == 0
            || self.max_readdir_response_size == 0
            || self.max_read_size as usize > read_capacity
            || self.max_write_size as usize > write_capacity
            || self.max_readdir_response_size as usize > readdir_capacity
        {
            return Err("transfer limits exceed the effective RPC transport capacity");
        }
        Ok(())
    }

    pub(crate) fn transport_record_capacity(&self) -> usize {
        self.max_rpc_record_size
            .min(self.max_rpc_fragment_size.saturating_mul(self.max_fragments_per_record))
    }
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self::production_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfs3::codec::EncodeNfsResult;
    use crate::nfs3::procedures::CreateResult;
    use crate::rpc::codec::Encoder;
    use crate::vfs::{FileAttributes, FileType, NfsTime, WccAttributes};

    #[test]
    fn mutation_reply_bound_covers_the_largest_complete_union_arm() {
        let time = NfsTime {
            seconds: u64::from(u32::MAX),
            nanoseconds: 999_999_999,
        };
        let attributes = FileAttributes {
            file_type: FileType::Regular,
            mode: u32::MAX,
            links: u32::MAX,
            uid: u32::MAX,
            gid: u32::MAX,
            size: u64::MAX,
            used: u64::MAX,
            device: None,
            fs_id: u64::MAX,
            file_id: u64::MAX,
            access_time: time,
            modify_time: time,
            change_time: time,
        };
        let mut body = Encoder::new();
        CreateResult::Ok {
            object_handle: Some(vec![0; 64]),
            object_attributes: Some(attributes.clone()),
            directory_wcc: crate::nfs3::types::WccData {
                before: Some(WccAttributes {
                    size: u64::MAX,
                    modify_time: time,
                    change_time: time,
                }),
                after: Some(attributes),
            },
        }
        .encode_result(&mut body)
        .unwrap();
        const RPC_ACCEPTED_REPLY_ENVELOPE: usize = 24;
        assert_eq!(body.len() + RPC_ACCEPTED_REPLY_ENVELOPE, MAXIMUM_MUTATION_REPLY_SIZE);
    }

    #[test]
    fn transfer_limits_include_protocol_and_fragment_overhead() {
        let mut limits = ServerLimits::production_defaults();
        limits.max_rpc_record_size = 1024;
        limits.max_rpc_fragment_size = 1024;
        limits.max_read_size = (1024 - MAXIMUM_READ_REPLY_OVERHEAD) as u32;
        limits.max_write_size = (1024 - MAXIMUM_WRITE_RECORD_OVERHEAD) as u32;
        limits.max_readdir_response_size = (1024 - READDIR_REPLY_OVERHEAD) as u32;
        assert!(limits.validate().is_ok());

        limits.max_write_size += 1;
        assert_eq!(limits.validate(), Err("transfer limits exceed the effective RPC transport capacity"));
    }
}
