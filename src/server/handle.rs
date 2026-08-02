use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;

use super::migration::{MigrationBundle, MigrationControl, MigrationControlError, MigrationId};
use super::ServerError;
use crate::vfs::{ExportId, Nfs4FsLocation, ProtocolVersion};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointInfo {
    pub version: ProtocolVersion,
    pub address: SocketAddr,
    pub export_path: String,
    pub nfs_port: u16,
    /// MOUNTv3 port, absent for an NFSv4-only endpoint.
    pub mount_port: Option<u16>,
}

/// Application-facing handle for a running NFS server instance.
///
/// Production callers should request [`Self::shutdown`] and then await
/// [`Self::wait`]. That path drains protocol critical sections, reconciles
/// indeterminate OPEN transactions, and retries backend pin cleanup within the
/// configured graceful-shutdown deadline. Dropping the last handle aborts the
/// server control task and cannot perform asynchronous cleanup; a backend
/// session/fence teardown must therefore reconcile orphaned OPEN operation
/// records and pins before that server identity is reused.
pub struct NfsServerHandle {
    endpoint_infos: Vec<EndpointInfo>,
    portmapper_addr: Option<SocketAddr>,
    shutdown: watch::Sender<bool>,
    task: SharedServerTask,
    migration: Option<Arc<MigrationControl>>,
}

type SharedServerTask = Arc<Mutex<Option<JoinHandle<Result<(), ServerError>>>>>;

impl NfsServerHandle {
    pub(crate) fn new(
        endpoint_infos: Vec<EndpointInfo>,
        portmapper_addr: Option<SocketAddr>,
        shutdown: watch::Sender<bool>,
        task: JoinHandle<Result<(), ServerError>>,
    ) -> Self {
        Self {
            endpoint_infos,
            portmapper_addr,
            shutdown,
            task: Arc::new(Mutex::new(Some(task))),
            migration: None,
        }
    }

    pub(crate) fn with_migration(mut self, migration: Arc<MigrationControl>) -> Self {
        self.migration = Some(migration);
        self
    }

    pub fn endpoint_info(&self) -> EndpointInfo {
        self.endpoint_infos[0].clone()
    }

    pub fn endpoint_infos(&self) -> &[EndpointInfo] {
        &self.endpoint_infos
    }

    /// Returns the shared TCP/UDP portmapper address, when configured.
    pub fn portmapper_addr(&self) -> Option<SocketAddr> {
        self.portmapper_addr
    }

    /// Quiesces one export, drains its in-flight mutations, obtains the
    /// application coordinator fence, and returns a bounded protocol-state
    /// bundle for the destination.
    pub async fn prepare_migration(
        &self,
        export_id: ExportId,
        destination: Nfs4FsLocation,
    ) -> Result<MigrationBundle, MigrationControlError> {
        self.migration
            .as_ref()
            .ok_or(MigrationControlError::NotConfigured)?
            .prepare(export_id, destination)
            .await
    }

    /// Validates and durably stages a source bundle. Staged state remains
    /// invisible until `commit_migration` succeeds.
    pub async fn import_migration(&self, bundle: MigrationBundle) -> Result<MigrationId, MigrationControlError> {
        self.migration
            .as_ref()
            .ok_or(MigrationControlError::NotConfigured)?
            .import(bundle)
            .await
    }

    /// Commits this server's source or destination half of a migration.
    pub async fn commit_migration(&self, id: MigrationId) -> Result<(), MigrationControlError> {
        self.migration
            .as_ref()
            .ok_or(MigrationControlError::NotConfigured)?
            .commit(id)
            .await
    }

    /// Aborts a prepared source or staged destination transaction.
    pub async fn abort_migration(&self, id: MigrationId) -> Result<(), MigrationControlError> {
        self.migration
            .as_ref()
            .ok_or(MigrationControlError::NotConfigured)?
            .abort(id)
            .await
    }

    /// Requests shutdown. Calling this more than once is harmless.
    pub async fn shutdown(&self) -> Result<(), ServerError> {
        let _ = self.shutdown.send(true);
        Ok(())
    }

    /// Waits for all listener and connection tasks to terminate.
    pub async fn wait(&self) -> Result<(), ServerError> {
        // Await by mutable reference so cancellation leaves the JoinHandle in
        // shared state. Concurrent waiters remain blocked until termination.
        let mut task = self.task.lock().await;
        let joined = match task.as_mut() {
            Some(task) => task.await,
            None => return Ok(()),
        };
        *task = None;
        joined.map_err(ServerError::Task)?
    }
}

impl std::fmt::Debug for NfsServerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NfsServerHandle")
            .field("endpoint_infos", &self.endpoint_infos)
            .field("portmapper_addr", &self.portmapper_addr)
            .field("migration", &self.migration.is_some())
            .finish_non_exhaustive()
    }
}

impl Drop for NfsServerHandle {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Ok(task) = self.task.try_lock() {
            if let Some(task) = task.as_ref() {
                task.abort();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wait_consumes_a_join_failure_before_returning_it() {
        let task = tokio::spawn(async { Ok(()) });
        task.abort();
        let (shutdown, _) = watch::channel(false);
        let handle = NfsServerHandle::new(Vec::new(), None, shutdown, task);

        assert!(matches!(handle.wait().await, Err(ServerError::Task(_))));
        assert!(handle.wait().await.is_ok());
    }
}
