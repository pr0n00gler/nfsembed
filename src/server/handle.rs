use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;

use super::ServerError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountInfo {
    pub server_addr: SocketAddr,
    pub export_path: String,
    pub nfs_version: u32,
    pub nfs_port: u16,
    pub mount_port: u16,
}

pub struct ServerHandle {
    mount_infos: Vec<MountInfo>,
    shutdown: watch::Sender<bool>,
    task: SharedServerTask,
}

type SharedServerTask = Arc<Mutex<Option<JoinHandle<Result<(), ServerError>>>>>;

impl ServerHandle {
    pub(crate) fn new(
        mount_infos: Vec<MountInfo>,
        shutdown: watch::Sender<bool>,
        task: JoinHandle<Result<(), ServerError>>,
    ) -> Self {
        Self {
            mount_infos,
            shutdown,
            task: Arc::new(Mutex::new(Some(task))),
        }
    }

    pub fn mount_info(&self) -> MountInfo {
        self.mount_infos[0].clone()
    }

    pub fn mount_infos(&self) -> &[MountInfo] {
        &self.mount_infos
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

impl std::fmt::Debug for ServerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerHandle")
            .field("mount_infos", &self.mount_infos)
            .finish_non_exhaustive()
    }
}

impl Drop for ServerHandle {
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
        let handle = ServerHandle::new(Vec::new(), shutdown, task);

        assert!(matches!(handle.wait().await, Err(ServerError::Task(_))));
        assert!(handle.wait().await.is_ok());
    }
}
