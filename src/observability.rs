use std::time::Duration;

/// Optional integration point for embedding applications that need metrics.
/// The crate deliberately does not install a recorder or tracing subscriber.
pub trait Metrics: Send + Sync + 'static {
    fn connection_opened(&self) {}
    fn connection_closed(&self) {}
    fn request_finished(&self, _procedure: u32, _duration: Duration, _status: u32) {}
    fn request_rejected(&self, _reason: &'static str) {}
}

#[derive(Debug, Default)]
pub struct NoopMetrics;

impl Metrics for NoopMetrics {}
