use tokio::sync::{mpsc, Mutex};
use tracing::info;

use super::mail_runtime::{
    self, MailRuntimeConfig, MailRuntimeHandle, MailRuntimeStartError, MailRuntimeTransition,
};
use crate::paths::RuntimePaths;

pub struct RuntimeSupervisor {
    runtime_paths: RuntimePaths,
    handle: Mutex<Option<SupervisorRuntimeHandle>>,
    transition_lock: Mutex<()>,
}

impl RuntimeSupervisor {
    pub fn new(runtime_paths: RuntimePaths) -> Self {
        Self {
            runtime_paths,
            handle: Mutex::new(None),
            transition_lock: Mutex::new(()),
        }
    }

    pub async fn start(
        &self,
        config: MailRuntimeConfig,
        transition: MailRuntimeTransition,
        notify_tx: Option<mpsc::UnboundedSender<String>>,
    ) -> Result<(), MailRuntimeStartError> {
        let _transition_guard = self.transition_lock.lock().await;
        self.start_locked(config, transition, notify_tx).await
    }

    pub async fn stop(&self, reason: &str) -> anyhow::Result<()> {
        let _transition_guard = self.transition_lock.lock().await;
        self.stop_locked(reason).await
    }

    pub async fn restart(
        &self,
        config: MailRuntimeConfig,
        transition: MailRuntimeTransition,
        notify_tx: Option<mpsc::UnboundedSender<String>>,
    ) -> Result<(), MailRuntimeStartError> {
        let _transition_guard = self.transition_lock.lock().await;
        self.stop_locked("restart")
            .await
            .map_err(|err| MailRuntimeStartError::Prepare(err.context("failed to stop runtime")))?;
        self.start_locked(config, transition, notify_tx).await
    }

    pub async fn is_running(&self) -> bool {
        let guard = self.handle.lock().await;
        guard.as_ref().is_some_and(|runtime| !runtime.is_finished())
    }

    async fn start_locked(
        &self,
        config: MailRuntimeConfig,
        transition: MailRuntimeTransition,
        notify_tx: Option<mpsc::UnboundedSender<String>>,
    ) -> Result<(), MailRuntimeStartError> {
        if let Some(finished) = self.take_finished_handle().await {
            finished.stop().await.map_err(|err| {
                MailRuntimeStartError::Prepare(
                    err.context("failed to drain completed runtime before start"),
                )
            })?;
        }

        if self.is_running().await {
            info!(
                transition = ?transition,
                "runtime supervisor start skipped: runtime already running"
            );
            return Ok(());
        }

        let handle =
            mail_runtime::start(self.runtime_paths.clone(), config, transition, notify_tx).await?;
        *self.handle.lock().await = Some(SupervisorRuntimeHandle::Live(handle));
        info!(
            transition = ?transition,
            "runtime supervisor started mail runtime"
        );
        Ok(())
    }

    async fn stop_locked(&self, reason: &str) -> anyhow::Result<()> {
        let existing = self.handle.lock().await.take();
        let Some(runtime) = existing else {
            info!(
                reason,
                "runtime supervisor stop skipped: runtime not running"
            );
            return Ok(());
        };

        info!(reason, "runtime supervisor stopping mail runtime");
        runtime.stop().await?;
        info!(reason, "runtime supervisor stopped mail runtime");
        Ok(())
    }

    async fn take_finished_handle(&self) -> Option<SupervisorRuntimeHandle> {
        let mut guard = self.handle.lock().await;
        if guard
            .as_ref()
            .is_some_and(SupervisorRuntimeHandle::is_finished)
        {
            return guard.take();
        }
        None
    }
}

enum SupervisorRuntimeHandle {
    Live(MailRuntimeHandle),
    #[cfg(test)]
    Test(TestRuntimeHandle),
}

impl SupervisorRuntimeHandle {
    fn is_finished(&self) -> bool {
        match self {
            Self::Live(handle) => handle.is_finished(),
            #[cfg(test)]
            Self::Test(handle) => handle.finished,
        }
    }

    async fn stop(self) -> anyhow::Result<()> {
        match self {
            Self::Live(handle) => handle.stop().await,
            #[cfg(test)]
            Self::Test(handle) => handle.stop().await,
        }
    }
}

#[cfg(test)]
struct TestRuntimeHandle {
    finished: bool,
    stop_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    stop_delay: std::time::Duration,
}

#[cfg(test)]
impl TestRuntimeHandle {
    fn new(finished: bool, stop_delay: std::time::Duration) -> Self {
        Self {
            finished,
            stop_count: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            stop_delay,
        }
    }

    async fn stop(self) -> anyhow::Result<()> {
        self.stop_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if !self.stop_delay.is_zero() {
            tokio::time::sleep(self.stop_delay).await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    fn dummy_config() -> MailRuntimeConfig {
        MailRuntimeConfig {
            bind_host: "127.0.0.1".to_string(),
            imap_port: 1143,
            smtp_port: 1025,
            disable_tls: true,
            use_ssl_for_imap: false,
            use_ssl_for_smtp: false,
            event_poll_interval: Duration::from_secs(30),
        }
    }

    fn new_supervisor() -> (RuntimeSupervisor, tempfile::TempDir) {
        let temp = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::resolve(Some(temp.path())).unwrap();
        (RuntimeSupervisor::new(paths), temp)
    }

    #[tokio::test]
    async fn is_running_is_false_when_stopped() {
        let (supervisor, _temp) = new_supervisor();
        assert!(!supervisor.is_running().await);
    }

    #[tokio::test]
    async fn stop_is_noop_when_runtime_is_not_running() {
        let (supervisor, _temp) = new_supervisor();
        supervisor.stop("test").await.unwrap();
        assert!(!supervisor.is_running().await);
    }

    #[tokio::test]
    async fn start_is_idempotent_when_runtime_already_running() {
        let (supervisor, _temp) = new_supervisor();
        let test_handle = TestRuntimeHandle::new(false, Duration::ZERO);
        let stop_count = test_handle.stop_count.clone();
        *supervisor.handle.lock().await = Some(SupervisorRuntimeHandle::Test(test_handle));

        supervisor
            .start(dummy_config(), MailRuntimeTransition::Startup, None)
            .await
            .unwrap();

        assert!(supervisor.is_running().await);
        assert_eq!(stop_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn start_drains_finished_handle_before_boot_attempt() {
        let (supervisor, _temp) = new_supervisor();
        let test_handle = TestRuntimeHandle::new(true, Duration::ZERO);
        let stop_count = test_handle.stop_count.clone();
        *supervisor.handle.lock().await = Some(SupervisorRuntimeHandle::Test(test_handle));

        let err = supervisor
            .start(dummy_config(), MailRuntimeTransition::Startup, None)
            .await
            .unwrap_err();

        assert!(matches!(err, MailRuntimeStartError::Prepare(_)));
        assert_eq!(stop_count.load(Ordering::SeqCst), 1);
        assert!(!supervisor.is_running().await);
    }

    #[tokio::test]
    async fn restart_stops_existing_runtime_before_restart_attempt() {
        let (supervisor, _temp) = new_supervisor();
        let test_handle = TestRuntimeHandle::new(false, Duration::ZERO);
        let stop_count = test_handle.stop_count.clone();
        *supervisor.handle.lock().await = Some(SupervisorRuntimeHandle::Test(test_handle));

        let err = supervisor
            .restart(dummy_config(), MailRuntimeTransition::SettingsChange, None)
            .await
            .unwrap_err();

        assert!(matches!(err, MailRuntimeStartError::Prepare(_)));
        assert_eq!(stop_count.load(Ordering::SeqCst), 1);
        assert!(!supervisor.is_running().await);
    }

    #[tokio::test]
    async fn concurrent_stop_calls_stop_runtime_only_once() {
        let (supervisor, _temp) = new_supervisor();
        let supervisor = Arc::new(supervisor);
        let test_handle = TestRuntimeHandle::new(false, Duration::from_millis(80));
        let stop_count = test_handle.stop_count.clone();
        *supervisor.handle.lock().await = Some(SupervisorRuntimeHandle::Test(test_handle));

        let s1 = supervisor.clone();
        let s2 = supervisor.clone();
        let stop_a = tokio::spawn(async move { s1.stop("a").await });
        let stop_b = tokio::spawn(async move { s2.stop("b").await });

        stop_a.await.unwrap().unwrap();
        stop_b.await.unwrap().unwrap();

        assert_eq!(stop_count.load(Ordering::SeqCst), 1);
        assert!(!supervisor.is_running().await);
    }
}
