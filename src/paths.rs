use std::path::{Path, PathBuf};

use anyhow::Context;

const PROTON_VENDOR_DIR: &str = "protonmail";
const BRIDGE_CONFIG_DIR: &str = "bridge-v3";
const GLUON_DIR: &str = "gluon";
const GLUON_BACKEND_DIR: &str = "backend";
const GLUON_STORE_DIR: &str = "store";
const GLUON_DB_DIR: &str = "db";
const GLUON_DEFERRED_DELETE_DIR: &str = "deferred_delete";
const SESSION_LOGS_DIR: &str = "sessions";
const CRASH_REPORTS_DIR: &str = "crash_reports";

fn is_windows_absolute_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'/' || bytes[2] == b'\\')
}

/// Runtime filesystem paths modeled after Proton Bridge locations.
///
/// Linux:
/// - settings: $XDG_CONFIG_HOME/protonmail/bridge-v3
/// - data: $XDG_DATA_HOME/protonmail/bridge-v3
/// - cache: $XDG_CACHE_HOME/protonmail/bridge-v3
///
/// Non-linux:
/// - settings: UserConfigDir/protonmail/bridge-v3
/// - data: UserConfigDir/protonmail/bridge-v3 (matches Proton's provider behavior)
/// - cache: UserCacheDir/protonmail/bridge-v3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePaths {
    settings_dir: PathBuf,
    data_dir: PathBuf,
    cache_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GluonPaths {
    root: PathBuf,
}

impl GluonPaths {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn backend_store_dir(&self) -> PathBuf {
        self.root.join(GLUON_BACKEND_DIR).join(GLUON_STORE_DIR)
    }

    pub fn backend_db_dir(&self) -> PathBuf {
        self.root.join(GLUON_BACKEND_DIR).join(GLUON_DB_DIR)
    }

    pub fn account_store_dir(&self, gluon_user_id: &str) -> PathBuf {
        self.backend_store_dir().join(gluon_user_id)
    }

    pub fn account_db_path(&self, gluon_user_id: &str) -> PathBuf {
        self.backend_db_dir().join(format!("{gluon_user_id}.db"))
    }

    pub fn account_db_wal_path(&self, gluon_user_id: &str) -> PathBuf {
        self.backend_db_dir()
            .join(format!("{gluon_user_id}.db-wal"))
    }

    pub fn account_db_shm_path(&self, gluon_user_id: &str) -> PathBuf {
        self.backend_db_dir()
            .join(format!("{gluon_user_id}.db-shm"))
    }

    pub fn deferred_delete_dir(&self) -> PathBuf {
        self.backend_db_dir().join(GLUON_DEFERRED_DELETE_DIR)
    }
}

impl RuntimePaths {
    pub fn resolve(settings_override: Option<&Path>) -> anyhow::Result<Self> {
        if let Some(dir) = settings_override {
            let override_dir = dir.to_path_buf();
            return Ok(Self {
                settings_dir: override_dir.clone(),
                data_dir: override_dir.clone(),
                cache_dir: override_dir,
            });
        }

        let config_base = dirs::config_dir().context("could not determine config directory")?;
        let cache_base = dirs::cache_dir().context("could not determine cache directory")?;

        let data_base = if cfg!(target_os = "linux") {
            dirs::data_dir().context("could not determine data directory")?
        } else {
            config_base.clone()
        };

        Ok(Self::from_bases(config_base, data_base, cache_base))
    }

    pub fn from_bases(config_base: PathBuf, data_base: PathBuf, cache_base: PathBuf) -> Self {
        Self {
            settings_dir: config_base.join(PROTON_VENDOR_DIR).join(BRIDGE_CONFIG_DIR),
            data_dir: data_base.join(PROTON_VENDOR_DIR).join(BRIDGE_CONFIG_DIR),
            cache_dir: cache_base.join(PROTON_VENDOR_DIR).join(BRIDGE_CONFIG_DIR),
        }
    }

    pub fn settings_dir(&self) -> &Path {
        &self.settings_dir
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    pub fn logs_dir(&self) -> PathBuf {
        self.data_dir.join("logs")
    }

    pub fn session_logs_dir(&self) -> PathBuf {
        self.logs_dir().join(SESSION_LOGS_DIR)
    }

    pub fn crash_reports_dir(&self) -> PathBuf {
        self.logs_dir().join(CRASH_REPORTS_DIR)
    }

    pub fn imap_sync_dir(&self) -> PathBuf {
        self.settings_dir.join("imap-sync")
    }

    pub fn tls_dir(&self) -> PathBuf {
        self.settings_dir.join("tls")
    }

    pub fn grpc_server_config_path(&self) -> PathBuf {
        self.settings_dir.join("grpcServerConfig.json")
    }

    pub fn grpc_mail_settings_path(&self) -> PathBuf {
        self.settings_dir.join("grpc_mail_settings.json")
    }

    pub fn grpc_app_settings_path(&self) -> PathBuf {
        self.settings_dir.join("grpc_app_settings.json")
    }

    pub fn disk_cache_dir(&self) -> PathBuf {
        self.settings_dir.join("cache")
    }

    pub fn default_gluon_dir(&self) -> PathBuf {
        self.data_dir.join(GLUON_DIR)
    }

    pub fn resolve_gluon_dir(&self, configured_gluon_dir: Option<&str>) -> PathBuf {
        let configured = configured_gluon_dir
            .map(str::trim)
            .filter(|path| !path.is_empty());

        match configured {
            Some(raw) => {
                let path = PathBuf::from(raw);
                if path.is_absolute() || is_windows_absolute_path(raw) {
                    path
                } else {
                    self.data_dir.join(path)
                }
            }
            None => self.default_gluon_dir(),
        }
    }

    pub fn gluon_paths(&self, configured_gluon_dir: Option<&str>) -> GluonPaths {
        GluonPaths::new(self.resolve_gluon_dir(configured_gluon_dir))
    }

    pub fn sync_state_path(&self, account_id: &str) -> PathBuf {
        self.settings_dir.join(format!("sync-{account_id}"))
    }

    pub fn sync_state_tmp_path(&self, account_id: &str) -> PathBuf {
        self.settings_dir.join(format!("sync-{account_id}.tmp"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bases_uses_proton_vendor_and_bridge_config_names() {
        let paths = RuntimePaths::from_bases(
            PathBuf::from("/cfg"),
            PathBuf::from("/data"),
            PathBuf::from("/cache"),
        );

        assert_eq!(
            paths.settings_dir(),
            Path::new("/cfg").join("protonmail").join("bridge-v3")
        );
        assert_eq!(
            paths.data_dir(),
            Path::new("/data").join("protonmail").join("bridge-v3")
        );
        assert_eq!(
            paths.cache_dir(),
            Path::new("/cache").join("protonmail").join("bridge-v3")
        );
    }

    #[test]
    fn override_pins_all_runtime_roots_to_override_directory() {
        let override_path = PathBuf::from("/tmp/openproton-custom");
        let paths = RuntimePaths::resolve(Some(&override_path)).unwrap();

        assert_eq!(paths.settings_dir(), override_path);
        assert_eq!(paths.data_dir(), override_path);
        assert_eq!(paths.cache_dir(), override_path);
    }

    #[test]
    fn derived_paths_are_resolved_from_runtime_roots() {
        let paths = RuntimePaths::from_bases(
            PathBuf::from("/cfg"),
            PathBuf::from("/data"),
            PathBuf::from("/cache"),
        );

        assert_eq!(
            paths.logs_dir(),
            Path::new("/data/protonmail/bridge-v3/logs")
        );
        assert_eq!(
            paths.session_logs_dir(),
            Path::new("/data/protonmail/bridge-v3/logs/sessions")
        );
        assert_eq!(
            paths.crash_reports_dir(),
            Path::new("/data/protonmail/bridge-v3/logs/crash_reports")
        );
        assert_eq!(
            paths.imap_sync_dir(),
            Path::new("/cfg/protonmail/bridge-v3/imap-sync")
        );
        assert_eq!(paths.tls_dir(), Path::new("/cfg/protonmail/bridge-v3/tls"));
        assert_eq!(
            paths.grpc_server_config_path(),
            Path::new("/cfg/protonmail/bridge-v3/grpcServerConfig.json")
        );
        assert_eq!(
            paths.grpc_mail_settings_path(),
            Path::new("/cfg/protonmail/bridge-v3/grpc_mail_settings.json")
        );
        assert_eq!(
            paths.grpc_app_settings_path(),
            Path::new("/cfg/protonmail/bridge-v3/grpc_app_settings.json")
        );
        assert_eq!(
            paths.disk_cache_dir(),
            Path::new("/cfg/protonmail/bridge-v3/cache")
        );
    }

    #[test]
    fn gluon_paths_default_to_data_root_gluon_directory() {
        let paths = RuntimePaths::from_bases(
            PathBuf::from("/cfg"),
            PathBuf::from("/data"),
            PathBuf::from("/cache"),
        );
        let gluon = paths.gluon_paths(None);

        assert_eq!(gluon.root(), Path::new("/data/protonmail/bridge-v3/gluon"));
        assert_eq!(
            gluon.backend_store_dir(),
            Path::new("/data/protonmail/bridge-v3/gluon/backend/store")
        );
        assert_eq!(
            gluon.backend_db_dir(),
            Path::new("/data/protonmail/bridge-v3/gluon/backend/db")
        );
        assert_eq!(
            gluon.account_db_path("user-1"),
            Path::new("/data/protonmail/bridge-v3/gluon/backend/db/user-1.db")
        );
        assert_eq!(
            gluon.deferred_delete_dir(),
            Path::new("/data/protonmail/bridge-v3/gluon/backend/db/deferred_delete")
        );
    }

    #[test]
    fn sync_state_paths_are_account_scoped() {
        let paths = RuntimePaths::from_bases(
            PathBuf::from("/cfg"),
            PathBuf::from("/data"),
            PathBuf::from("/cache"),
        );

        assert_eq!(
            paths.sync_state_path("uid-alpha"),
            Path::new("/cfg/protonmail/bridge-v3/sync-uid-alpha")
        );
        assert_eq!(
            paths.sync_state_tmp_path("uid-alpha"),
            Path::new("/cfg/protonmail/bridge-v3/sync-uid-alpha.tmp")
        );
    }

    #[test]
    fn resolve_gluon_dir_accepts_windows_drive_override() {
        let paths = RuntimePaths::from_bases(
            PathBuf::from("/cfg"),
            PathBuf::from("/data"),
            PathBuf::from("/cache"),
        );

        assert_eq!(
            paths.resolve_gluon_dir(Some("D:/BridgeCache/gluon")),
            Path::new("D:/BridgeCache/gluon")
        );
    }
}
