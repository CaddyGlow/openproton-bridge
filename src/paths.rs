use std::path::{Path, PathBuf};

use anyhow::Context;

const PROTON_VENDOR_DIR: &str = "protonmail";
const BRIDGE_CONFIG_DIR: &str = "bridge-v3";

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
}
