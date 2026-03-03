use std::path::Path;
use std::path::PathBuf;

use openproton_bridge::paths::RuntimePaths;

#[test]
fn be019_resolves_linux_style_gluon_layout_from_data_root() {
    let runtime_paths = RuntimePaths::from_bases(
        PathBuf::from("/home/alice/.config"),
        PathBuf::from("/home/alice/.local/share"),
        PathBuf::from("/home/alice/.cache"),
    );

    let gluon = runtime_paths.gluon_paths(None);

    assert_eq!(
        gluon.root(),
        Path::new("/home/alice/.local/share/protonmail/bridge-v3/gluon")
    );
    assert_eq!(
        gluon.backend_store_dir(),
        Path::new("/home/alice/.local/share/protonmail/bridge-v3/gluon/backend/store")
    );
    assert_eq!(
        gluon.backend_db_dir(),
        Path::new("/home/alice/.local/share/protonmail/bridge-v3/gluon/backend/db")
    );
    assert_eq!(
        gluon.account_store_dir("gluon-alpha"),
        Path::new("/home/alice/.local/share/protonmail/bridge-v3/gluon/backend/store/gluon-alpha")
    );
    assert_eq!(
        gluon.account_db_path("gluon-alpha"),
        Path::new("/home/alice/.local/share/protonmail/bridge-v3/gluon/backend/db/gluon-alpha.db")
    );
    assert_eq!(
        gluon.account_db_wal_path("gluon-alpha"),
        Path::new(
            "/home/alice/.local/share/protonmail/bridge-v3/gluon/backend/db/gluon-alpha.db-wal"
        )
    );
    assert_eq!(
        gluon.account_db_shm_path("gluon-alpha"),
        Path::new(
            "/home/alice/.local/share/protonmail/bridge-v3/gluon/backend/db/gluon-alpha.db-shm"
        )
    );
    assert_eq!(
        gluon.deferred_delete_dir(),
        Path::new("/home/alice/.local/share/protonmail/bridge-v3/gluon/backend/db/deferred_delete")
    );
}

#[test]
fn be019_resolves_relative_vault_gluon_dir_against_data_root() {
    let runtime_paths = RuntimePaths::from_bases(
        PathBuf::from("/cfg"),
        PathBuf::from("/data"),
        PathBuf::from("/cache"),
    );

    let gluon = runtime_paths.gluon_paths(Some("fixture-gluon"));

    assert_eq!(
        gluon.root(),
        Path::new("/data/protonmail/bridge-v3/fixture-gluon")
    );
}

#[test]
fn be019_accepts_windows_style_roots_and_sync_sidecars() {
    let runtime_paths = RuntimePaths::from_bases(
        PathBuf::from("C:/Users/Alice/AppData/Roaming"),
        PathBuf::from("C:/Users/Alice/AppData/Roaming"),
        PathBuf::from("C:/Users/Alice/AppData/Local"),
    );

    let gluon = runtime_paths.gluon_paths(Some("D:/BridgeCache/gluon"));

    assert_eq!(gluon.root(), Path::new("D:/BridgeCache/gluon"));
    assert_eq!(
        runtime_paths.sync_state_path("uid-1"),
        Path::new("C:/Users/Alice/AppData/Roaming/protonmail/bridge-v3/sync-uid-1")
    );
    assert_eq!(
        runtime_paths.sync_state_tmp_path("uid-1"),
        Path::new("C:/Users/Alice/AppData/Roaming/protonmail/bridge-v3/sync-uid-1.tmp")
    );
}
