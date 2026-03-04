use std::cmp::Reverse;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::paths::RuntimePaths;

pub const DEFAULT_MAX_SESSION_LOG_FILES: usize = 20;
pub const DEFAULT_MAX_CRASH_REPORT_FILES: usize = 20;
pub const DEFAULT_MAX_SUPPORT_BUNDLE_FILES: usize = 20;
pub const DEFAULT_BUNDLE_FILE_LIMIT: usize = 25;

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis()
}

fn list_files_by_mtime(dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut files: Vec<(SystemTime, PathBuf)> = Vec::new();
    if !dir.exists() {
        return Ok(Vec::new());
    }

    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("failed to read directory {}", dir.display()))?
    {
        let entry =
            entry.with_context(|| format!("failed to enumerate entries in {}", dir.display()))?;
        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if !metadata.is_file() {
            continue;
        }

        let modified = metadata.modified().unwrap_or(UNIX_EPOCH);
        files.push((modified, path));
    }

    files.sort_by_key(|(modified, path)| (*modified, path.clone()));
    Ok(files.into_iter().map(|(_, path)| path).collect())
}

pub fn prune_old_files(dir: &Path, max_files: usize) -> anyhow::Result<usize> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("failed to create directory {}", dir.display()))?;

    let files = list_files_by_mtime(dir)?;
    if files.len() <= max_files {
        return Ok(0);
    }

    let to_remove = files.len().saturating_sub(max_files);
    for file in files.into_iter().take(to_remove) {
        std::fs::remove_file(&file)
            .with_context(|| format!("failed to remove old log file {}", file.display()))?;
    }

    Ok(to_remove)
}

pub fn initialize_observability_dirs(runtime_paths: &RuntimePaths) -> anyhow::Result<()> {
    std::fs::create_dir_all(runtime_paths.session_logs_dir()).with_context(|| {
        format!(
            "failed to create session logs dir {}",
            runtime_paths.session_logs_dir().display()
        )
    })?;
    std::fs::create_dir_all(runtime_paths.crash_reports_dir()).with_context(|| {
        format!(
            "failed to create crash reports dir {}",
            runtime_paths.crash_reports_dir().display()
        )
    })?;
    std::fs::create_dir_all(runtime_paths.support_bundles_dir()).with_context(|| {
        format!(
            "failed to create support bundles dir {}",
            runtime_paths.support_bundles_dir().display()
        )
    })?;

    Ok(())
}

pub fn create_session_log(runtime_paths: &RuntimePaths) -> anyhow::Result<PathBuf> {
    initialize_observability_dirs(runtime_paths)?;
    prune_old_files(
        &runtime_paths.crash_reports_dir(),
        DEFAULT_MAX_CRASH_REPORT_FILES,
    )?;

    let path = runtime_paths.session_logs_dir().join(format!(
        "session-{}-{}.log",
        std::process::id(),
        unix_millis()
    ));
    append_session_log_line(
        &path,
        &format!(
            "session_started_unix_ms={} pid={}",
            unix_millis(),
            std::process::id()
        ),
    )?;
    prune_old_files(
        &runtime_paths.session_logs_dir(),
        DEFAULT_MAX_SESSION_LOG_FILES,
    )?;
    Ok(path)
}

pub fn install_tracing(
    runtime_paths: &RuntimePaths,
) -> anyhow::Result<(PathBuf, tracing_appender::non_blocking::WorkerGuard)> {
    let session_log = create_session_log(runtime_paths)?;
    let session_log_dir = session_log
        .parent()
        .context("session log path has no parent directory")?;
    let session_log_name = session_log
        .file_name()
        .and_then(|name| name.to_str())
        .context("session log path has invalid file name")?
        .to_string();

    let file_appender = tracing_appender::rolling::never(session_log_dir, session_log_name);
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(file_writer),
        )
        .init();

    Ok((session_log, guard))
}

pub fn append_session_log_line(session_log: &Path, message: &str) -> anyhow::Result<()> {
    use std::io::Write;

    if let Some(parent) = session_log.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create session log dir {}", parent.display()))?;
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(session_log)
        .with_context(|| format!("failed to open session log {}", session_log.display()))?;
    writeln!(file, "{}", message)
        .with_context(|| format!("failed to write session log {}", session_log.display()))?;

    Ok(())
}

fn copy_recent_files(source: &Path, target: &Path, max_files: usize) -> anyhow::Result<usize> {
    std::fs::create_dir_all(target)
        .with_context(|| format!("failed to create directory {}", target.display()))?;

    let mut files = list_files_by_mtime(source)?
        .into_iter()
        .map(|path| {
            let modified = std::fs::metadata(&path)
                .ok()
                .and_then(|meta| meta.modified().ok())
                .unwrap_or(UNIX_EPOCH);
            (modified, path)
        })
        .collect::<Vec<_>>();

    files.sort_by_key(|(modified, path)| (Reverse(*modified), path.clone()));

    let mut copied = 0usize;
    for (_, source_path) in files.into_iter().take(max_files) {
        let Some(file_name) = source_path.file_name() else {
            continue;
        };
        std::fs::copy(&source_path, target.join(file_name)).with_context(|| {
            format!(
                "failed to copy {} into {}",
                source_path.display(),
                target.display()
            )
        })?;
        copied += 1;
    }

    Ok(copied)
}

fn write_tar_gz_archive(source_dir: &Path, archive_path: &Path) -> anyhow::Result<()> {
    let archive_file = std::fs::File::create(archive_path)
        .with_context(|| format!("failed to create archive {}", archive_path.display()))?;
    let encoder = flate2::write::GzEncoder::new(archive_file, flate2::Compression::default());
    let mut tar = tar::Builder::new(encoder);

    let root_name = source_dir
        .file_name()
        .and_then(|name| name.to_str())
        .context("support bundle directory has invalid name")?;

    tar.append_dir_all(root_name, source_dir).with_context(|| {
        format!(
            "failed to write bundle archive from {}",
            source_dir.display()
        )
    })?;
    let encoder = tar
        .into_inner()
        .context("failed to finalize tar archive stream")?;
    encoder.finish().context("failed to finish gzip stream")?;

    Ok(())
}

pub fn generate_support_log_bundle(
    runtime_paths: &RuntimePaths,
    diagnostics: &str,
) -> anyhow::Result<PathBuf> {
    initialize_observability_dirs(runtime_paths)?;

    let bundle_root = runtime_paths.support_bundles_dir().join(format!(
        "support-{}-{}",
        std::process::id(),
        unix_millis()
    ));
    std::fs::create_dir_all(&bundle_root)
        .with_context(|| format!("failed to create bundle dir {}", bundle_root.display()))?;

    std::fs::write(bundle_root.join("diagnostics.txt"), diagnostics)
        .with_context(|| format!("failed to write diagnostics in {}", bundle_root.display()))?;

    let sessions_copied = copy_recent_files(
        &runtime_paths.session_logs_dir(),
        &bundle_root.join("sessions"),
        DEFAULT_BUNDLE_FILE_LIMIT,
    )?;
    let crashes_copied = copy_recent_files(
        &runtime_paths.crash_reports_dir(),
        &bundle_root.join("crash_reports"),
        DEFAULT_BUNDLE_FILE_LIMIT,
    )?;

    let archive_path = bundle_root.with_extension("tar.gz");
    let manifest = serde_json::json!({
        "bundle_archive": archive_path.display().to_string(),
        "sessions_copied": sessions_copied,
        "crash_reports_copied": crashes_copied,
    });
    std::fs::write(
        bundle_root.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap_or_else(|_| b"{}".to_vec()),
    )
    .with_context(|| format!("failed to write manifest in {}", bundle_root.display()))?;

    write_tar_gz_archive(&bundle_root, &archive_path)?;
    std::fs::remove_dir_all(&bundle_root).with_context(|| {
        format!(
            "failed to remove temporary bundle directory {}",
            bundle_root.display()
        )
    })?;

    prune_old_files(
        &runtime_paths.support_bundles_dir(),
        DEFAULT_MAX_SUPPORT_BUNDLE_FILES,
    )?;

    Ok(archive_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tar_gz_entries(path: &Path) -> Vec<String> {
        let file = std::fs::File::open(path).expect("open archive");
        let decoder = flate2::read::GzDecoder::new(file);
        let mut archive = tar::Archive::new(decoder);
        archive
            .entries()
            .expect("read entries")
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let path = entry.path().ok()?;
                Some(path.to_string_lossy().to_string())
            })
            .collect()
    }

    #[test]
    fn prune_old_files_keeps_newest_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("session-logs");
        std::fs::create_dir_all(&dir).unwrap();

        for index in 0..5 {
            let path = dir.join(format!("session-{index}.log"));
            std::fs::write(path, format!("log-{index}")).expect("should write test log file");
            std::thread::sleep(std::time::Duration::from_millis(2));
        }

        let removed = prune_old_files(&dir, 2).unwrap();
        assert_eq!(removed, 3);

        let remaining = list_files_by_mtime(&dir).unwrap();
        assert_eq!(remaining.len(), 2);
        assert!(remaining[0].ends_with("session-3.log"));
        assert!(remaining[1].ends_with("session-4.log"));
    }

    #[test]
    fn generate_support_log_bundle_archives_recent_logs_and_reports() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime_paths = RuntimePaths::resolve(Some(tmp.path())).unwrap();

        let session_a = runtime_paths.session_logs_dir().join("session-a.log");
        let session_b = runtime_paths.session_logs_dir().join("session-b.log");
        let crash = runtime_paths.crash_reports_dir().join("panic-1.log");
        std::fs::create_dir_all(runtime_paths.session_logs_dir()).unwrap();
        std::fs::create_dir_all(runtime_paths.crash_reports_dir()).unwrap();
        std::fs::write(session_a, "session-a").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        std::fs::write(session_b, "session-b").unwrap();
        std::fs::write(crash, "panic-report").unwrap();

        let archive = generate_support_log_bundle(&runtime_paths, "diag=ok").unwrap();
        assert!(archive.exists());

        let entries = tar_gz_entries(&archive);
        assert!(entries
            .iter()
            .any(|entry| entry.ends_with("diagnostics.txt")));
        assert!(entries.iter().any(|entry| entry.ends_with("manifest.json")));
        assert!(entries
            .iter()
            .any(|entry| entry.ends_with("crash_reports/panic-1.log")));
        assert!(entries
            .iter()
            .any(|entry| entry.ends_with("sessions/session-b.log")));
    }
}
