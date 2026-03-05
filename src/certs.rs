use std::path::Path;

#[cfg(target_os = "macos")]
use anyhow::Context;

pub fn os_supports_cert_install() -> bool {
    cfg!(target_os = "macos")
}

pub fn install_certificate(cert_path: &Path) -> anyhow::Result<()> {
    if !os_supports_cert_install() {
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        install_certificate_macos(cert_path)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = cert_path;
        Ok(())
    }
}

pub fn uninstall_certificate(cert_path: &Path) -> anyhow::Result<()> {
    if !os_supports_cert_install() {
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        uninstall_certificate_macos(cert_path)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = cert_path;
        Ok(())
    }
}

pub fn is_certificate_installed(cert_path: &Path) -> anyhow::Result<bool> {
    if !cert_path.exists() {
        return Ok(false);
    }
    if !os_supports_cert_install() {
        return Ok(false);
    }

    #[cfg(target_os = "macos")]
    {
        is_certificate_installed_macos(cert_path)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = cert_path;
        Ok(false)
    }
}

#[cfg(target_os = "macos")]
fn is_certificate_installed_macos(cert_path: &Path) -> anyhow::Result<bool> {
    let output = std::process::Command::new("security")
        .arg("verify-cert")
        .arg("-c")
        .arg(cert_path)
        .arg("-p")
        .arg("ssl")
        .output()
        .with_context(|| {
            format!(
                "failed to run security verify-cert for {}",
                cert_path.display()
            )
        })?;
    Ok(output.status.success())
}

#[cfg(target_os = "macos")]
fn install_certificate_macos(cert_path: &Path) -> anyhow::Result<()> {
    if is_certificate_installed_macos(cert_path)? {
        return Ok(());
    }

    let output = std::process::Command::new("security")
        .arg("add-trusted-cert")
        .arg("-d")
        .arg("-r")
        .arg("trustRoot")
        .arg("-p")
        .arg("ssl")
        .arg(cert_path)
        .output()
        .with_context(|| {
            format!(
                "failed to run security add-trusted-cert for {}",
                cert_path.display()
            )
        })?;
    if output.status.success() {
        return Ok(());
    }

    anyhow::bail!(
        "security add-trusted-cert failed (status {:?}): {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
}

#[cfg(target_os = "macos")]
fn uninstall_certificate_macos(cert_path: &Path) -> anyhow::Result<()> {
    if !cert_path.exists() || !is_certificate_installed_macos(cert_path)? {
        return Ok(());
    }

    let output = std::process::Command::new("security")
        .arg("remove-trusted-cert")
        .arg("-d")
        .arg(cert_path)
        .output()
        .with_context(|| {
            format!(
                "failed to run security remove-trusted-cert for {}",
                cert_path.display()
            )
        })?;
    if output.status.success() {
        return Ok(());
    }

    anyhow::bail!(
        "security remove-trusted-cert failed (status {:?}): {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
}
