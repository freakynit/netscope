use anyhow::{Context, Result, anyhow};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Debug, Clone)]
pub struct CaPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
}
impl CaPaths {
    pub fn in_dir(dir: impl AsRef<Path>) -> Self {
        let dir = dir.as_ref();
        Self {
            cert: dir.join("netscope-ca.pem"),
            key: dir.join("netscope-ca-key.pem"),
        }
    }
}

pub fn generate_ca(paths: &CaPaths) -> Result<()> {
    if let Some(parent) = paths.cert.parent() {
        fs::create_dir_all(parent)?;
    }
    if paths.cert.exists() || paths.key.exists() {
        return Err(anyhow!(
            "CA already exists at {}; remove it first or choose another directory",
            paths.cert.display()
        ));
    }
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
        .distinguished_name
        .push(DnType::CommonName, "NetScope Local Inspection CA");
    let key = KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    fs::write(&paths.cert, cert.pem())?;
    fs::write(&paths.key, key.serialize_pem())?;
    #[cfg(unix)]
    fs::set_permissions(&paths.key, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

pub fn install_ca(paths: &CaPaths) -> Result<()> {
    run_security(&[
        "add-trusted-cert",
        "-d",
        "-r",
        "trustRoot",
        "-k",
        "/Library/Keychains/System.keychain",
        paths
            .cert
            .to_str()
            .ok_or_else(|| anyhow!("non-UTF8 path"))?,
    ])
}
pub fn remove_ca(paths: &CaPaths) -> Result<()> {
    run_security(&[
        "delete-certificate",
        "-c",
        "NetScope Local Inspection CA",
        "/Library/Keychains/System.keychain",
    ])?;
    for path in [&paths.cert, &paths.key] {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn run_security(args: &[&str]) -> Result<()> {
    let status = Command::new("security")
        .args(args)
        .status()
        .context("run macOS security tool")?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow!(
            "security command failed (install/remove may require sudo)"
        ))
    }
}

pub fn load_server_config(paths: &CaPaths, hostname: &str) -> Result<rustls::ServerConfig> {
    let ca_key_pem =
        fs::read(&paths.key).with_context(|| format!("read {}", paths.key.display()))?;
    let ca_cert_pem =
        fs::read(&paths.cert).with_context(|| format!("read {}", paths.cert.display()))?;
    let ca_key = KeyPair::from_pem(&String::from_utf8(ca_key_pem)?).context("parse CA key")?;
    let ca_params = CertificateParams::from_ca_cert_pem(&String::from_utf8(ca_cert_pem)?)
        .context("parse CA certificate")?;
    // Recreate the certificate object from its parsed parameters and persisted key. The public
    // key and issuer name are the same as the trusted CA written by `generate_ca`.
    let issuer = ca_params.self_signed(&ca_key).context("load CA issuer")?;
    let mut params = CertificateParams::new(vec![hostname.to_owned()])?;
    params.distinguished_name.push(DnType::CommonName, hostname);
    let leaf_key = KeyPair::generate()?;
    let leaf = params.signed_by(&leaf_key, &issuer, &ca_key)?;
    let cert = CertificateDer::from(leaf.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into());
    Ok(rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_ca_that_can_issue_a_leaf() {
        let directory = tempfile::tempdir().unwrap();
        let paths = CaPaths::in_dir(directory.path());
        generate_ca(&paths).unwrap();
        assert!(paths.cert.exists());
        assert!(paths.key.exists());
        load_server_config(&paths, "example.test").unwrap();
    }
}
