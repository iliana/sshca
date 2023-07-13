#![warn(clippy::pedantic)]
#![allow(clippy::uninlined_format_args)]

use anyhow::{bail, Context, Result};
use aws_sdk_kms::{primitives::Blob, types::SigningAlgorithmSpec, Client};
use camino::{Utf8Path, Utf8PathBuf};
use spki::{der::Decode, SubjectPublicKeyInfoRef};
use sshcerts::ssh::{KeyType, PublicKeyKind, RsaPublicKey, SSHCertificateSigner};
use sshcerts::{CertType, Certificate, PublicKey};
use std::env;
use std::fmt::{self, Display};
use std::fs::File;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

lazy_static::lazy_static! {
    // the `sshcerts` crate is not async-aware, so we only run async operations with
    // `Runtime::block_on` where we need them
    static ref RT: tokio::runtime::Runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build().unwrap();
}

fn main() -> Result<()> {
    let home = env_path("HOME")?;
    home.as_ref()
        .and_then(|home| dotenvy::from_path(home.join(".config").join("sshca").join("env")).ok());

    let user = env::var("SSHCA_USER")
        .or_else(|_| env::var("USER"))
        .context("$SSHCA_USER and $USER not set")?;
    let key_id = env::var("SSHCA_KEY_ID").context("$SSHCA_KEY_ID not set")?;

    let client = Client::new(&RT.block_on(aws_config::load_from_env()));
    let key = Key::get(client, &key_id, user)?;

    match env::args().nth(1).as_deref() {
        Some("pubkey") => println!("{}", key),
        Some("sign") => key.sign_path(&match env_path("SSHCA_KEY_PATH")? {
            Some(path) => path,
            None => home
                .context("$SSHCA_KEY_PATH and $HOME not set")?
                .join(".ssh")
                .join("id_ed25519.pub"),
        })?,
        _ => bail!("invalid command"),
    }

    Ok(())
}

#[derive(Debug)]
struct Key {
    client: Client,
    public_key: PublicKey,
    signing_algorithm: SigningAlgorithmSpec,
    user: String,
}

impl Key {
    fn get(client: Client, key_id: &str, user: String) -> Result<Key> {
        let response = RT.block_on(client.get_public_key().key_id(key_id).send())?;
        let key_id = response
            .key_id
            .context("GetPublicKey response missing `key_id` field")?;

        let der = response
            .public_key
            .context("GetPublicKey response missing `public_key` field")?;
        let spki = SubjectPublicKeyInfoRef::try_from(der.as_ref())?;

        Ok(match spki.algorithm {
            pkcs1::ALGORITHM_ID => {
                let key = pkcs1::RsaPublicKey::from_der(spki.subject_public_key.raw_bytes())?;
                Key {
                    client,
                    public_key: PublicKey {
                        key_type: KeyType::from_name("ssh-rsa")?,
                        kind: PublicKeyKind::Rsa(RsaPublicKey {
                            e: key.public_exponent.as_bytes().into(),
                            n: key.modulus.as_bytes().into(),
                        }),
                        comment: Some(key_id),
                    },
                    signing_algorithm: SigningAlgorithmSpec::RsassaPkcs1V15Sha512,
                    user,
                }
            }
            _ => bail!("unsupported key algorithm"),
        })
    }

    fn sign_path(&self, path: &Utf8Path) -> Result<()> {
        let out = cert_path(path).context("could not automatically determine output path")?;

        let key = PublicKey::from_path(path)
            .with_context(|| format!("failed to load public key at {}", path))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("it is not yet 1970")?
            .as_secs();
        let cert = Certificate::builder(&key, CertType::User, &self.public_key)?
            .principal(&self.user)
            .key_id(&self.user)
            .set_extensions(Certificate::standard_extensions())
            .valid_after(now)
            .valid_before(now + 86400)
            .sign(self)?;

        let mut file = File::create(out)?;
        writeln!(file, "{}", cert)?;
        Ok(())
    }

    fn key_id(&self) -> &str {
        self.public_key.comment.as_ref().unwrap()
    }
}

impl Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "cert-authority,principals=\"{user}\" {key}",
            user = self.user,
            key = self.public_key
        )
    }
}

impl SSHCertificateSigner for Key {
    fn sign(&self, data: &[u8]) -> Option<Vec<u8>> {
        let response = RT
            .block_on(
                self.client
                    .sign()
                    .key_id(self.key_id())
                    .message(Blob::new(data))
                    .signing_algorithm(self.signing_algorithm.clone())
                    .send(),
            )
            .ok()?;
        sshcerts::utils::format_signature_for_ssh(&self.public_key, response.signature?.as_ref())
    }
}

fn env_path(key: &str) -> Result<Option<Utf8PathBuf>> {
    Ok(match env::var_os(key) {
        Some(value) => Some(Utf8PathBuf::try_from(std::path::PathBuf::from(value))?),
        None => None,
    })
}

fn cert_path(path: &Utf8Path) -> Option<Utf8PathBuf> {
    path.file_name()
        .and_then(|name| name.strip_suffix(".pub"))
        .map(|name| path.with_file_name(format!("{}-cert.pub", name)))
}
