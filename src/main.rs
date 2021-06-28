use anyhow::{anyhow, bail, ensure, Context, Result};
use cmd_lib::run_fun;
use der::{asn1::UIntBytes, Decodable, Message};
use serde::Deserialize;
use spki::SubjectPublicKeyInfo;
use sshcerts::ssh::{
    CertType, Certificate, Extensions, KeyType, PublicKey, PublicKeyKind, RsaPublicKey,
};
use std::convert::{TryFrom, TryInto};
use std::env::{self, VarError};
use std::fs;
use std::path::{Path, PathBuf};
use time::{Duration, OffsetDateTime};

macro_rules! env {
    ($var:expr) => {
        env::var_os($var).context(concat!("$", $var, " not set"))
    };
}

fn main() -> Result<()> {
    let home = PathBuf::from(env!("HOME")?);
    dotenv::from_path(home.join(".config").join("sshca").join("env"))?;

    let user = env!("USER")?.into_string().map_err(VarError::NotUnicode)?;

    let mut args = std::env::args_os().skip(1);
    match args.next().as_deref().and_then(|s| s.to_str()) {
        Some("pubkey") => {
            println!(
                "cert-authority,principals=\"{user}\" {key}",
                user = user,
                key = get_ca_key()?
            );
            Ok(())
        }
        Some("sign") => sign_key(&home, &user),
        _ => bail!("invalid command"),
    }
}

fn get_ca_key() -> Result<PublicKey> {
    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Response {
        key_id: String,
        public_key: String,
        customer_master_key_spec: String,
    }

    #[derive(Debug, Message)]
    struct RSAPublicKeySequence<'a> {
        n: UIntBytes<'a>,
        e: UIntBytes<'a>,
    }

    let key_id = env!("SSHCA_KEY_ID")?;
    let response: Response =
        serde_json::from_str(&run_fun!(aws kms get-public-key --key-id $key_id --output json)?)?;
    ensure!(
        response.customer_master_key_spec.starts_with("RSA_"),
        "unsupported key type"
    );

    let der = base64::decode(&response.public_key)?;
    let spki = SubjectPublicKeyInfo::from_der(der.as_slice()).map_err(|e| anyhow!(e))?;
    let key = RSAPublicKeySequence::from_der(spki.subject_public_key).map_err(|e| anyhow!(e))?;

    Ok(PublicKey {
        key_type: KeyType::from_name("ssh-rsa")?,
        kind: PublicKeyKind::Rsa(RsaPublicKey {
            e: key.e.as_bytes().into(),
            n: key.n.as_bytes().into(),
        }),
        comment: Some(response.key_id),
    })
}

fn sign_key(home: &Path, user: &str) -> Result<()> {
    let key_type = "ed25519";
    let user_key = PublicKey::from_path(home.join(".ssh").join(format!("id_{}.pub", key_type)))?;
    let signing_key = get_ca_key()?;
    let key_id = signing_key
        .comment
        .as_ref()
        .expect("get_ca_key() always returns a key with a comment");

    let mut err = None;
    let cert = Certificate::builder(&user_key, CertType::User, &signing_key)?
        .principal(&user)
        .key_id(&user)
        .set_extensions(Extensions::Standard)
        .valid_after(OffsetDateTime::now_utc().unix_timestamp().try_into()?)
        .valid_before(
            (OffsetDateTime::now_utc() + Duration::day())
                .unix_timestamp()
                .try_into()?,
        )
        .sign(|data| match signer(data, key_id) {
            Ok(v) => Some(v),
            Err(e) => {
                err = Some(e);
                None
            }
        });
    if let Some(err) = err {
        return Err(err);
    }
    let cert = cert?;
    fs::write(
        home.join(".ssh").join(format!("id_{}-cert.pub", key_type)),
        format!("{}\n", cert),
    )?;
    Ok(())
}

fn signer(data: &[u8], key_id: &str) -> Result<Vec<u8>> {
    let sig_type = "rsa-sha2-512";
    let data = base64::encode(data);

    let signature = base64::decode(
        &run_fun!(aws kms sign --key-id $key_id --message $data --query Signature --output text
            --signing-algorithm RSASSA_PKCS1_V1_5_SHA_512)?,
    )?;

    let mut result = Vec::new();
    result.extend(u32::try_from(sig_type.len())?.to_be_bytes());
    result.extend(sig_type.as_bytes());
    result.extend(u32::try_from(signature.len())?.to_be_bytes());
    result.extend(signature);
    Ok(result)
}
