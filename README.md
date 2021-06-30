⚠️ **Do NOT use this unless you understand what you are doing.** See below for why. I wrote this for my personal use and provide no support.

---

# sshca

This is a small Rust program to use an asymmetric RSA key from AWS KMS as a single-user [SSH certificate authority](https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD).

## Installation

Requires AWS CLI on your `$PATH`.

```
cargo install --git https://github.com/iliana/sshca
```

Set up an environment file at `~/.config/sshca/env`, which should define `SSHCA_KEY_ID` with the KMS key ID. You can set other environment variables, which may assist with coercing the AWS CLI to find correct credentials.

## Usage

* **`sshca pubkey`**: Outputs the public CA signing key in a form usable by `~/.ssh/authorized_keys`.
* **`sshca sign`**: Signs `~/.ssh/id_ed25519.pub` with the CA signing key, writing the certificate to `~/.ssh/id_ed25519-cert.pub`.

sshca is licensed under the WTFPL.

## Thoughts

I prefer to avoid copying SSH keys between machines; in the past I used the PGP applet on YubiKeys with an authentication subkey and the GnuPG SSH agent, and had a handful of YubiKeys with my PGP key burned into them. I've since made the healthy decision to eliminate PGP from my life as much as possible, but still wanted a system where a single `~/.ssh/authorized_keys` entry could authenticate me to nearly all systems without copying keys around. Thus, a basic CA.

This is not a multi-user SSH CA. In my setup, I have a separate AWS account that stores the key for my SSH CA, accessible solely by me via AWS SSO with two-factor authentication. Anybody with access to the signing key can sign anything they like, including SSH certificates for indefinite periods of time. A multi-user SSH CA requires application code to validate a user's request before signing a key.

Instead of using an AWS SDK, I opted to shell out to the AWS CLI, mainly to have support for complicated credential providers (e.g. AWS SSO, source profiles).

Crates I used for the first time:
* [sshcerts](https://docs.rs/sshcerts) is lovely, but could use additional example documentation. It was difficult to get going at first.
* [cmd_lib](https://docs.rs/cmd_lib) has incredible macros for running shell commands without a shell and I strongly recommend it; I wish it were more flexible for displaying stderr without a logger set up.

Parsing RSA keys out of `SubjectPublicKeyInfo` DER documents in Rust remains a total pain in the ass. This is about the fourth time I've had to do this.
