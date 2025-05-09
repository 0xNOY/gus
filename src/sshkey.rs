use anyhow::{ensure, Context, Result};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, process::Command};

#[derive(Serialize, Deserialize, Debug, Clone, ValueEnum)]
pub enum SshKeyType {
    Ed25519,
    Ed25519Sk,
    Rsa,
    Ecdsa,
    EcdsaSk,
    Dsa,
}

impl ToString for SshKeyType {
    fn to_string(&self) -> String {
        match self {
            Self::Ed25519 => "ed25519",
            Self::Ed25519Sk => "ed25519-sk",
            Self::Rsa => "rsa",
            Self::Ecdsa => "ecdsa",
            Self::EcdsaSk => "ecdsa-sk",
            Self::Dsa => "dsa",
        }
        .to_string()
    }
}

pub fn generate_ssh_key(
    key_type: SshKeyType,
    rounds: usize,
    comment: &str,
    passphrase: &str,
    path: &PathBuf,
) -> Result<()> {
    ensure!(
        !path.exists(),
        "ssh key already exists at path: {}",
        path.display()
    );

    std::fs::create_dir_all(&path.parent().unwrap()).with_context(|| {
        format!(
            "failed to create ssh key directory: {}",
            path.parent().unwrap().display()
        )
    })?;

    let mut cmd = Command::new("ssh-keygen");
    cmd.arg("-o");
    cmd.arg("-a").arg(rounds.to_string());
    cmd.arg("-t").arg(key_type.to_string());
    cmd.arg("-C").arg(comment);
    cmd.arg("-f").arg(path);
    cmd.arg("-N").arg(passphrase);
    let output = cmd.output().context("failed to run ssh-keygen")?;
    ensure!(
        output.status.success(),
        "ssh-keygen failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
