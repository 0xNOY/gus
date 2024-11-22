use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::sshkey::SshKeyType;

static DEFAULT_DATA_DIR: Lazy<PathBuf> = Lazy::new(|| dirs::home_dir().unwrap().join(".gus"));

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
pub struct Config {
    pub users_file_path: PathBuf,
    pub default_sshkey_dir: PathBuf,
    pub default_sshkey_type: SshKeyType,
    pub force_use_gus: bool,
    pub min_sshkey_passphrase_length: usize,
    pub sign_commits: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            users_file_path: DEFAULT_DATA_DIR.join("users.toml"),
            default_sshkey_dir: DEFAULT_DATA_DIR.join("sshkeys/"),
            default_sshkey_type: SshKeyType::Ed25519,
            force_use_gus: true,
            min_sshkey_passphrase_length: 10,
            sign_commits: true,
        }
    }
}

impl Config {
    pub fn save(&self, path: &PathBuf) -> Result<()> {
        if !path.exists() {
            std::fs::create_dir_all(&path.parent().unwrap()).with_context(|| {
                format!("failed to create config directory: {}", path.display())
            })?;
        }

        let contents = toml::to_string(&self)
            .with_context(|| format!("failed to serialize config file: {}", path.display()))?;
        std::fs::write(&path, contents)
            .with_context(|| format!("failed to write config file: {}", path.display()))?;
        Ok(())
    }

    pub fn open(path: &PathBuf) -> Result<Self> {
        if !path.exists() {
            let config = Self::default();
            config.save(path)?;
            return Ok(config);
        }

        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;
        let config = toml::from_str(&contents)
            .with_context(|| format!("failed to parse config file: {}", path.display()))?;
        Ok(config)
    }
}
