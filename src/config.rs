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
    pub default_sshkey_rounds: usize,
    pub force_use_gus: bool,
    pub min_sshkey_passphrase_length: usize,
    pub auto_switch_enabled: bool,
    pub auto_switch_patterns: Vec<AutoSwitchPattern>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AutoSwitchPattern {
    pub pattern: String,
    pub user_id: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            users_file_path: DEFAULT_DATA_DIR.join("users.toml"),
            default_sshkey_dir: DEFAULT_DATA_DIR.join("sshkeys/"),
            default_sshkey_type: SshKeyType::Ed25519,
            default_sshkey_rounds: 100,
            force_use_gus: true,
            min_sshkey_passphrase_length: 10,
            auto_switch_enabled: false,
            auto_switch_patterns: Vec::new(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use assert_fs::prelude::*;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.default_sshkey_type, SshKeyType::Ed25519);
        assert_eq!(config.default_sshkey_rounds, 100);
        assert!(config.force_use_gus);
        assert_eq!(config.min_sshkey_passphrase_length, 10);
    }

    #[test]
    fn test_config_file_operations() -> Result<()> {
        let temp_dir = assert_fs::TempDir::new()?;
        let config_file = temp_dir.child("config.toml");
        
        // Test creating new config file
        let config = Config::open(&config_file.path().to_path_buf())?;
        assert_eq!(config.default_sshkey_type, SshKeyType::Ed25519);
        
        // Test saving and loading config
        let mut config = Config::default();
        config.default_sshkey_rounds = 200;
        config.save(&config_file.path().to_path_buf())?;
        
        let loaded_config = Config::open(&config_file.path().to_path_buf())?;
        assert_eq!(loaded_config.default_sshkey_rounds, 200);
        
        Ok(())
    }

    #[test]
    fn test_config_serialization() -> Result<()> {
        let config = Config::default();
        let serialized = toml::to_string(&config)?;
        let deserialized: Config = toml::from_str(&serialized)?;
        
        assert_eq!(config.default_sshkey_type, deserialized.default_sshkey_type);
        assert_eq!(config.default_sshkey_rounds, deserialized.default_sshkey_rounds);
        assert_eq!(config.force_use_gus, deserialized.force_use_gus);
        assert_eq!(config.min_sshkey_passphrase_length, deserialized.min_sshkey_passphrase_length);
        
        Ok(())
    }
}
