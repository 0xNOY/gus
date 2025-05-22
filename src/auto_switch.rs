use anyhow::{Context, Result};
use glob::Pattern;
use std::path::Path;

use crate::{config::Config, user::Users};

pub fn expand_tilde(path: &str) -> String {
    if path.starts_with('~') {
        if let Some(home) = dirs::home_dir() {
            return path.replacen('~', &home.to_string_lossy(), 1);
        }
    }
    path.to_string()
}

pub fn should_switch(config: &Config, users: &Users, current_dir: &Path) -> Option<String> {
    if !config.auto_switch_enabled {
        return None;
    }

    let current_dir_str = current_dir.to_string_lossy();
    
    for pattern in &config.auto_switch_patterns {
        let expanded_pattern = expand_tilde(&pattern.pattern);
        if let Ok(glob_pattern) = Pattern::new(&expanded_pattern) {
            if glob_pattern.matches(&current_dir_str) {
                // ユーザーが存在することを確認
                if users.exists(&pattern.user_id) {
                    return Some(pattern.user_id.clone());
                }
            }
        }
    }
    
    None
}

pub fn validate_pattern(pattern: &str, user_id: &str, users: &Users) -> Result<()> {
    // ユーザーが存在することを確認
    if !users.exists(user_id) {
        anyhow::bail!("User '{}' does not exist", user_id);
    }

    // パターンの有効性を確認
    Pattern::new(pattern)
        .with_context(|| format!("Invalid glob pattern: {}", pattern))?;

    Ok(())
}

pub fn list_patterns(config: &Config) -> Vec<(&str, &str)> {
    config
        .auto_switch_patterns
        .iter()
        .map(|p| (p.pattern.as_str(), p.user_id.as_str()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AutoSwitchPattern;
    use std::path::PathBuf;

    fn create_test_config() -> Config {
        Config {
            auto_switch_enabled: true,
            auto_switch_patterns: vec![
                AutoSwitchPattern {
                    pattern: "~/work/*".to_string(),
                    user_id: "work".to_string(),
                },
                AutoSwitchPattern {
                    pattern: "~/personal/*".to_string(),
                    user_id: "personal".to_string(),
                },
            ],
            ..Config::default()
        }
    }

    fn create_test_users() -> Users {
        let mut users = Users::new();
        users
            .add(crate::user::User {
                id: "work".to_string(),
                name: "Work User".to_string(),
                email: "work@example.com".to_string(),
                sshkey_path: None,
            })
            .unwrap();
        users
            .add(crate::user::User {
                id: "personal".to_string(),
                name: "Personal User".to_string(),
                email: "personal@example.com".to_string(),
                sshkey_path: None,
            })
            .unwrap();
        users
    }

    #[test]
    fn test_should_switch() {
        let config = create_test_config();
        let users = create_test_users();

        let home = dirs::home_dir().unwrap();
        let work_path = home.join("work/project");
        let personal_path = home.join("personal/project");
        let other_path = home.join("other");

        assert_eq!(
            should_switch(&config, &users, &work_path),
            Some("work".to_string())
        );
        assert_eq!(
            should_switch(&config, &users, &personal_path),
            Some("personal".to_string())
        );
        assert_eq!(
            should_switch(&config, &users, &other_path),
            None
        );
    }

    #[test]
    fn test_validate_pattern() {
        let users = create_test_users();

        // 有効なパターンの追加
        assert!(validate_pattern("~/new/*", "work", &users).is_ok());

        // 無効なユーザーID
        assert!(validate_pattern("~/new/*", "invalid", &users).is_err());

        // 無効なパターン
        assert!(validate_pattern("invalid[", "work", &users).is_err());
    }

    #[test]
    fn test_list_patterns() {
        let config = create_test_config();
        let patterns = list_patterns(&config);
        assert_eq!(patterns.len(), 2);
        assert!(patterns.contains(&("~/work/*", "work")));
        assert!(patterns.contains(&("~/personal/*", "personal")));
    }
} 