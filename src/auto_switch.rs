use anyhow::{Context, Result};
use glob::Pattern;
use std::path::Path;
use std::env;

use crate::{config::Config, user::Users};

pub struct AutoSwitcher<'a> {
    pub config: &'a Config,
    users: Users,
}

impl<'a> AutoSwitcher<'a> {
    pub fn new(config: &'a Config, users: Users) -> Self {
        Self { config, users }
    }

    fn expand_tilde(path: &str) -> String {
        if path.starts_with('~') {
            if let Some(home) = dirs::home_dir() {
                return path.replacen('~', &home.to_string_lossy(), 1);
            }
        }
        path.to_string()
    }

    pub fn should_switch(&self, current_dir: &Path) -> Option<String> {
        if !self.config.auto_switch_enabled {
            return None;
        }

        let current_dir_str = current_dir.to_string_lossy();
        
        for pattern in &self.config.auto_switch_patterns {
            let expanded_pattern = Self::expand_tilde(&pattern.pattern);
            if let Ok(glob_pattern) = Pattern::new(&expanded_pattern) {
                if glob_pattern.matches(&current_dir_str) {
                    // ユーザーが存在することを確認
                    if self.users.exists(&pattern.user_id) {
                        return Some(pattern.user_id.clone());
                    }
                }
            }
        }
        
        None
    }

    pub fn add_pattern(&mut self, pattern: String, user_id: String) -> Result<()> {
        // ユーザーが存在することを確認
        if !self.users.exists(&user_id) {
            anyhow::bail!("User '{}' does not exist", user_id);
        }

        // パターンの有効性を確認
        Pattern::new(&pattern)
            .with_context(|| format!("Invalid glob pattern: {}", pattern))?;

        // 注意: このメソッドは外部でConfigを更新する必要がある
        Ok(())
    }

    pub fn remove_pattern(&mut self, pattern: &str) -> bool {
        // 注意: このメソッドは外部でConfigを更新する必要がある
        self.config.auto_switch_patterns.iter().any(|p| p.pattern == pattern)
    }

    pub fn list_patterns(&self) -> Vec<(&str, &str)> {
        self.config
            .auto_switch_patterns
            .iter()
            .map(|p| (p.pattern.as_str(), p.user_id.as_str()))
            .collect()
    }
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
        let switcher = AutoSwitcher::new(&config, users);

        let home = dirs::home_dir().unwrap();
        let work_path = home.join("work/project");
        let personal_path = home.join("personal/project");
        let other_path = home.join("other");

        assert_eq!(
            switcher.should_switch(&work_path),
            Some("work".to_string())
        );
        assert_eq!(
            switcher.should_switch(&personal_path),
            Some("personal".to_string())
        );
        assert_eq!(
            switcher.should_switch(&other_path),
            None
        );
    }

    #[test]
    fn test_add_pattern() {
        let config = create_test_config();
        let users = create_test_users();
        let mut switcher = AutoSwitcher::new(&config, users);

        // 有効なパターンの追加
        assert!(switcher
            .add_pattern("~/new/*".to_string(), "work".to_string())
            .is_ok());

        // 無効なユーザーID
        assert!(switcher
            .add_pattern("~/new/*".to_string(), "invalid".to_string())
            .is_err());

        // 無効なパターン
        assert!(switcher
            .add_pattern("invalid[".to_string(), "work".to_string())
            .is_err());
    }

    #[test]
    fn test_remove_pattern() {
        let config = create_test_config();
        let users = create_test_users();
        let mut switcher = AutoSwitcher::new(&config, users);

        assert!(switcher.remove_pattern("~/work/*"));
        assert!(!switcher.remove_pattern("~/nonexistent/*"));
    }

    #[test]
    fn test_list_patterns() {
        let config = create_test_config();
        let users = create_test_users();
        let switcher = AutoSwitcher::new(&config, users);

        let patterns = switcher.list_patterns();
        assert_eq!(patterns.len(), 2);
        assert!(patterns.contains(&("~/work/*", "work")));
        assert!(patterns.contains(&("~/personal/*", "personal")));
    }
} 