use anyhow::{ensure, Context, Result};
use clap::Args;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt::Display, path::PathBuf};

#[derive(Serialize, Deserialize, Debug, Clone, Args)]
pub struct User {
    /// The user's ID (must be unique)
    pub id: String,
    /// The user's name
    pub name: String,
    /// The user's email
    pub email: String,

    /// The path to the user's ssh key
    #[clap(long, short)]
    pub sshkey_path: Option<PathBuf>,
}

impl Display for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {} <{}>", self.id, self.name, self.email)
    }
}

impl User {
    pub fn get_sshkey_name(&self) -> String {
        if let Some(path) = &self.sshkey_path {
            path.file_name().unwrap().to_str().unwrap().to_string()
        } else {
            format!("id_{}", self.id)
        }
    }

    pub fn get_sshkey_path(&self, default_sshkey_dir: &PathBuf) -> PathBuf {
        if let Some(path) = &self.sshkey_path {
            path.clone()
        } else {
            default_sshkey_dir.join(&self.get_sshkey_name())
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Users {
    #[serde(flatten)]
    hashmap: HashMap<String, User>,
}

impl Users {
    pub fn new() -> Self {
        Self {
            hashmap: HashMap::new(),
        }
    }

    pub fn open(path: &PathBuf) -> Result<Self> {
        if !path.exists() {
            let users = Self::new();
            users.save(path)?;
            return Ok(users);
        }

        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read users file: {}", path.display()))?;
        let users = toml::from_str(&contents)
            .with_context(|| format!("failed to parse users file: {}", path.display()))?;
        Ok(users)
    }

    pub fn save(&self, path: &PathBuf) -> Result<()> {
        if !path.exists() {
            std::fs::create_dir_all(&path.parent().unwrap())
                .with_context(|| format!("failed to create users directory: {}", path.display()))?;
        }

        let contents = toml::to_string(&self)
            .with_context(|| format!("failed to serialize users file: {}", path.display()))?;
        std::fs::write(&path, contents)
            .with_context(|| format!("failed to write users file: {}", path.display()))?;
        Ok(())
    }

    pub fn exists(&self, id: &str) -> bool {
        self.hashmap.contains_key(id)
    }

    pub fn add(&mut self, user: User) -> Result<()> {
        ensure!(
            !self.exists(&user.id),
            "user with id '{}' already exists",
            user.id
        );
        self.hashmap.insert(user.id.clone(), user);
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&User> {
        self.hashmap.get(id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut User> {
        self.hashmap.get_mut(id)
    }

    pub fn remove(&mut self, id: &str) -> Option<User> {
        self.hashmap.remove(id)
    }

    pub fn list(&self) -> Vec<&User> {
        self.hashmap.values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_fs::prelude::*;
    use predicates::prelude::*;
    use std::path::PathBuf;

    #[test]
    fn test_user_display() {
        let user = User {
            id: "test".to_string(),
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            sshkey_path: None,
        };
        assert_eq!(user.to_string(), "test: Test User <test@example.com>");
    }

    #[test]
    fn test_user_sshkey_name() {
        let user = User {
            id: "test".to_string(),
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            sshkey_path: None,
        };
        assert_eq!(user.get_sshkey_name(), "id_test");

        let user_with_path = User {
            id: "test".to_string(),
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            sshkey_path: Some(PathBuf::from("/path/to/id_rsa")),
        };
        assert_eq!(user_with_path.get_sshkey_name(), "id_rsa");
    }

    #[test]
    fn test_users_operations() {
        let mut users = Users::new();
        
        // Test adding a user
        let user = User {
            id: "test".to_string(),
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            sshkey_path: None,
        };
        assert!(users.add(user.clone()).is_ok());
        
        // Test duplicate user
        assert!(users.add(user.clone()).is_err());
        
        // Test getting a user
        assert!(users.exists("test"));
        let retrieved_user = users.get("test").unwrap();
        assert_eq!(retrieved_user.name, "Test User");
        
        // Test listing users
        let user_list = users.list();
        assert_eq!(user_list.len(), 1);
        
        // Test removing a user
        let removed_user = users.remove("test").unwrap();
        assert_eq!(removed_user.id, "test");
        assert!(!users.exists("test"));
    }

    #[test]
    fn test_users_file_operations() -> Result<()> {
        let temp_dir = assert_fs::TempDir::new()?;
        let users_file = temp_dir.child("users.toml");
        
        // Test creating new users file
        let users = Users::open(&users_file.path().to_path_buf())?;
        assert_eq!(users.list().len(), 0);
        
        // Test saving and loading users
        let mut users = Users::new();
        let user = User {
            id: "test".to_string(),
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            sshkey_path: None,
        };
        users.add(user)?;
        users.save(&users_file.path().to_path_buf())?;
        
        let loaded_users = Users::open(&users_file.path().to_path_buf())?;
        assert_eq!(loaded_users.list().len(), 1);
        let loaded_user = loaded_users.get("test").unwrap();
        assert_eq!(loaded_user.name, "Test User");
        
        Ok(())
    }
}
