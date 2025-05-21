use anyhow::{ensure, Context, Result};
use std::env;
use std::path::PathBuf;

use crate::auto_switch::AutoSwitcher;
use crate::config::Config;
use crate::shell::{get_app_name, get_setup_script, write_session_script};
use crate::sshkey::generate_ssh_key;
use crate::user::{User, Users};

pub struct GitUserSwitcher {
    pub users: Users,
    pub config: Config,
    auto_switcher: AutoSwitcher<'static>,
    config_path: PathBuf,
}

impl From<&PathBuf> for GitUserSwitcher {
    fn from(config_path: &PathBuf) -> Self {
        let mut org_config = config_path.clone();
        org_config.set_extension("default.toml");
        Config::default().save(&org_config);
        let config = Config::open(config_path).unwrap();
        let users = Users::open(&config.users_file_path).unwrap();
        
        // Box::leakを使用して'staticライフタイムを取得
        let config_ref = Box::leak(Box::new(config.clone()));
        let auto_switcher = AutoSwitcher::new(config_ref, users.clone());
        
        Self { 
            users, 
            config, 
            auto_switcher,
            config_path: config_path.to_path_buf(),
        }
    }
}

impl Drop for GitUserSwitcher {
    fn drop(&mut self) {
        // Box::leakで作成したメモリを解放
        unsafe {
            let ptr = self.auto_switcher.config as *const _ as *mut Config;
            Box::from_raw(ptr);
        }
    }
}

impl GitUserSwitcher {
    pub fn add_user(&mut self, user: User, sshkey_passphrase: Option<&str>) -> Result<()> {
        self.users.add(user.clone())?;

        let sshkey_path = user.get_sshkey_path(&self.config.default_sshkey_dir);

        if !sshkey_path.exists() {
            let pass = sshkey_passphrase.context("ssh key passphrase required")?;
            ensure!(
                pass.len() >= self.config.min_sshkey_passphrase_length,
                "ssh key passphrase must be at least {} characters",
                self.config.min_sshkey_passphrase_length
            );

            generate_ssh_key(
                &self.config.default_sshkey_type,
                self.config.default_sshkey_rounds,
                &user.get_sshkey_name(),
                &pass,
                &sshkey_path,
            )
            .with_context(|| format!("failed to generate ssh key for user: {}", &user.id))?;
        }

        self.users.save(&self.config.users_file_path)?;
        Ok(())
    }

    pub fn remove_user(&mut self, id: &str) -> Result<()> {
        ensure!(
            self.users.exists(id),
            "user with id '{}' does not exist",
            id
        );
        self.users.remove(id);
        self.users.save(&self.config.users_file_path)?;
        Ok(())
    }

    pub fn switch_user(&self, id: &str) -> Result<()> {
        ensure!(
            self.users.exists(id),
            "user with id '{}' does not exist",
            id
        );
        let user = self.users.get(id).unwrap();

        let script = format!(
            "\
            export GUS_USER_ID=\"{id}\"\n\
            export GIT_AUTHOR_NAME=\"{name}\"\n\
            export GIT_AUTHOR_EMAIL=\"{email}\"\n\
            export GIT_COMMITTER_NAME=\"{name}\"\n\
            export GIT_COMMITTER_EMAIL=\"{email}\"\n\
            export GIT_SSH_COMMAND=\"ssh -i {sshkey_path} -F /dev/null\"\n\
            ",
            id = user.id,
            name = user.name,
            email = user.email,
            sshkey_path = user
                .get_sshkey_path(&self.config.default_sshkey_dir)
                .to_string_lossy(),
        );

        write_session_script(&script)?;

        Ok(())
    }

    pub fn get_current_user(&self) -> Option<&User> {
        self.users
            .get(env::var("GUS_USER_ID").unwrap_or_default().as_str())
    }

    pub fn list_users(&self) -> Vec<&User> {
        self.users.list()
    }

    pub fn exists_user(&self, id: &str) -> bool {
        self.users.exists(id)
    }

    pub fn get_public_sshkey(&self, id: &str) -> Result<String> {
        ensure!(
            self.users.exists(id),
            "user with id '{}' does not exist",
            id
        );
        let user = self.users.get(id).unwrap();
        let sshkey_path = user
            .get_sshkey_path(&self.config.default_sshkey_dir)
            .with_extension("pub");
        let contents = std::fs::read_to_string(&sshkey_path)
            .with_context(|| format!("failed to read ssh key: {}", sshkey_path.display()))?;
        Ok(contents)
    }

    pub fn enable_auto_switch(&mut self) -> Result<()> {
        self.config.auto_switch_enabled = true;
        self.config.save(&self.config_path)?;
        Ok(())
    }

    pub fn disable_auto_switch(&mut self) -> Result<()> {
        self.config.auto_switch_enabled = false;
        self.config.save(&self.config_path)?;
        Ok(())
    }

    pub fn add_auto_switch_pattern(&mut self, pattern: &str, user_id: &str) -> Result<()> {
        if !self.users.exists(user_id) {
            anyhow::bail!("User '{}' does not exist", user_id);
        }

        glob::Pattern::new(pattern)
            .with_context(|| format!("Invalid glob pattern: {}", pattern))?;

        self.config.auto_switch_patterns.push(crate::config::AutoSwitchPattern {
            pattern: pattern.to_string(),
            user_id: user_id.to_string(),
        });
        self.config.save(&self.config_path)?;
        Ok(())
    }

    pub fn remove_auto_switch_pattern(&mut self, pattern: &str) -> Result<bool> {
        let initial_len = self.config.auto_switch_patterns.len();
        self.config.auto_switch_patterns.retain(|p| p.pattern != pattern);
        let removed = initial_len != self.config.auto_switch_patterns.len();
        if removed {
            self.config.save(&self.config_path)?;
        }
        Ok(removed)
    }

    pub fn list_auto_switch_patterns(&self) -> Vec<(&str, &str)> {
        self.auto_switcher.list_patterns()
    }

    pub fn check_auto_switch(&self) -> Result<()> {
        if let Some(user_id) = self.auto_switcher.should_switch(&std::env::current_dir()?) {
            self.switch_user(&user_id)?;
        }
        Ok(())
    }

    pub fn get_setup_script(&self) -> String {
        write_session_script("").unwrap();

        let app_name = get_app_name();

        let force_use_gus_script = if self.config.force_use_gus {
            format!(
                "\
            if [ -z \"$GUS_USER_ID\" ]; then\n\
                echo The use of GUS is mandatory. Users who have not yet registered their information in GUS should use 'gus add' to register their information.;\n\
                echo === Available users: ===;\n\
                {app_name} list;\n\
                echo ========================;\n\
                echo -n \"Enter user id: \";\n\
                read user_id;\n\
                {app_name} set \"$user_id\";\n\
                status=$?;\n\
                if [ $status -ne 0 ]; then\n\
                    return $status;\n\
                fi;\n\
            fi;\n\
            "
            )
        } else {
            "".to_owned()
        };

        let auto_switch_script = if self.config.auto_switch_enabled {
            format!(
                "\
            cd() {{
                command cd \"$@\";
                {app_name} auto-switch check;
            }}\n\
            "
            )
        } else {
            "".to_owned()
        };

        get_setup_script(&format!(
            "\
            git() {{\n\
                {force_use_gus_script}\
                command git \"$@\";\n\
            }}\n\
            {auto_switch_script}\
            "
        ))
    }
}
