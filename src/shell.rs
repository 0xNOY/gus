use anyhow::{Context, Result};
use std::{collections::HashMap, env, os::unix::process::parent_id, path::PathBuf};

pub fn str2envkey(s: &str) -> String {
    // [a-zA-Z_][a-zA-Z0-9_]*
    let mut result = String::new();
    let mut chars = s.chars();
    if let Some(c) = chars.next() {
        if c.is_ascii_alphabetic() || c == '_' {
            result.push(c);
        } else {
            result.push('_');
            result.push(c);
        }
    }
    result.extend(chars.filter(|c| c.is_ascii_alphanumeric() || *c == '_'));
    result
}

pub fn get_session_script_path() -> PathBuf {
    env::temp_dir()
        .join(env::current_exe().unwrap().file_name().unwrap())
        .join(format!("session{}.sh", parent_id()))
}

pub fn get_app_path() -> PathBuf {
    env::current_exe().unwrap()
}

pub fn get_app_name() -> String {
    env::args().next().unwrap()
}

pub fn write_session_script(script: &str) -> Result<()> {
    let path = get_session_script_path();

    if !path.parent().unwrap().exists() {
        std::fs::create_dir_all(&path.parent().unwrap()).with_context(|| {
            format!(
                "failed to create session script directory: {}",
                path.display()
            )
        })?;
    }

    std::fs::write(&path, script)
        .with_context(|| format!("failed to write session script: {}", path.display()))?;
    Ok(())
}

pub fn get_setup_script(script: &str) -> String {
    format!(
        "\
        if [ -z ${{{loaded_flag_key}}} ]; then\n\
            export {loaded_flag_key}=1\n\
            rm -f \"{session_script_path}\"\n\
            function {app_name}() {{\n\
                \"{app_path}\" \"$@\"\n\
                status=$?\n\
                if [ $status -ne 0 ]; then\n\
                    return $status\n\
                fi\n\
                source \"{session_script_path}\"\n\
            }}\n\
            {script}\
        fi\n\
        ",
        loaded_flag_key = "GUS_LOADED_FLAG",
        app_path = get_app_path().to_string_lossy(),
        app_name = get_app_name(),
        session_script_path = get_session_script_path().to_string_lossy(),
    )
}
