use std::process::ExitCode;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
};

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
use gus_core::{NEUTRAL_REFLOG_EMAIL, NEUTRAL_REFLOG_NAME, ProfileRequirement, RequirementReason};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
use gus_platform::{CurrentSessionObserver, ExecutableExclusionSet, VerifiedRealGit};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
use gus_profile::{Profile, ProfileId, ProfileSet};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
use gus_shim::{ExplicitProfileAdmission, InitialRoute, LocalPolicyAdmission, ShimInvocation};

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
const MAX_PROFILE_STORE_BYTES: u64 = 1024 * 1024;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
const MAX_SELECTION_BYTES: usize = 128;

fn main() -> ExitCode {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    {
        run_unix()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
    {
        eprintln!("GUS_E_PLATFORM_UNSUPPORTED: the Git shim is not implemented on this platform");
        ExitCode::from(126)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn run_unix() -> ExitCode {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.as_slice() == ["--gus-shim-probe"] {
        println!("gus-git-shim-v1");
        return ExitCode::SUCCESS;
    }
    match ShimInvocation::parse(&arguments).route() {
        InitialRoute::Forward(admission) => execute_git(admission),
        InitialRoute::Resolve(required) => match selected_profile() {
            Ok(Some(profile)) => match required.select_explicit_profile(&profile) {
                Ok(admission) => execute_profiled_git(admission),
                Err(error) => explicit_admission_error(&error),
            },
            Ok(None) => selection_required(
                requirement_message(required.invocation().profile_requirement()),
                "no explicit profile was selected",
            ),
            Err(error) => {
                eprintln!("GUS_E_SELECTION_FAILED: {error}; Git was not started");
                ExitCode::from(125)
            }
        },
        InitialRoute::Reject(rejection) => {
            eprintln!(
                "GUS_E_POLICY_REJECTED: {}; Git was not started",
                reason_message(rejection.reason())
            );
            ExitCode::from(125)
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn execute_git(admission: LocalPolicyAdmission) -> ExitCode {
    execute_git_arguments(admission.into_arguments(), &neutral_environment())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn execute_profiled_git(admission: ExplicitProfileAdmission) -> ExitCode {
    let (arguments, author, committer) = admission.into_execution();
    execute_git_arguments(arguments, &profile_environment(&author, &committer))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn execute_git_arguments(
    arguments: Vec<OsString>,
    environment: &[(OsString, OsString)],
) -> ExitCode {
    let current = match std::env::current_exe() {
        Ok(current) => current,
        Err(error) => return launch_error("resolve the running shim", &error),
    };
    let Some(owned_root) = current.parent() else {
        return launch_message("the running shim has no installation directory");
    };
    let exclusions = match ExecutableExclusionSet::new(owned_root, 1) {
        Ok(exclusions) => exclusions,
        Err(error) => return launch_error("build the GUS exclusion set", &error),
    };
    let git = match VerifiedRealGit::discover_system(exclusions) {
        Ok(git) => git,
        Err(error) => return launch_error("verify the fixed system Git", &error),
    };

    let mut forwarded = Vec::with_capacity(arguments.len() + 1);
    forwarded.push(OsString::from("git"));
    forwarded.extend(arguments);
    match git.exec(&forwarded, environment) {
        Ok(never) => match never {},
        Err(error) => launch_error("execute the retained system Git", &error),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn selected_profile() -> Result<Option<Profile>, String> {
    if let Some(raw_id) = std::env::var_os("GUS_PROFILE_ID") {
        let id = raw_id
            .into_string()
            .map_err(|_| "GUS_PROFILE_ID is not valid UTF-8".to_owned())
            .and_then(|id| ProfileId::try_from(id).map_err(|error| error.to_string()))?;
        return profile_by_id(&load_profile_set()?, &id).map(Some);
    }

    let observation = CurrentSessionObserver::new()
        .observe()
        .map_err(|error| format!("cannot establish the terminal session: {error}"))?;
    let Some(terminal) = observation.terminal_session() else {
        return Ok(None);
    };
    let profiles = load_profile_set()?;
    let selection_path = selection_path(&terminal.selection_key().encode_hex())?;
    if let Some(id) = read_session_selection(&selection_path)? {
        if let Some(profile) = profiles.profiles.get(&id) {
            return Ok(Some(profile.clone()));
        }
    }
    let id = prompt_for_profile(&profiles)?;
    let profile = profile_by_id(&profiles, &id)?;
    write_session_selection(&selection_path, &id)?;
    Ok(Some(profile))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn load_profile_set() -> Result<ProfileSet, String> {
    let path = profile_store_path()?;
    let mut bytes = Vec::new();
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .map_err(|error| format!("cannot securely open {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    // SAFETY: `geteuid` has no preconditions and only reads process credentials.
    let effective_user = unsafe { libc::geteuid() };
    if !metadata.is_file() || metadata.uid() != effective_user || metadata.mode() & 0o022 != 0 {
        return Err(format!(
            "{} must be a regular file owned by the current user and not group/world writable",
            path.display()
        ));
    }
    file.take(MAX_PROFILE_STORE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if bytes.len() as u64 > MAX_PROFILE_STORE_BYTES {
        return Err(format!("{} exceeds the 1 MiB limit", path.display()));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| format!("{} is not valid UTF-8", path.display()))?;
    let profiles: ProfileSet = toml::from_str(text)
        .map_err(|error| format!("cannot parse {}: {error}", path.display()))?;
    profiles
        .validate()
        .map_err(|error| format!("{} is invalid: {error}", path.display()))?;
    Ok(profiles)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn profile_by_id(profiles: &ProfileSet, id: &ProfileId) -> Result<Profile, String> {
    profiles
        .profiles
        .get(id)
        .cloned()
        .ok_or_else(|| format!("profile '{id}' does not exist in the profile store"))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn profile_store_path() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("GUS_PROFILE_STORE") {
        let path = PathBuf::from(path);
        return path
            .is_absolute()
            .then_some(path)
            .ok_or_else(|| "GUS_PROFILE_STORE must be an absolute path".to_owned());
    }
    if let Some(root) = std::env::var_os("XDG_CONFIG_HOME") {
        let root = PathBuf::from(root);
        return root
            .is_absolute()
            .then(|| root.join("gus/profiles.toml"))
            .ok_or_else(|| "XDG_CONFIG_HOME must be an absolute path".to_owned());
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| home.is_absolute())
        .map(|home| home.join(".config/gus/profiles.toml"))
        .ok_or_else(|| "neither GUS_PROFILE_STORE, XDG_CONFIG_HOME, nor HOME is set".to_owned())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn selection_path(key: &str) -> Result<PathBuf, String> {
    let root = if let Some(root) = std::env::var_os("GUS_RUNTIME_DIR") {
        absolute_path("GUS_RUNTIME_DIR", root)?
    } else if let Some(root) = std::env::var_os("XDG_RUNTIME_DIR") {
        absolute_path("XDG_RUNTIME_DIR", root)?
    } else {
        // SAFETY: `geteuid` has no preconditions and only reads process credentials.
        PathBuf::from(format!("/tmp/gus-{}", unsafe { libc::geteuid() }))
    };
    ensure_private_directory(&root)?;
    let selections = root.join("gus-selections");
    ensure_private_directory(&selections)?;
    Ok(selections.join(key))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn absolute_path(name: &str, value: OsString) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    path.is_absolute()
        .then_some(path)
        .ok_or_else(|| format!("{name} must be an absolute path"))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn ensure_private_directory(path: &Path) -> Result<(), String> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(format!("cannot create {}: {error}", path.display())),
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    // SAFETY: `geteuid` has no preconditions and only reads process credentials.
    let effective_user = unsafe { libc::geteuid() };
    if !metadata.is_dir() || metadata.uid() != effective_user || metadata.mode() & 0o077 != 0 {
        return Err(format!(
            "{} must be a private directory owned by the current user",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn read_session_selection(path: &Path) -> Result<Option<ProfileId>, String> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("cannot open {}: {error}", path.display())),
    };
    validate_private_file(&file, path)?;
    let mut bytes = Vec::new();
    file.take(129)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if bytes.len() > MAX_SELECTION_BYTES {
        return Err(format!(
            "{} exceeds the selection size limit",
            path.display()
        ));
    }
    let id = std::str::from_utf8(&bytes)
        .map_err(|_| format!("{} is not valid UTF-8", path.display()))?
        .trim_end_matches(['\r', '\n'])
        .to_owned();
    ProfileId::try_from(id)
        .map(Some)
        .map_err(|error| format!("{} contains an invalid profile ID: {error}", path.display()))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn write_session_selection(path: &Path, id: &ProfileId) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{} has no portable file name", path.display()))?;
    let temporary = parent.join(format!(".{file_name}-{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&temporary)
        .map_err(|error| format!("cannot create {}: {error}", temporary.display()))?;
    validate_private_file(&file, &temporary)?;
    let result = (|| {
        writeln!(file, "{id}")
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("cannot write {}: {error}", temporary.display()))?;
        fs::rename(&temporary, path).map_err(|error| {
            format!(
                "cannot publish {} as {}: {error}",
                temporary.display(),
                path.display()
            )
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn validate_private_file(file: &File, path: &Path) -> Result<(), String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    // SAFETY: `geteuid` has no preconditions and only reads process credentials.
    let effective_user = unsafe { libc::geteuid() };
    if !metadata.is_file() || metadata.uid() != effective_user || metadata.mode() & 0o077 != 0 {
        return Err(format!(
            "{} must be a private regular file owned by the current user",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn prompt_for_profile(profiles: &ProfileSet) -> Result<ProfileId, String> {
    if profiles.profiles.is_empty() {
        return Err("the profile store contains no profiles".to_owned());
    }
    let mut terminal = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open("/dev/tty")
        .map_err(|error| format!("cannot open the controlling terminal: {error}"))?;
    writeln!(terminal, "GUS: select a profile for this terminal session:")
        .map_err(|error| format!("cannot write the profile prompt: {error}"))?;
    for (index, (id, profile)) in profiles.profiles.iter().enumerate() {
        writeln!(
            terminal,
            "  {}. {} — {} <{}>",
            index + 1,
            id,
            profile.author.name(),
            profile.author.email()
        )
        .map_err(|error| format!("cannot write the profile prompt: {error}"))?;
    }
    write!(terminal, "Profile number or ID: ")
        .and_then(|()| terminal.flush())
        .map_err(|error| format!("cannot write the profile prompt: {error}"))?;

    let response = read_terminal_line(&mut terminal)?;
    resolve_prompt_response(profiles, &response)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn resolve_prompt_response(profiles: &ProfileSet, response: &str) -> Result<ProfileId, String> {
    if let Ok(id) = ProfileId::try_from(response.to_owned()) {
        if profiles.profiles.contains_key(&id) {
            return Ok(id);
        }
    }
    if let Ok(index) = response.parse::<usize>() {
        if let Some(id) = index
            .checked_sub(1)
            .and_then(|index| profiles.profiles.keys().nth(index))
        {
            return Ok(id.clone());
        }
    }
    Err("the selected profile does not exist".to_owned())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn read_terminal_line(terminal: &mut File) -> Result<String, String> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        let count = terminal
            .read(&mut byte)
            .map_err(|error| format!("cannot read the profile selection: {error}"))?;
        if count == 0 || byte[0] == b'\n' {
            break;
        }
        if byte[0] != b'\r' {
            bytes.push(byte[0]);
        }
        if bytes.len() > MAX_SELECTION_BYTES {
            return Err("the profile selection is too long".to_owned());
        }
    }
    String::from_utf8(bytes).map_err(|_| "the profile selection is not valid UTF-8".to_owned())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn selection_required(reason: &str, context: &str) -> ExitCode {
    eprintln!(
        "GUS_E_SELECTION_REQUIRED: {reason}; {context}, so Git was not started\nhint: run the command from an interactive terminal to select a profile"
    );
    ExitCode::from(125)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn explicit_admission_error(error: &gus_shim::ExplicitProfileError) -> ExitCode {
    match error {
        gus_shim::ExplicitProfileError::ResolutionRequired => {
            eprintln!(
                "GUS_E_RESOLUTION_UNAVAILABLE: the selected profile remains valid, but this Git operation needs trusted repository/transport resolution that is not available in this build; Git was not started"
            );
            ExitCode::from(125)
        }
        gus_shim::ExplicitProfileError::InvalidProfile(error) => {
            eprintln!("GUS_E_PROFILE_INVALID: {error}; Git was not started");
            ExitCode::from(125)
        }
        gus_shim::ExplicitProfileError::UnsupportedInvocation
        | gus_shim::ExplicitProfileError::SigningUnsupported => {
            eprintln!(
                "GUS_E_POLICY_REJECTED: {error}; Git was not started\nhint: use a plain unsigned commit or wait for trusted signing/config resolution support"
            );
            ExitCode::from(125)
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
const fn reason_message(reason: RequirementReason) -> &'static str {
    match reason {
        RequirementReason::AuthorIdentity => "this Git operation needs an author identity",
        RequirementReason::SigningIdentity => "this Git operation needs a signing identity",
        RequirementReason::SshTransport => "this Git operation needs an SSH identity",
        RequirementReason::HttpCredential => "this Git operation may need an HTTP credential",
        RequirementReason::PreHandshakeHttpIdentity => {
            "this Git operation needs an HTTP identity before authentication"
        }
        RequirementReason::ProxyTransport => "this Git operation uses an unsupported proxy path",
        RequirementReason::PublishAuthentication => {
            "this Git operation needs publication authentication"
        }
        RequirementReason::UnresolvedTransport => {
            "the effective remote transport has not been resolved"
        }
        RequirementReason::UnresolvedIdentityCreation => {
            "the effective Git configuration may create an identity-bearing object"
        }
        RequirementReason::UnverifiedCredentialProtocol => {
            "the Git credential protocol has not been verified"
        }
        RequirementReason::AmbiguousConfiguration => "the effective Git configuration is ambiguous",
        RequirementReason::AmbiguousInvocation => "the Git invocation is ambiguous",
        RequirementReason::UnknownOrExternalCommand => {
            "the Git command is unknown or externally implemented"
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
const fn requirement_message(requirement: ProfileRequirement) -> &'static str {
    match requirement {
        ProfileRequirement::Deferred(reason)
        | ProfileRequirement::Required(reason)
        | ProfileRequirement::Unsupported(reason) => reason_message(reason),
        ProfileRequirement::NotRequired => "this Git operation needs trusted repository evidence",
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn neutral_environment() -> Vec<(OsString, OsString)> {
    const REMOVED: &[&str] = &[
        "EMAIL",
        "GIT_AUTHOR_EMAIL",
        "GIT_AUTHOR_NAME",
        "GIT_COMMITTER_EMAIL",
        "GIT_COMMITTER_NAME",
        "GIT_ASKPASS",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GUS_PROFILE_ID",
        "GUS_PROFILE_STORE",
        "GUS_RUNTIME_DIR",
        "SSH_AGENT_PID",
        "SSH_ASKPASS",
        "SSH_ASKPASS_REQUIRE",
        "SSH_AUTH_SOCK",
    ];
    let mut environment = std::env::vars_os()
        .filter(|(name, _)| {
            !REMOVED.iter().any(|removed| name == removed)
                && !name
                    .to_str()
                    .is_some_and(|name| name.starts_with("GIT_CONFIG_"))
        })
        .collect::<Vec<_>>();
    environment.extend([
        (
            OsString::from("GIT_AUTHOR_NAME"),
            OsString::from(NEUTRAL_REFLOG_NAME),
        ),
        (
            OsString::from("GIT_AUTHOR_EMAIL"),
            OsString::from(NEUTRAL_REFLOG_EMAIL),
        ),
        (
            OsString::from("GIT_COMMITTER_NAME"),
            OsString::from(NEUTRAL_REFLOG_NAME),
        ),
        (
            OsString::from("GIT_COMMITTER_EMAIL"),
            OsString::from(NEUTRAL_REFLOG_EMAIL),
        ),
    ]);
    environment
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn profile_environment(
    author: &gus_profile::PersonIdentity,
    committer: &gus_profile::PersonIdentity,
) -> Vec<(OsString, OsString)> {
    const REPOSITORY_OVERRIDES: &[&str] = &[
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CEILING_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_DIR",
        "GIT_DISCOVERY_ACROSS_FILESYSTEM",
        "GIT_INDEX_FILE",
        "GIT_NAMESPACE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_WORK_TREE",
    ];
    let mut environment = neutral_environment();
    environment.retain(|(name, _)| !REPOSITORY_OVERRIDES.iter().any(|removed| name == removed));
    for (name, value) in [
        ("GIT_AUTHOR_NAME", author.name()),
        ("GIT_AUTHOR_EMAIL", author.email()),
        ("GIT_COMMITTER_NAME", committer.name()),
        ("GIT_COMMITTER_EMAIL", committer.email()),
    ] {
        if let Some((_, current)) = environment
            .iter_mut()
            .find(|(current_name, _)| current_name == name)
        {
            *current = OsString::from(value);
        }
    }
    environment.extend([
        (OsString::from("GIT_CONFIG_COUNT"), OsString::from("2")),
        (
            OsString::from("GIT_CONFIG_KEY_0"),
            OsString::from("commit.gpgSign"),
        ),
        (
            OsString::from("GIT_CONFIG_VALUE_0"),
            OsString::from("false"),
        ),
        (
            OsString::from("GIT_CONFIG_KEY_1"),
            OsString::from("credential.helper"),
        ),
        (OsString::from("GIT_CONFIG_VALUE_1"), OsString::new()),
    ]);
    environment
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn launch_error(action: &str, error: &dyn std::error::Error) -> ExitCode {
    eprintln!("GUS_E_REAL_GIT: failed to {action}: {error}");
    ExitCode::from(126)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn launch_message(message: &str) -> ExitCode {
    eprintln!("GUS_E_REAL_GIT: {message}");
    ExitCode::from(126)
}

#[cfg(all(
    test,
    any(target_os = "linux", target_os = "macos", target_os = "freebsd")
))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn profiles() -> ProfileSet {
        toml::from_str(
            r#"
version = 2
generation = 1

[profiles.2]
id = "2"
generation = 1
[profiles.2.author]
name = "Numeric"
email = "numeric@example.test"
[profiles.2.committer]
name = "Numeric"
email = "numeric@example.test"

[profiles.alpha]
id = "alpha"
generation = 1
[profiles.alpha.author]
name = "Alpha"
email = "alpha@example.test"
[profiles.alpha.committer]
name = "Alpha"
email = "alpha@example.test"
"#,
        )
        .expect("valid profile set")
    }

    #[test]
    fn exact_numeric_profile_id_takes_precedence_over_menu_position() {
        let selected = resolve_prompt_response(&profiles(), "2").expect("selection");
        assert_eq!(selected.as_str(), "2");
    }

    #[test]
    fn session_selection_is_atomically_replaced() {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let path = directory.path().join("selection");
        let work = ProfileId::try_from("work".to_owned()).expect("work ID");
        let personal = ProfileId::try_from("personal".to_owned()).expect("personal ID");

        write_session_selection(&path, &work).expect("initial selection");
        write_session_selection(&path, &personal).expect("replacement selection");

        assert_eq!(
            read_session_selection(&path).expect("read selection"),
            Some(personal)
        );
        assert_eq!(
            fs::read_dir(directory.path())
                .expect("read directory")
                .count(),
            1
        );
    }
}
