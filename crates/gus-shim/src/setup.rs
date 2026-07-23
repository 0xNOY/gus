use std::{env, ffi::OsString, process::ExitCode};

#[cfg(unix)]
use gus_profile::{PersonIdentity, Profile, ProfileId, ProfileSet};
#[cfg(unix)]
use sha2::{Digest as _, Sha256};
#[cfg(unix)]
use std::os::{
    fd::AsRawFd as _,
    unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
};
#[cfg(unix)]
use std::{
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    process::Command,
};

#[cfg(unix)]
const OWNER_FILE: &str = ".gus-git-shim-owner-v1";
#[cfg(unix)]
const INSTALL_LOCK_FILE: &str = ".gus-git-shim-install.lock";
#[cfg(unix)]
const UPDATE_JOURNAL_FILE: &str = ".gus-git-shim-update-v1";
#[cfg(unix)]
const MAX_PROFILE_STORE_BYTES: u64 = 1024 * 1024;

fn main() -> ExitCode {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    match run(&arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("gus: {error}");
            ExitCode::from(78)
        }
    }
}

fn run(arguments: &[OsString]) -> Result<(), String> {
    let Some(command) = arguments.first().and_then(|value| value.to_str()) else {
        return Err(usage());
    };
    match command {
        "setup" => setup(&arguments[1..]),
        "doctor" if arguments.len() == 1 => doctor(),
        "uninstall-shim" if arguments.len() == 1 => uninstall(),
        "user" => user(&arguments[1..]),
        _ => Err(usage()),
    }
}

fn usage() -> String {
    "usage: gus <setup [--dry-run] [--target-dir PATH]|doctor|uninstall-shim|user <add|remove|list>>"
        .to_owned()
}

fn user(arguments: &[OsString]) -> Result<(), String> {
    #[cfg(not(unix))]
    {
        let _ = arguments;
        Err("profile management is not implemented on this platform yet".to_owned())
    }

    #[cfg(unix)]
    {
        let path = profile_store_path()?;
        match arguments {
            [command, id, name, email] if command == "add" => user_add(
                &path,
                os_string(id, "profile ID")?,
                os_string(name, "name")?,
                os_string(email, "email")?,
            ),
            [command, id] if command == "remove" => {
                user_remove(&path, os_string(id, "profile ID")?)
            }
            [command] if command == "list" => user_list(&path),
            _ => Err("usage: gus user <add <id> <name> <email>|remove <id>|list>".to_owned()),
        }
    }
}

#[cfg(unix)]
fn os_string(value: &OsString, label: &str) -> Result<String, String> {
    value
        .clone()
        .into_string()
        .map_err(|_| format!("{label} must be valid UTF-8"))
}

fn setup(arguments: &[OsString]) -> Result<(), String> {
    #[cfg(not(unix))]
    {
        let _ = arguments;
        Err("setup is not implemented on this platform yet".to_owned())
    }

    #[cfg(unix)]
    {
        let (dry_run, requested_target) = parse_setup_arguments(arguments)?;
        let source = shim_source()?;
        let path = executable_path_entries()?;
        let real_git_index = first_unowned_git_index(&path)
            .ok_or_else(|| "no existing Git executable was found on PATH".to_owned())?;
        let target = select_target(&path, real_git_index, requested_target.as_deref())?;
        let destination = target.join("git");
        let owner = target.join(OWNER_FILE);
        validate_target_directory(&target)?;

        println!("GUS shim source: {}", source.display());
        println!("Install target: {}", destination.display());
        if dry_run {
            println!("Dry run: no files were changed");
            return Ok(());
        }

        let directory = open_target_directory(&target)?;
        let _lock = acquire_install_lock(&target)?;
        let installed = install_shim(&source, &destination, &owner, &directory)?;
        if let Err(error) = verify_installed_shim(&destination) {
            if installed && is_owned_shim(&destination, &owner) {
                if let Err(cleanup) = rollback_new_install(&destination, &owner, &directory) {
                    return Err(format!(
                        "{error}; install rollback is incomplete: {cleanup}"
                    ));
                }
            }
            return Err(error);
        }
        println!("GUS Git shim installed and verified");
        println!("Open a new shell or restart the IDE if it cached the previous Git path");
        Ok(())
    }
}

#[cfg(unix)]
fn parse_setup_arguments(arguments: &[OsString]) -> Result<(bool, Option<PathBuf>), String> {
    let mut dry_run = false;
    let mut target = None;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].to_str() {
            Some("--dry-run") if !dry_run => dry_run = true,
            Some("--target-dir") if target.is_none() => {
                index += 1;
                let value = arguments
                    .get(index)
                    .ok_or_else(|| "--target-dir requires a path".to_owned())?;
                target = Some(PathBuf::from(value));
            }
            _ => return Err("unsupported or duplicate setup option".to_owned()),
        }
        index += 1;
    }
    Ok((dry_run, target))
}

#[cfg(unix)]
fn shim_source() -> Result<PathBuf, String> {
    let current = env::current_exe().map_err(|error| format!("cannot locate gus: {error}"))?;
    let directory = current
        .parent()
        .ok_or_else(|| "gus has no installation directory".to_owned())?;
    #[cfg(windows)]
    let name = "gus-git-shim.exe";
    #[cfg(not(windows))]
    let name = "gus-git-shim";
    let source = directory.join(name);
    source
        .is_file()
        .then_some(source)
        .ok_or_else(|| format!("bundled Git shim is missing from {}", directory.display()))
}

#[cfg(unix)]
fn executable_path_entries() -> Result<Vec<PathBuf>, String> {
    let raw = env::var_os("PATH").ok_or_else(|| "PATH is not set".to_owned())?;
    let mut entries = Vec::new();
    for entry in env::split_paths(&raw) {
        if !entry.is_absolute() {
            return Err(format!(
                "PATH contains a relative entry: {}",
                entry.display()
            ));
        }
        let canonical = match fs::canonicalize(&entry) {
            Ok(canonical) => canonical,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "cannot resolve PATH entry {}: {error}",
                    entry.display()
                ));
            }
        };
        if !entries.contains(&canonical) {
            entries.push(canonical);
        }
    }
    Ok(entries)
}

#[cfg(unix)]
fn first_git_index(path: &[PathBuf]) -> Option<usize> {
    path.iter()
        .position(|directory| git_path(directory).is_file())
}

#[cfg(unix)]
fn first_unowned_git_index(path: &[PathBuf]) -> Option<usize> {
    path.iter().position(|directory| {
        let git = git_path(directory);
        git.is_file()
            && !is_owned_shim(&git, &directory.join(OWNER_FILE))
            && read_update_journal(&directory.join(UPDATE_JOURNAL_FILE)).is_err()
    })
}

#[cfg(unix)]
fn is_owned_shim(shim: &Path, owner: &Path) -> bool {
    owner.is_file()
        && read_owner_digest(owner)
            .and_then(|expected| file_digest(shim).map(|actual| expected == actual))
            .unwrap_or(false)
}

#[cfg(unix)]
fn git_path(directory: &Path) -> PathBuf {
    #[cfg(windows)]
    let name = "git.exe";
    #[cfg(not(windows))]
    let name = "git";
    directory.join(name)
}

#[cfg(unix)]
fn select_target(
    path: &[PathBuf],
    real_git_index: usize,
    requested: Option<&Path>,
) -> Result<PathBuf, String> {
    let target = match requested {
        Some(target) if target.is_absolute() => fs::canonicalize(target)
            .map_err(|error| format!("cannot resolve target {}: {error}", target.display()))?,
        Some(_) => return Err("--target-dir must be absolute".to_owned()),
        None => env::current_exe()
            .map_err(|error| format!("cannot locate gus: {error}"))?
            .parent()
            .map(Path::to_path_buf)
            .and_then(|directory| fs::canonicalize(directory).ok())
            .ok_or_else(|| "cannot resolve the gus installation directory".to_owned())?,
    };
    let target_index = path
        .iter()
        .position(|entry| entry == &target)
        .ok_or_else(|| format!("{} is not an existing PATH directory", target.display()))?;
    if target_index >= real_git_index {
        return Err(format!(
            "{} does not precede the existing Git on PATH",
            target.display()
        ));
    }
    Ok(target)
}

#[cfg(unix)]
fn install_shim(
    source: &Path,
    destination: &Path,
    owner: &Path,
    directory: &File,
) -> Result<bool, String> {
    let target = destination
        .parent()
        .ok_or_else(|| "install target has no parent".to_owned())?;
    recover_interrupted_update(target, destination, owner, directory)?;

    let suffix = format!("{}-{}", std::process::id(), monotonic_suffix()?);
    let staged_shim = target.join(format!(".gus-git-shim-{suffix}.tmp"));
    let staged_owner = target.join(format!(".gus-owner-{suffix}.tmp"));
    let digest = stage_executable(source, &staged_shim)?;
    write_new_file(
        &staged_owner,
        format!("sha256={digest}\n").as_bytes(),
        0o600,
    )?;

    let result = if !destination.exists() && !owner.exists() {
        publish_no_replace(&staged_owner, owner)?;
        directory
            .sync_all()
            .map_err(|error| sync_directory_error(&error))?;
        if let Err(error) = publish_no_replace(&staged_shim, destination) {
            let cleanup = directory
                .sync_all()
                .and_then(|()| fs::remove_file(owner))
                .and_then(|()| directory.sync_all());
            match cleanup {
                Ok(()) => Err(error),
                Err(cleanup) => Err(format!(
                    "{error}; preserving ownership metadata because rollback is incomplete: {cleanup}"
                )),
            }
        } else {
            directory
                .sync_all()
                .map_err(|error| sync_directory_error(&error))?;
            Ok(true)
        }
    } else if destination.is_file() && owner.is_file() {
        let current = secure_file_digest(destination)?;
        let recorded = read_owner_digest(owner)?;
        if current != recorded {
            Err(format!(
                "the existing Git at {} is not owned by GUS",
                destination.display()
            ))
        } else if current == digest {
            Ok(false)
        } else {
            update_owned_shim(
                target,
                destination,
                owner,
                &staged_shim,
                &staged_owner,
                &current,
                &digest,
                directory,
            )?;
            Ok(false)
        }
    } else if !destination.exists() && owner.is_file() {
        let _ = read_owner_digest(owner)?;
        fs::remove_file(owner)
            .and_then(|()| directory.sync_all())
            .map_err(|error| format!("cannot recover {}: {error}", owner.display()))?;
        publish_no_replace(&staged_owner, owner)?;
        directory
            .sync_all()
            .map_err(|error| sync_directory_error(&error))?;
        publish_no_replace(&staged_shim, destination)?;
        directory
            .sync_all()
            .map_err(|error| sync_directory_error(&error))?;
        Ok(true)
    } else {
        Err(format!(
            "refusing to overwrite existing {} or ownership metadata",
            destination.display()
        ))
    };
    let _ = fs::remove_file(&staged_shim);
    let _ = fs::remove_file(&staged_owner);
    result
}

#[cfg(unix)]
fn stage_executable(source: &Path, destination: &Path) -> Result<String, String> {
    let mut input = open_checked_file(source, false)?;
    let mut output = new_file(destination, 0o700)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = input
            .read(&mut buffer)
            .map_err(|error| format!("cannot read {}: {error}", source.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        output
            .write_all(&buffer[..count])
            .map_err(|error| format!("cannot stage {}: {error}", destination.display()))?;
    }
    output
        .sync_all()
        .map_err(|error| format!("cannot stage {}: {error}", destination.display()))?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o755))
        .and_then(|()| output.sync_all())
        .map_err(|error| format!("cannot make {} executable: {error}", destination.display()))?;
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(unix)]
fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let mut file = new_file(path, mode)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot write {}: {error}", path.display()))
}

#[cfg(unix)]
fn new_file(path: &Path, mode: u32) -> Result<File, String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))
}

#[cfg(unix)]
fn validate_target_directory(path: &Path) -> Result<(), String> {
    open_target_directory(path).map(|_| ())
}

#[cfg(unix)]
fn open_target_directory(path: &Path) -> Result<File, String> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("cannot securely open {}: {error}", path.display()))?;
    let metadata = directory
        .metadata()
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    // SAFETY: `geteuid` has no preconditions and only reads process credentials.
    let effective_user = unsafe { libc::geteuid() };
    if !metadata.is_dir() || metadata.uid() != effective_user || metadata.mode() & 0o022 != 0 {
        return Err(format!(
            "{} must be a non-group/world-writable directory owned by the current user",
            path.display()
        ));
    }
    Ok(directory)
}

#[cfg(unix)]
fn open_checked_file(path: &Path, require_single_link: bool) -> Result<File, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| format!("cannot securely open {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    // SAFETY: `geteuid` has no preconditions and only reads process credentials.
    let effective_user = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.uid() != effective_user
        || metadata.mode() & 0o022 != 0
        || (require_single_link && metadata.nlink() != 1)
    {
        return Err(format!(
            "{} must be an unmodified regular file owned by the current user",
            path.display()
        ));
    }
    Ok(file)
}

#[cfg(unix)]
fn acquire_install_lock(target: &Path) -> Result<File, String> {
    let path = target.join(INSTALL_LOCK_FILE);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .map_err(|error| format!("cannot open install lock {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect install lock {}: {error}", path.display()))?;
    // SAFETY: `geteuid` has no preconditions and only reads process credentials.
    let effective_user = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.uid() != effective_user
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(format!("install lock {} is not private", path.display()));
    }
    // SAFETY: the descriptor is live for this function and `flock` has no pointer arguments.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(format!(
            "another GUS setup is active for {}: {}",
            target.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(file)
}

#[cfg(unix)]
fn publish_no_replace(staged: &Path, destination: &Path) -> Result<bool, String> {
    fs::hard_link(staged, destination).map_err(|error| {
        format!(
            "cannot publish {} without replacing an existing file: {error}",
            destination.display()
        )
    })?;
    if let Err(error) = fs::remove_file(staged) {
        let rollback = fs::remove_file(destination);
        return match rollback {
            Ok(()) => Err(format!(
                "published {} but could not remove staged {}: {error}; publication was rolled back",
                destination.display(),
                staged.display()
            )),
            Err(_) => Ok(false),
        };
    }
    Ok(true)
}

#[cfg(unix)]
fn rollback_new_install(destination: &Path, owner: &Path, directory: &File) -> Result<(), String> {
    fs::remove_file(destination)
        .and_then(|()| directory.sync_all())
        .map_err(|error| format!("cannot remove {}: {error}", destination.display()))?;
    fs::remove_file(owner)
        .and_then(|()| directory.sync_all())
        .map_err(|error| format!("cannot remove {}: {error}", owner.display()))
}

#[cfg(unix)]
fn monotonic_suffix() -> Result<u128, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .map_err(|error| format!("system clock is before the Unix epoch: {error}"))
}

#[cfg(unix)]
fn sync_directory_error(error: &std::io::Error) -> String {
    format!("cannot durably update the install directory: {error}")
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn update_owned_shim(
    target: &Path,
    destination: &Path,
    owner: &Path,
    staged_shim: &Path,
    staged_owner: &Path,
    old_digest: &str,
    new_digest: &str,
    directory: &File,
) -> Result<(), String> {
    let journal = target.join(UPDATE_JOURNAL_FILE);
    let backup = target.join(".gus-git-shim-previous-v1");
    if journal.exists() || backup.exists() {
        return Err("an unrecognized GUS update recovery file already exists".to_owned());
    }
    write_new_file(
        &journal,
        format!("old={old_digest}\nnew={new_digest}\n").as_bytes(),
        0o600,
    )?;
    directory.sync_all().map_err(|error| {
        format!(
            "cannot durably publish update journal {}: {error}",
            journal.display()
        )
    })?;
    fs::hard_link(destination, &backup)
        .and_then(|()| directory.sync_all())
        .map_err(|error| format!("cannot retain the previous Git shim: {error}"))?;
    fs::rename(staged_shim, destination)
        .and_then(|()| directory.sync_all())
        .map_err(|error| format!("cannot activate the updated Git shim: {error}"))?;
    if let Err(error) = verify_installed_shim(destination) {
        fs::rename(&backup, destination)
            .and_then(|()| directory.sync_all())
            .map_err(|rollback| format!("{error}; rollback failed: {rollback}"))?;
        let _ = fs::remove_file(&journal);
        let _ = directory.sync_all();
        return Err(error);
    }
    fs::rename(staged_owner, owner)
        .and_then(|()| directory.sync_all())
        .map_err(|error| format!("cannot publish updated ownership metadata: {error}"))?;
    fs::remove_file(&backup)
        .and_then(|()| fs::remove_file(&journal))
        .and_then(|()| directory.sync_all())
        .map_err(|error| format!("cannot finish the Git shim update: {error}"))
}

#[cfg(unix)]
fn recover_interrupted_update(
    target: &Path,
    destination: &Path,
    owner: &Path,
    directory: &File,
) -> Result<(), String> {
    let journal = target.join(UPDATE_JOURNAL_FILE);
    let backup = target.join(".gus-git-shim-previous-v1");
    if !journal.exists() {
        if backup.exists() {
            let active = secure_file_digest(destination)?;
            let recorded = read_owner_digest(owner)?;
            let retained = secure_file_digest(&backup)?;
            if active != recorded || retained != active {
                return Err("orphaned update backup does not match the active GUS shim".to_owned());
            }
            fs::remove_file(&backup)
                .and_then(|()| directory.sync_all())
                .map_err(|error| format!("cannot remove orphaned update backup: {error}"))?;
        }
        return Ok(());
    }
    let (old, new) = read_update_journal(&journal)?;
    let active = secure_file_digest(destination)?;
    let recorded = read_owner_digest(owner)?;
    match (active.as_str(), recorded.as_str()) {
        (active, recorded) if active == old && recorded == old => {}
        (active, recorded) if active == new && recorded == old => {
            if verify_installed_shim(destination).is_ok() {
                let staged =
                    target.join(format!(".gus-recovered-owner-{}.tmp", monotonic_suffix()?));
                write_new_file(&staged, format!("sha256={new}\n").as_bytes(), 0o600)?;
                fs::rename(&staged, owner)
                    .and_then(|()| directory.sync_all())
                    .map_err(|error| format!("cannot recover ownership metadata: {error}"))?;
            } else {
                if secure_file_digest(&backup)? != old {
                    return Err("the retained pre-update Git shim was modified".to_owned());
                }
                fs::rename(&backup, destination)
                    .and_then(|()| directory.sync_all())
                    .map_err(|error| format!("cannot roll back interrupted update: {error}"))?;
            }
        }
        (active, recorded) if active == new && recorded == new => {}
        _ => return Err("interrupted update state does not match its journal".to_owned()),
    }
    if backup.exists() {
        fs::remove_file(&backup)
            .map_err(|error| format!("cannot remove recovered backup: {error}"))?;
    }
    fs::remove_file(&journal)
        .and_then(|()| directory.sync_all())
        .map_err(|error| format!("cannot finish interrupted update recovery: {error}"))
}

#[cfg(unix)]
fn read_update_journal(path: &Path) -> Result<(String, String), String> {
    let text = read_checked_text(path, 256)?;
    let mut lines = text.lines();
    let old = lines.next().and_then(|line| line.strip_prefix("old="));
    let new = lines.next().and_then(|line| line.strip_prefix("new="));
    if lines.next().is_some() || !old.is_some_and(valid_digest) || !new.is_some_and(valid_digest) {
        return Err(format!("{} is not a valid update journal", path.display()));
    }
    Ok((
        old.unwrap_or_default().to_owned(),
        new.unwrap_or_default().to_owned(),
    ))
}

#[cfg(unix)]
fn file_digest(path: &Path) -> Result<String, String> {
    let mut file = open_checked_file(path, false)?;
    digest_reader(&mut file, path)
}

#[cfg(unix)]
fn secure_file_digest(path: &Path) -> Result<String, String> {
    let mut file = open_checked_file(path, false)?;
    digest_reader(&mut file, path)
}

#[cfg(unix)]
fn digest_reader(file: &mut File, path: &Path) -> Result<String, String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(unix)]
fn read_owner_digest(path: &Path) -> Result<String, String> {
    let text = read_checked_text(path, 128)?;
    text.strip_prefix("sha256=")
        .and_then(|value| value.strip_suffix('\n'))
        .filter(|value| valid_digest(value))
        .map(str::to_owned)
        .ok_or_else(|| format!("{} is not valid GUS ownership metadata", path.display()))
}

#[cfg(unix)]
fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(unix)]
fn profile_store_path() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("GUS_PROFILE_STORE") {
        let path = PathBuf::from(path);
        return path
            .is_absolute()
            .then_some(path)
            .ok_or_else(|| "GUS_PROFILE_STORE must be an absolute path".to_owned());
    }
    if let Some(root) = env::var_os("XDG_CONFIG_HOME") {
        let root = PathBuf::from(root);
        return root
            .is_absolute()
            .then(|| root.join("gus/profiles.toml"))
            .ok_or_else(|| "XDG_CONFIG_HOME must be an absolute path".to_owned());
    }
    env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| home.is_absolute())
        .map(|home| home.join(".config/gus/profiles.toml"))
        .ok_or_else(|| "neither GUS_PROFILE_STORE, XDG_CONFIG_HOME, nor HOME is set".to_owned())
}

#[cfg(unix)]
fn user_add(path: &Path, id: String, name: String, email: String) -> Result<(), String> {
    let id = ProfileId::try_from(id).map_err(|error| error.to_string())?;
    let person = PersonIdentity::new(name, email).map_err(|error| error.to_string())?;
    let (_directory, _lock) = lock_profile_store(path)?;
    let mut profiles = read_profile_store(path)?;
    if profiles.profiles.contains_key(&id) {
        return Err(format!("profile '{id}' already exists"));
    }
    profiles.generation = next_generation(profiles.generation)?;
    profiles.profiles.insert(
        id.clone(),
        Profile {
            id: id.clone(),
            author: person.clone(),
            committer: person,
            signing: None,
            ssh_transport: None,
            http: None,
            generation: 1,
        },
    );
    write_profile_store(path, &profiles)?;
    println!("Added GUS profile '{id}'");
    Ok(())
}

#[cfg(unix)]
fn user_remove(path: &Path, id: String) -> Result<(), String> {
    let id = ProfileId::try_from(id).map_err(|error| error.to_string())?;
    let (_directory, _lock) = lock_profile_store(path)?;
    let mut profiles = read_profile_store(path)?;
    if profiles.profiles.remove(&id).is_none() {
        return Err(format!("profile '{id}' does not exist"));
    }
    profiles.generation = next_generation(profiles.generation)?;
    write_profile_store(path, &profiles)?;
    println!("Removed GUS profile '{id}'");
    Ok(())
}

#[cfg(unix)]
fn user_list(path: &Path) -> Result<(), String> {
    let profiles = read_profile_store(path)?;
    for (id, profile) in profiles.profiles {
        println!(
            "{id}\t{} <{}>",
            profile.author.name(),
            profile.author.email()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn next_generation(generation: u64) -> Result<u64, String> {
    generation
        .checked_add(1)
        .ok_or_else(|| "profile store generation is exhausted".to_owned())
}

#[cfg(unix)]
fn lock_profile_store(path: &Path) -> Result<(File, File), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    create_private_profile_directory(parent)?;
    let directory = File::open(parent).map_err(|error| {
        format!(
            "cannot open profile directory {}: {error}",
            parent.display()
        )
    })?;
    let lock_path = parent.join(".profiles.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&lock_path)
        .map_err(|error| format!("cannot open profile lock {}: {error}", lock_path.display()))?;
    validate_private_profile_file(&lock, &lock_path)?;
    // SAFETY: `lock` is a live descriptor and `flock` has no pointer arguments.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(format!(
            "another GUS profile update is active for {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok((directory, lock))
}

#[cfg(unix)]
fn create_private_profile_directory(path: &Path) -> Result<(), String> {
    if !path.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .map_err(|error| {
                format!(
                    "cannot create profile directory {}: {error}",
                    path.display()
                )
            })?;
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "cannot inspect profile directory {}: {error}",
            path.display()
        )
    })?;
    // SAFETY: `geteuid` has no preconditions and reads process credentials.
    let effective_user = unsafe { libc::geteuid() };
    if !metadata.is_dir() || metadata.uid() != effective_user || metadata.mode() & 0o022 != 0 {
        return Err(format!(
            "profile directory {} must be owned by the current user and not group/world writable",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn read_profile_store(path: &Path) -> Result<ProfileSet, String> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ProfileSet::default());
        }
        Err(error) => return Err(format!("cannot open {}: {error}", path.display())),
    };
    validate_private_profile_file(&file, path)?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_PROFILE_STORE_BYTES + 1)
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

#[cfg(unix)]
fn write_profile_store(path: &Path, profiles: &ProfileSet) -> Result<(), String> {
    profiles
        .validate()
        .map_err(|error| format!("profile update is invalid: {error}"))?;
    let contents = toml::to_string_pretty(profiles)
        .map_err(|error| format!("cannot encode profile store: {error}"))?;
    if contents.len() as u64 > MAX_PROFILE_STORE_BYTES {
        return Err("profile store exceeds the 1 MiB limit".to_owned());
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{} has no portable file name", path.display()))?;
    let temporary = parent.join(format!(
        ".{name}-{}-{}.tmp",
        std::process::id(),
        monotonic_suffix()?
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&temporary)
        .map_err(|error| format!("cannot create {}: {error}", temporary.display()))?;
    validate_private_profile_file(&file, &temporary)?;
    let result = (|| {
        file.write_all(contents.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("cannot write {}: {error}", temporary.display()))?;
        fs::rename(&temporary, path)
            .map_err(|error| format!("cannot publish {}: {error}", path.display()))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("cannot sync profile directory: {error}"))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(unix)]
fn validate_private_profile_file(file: &File, path: &Path) -> Result<(), String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    // SAFETY: `geteuid` has no preconditions and reads process credentials.
    let effective_user = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.uid() != effective_user
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(format!(
            "{} must be a private, singly linked file owned by the current user",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn read_checked_text(path: &Path, limit: u64) -> Result<String, String> {
    let file = open_checked_file(path, true)?;
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(format!("{} exceeds its size limit", path.display()));
    }
    String::from_utf8(bytes).map_err(|_| format!("{} is not valid UTF-8", path.display()))
}

#[cfg(unix)]
fn verify_installed_shim(path: &Path) -> Result<(), String> {
    let probe = Command::new(path)
        .arg("--gus-shim-probe")
        .output()
        .map_err(|error| format!("cannot probe {}: {error}", path.display()))?;
    if !probe.status.success() || probe.stdout != b"gus-git-shim-v1\n" || !probe.stderr.is_empty() {
        return Err(format!("{} is not a GUS Git shim", path.display()));
    }
    let output = Command::new(path)
        .arg("--version")
        .output()
        .map_err(|error| format!("cannot probe {}: {error}", path.display()))?;
    if output.status.success() && output.stdout.starts_with(b"git version ") {
        Ok(())
    } else {
        Err(format!(
            "{} did not forward a valid Git version",
            path.display()
        ))
    }
}

#[cfg(unix)]
fn active_shim_paths() -> Result<(PathBuf, PathBuf, PathBuf), String> {
    let path = executable_path_entries()?;
    let index = first_git_index(&path).ok_or_else(|| "Git is not present on PATH".to_owned())?;
    let shim = git_path(&path[index]);
    let owner = path[index].join(OWNER_FILE);
    validate_target_directory(&path[index])?;
    Ok((path[index].clone(), shim, owner))
}

#[cfg(unix)]
fn validate_owned_shim(shim: &Path, owner: &Path) -> Result<(), String> {
    if !owner.is_file() {
        return Err(format!(
            "the active Git at {} is not owned by GUS",
            shim.display()
        ));
    }
    let expected = read_owner_digest(owner)?;
    let actual = secure_file_digest(shim)?;
    if expected != actual {
        return Err(format!(
            "the active GUS shim at {} was modified",
            shim.display()
        ));
    }
    Ok(())
}

fn doctor() -> Result<(), String> {
    #[cfg(not(unix))]
    return Err("doctor is not implemented on this platform yet".to_owned());

    #[cfg(unix)]
    {
        let (target, shim, owner) = active_shim_paths()?;
        let directory = open_target_directory(&target)?;
        let _lock = acquire_install_lock(&target)?;
        recover_interrupted_update(&target, &shim, &owner, &directory)?;
        validate_owned_shim(&shim, &owner)?;
        verify_installed_shim(&shim)?;
        println!("GUS Git shim is active and verified: {}", shim.display());
        Ok(())
    }
}

fn uninstall() -> Result<(), String> {
    #[cfg(not(unix))]
    return Err("uninstall is not implemented on this platform yet".to_owned());

    #[cfg(unix)]
    {
        let (target, shim, owner) = active_shim_paths()?;
        let directory = open_target_directory(&target)?;
        let _lock = acquire_install_lock(&target)?;
        recover_interrupted_update(&target, &shim, &owner, &directory)?;
        validate_owned_shim(&shim, &owner)?;
        verify_installed_shim(&shim)?;
        fs::remove_file(&shim)
            .and_then(|()| directory.sync_all())
            .map_err(|error| format!("cannot remove {}: {error}", shim.display()))?;
        fs::remove_file(&owner)
            .and_then(|()| directory.sync_all())
            .map_err(|error| format!("cannot remove {}: {error}", owner.display()))?;
        println!("Removed GUS Git shim: {}", shim.display());
        println!("Open a new shell or restart the IDE if it cached the removed Git path");
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn no_replace_publish_preserves_a_colliding_file() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let staged = directory.path().join("staged");
        let destination = directory.path().join("destination");
        fs::write(&staged, b"gus").expect("write staged file");
        fs::write(&destination, b"third party").expect("write collision");

        assert!(publish_no_replace(&staged, &destination).is_err());
        assert_eq!(
            fs::read(&destination).expect("read collision"),
            b"third party"
        );
        assert_eq!(fs::read(&staged).expect("read staged"), b"gus");
    }

    #[test]
    fn profile_commands_round_trip_without_manual_file_editing() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("gus/profiles.toml");

        user_add(
            &path,
            "work".to_owned(),
            "Work User".to_owned(),
            "work@example.test".to_owned(),
        )
        .expect("add profile");
        let profiles = read_profile_store(&path).expect("read added profile");
        assert_eq!(profiles.generation, 2);
        let profile = profiles
            .profiles
            .get(&ProfileId::try_from("work".to_owned()).expect("profile id"))
            .expect("stored profile");
        assert_eq!(profile.author.name(), "Work User");
        assert_eq!(profile.committer.email(), "work@example.test");
        assert_eq!(
            fs::metadata(&path).expect("profile metadata").mode() & 0o777,
            0o600
        );

        assert!(
            user_add(
                &path,
                "work".to_owned(),
                "Other User".to_owned(),
                "other@example.test".to_owned(),
            )
            .is_err()
        );
        user_remove(&path, "work".to_owned()).expect("remove profile");
        let profiles = read_profile_store(&path).expect("read removed profile");
        assert_eq!(profiles.generation, 3);
        assert!(profiles.profiles.is_empty());
        assert!(user_remove(&path, "work".to_owned()).is_err());
    }

    #[test]
    fn profile_add_validates_identity_before_creating_the_store() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("gus/profiles.toml");
        assert!(
            user_add(
                &path,
                "bad id".to_owned(),
                "Work User".to_owned(),
                "work@example.test".to_owned(),
            )
            .is_err()
        );
        assert!(!path.exists());
        assert!(
            user_add(
                &path,
                "work".to_owned(),
                "Work User".to_owned(),
                "invalid-email".to_owned(),
            )
            .is_err()
        );
        assert!(!path.exists());
    }
}
