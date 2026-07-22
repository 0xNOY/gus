use sha2::{Digest as _, Sha256};
use std::{
    env,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

const OWNER_FILE: &str = ".gus-git-shim-owner-v1";

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
        return Err("usage: gus <setup|doctor|uninstall-shim>".to_owned());
    };
    match command {
        "setup" => setup(&arguments[1..]),
        "doctor" if arguments.len() == 1 => doctor(),
        "uninstall-shim" if arguments.len() == 1 => uninstall(),
        _ => Err(
            "usage: gus <setup [--dry-run] [--target-dir PATH]|doctor|uninstall-shim>".to_owned(),
        ),
    }
}

fn setup(arguments: &[OsString]) -> Result<(), String> {
    #[cfg(not(unix))]
    return Err("setup is not implemented on this platform yet".to_owned());

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

        println!("GUS shim source: {}", source.display());
        println!("Install target: {}", destination.display());
        if dry_run {
            println!("Dry run: no files were changed");
            return Ok(());
        }

        let installed = install_new_shim(&source, &destination, &owner)?;
        if let Err(error) = verify_installed_shim(&destination) {
            if installed && is_owned_shim(&destination, &owner) {
                let _ = fs::remove_file(&destination);
                let _ = fs::remove_file(&owner);
            }
            return Err(error);
        }
        println!("GUS Git shim installed and verified");
        println!("Open a new shell or restart the IDE if it cached the previous Git path");
        Ok(())
    }
}

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
        let canonical = fs::canonicalize(&entry)
            .map_err(|error| format!("cannot resolve PATH entry {}: {error}", entry.display()))?;
        if !entries.contains(&canonical) {
            entries.push(canonical);
        }
    }
    Ok(entries)
}

fn first_git_index(path: &[PathBuf]) -> Option<usize> {
    path.iter()
        .position(|directory| git_path(directory).is_file())
}

fn first_unowned_git_index(path: &[PathBuf]) -> Option<usize> {
    path.iter().position(|directory| {
        let git = git_path(directory);
        git.is_file() && !is_owned_shim(&git, &directory.join(OWNER_FILE))
    })
}

fn is_owned_shim(shim: &Path, owner: &Path) -> bool {
    owner.is_file()
        && read_owner_digest(owner)
            .and_then(|expected| file_digest(shim).map(|actual| expected == actual))
            .unwrap_or(false)
}

fn git_path(directory: &Path) -> PathBuf {
    #[cfg(windows)]
    let name = "git.exe";
    #[cfg(not(windows))]
    let name = "git";
    directory.join(name)
}

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
fn install_new_shim(source: &Path, destination: &Path, owner: &Path) -> Result<bool, String> {
    let digest = file_digest(source)?;
    if !destination.exists() && owner.is_file() && read_owner_digest(owner)? == digest {
        fs::remove_file(owner)
            .map_err(|error| format!("cannot recover {}: {error}", owner.display()))?;
    }
    if destination.exists() || owner.exists() {
        if destination.is_file()
            && owner.is_file()
            && read_owner_digest(owner)? == digest
            && file_digest(destination)? == digest
        {
            return Ok(false);
        }
        return Err(format!(
            "refusing to overwrite existing {} or ownership metadata",
            destination.display()
        ));
    }

    let process = std::process::id();
    let staged_shim = destination.with_file_name(format!(".gus-git-shim-{process}.tmp"));
    let staged_owner = owner.with_file_name(format!(".gus-owner-{process}.tmp"));
    let result = (|| {
        copy_executable(source, &staged_shim)?;
        write_new_file(
            &staged_owner,
            format!("sha256={digest}\n").as_bytes(),
            0o600,
        )?;
        fs::rename(&staged_owner, owner)
            .map_err(|error| format!("cannot publish {}: {error}", owner.display()))?;
        if let Err(error) = fs::rename(&staged_shim, destination) {
            let _ = fs::remove_file(owner);
            return Err(format!("cannot publish {}: {error}", destination.display()));
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&staged_shim);
        let _ = fs::remove_file(&staged_owner);
    }
    result.map(|()| true)
}

#[cfg(unix)]
fn copy_executable(source: &Path, destination: &Path) -> Result<(), String> {
    let mut input =
        File::open(source).map_err(|error| format!("cannot open {}: {error}", source.display()))?;
    let mut output = new_file(destination, 0o700)?;
    std::io::copy(&mut input, &mut output)
        .and_then(|_| output.sync_all())
        .map_err(|error| format!("cannot stage {}: {error}", destination.display()))?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o755))
        .and_then(|()| output.sync_all())
        .map_err(|error| format!("cannot make {} executable: {error}", destination.display()))
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

fn file_digest(path: &Path) -> Result<String, String> {
    let mut file =
        File::open(path).map_err(|error| format!("cannot open {}: {error}", path.display()))?;
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

fn read_owner_digest(path: &Path) -> Result<String, String> {
    let text = fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    text.strip_prefix("sha256=")
        .and_then(|value| value.strip_suffix('\n'))
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .map(str::to_owned)
        .ok_or_else(|| format!("{} is not valid GUS ownership metadata", path.display()))
}

fn verify_installed_shim(path: &Path) -> Result<(), String> {
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

fn active_owned_shim() -> Result<(PathBuf, PathBuf), String> {
    let path = executable_path_entries()?;
    let index = first_git_index(&path).ok_or_else(|| "Git is not present on PATH".to_owned())?;
    let shim = git_path(&path[index]);
    let owner = path[index].join(OWNER_FILE);
    if !owner.is_file() {
        return Err(format!(
            "the active Git at {} is not owned by GUS",
            shim.display()
        ));
    }
    let expected = read_owner_digest(&owner)?;
    let actual = file_digest(&shim)?;
    if expected != actual {
        return Err(format!(
            "the active GUS shim at {} was modified",
            shim.display()
        ));
    }
    Ok((shim, owner))
}

fn doctor() -> Result<(), String> {
    let (shim, _) = active_owned_shim()?;
    verify_installed_shim(&shim)?;
    println!("GUS Git shim is active and verified: {}", shim.display());
    Ok(())
}

fn uninstall() -> Result<(), String> {
    let (shim, owner) = active_owned_shim()?;
    fs::remove_file(&shim).map_err(|error| format!("cannot remove {}: {error}", shim.display()))?;
    fs::remove_file(&owner)
        .map_err(|error| format!("cannot remove {}: {error}", owner.display()))?;
    println!("Removed GUS Git shim: {}", shim.display());
    println!("Open a new shell or restart the IDE if it cached the removed Git path");
    Ok(())
}
