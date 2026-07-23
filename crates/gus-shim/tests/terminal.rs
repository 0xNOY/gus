#![cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]

use std::{
    ffi::CStr,
    fs,
    io::{Read as _, Write as _},
    os::{
        fd::{AsRawFd as _, FromRawFd as _, OwnedFd},
        unix::{fs::PermissionsExt as _, process::CommandExt as _},
    },
    path::Path,
    process::{Command, Stdio},
    thread,
};

fn shim() -> Command {
    Command::new(env!("CARGO_BIN_EXE_gus-git-shim"))
}

fn system_git() -> Command {
    #[cfg(target_os = "linux")]
    let path = "/usr/bin/git";
    #[cfg(target_os = "macos")]
    let path = "/usr/bin/git";
    #[cfg(target_os = "freebsd")]
    let path = "/usr/local/bin/git";
    Command::new(path)
}

fn initialize_repository(path: &Path) {
    let output = system_git()
        .args(["init", "--quiet"])
        .current_dir(path)
        .output()
        .expect("initialize repository");
    assert!(
        output.status.success(),
        "git init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn write_unsigned_profile_store(path: &Path) {
    fs::write(
        path,
        r#"
version = 2
generation = 1

[profiles.work]
id = "work"
generation = 1

[profiles.work.author]
name = "Selected Author"
email = "selected-author@example.test"

[profiles.work.committer]
name = "Selected Committer"
email = "selected-committer@example.test"
"#,
    )
    .expect("write profile store");
}

fn write_two_profile_store(path: &Path) {
    fs::write(
        path,
        r#"
version = 2
generation = 1

[profiles.personal]
id = "personal"
generation = 1

[profiles.personal.author]
name = "Personal Author"
email = "personal@example.test"

[profiles.personal.committer]
name = "Personal Committer"
email = "personal@example.test"

[profiles.work]
id = "work"
generation = 1

[profiles.work.author]
name = "Work Author"
email = "work@example.test"

[profiles.work.committer]
name = "Work Committer"
email = "work@example.test"
"#,
    )
    .expect("write two-profile store");
}

fn stage(path: &Path, name: &str, contents: &[u8]) {
    fs::write(path.join(name), contents).expect("write commit fixture");
    let add = system_git()
        .args(["add", name])
        .current_dir(path)
        .output()
        .expect("stage commit fixture");
    assert!(add.status.success());
}

fn run_commit_in_new_terminal(
    repository: &Path,
    store: &Path,
    runtime: &Path,
    selection: &str,
    message: &str,
) {
    let mut master = 0;
    let mut slave = 0;
    // SAFETY: both output pointers are valid and no optional termios/winsize is supplied.
    let result = unsafe {
        libc::openpty(
            &raw mut master,
            &raw mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(
        result,
        0,
        "openpty failed: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: `openpty` initialized both descriptors on success, transferring ownership here.
    let mut master = unsafe { fs::File::from_raw_fd(master) };
    // SAFETY: see above.
    let slave = unsafe { OwnedFd::from_raw_fd(slave) };
    let mut name = [0_i8; 256];
    // SAFETY: the slave descriptor is live and `name` is a writable bounded buffer.
    let tty_result = unsafe { libc::ttyname_r(slave.as_raw_fd(), name.as_mut_ptr(), name.len()) };
    assert_eq!(tty_result, 0, "ttyname_r failed with {tty_result}");
    // SAFETY: successful `ttyname_r` wrote a NUL-terminated string into `name`.
    let slave_path = unsafe { CStr::from_ptr(name.as_ptr()) }
        .to_str()
        .expect("PTY path is UTF-8")
        .to_owned();

    let mut child = Command::new(std::env::current_exe().expect("resolve test executable"))
        .args(["--ignored", "--exact", "pty_commit_child"])
        .env("GUS_TEST_PTY", slave_path)
        .env("GUS_TEST_MESSAGE", message)
        .env("GUS_PROFILE_STORE", store)
        .env("GUS_RUNTIME_DIR", runtime)
        .current_dir(repository)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn PTY child");
    drop(slave);
    writeln!(master, "{selection}").expect("send profile selection");
    let reader = thread::spawn(move || {
        let mut transcript = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            match master.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => transcript.extend_from_slice(&chunk[..read]),
                Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
                Err(error) => panic!("read PTY transcript: {error}"),
            }
        }
        transcript
    });
    let status = child.wait().expect("wait for PTY child");
    let transcript = reader.join().expect("PTY transcript reader");
    assert!(
        status.success(),
        "PTY commit failed with {status}: {}",
        String::from_utf8_lossy(&transcript)
    );
}

#[test]
#[ignore = "internal child process for PTY session tests"]
fn pty_commit_child() {
    let slave_path = std::env::var("GUS_TEST_PTY").expect("PTY path");
    let message = std::env::var("GUS_TEST_MESSAGE").expect("commit message");
    // SAFETY: `setsid` has no pointer arguments; this helper is a fresh child process.
    assert_ne!(unsafe { libc::setsid() }, -1, "setsid failed");
    let slave = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(slave_path)
        .expect("open PTY slave as controlling terminal");
    // SAFETY: this fresh process is a session leader without a controlling
    // terminal, and `slave` is a live terminal descriptor.
    assert_ne!(
        unsafe { libc::ioctl(slave.as_raw_fd(), libc::c_ulong::from(libc::TIOCSCTTY), 0,) },
        -1,
        "TIOCSCTTY failed: {}",
        std::io::Error::last_os_error()
    );
    for descriptor in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // SAFETY: the source descriptor is live and each target is a standard descriptor.
        assert_ne!(unsafe { libc::dup2(slave.as_raw_fd(), descriptor) }, -1);
    }
    let error = shim().args(["commit", "--quiet", "-m", &message]).exec();
    panic!("exec shim failed: {error}");
}

#[test]
fn separate_terminal_sessions_select_independent_profiles_for_one_repository() {
    let repository = tempfile::tempdir().expect("temporary repository");
    let runtime = tempfile::tempdir().expect("temporary runtime directory");
    fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o700))
        .expect("make runtime directory private");
    initialize_repository(repository.path());
    let store = repository.path().join("profiles.toml");
    write_two_profile_store(&store);

    stage(repository.path(), "work.txt", b"work\n");
    run_commit_in_new_terminal(
        repository.path(),
        &store,
        runtime.path(),
        "2",
        "work session",
    );

    stage(repository.path(), "personal.txt", b"personal\n");
    run_commit_in_new_terminal(
        repository.path(),
        &store,
        runtime.path(),
        "1",
        "personal session",
    );

    let identities = system_git()
        .args(["log", "-2", "--format=%an <%ae>"])
        .current_dir(repository.path())
        .output()
        .expect("inspect identities from both sessions");
    assert!(identities.status.success());
    assert_eq!(
        identities.stdout,
        b"Personal Author <personal@example.test>\nWork Author <work@example.test>\n"
    );
    let selection_count = fs::read_dir(runtime.path().join("gus-selections"))
        .expect("read session selections")
        .count();
    assert_eq!(
        selection_count, 2,
        "each terminal must have its own selection"
    );
}

#[test]
fn version_is_forwarded_by_the_real_git_image() {
    let expected = system_git()
        .arg("--version")
        .output()
        .expect("run system Git version");
    let actual = shim().arg("--version").output().expect("run GUS Git shim");

    assert_eq!(actual.status, expected.status);
    assert_eq!(actual.stdout, expected.stdout);
    assert_eq!(actual.stderr, expected.stderr);
}

#[test]
fn private_probe_identifies_the_gus_shim() {
    let output = shim()
        .arg("--gus-shim-probe")
        .output()
        .expect("probe GUS Git shim");
    assert!(output.status.success());
    assert_eq!(output.stdout, b"gus-git-shim-v1\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn status_preserves_porcelain_output_without_profile_selection() {
    let repository = tempfile::tempdir().expect("temporary repository");
    initialize_repository(repository.path());
    fs::write(repository.path().join("untracked.txt"), b"fixture\n")
        .expect("write untracked fixture");

    let output = shim()
        .args(["status", "--porcelain=v1"])
        .current_dir(repository.path())
        .output()
        .expect("run status through shim");

    assert!(
        output.status.success(),
        "shim status failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"?? untracked.txt\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn commit_without_a_selected_profile_fails_before_git_starts() {
    let repository = tempfile::tempdir().expect("temporary repository");
    initialize_repository(repository.path());
    fs::write(repository.path().join("tracked.txt"), b"fixture\n").expect("write commit fixture");
    let add = system_git()
        .args(["add", "tracked.txt"])
        .current_dir(repository.path())
        .output()
        .expect("stage commit fixture");
    assert!(add.status.success());

    let trace = repository.path().join("must-not-start.trace2");
    let rejected = shim()
        .args(["commit", "-m", "must-not-exist"])
        .env("GIT_TRACE2_EVENT", &trace)
        .current_dir(repository.path())
        .output()
        .expect("run protected commit through shim");
    assert_eq!(rejected.status.code(), Some(125));
    assert!(rejected.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("author identity"),
        "unexpected rejection: {}",
        String::from_utf8_lossy(&rejected.stderr)
    );
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("Git was not started"),
        "rejection must state the execution outcome"
    );
    assert!(!trace.exists(), "real Git emitted trace2 before rejection");

    let head = system_git()
        .args(["rev-parse", "--verify", "HEAD"])
        .current_dir(repository.path())
        .output()
        .expect("verify commit absence");
    assert!(
        !head.status.success(),
        "rejected commit unexpectedly created HEAD"
    );
}

#[test]
fn explicit_profile_commit_uses_only_the_selected_identity() {
    let repository = tempfile::tempdir().expect("temporary repository");
    initialize_repository(repository.path());
    fs::write(repository.path().join("tracked.txt"), b"fixture\n").expect("write commit fixture");
    let add = system_git()
        .args(["add", "tracked.txt"])
        .current_dir(repository.path())
        .output()
        .expect("stage commit fixture");
    assert!(add.status.success());

    let store = repository.path().join("profiles.toml");
    write_unsigned_profile_store(&store);
    let signing_config = system_git()
        .args(["config", "--local", "commit.gpgSign", "true"])
        .current_dir(repository.path())
        .output()
        .expect("configure hostile ambient signing policy");
    assert!(signing_config.status.success());
    let signing_program = system_git()
        .args(["config", "--local", "gpg.program", "/usr/bin/false"])
        .current_dir(repository.path())
        .output()
        .expect("configure failing ambient signer");
    assert!(signing_program.status.success());
    let hook = repository.path().join(".git/hooks/pre-commit");
    fs::write(
        &hook,
        b"#!/bin/sh\ntest -z \"${GUS_PROFILE_ID+x}\" && test -z \"${GUS_PROFILE_STORE+x}\"\n",
    )
    .expect("write environment-checking hook");
    let mut permissions = fs::metadata(&hook)
        .expect("read hook metadata")
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&hook, permissions).expect("make hook executable");

    let commit = shim()
        .args(["commit", "--quiet", "-m", "selected identity"])
        .env("GUS_PROFILE_ID", "work")
        .env("GUS_PROFILE_STORE", &store)
        .env("GIT_AUTHOR_NAME", "Wrong Ambient Author")
        .env("GIT_AUTHOR_EMAIL", "wrong-author@example.test")
        .env("GIT_COMMITTER_NAME", "Wrong Ambient Committer")
        .env("GIT_COMMITTER_EMAIL", "wrong-committer@example.test")
        .current_dir(repository.path())
        .output()
        .expect("commit through selected profile");
    assert!(
        commit.status.success(),
        "profiled commit failed: {}",
        String::from_utf8_lossy(&commit.stderr)
    );

    let identity = system_git()
        .args(["show", "-s", "--format=%an <%ae>%n%cn <%ce>", "HEAD"])
        .current_dir(repository.path())
        .output()
        .expect("inspect committed identity");
    assert!(identity.status.success());
    assert_eq!(
        identity.stdout,
        b"Selected Author <selected-author@example.test>\nSelected Committer <selected-committer@example.test>\n"
    );
}

#[test]
fn explicit_profile_rejects_author_override_before_git_starts() {
    let repository = tempfile::tempdir().expect("temporary repository");
    initialize_repository(repository.path());
    fs::write(repository.path().join("tracked.txt"), b"fixture\n").expect("write commit fixture");
    let add = system_git()
        .args(["add", "tracked.txt"])
        .current_dir(repository.path())
        .output()
        .expect("stage commit fixture");
    assert!(add.status.success());
    let store = repository.path().join("profiles.toml");
    write_unsigned_profile_store(&store);
    let trace = repository.path().join("must-not-start.trace2");

    let rejected = shim()
        .args([
            "commit",
            "--auth=Bypass Author <bypass@example.test>",
            "-m",
            "must not exist",
        ])
        .env("GUS_PROFILE_ID", "work")
        .env("GUS_PROFILE_STORE", &store)
        .env("GIT_TRACE2_EVENT", &trace)
        .current_dir(repository.path())
        .output()
        .expect("reject author override");
    assert_eq!(rejected.status.code(), Some(125));
    assert!(rejected.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("plain unsigned commit"),
        "unexpected rejection: {}",
        String::from_utf8_lossy(&rejected.stderr)
    );
    assert!(
        !trace.exists(),
        "real Git started before override rejection"
    );
    let head = system_git()
        .args(["rev-parse", "--verify", "HEAD"])
        .current_dir(repository.path())
        .output()
        .expect("verify commit absence");
    assert!(!head.status.success());
}

#[test]
fn explicit_profile_rejects_signing_flag_before_git_starts() {
    let repository = tempfile::tempdir().expect("temporary repository");
    initialize_repository(repository.path());
    fs::write(repository.path().join("tracked.txt"), b"fixture\n").expect("write commit fixture");
    let add = system_git()
        .args(["add", "tracked.txt"])
        .current_dir(repository.path())
        .output()
        .expect("stage commit fixture");
    assert!(add.status.success());
    let store = repository.path().join("profiles.toml");
    write_unsigned_profile_store(&store);
    let trace = repository.path().join("must-not-sign.trace2");

    let rejected = shim()
        .args(["commit", "-S", "-m", "must not exist"])
        .env("GUS_PROFILE_ID", "work")
        .env("GUS_PROFILE_STORE", &store)
        .env("GIT_TRACE2_EVENT", &trace)
        .current_dir(repository.path())
        .output()
        .expect("reject signing override");
    assert_eq!(rejected.status.code(), Some(125));
    assert!(rejected.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("plain unsigned commit"),
        "unexpected rejection: {}",
        String::from_utf8_lossy(&rejected.stderr)
    );
    assert!(!trace.exists(), "real Git started before signing rejection");
    let head = system_git()
        .args(["rev-parse", "--verify", "HEAD"])
        .current_dir(repository.path())
        .output()
        .expect("verify commit absence");
    assert!(!head.status.success());
}

#[test]
fn identity_free_checkout_uses_the_neutral_reflog_identity() {
    let repository = tempfile::tempdir().expect("temporary repository");
    initialize_repository(repository.path());
    fs::write(repository.path().join("tracked.txt"), b"base\n").expect("write base fixture");
    let add = system_git()
        .args(["add", "tracked.txt"])
        .current_dir(repository.path())
        .output()
        .expect("stage base fixture");
    assert!(add.status.success());
    let commit = system_git()
        .args(["commit", "--quiet", "-m", "base"])
        .env("GIT_AUTHOR_NAME", "Fixture Author")
        .env("GIT_AUTHOR_EMAIL", "fixture-author@example.test")
        .env("GIT_COMMITTER_NAME", "Fixture Committer")
        .env("GIT_COMMITTER_EMAIL", "fixture-committer@example.test")
        .current_dir(repository.path())
        .output()
        .expect("create base commit");
    assert!(
        commit.status.success(),
        "base commit failed: {}",
        String::from_utf8_lossy(&commit.stderr)
    );

    let checkout = shim()
        .args(["checkout", "-b", "neutral-reflog"])
        .env("GIT_AUTHOR_NAME", "Wrong Ambient Author")
        .env("GIT_AUTHOR_EMAIL", "wrong-author@example.test")
        .env("GIT_COMMITTER_NAME", "Wrong Ambient Committer")
        .env("GIT_COMMITTER_EMAIL", "wrong-committer@example.test")
        .current_dir(repository.path())
        .output()
        .expect("checkout through shim");
    assert!(
        checkout.status.success(),
        "checkout failed: {}",
        String::from_utf8_lossy(&checkout.stderr)
    );

    let reflog = system_git()
        .args(["reflog", "-1", "--format=%gn <%ge>"])
        .current_dir(repository.path())
        .output()
        .expect("read HEAD reflog identity");
    assert!(reflog.status.success());
    assert_eq!(reflog.stdout, b"GUS Reflog <reflog@gus.invalid>\n");
}
