#![cfg(any(target_os = "linux", target_os = "freebsd"))]

use std::{fs, path::Path, process::Command};

fn shim() -> Command {
    Command::new(env!("CARGO_BIN_EXE_git"))
}

fn system_git() -> Command {
    #[cfg(target_os = "linux")]
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
