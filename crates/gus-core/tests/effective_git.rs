use std::{fs, path::Path, process::Command};

use gus_core::{
    EffectiveConfigEntry, EndpointObservation, EndpointRole, GitResolver, InvocationContext,
    NEUTRAL_REFLOG_EMAIL, NEUTRAL_REFLOG_NAME, ProfileRequirement, RequirementReason,
    ResolverSnapshot, SnapshotGenerations, Transport, VerifiedGitSemantics,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

fn git(repo: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .current_dir(repo)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_CONFIG_GLOBAL")
        .env_remove("GIT_AUTHOR_NAME")
        .env_remove("GIT_AUTHOR_EMAIL")
        .env_remove("GIT_COMMITTER_NAME")
        .env_remove("GIT_COMMITTER_EMAIL")
        .output()
        .expect("test fixture requires Git")
}

fn success(repo: &Path, args: &[&str]) -> std::process::Output {
    let output = git(repo, args);
    assert!(
        output.status.success(),
        "git {args:?} failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn neutral_success(repo: &Path, args: &[&str]) -> std::process::Output {
    let output = Command::new("git")
        .current_dir(repo)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_CONFIG_GLOBAL")
        .env_remove("EMAIL")
        .env("GIT_AUTHOR_NAME", NEUTRAL_REFLOG_NAME)
        .env("GIT_AUTHOR_EMAIL", NEUTRAL_REFLOG_EMAIL)
        .env("GIT_COMMITTER_NAME", NEUTRAL_REFLOG_NAME)
        .env("GIT_COMMITTER_EMAIL", NEUTRAL_REFLOG_EMAIL)
        .output()
        .expect("test fixture requires Git");
    assert!(
        output.status.success(),
        "neutral git {args:?} failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn digest(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

fn effective_entries(repo: &Path, names: &[&str]) -> Vec<EffectiveConfigEntry> {
    let mut entries = Vec::new();
    for name in names {
        let output = git(repo, &["config", "--null", "--get-all", name]);
        if output.status.code() == Some(1) {
            continue;
        }
        assert!(output.status.success(), "failed to read config {name}");
        for value in output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|v| !v.is_empty())
        {
            entries.push(EffectiveConfigEntry::new(
                (*name).to_owned(),
                String::from_utf8(value.to_vec())
                    .expect("ASCII integration fixture")
                    .into(),
            ));
        }
    }
    entries
}

fn resolved_requirement(
    repo: &Path,
    args: &[&str],
    config_names: &[&str],
    endpoints: Vec<EndpointObservation>,
) -> ProfileRequirement {
    let git_dir = fs::canonicalize(repo.join(".git")).expect("canonical Git directory");
    let branch = success(repo, &["symbolic-ref", "--quiet", "--short", "HEAD"]);
    let branch = String::from_utf8(branch.stdout)
        .expect("ASCII fixture branch")
        .trim()
        .to_owned();
    let head = success(repo, &["rev-parse", "HEAD"]);
    let head_state = digest(&[branch.as_bytes(), head.stdout.as_slice()].concat());
    let git_version = success(repo, &["--version"]);
    let git_version = String::from_utf8(git_version.stdout).expect("UTF-8 Git version");
    let git_semantics = VerifiedGitSemantics::from_version_output(
        digest(b"real Git executable selected by integration fixture"),
        &git_version,
    )
    .expect("supported or conservative real-Git semantics");
    let snapshot = ResolverSnapshot::new(
        digest(git_dir.as_os_str().as_encoded_bytes()),
        git_semantics,
        Some(head_state),
        SnapshotGenerations::new(1, 1).expect("valid fixture generations"),
        Some(branch),
        effective_entries(repo, config_names),
        endpoints,
    )
    .expect("valid real-Git snapshot");
    GitResolver
        .resolve(InvocationContext::parse(args), snapshot)
        .expect("snapshot matches invocation")
        .profile_requirement()
}

fn local_fetch_endpoint() -> Vec<EndpointObservation> {
    vec![EndpointObservation::new(
        EndpointRole::Fetch,
        Transport::Local,
        [7; 32],
    )]
}

fn repository() -> TempDir {
    let directory = tempfile::tempdir().expect("temporary repository");
    success(directory.path(), &["init", "--initial-branch=main"]);
    success(directory.path(), &["config", "user.name", "Wrong Ambient"]);
    success(
        directory.path(),
        &["config", "user.email", "wrong@example.test"],
    );
    fs::write(directory.path().join("tracked"), "base\n").expect("write base file");
    success(directory.path(), &["add", "tracked"]);
    success(directory.path(), &["commit", "-m", "base"]);
    directory
}

fn pull_fixture() -> (TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().expect("temporary pull fixture");
    let remote = directory.path().join("remote.git");
    let producer = directory.path().join("producer");
    let consumer = directory.path().join("consumer");
    fs::create_dir(&producer).expect("producer directory");
    success(
        directory.path(),
        &[
            "init",
            "--bare",
            "--initial-branch=main",
            remote.to_str().expect("UTF-8 fixture path"),
        ],
    );
    success(&producer, &["init", "--initial-branch=main"]);
    success(&producer, &["config", "user.name", "Producer"]);
    success(
        &producer,
        &["config", "user.email", "producer@example.test"],
    );
    fs::write(producer.join("tracked"), "base\n").expect("base file");
    success(&producer, &["add", "tracked"]);
    success(&producer, &["commit", "-m", "base"]);
    success(
        &producer,
        &[
            "remote",
            "add",
            "origin",
            remote.to_str().expect("UTF-8 fixture path"),
        ],
    );
    success(&producer, &["push", "-u", "origin", "main"]);
    success(
        directory.path(),
        &[
            "clone",
            remote.to_str().expect("UTF-8 fixture path"),
            consumer.to_str().expect("UTF-8 fixture path"),
        ],
    );
    success(&consumer, &["config", "user.name", "Wrong Ambient"]);
    success(&consumer, &["config", "user.email", "wrong@example.test"]);
    fs::write(producer.join("tracked"), "remote\n").expect("remote update");
    success(&producer, &["commit", "-am", "remote update"]);
    success(&producer, &["push"]);
    fs::write(consumer.join("tracked"), "local\n").expect("dirty consumer");
    (directory, consumer)
}

fn created_autostash_oid(output: &std::process::Output) -> String {
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    combined
        .lines()
        .find_map(|line| line.trim().strip_prefix("Created autostash: "))
        .map_or_else(
            || panic!("Git did not report an autostash:\n{combined}"),
            str::to_owned,
        )
}

#[test]
fn effective_merge_autostash_can_create_an_ambient_identity_commit() {
    let directory = repository();
    let repo = directory.path();
    success(repo, &["switch", "-c", "topic"]);
    fs::write(repo.join("tracked"), "topic\n").expect("write topic file");
    success(repo, &["commit", "-am", "topic"]);
    success(repo, &["switch", "main"]);
    fs::write(repo.join("tracked"), "local\n").expect("write dirty file");
    success(repo, &["config", "merge.autoStash", "true"]);

    assert_eq!(
        resolved_requirement(
            repo,
            &["merge", "--ff-only", "topic"],
            &["merge.autoStash", "branch.main.mergeOptions"],
            Vec::new(),
        ),
        ProfileRequirement::Required(RequirementReason::AuthorIdentity)
    );

    let merge = git(repo, &["merge", "--ff-only", "topic"]);
    let oid = created_autostash_oid(&merge);
    let author = success(repo, &["show", "-s", "--format=%an <%ae>", &oid]);
    assert_eq!(
        String::from_utf8_lossy(&author.stdout).trim(),
        "Wrong Ambient <wrong@example.test>"
    );
}

#[test]
fn branch_merge_options_can_enable_autostash_when_global_config_disables_it() {
    let directory = repository();
    let repo = directory.path();
    success(repo, &["switch", "-c", "topic"]);
    fs::write(repo.join("tracked"), "topic\n").expect("write topic file");
    success(repo, &["commit", "-am", "topic"]);
    success(repo, &["switch", "main"]);
    fs::write(repo.join("tracked"), "local\n").expect("write dirty file");
    success(repo, &["config", "merge.autoStash", "false"]);
    success(repo, &["config", "branch.main.mergeOptions", "--autostash"]);

    assert_eq!(
        resolved_requirement(
            repo,
            &["merge", "--ff-only", "topic"],
            &["merge.autoStash", "branch.main.mergeOptions"],
            Vec::new(),
        ),
        ProfileRequirement::Required(RequirementReason::AuthorIdentity)
    );

    let merge = git(repo, &["merge", "--ff-only", "topic"]);
    let oid = created_autostash_oid(&merge);
    let author = success(repo, &["show", "-s", "--format=%an <%ae>", &oid]);
    assert_eq!(
        String::from_utf8_lossy(&author.stdout).trim(),
        "Wrong Ambient <wrong@example.test>"
    );
}

#[test]
fn pull_autostash_overrides_merge_autostash_and_creates_an_ambient_commit() {
    let (_directory, consumer) = pull_fixture();
    success(&consumer, &["config", "merge.autoStash", "false"]);
    success(&consumer, &["config", "pull.autoStash", "true"]);
    success(&consumer, &["config", "pull.rebase", "false"]);

    assert_eq!(
        resolved_requirement(
            &consumer,
            &["pull", "--ff-only"],
            &[
                "merge.autoStash",
                "pull.autoStash",
                "pull.rebase",
                "branch.main.rebase",
                "rebase.autoStash",
                "branch.main.mergeOptions",
            ],
            local_fetch_endpoint(),
        ),
        ProfileRequirement::Required(RequirementReason::AuthorIdentity)
    );

    let pull = git(&consumer, &["pull", "--ff-only"]);
    let oid = created_autostash_oid(&pull);
    let author = success(&consumer, &["show", "-s", "--format=%an <%ae>", &oid]);
    assert_eq!(
        String::from_utf8_lossy(&author.stdout).trim(),
        "Wrong Ambient <wrong@example.test>"
    );
}

#[test]
fn pull_rebase_autostash_can_create_an_ambient_commit_for_ff_only_pull() {
    let (_directory, consumer) = pull_fixture();
    success(&consumer, &["config", "merge.autoStash", "false"]);
    success(&consumer, &["config", "pull.rebase", "true"]);
    success(&consumer, &["config", "rebase.autoStash", "true"]);

    assert_eq!(
        resolved_requirement(
            &consumer,
            &["pull", "--ff-only"],
            &[
                "merge.autoStash",
                "pull.autoStash",
                "pull.rebase",
                "branch.main.rebase",
                "rebase.autoStash",
                "branch.main.mergeOptions",
            ],
            local_fetch_endpoint(),
        ),
        ProfileRequirement::Required(RequirementReason::AuthorIdentity)
    );

    let pull = git(&consumer, &["pull", "--ff-only"]);
    let oid = created_autostash_oid(&pull);
    let author = success(&consumer, &["show", "-s", "--format=%an <%ae>", &oid]);
    assert_eq!(
        String::from_utf8_lossy(&author.stdout).trim(),
        "Wrong Ambient <wrong@example.test>"
    );
}

#[test]
fn pull_no_rebase_cli_override_selects_merge_autostash() {
    let (_directory, consumer) = pull_fixture();
    success(&consumer, &["config", "pull.rebase", "true"]);
    success(&consumer, &["config", "rebase.autoStash", "false"]);
    success(&consumer, &["config", "merge.autoStash", "true"]);

    assert_eq!(
        resolved_requirement(
            &consumer,
            &["pull", "--ff-only", "--no-rebase"],
            &[
                "merge.autoStash",
                "pull.autoStash",
                "pull.rebase",
                "branch.main.rebase",
                "rebase.autoStash",
                "branch.main.mergeOptions",
            ],
            local_fetch_endpoint(),
        ),
        ProfileRequirement::Required(RequirementReason::AuthorIdentity)
    );

    let pull = git(&consumer, &["pull", "--ff-only", "--no-rebase"]);
    let oid = created_autostash_oid(&pull);
    let author = success(&consumer, &["show", "-s", "--format=%an <%ae>", &oid]);
    assert_eq!(
        String::from_utf8_lossy(&author.stdout).trim(),
        "Wrong Ambient <wrong@example.test>"
    );
}

#[test]
fn effective_tag_signing_promotes_a_bare_tag_command() {
    let directory = repository();
    let repo = directory.path();
    success(repo, &["config", "tag.gpgSign", "true"]);
    success(
        repo,
        &["config", "gpg.program", "/gus-test/nonexistent-gpg"],
    );

    assert_eq!(
        resolved_requirement(repo, &["tag", "v1"], &["tag.gpgSign"], Vec::new(),),
        ProfileRequirement::Required(RequirementReason::SigningIdentity)
    );

    let tag = git(repo, &["tag", "v1"]);
    assert!(
        !tag.status.success(),
        "bare tag unexpectedly skipped signing"
    );
    assert!(
        !git(repo, &["show-ref", "--verify", "refs/tags/v1"])
            .status
            .success(),
        "failed signing operation must not leave a lightweight tag"
    );
}

#[test]
fn identity_free_checkout_and_fetch_use_a_neutral_reflog_identity() {
    let checkout = repository();
    neutral_success(checkout.path(), &["switch", "-c", "neutral"]);
    let head_reflog = success(
        checkout.path(),
        &["reflog", "show", "-1", "--format=%gN <%gE>", "HEAD"],
    );
    assert_eq!(
        String::from_utf8_lossy(&head_reflog.stdout).trim(),
        format!("{NEUTRAL_REFLOG_NAME} <{NEUTRAL_REFLOG_EMAIL}>")
    );

    let (_directory, consumer) = pull_fixture();
    neutral_success(&consumer, &["fetch", "origin"]);
    let fetch_reflog = success(
        &consumer,
        &[
            "reflog",
            "show",
            "-1",
            "--format=%gN <%gE>",
            "refs/remotes/origin/main",
        ],
    );
    assert_eq!(
        String::from_utf8_lossy(&fetch_reflog.stdout).trim(),
        format!("{NEUTRAL_REFLOG_NAME} <{NEUTRAL_REFLOG_EMAIL}>")
    );
}
