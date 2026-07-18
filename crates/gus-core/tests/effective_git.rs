use std::{fs, path::Path, process::Command};

use gus_core::{
    EffectiveConfigEvidence, EndpointRole, IdentityCreationEvidence, InvocationContext,
    ProfileRequirement, RequirementReason, ResolvedEndpoint, SnapshotGenerations, Transport,
};
use tempfile::TempDir;

const PROVEN: IdentityCreationEvidence = IdentityCreationEvidence::IdentityFreeProven;
const MAY_CREATE: IdentityCreationEvidence = IdentityCreationEvidence::MayCreateOrUnresolved;

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

fn generations() -> SnapshotGenerations {
    SnapshotGenerations::new(1, 1).expect("non-zero fixture generations")
}

fn requirement(
    args: &[&str],
    merge: IdentityCreationEvidence,
    pull: IdentityCreationEvidence,
    tag: IdentityCreationEvidence,
) -> ProfileRequirement {
    InvocationContext::parse(args)
        .begin_resolution([1; 32], [2; 32], Some([3; 32]), generations())
        .resolve(
            vec![ResolvedEndpoint::new(
                EndpointRole::Fetch,
                Transport::Local,
                [1; 32],
            )],
            EffectiveConfigEvidence::new(merge, pull, tag),
        )
        .profile_requirement()
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

    let merge = git(repo, &["merge", "--ff-only", "topic"]);
    let oid = created_autostash_oid(&merge);
    let author = success(repo, &["show", "-s", "--format=%an <%ae>", &oid]);
    assert_eq!(
        String::from_utf8_lossy(&author.stdout).trim(),
        "Wrong Ambient <wrong@example.test>"
    );
    assert_eq!(
        requirement(&["merge", "--ff-only", "topic"], MAY_CREATE, PROVEN, PROVEN,),
        ProfileRequirement::Required(RequirementReason::AuthorIdentity)
    );
    assert_eq!(
        requirement(
            &["merge", "--ff-only", "--autostash", "topic"],
            PROVEN,
            PROVEN,
            PROVEN,
        ),
        ProfileRequirement::Required(RequirementReason::AuthorIdentity)
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

    let merge = git(repo, &["merge", "--ff-only", "topic"]);
    let oid = created_autostash_oid(&merge);
    let author = success(repo, &["show", "-s", "--format=%an <%ae>", &oid]);
    assert_eq!(
        String::from_utf8_lossy(&author.stdout).trim(),
        "Wrong Ambient <wrong@example.test>"
    );
    assert_eq!(
        requirement(&["merge", "--ff-only", "topic"], MAY_CREATE, PROVEN, PROVEN,),
        ProfileRequirement::Required(RequirementReason::AuthorIdentity)
    );
}

#[test]
fn pull_autostash_overrides_merge_autostash_and_creates_an_ambient_commit() {
    let (_directory, consumer) = pull_fixture();
    success(&consumer, &["config", "merge.autoStash", "false"]);
    success(&consumer, &["config", "pull.autoStash", "true"]);
    success(&consumer, &["config", "pull.rebase", "false"]);

    let pull = git(&consumer, &["pull", "--ff-only"]);
    let oid = created_autostash_oid(&pull);
    let author = success(&consumer, &["show", "-s", "--format=%an <%ae>", &oid]);
    assert_eq!(
        String::from_utf8_lossy(&author.stdout).trim(),
        "Wrong Ambient <wrong@example.test>"
    );

    let policy = InvocationContext::parse(["pull", "--ff-only"])
        .begin_resolution([1; 32], [2; 32], Some([3; 32]), generations())
        .resolve(
            vec![ResolvedEndpoint::new(
                EndpointRole::Fetch,
                Transport::Local,
                [1; 32],
            )],
            EffectiveConfigEvidence::new(
                IdentityCreationEvidence::IdentityFreeProven,
                IdentityCreationEvidence::MayCreateOrUnresolved,
                IdentityCreationEvidence::IdentityFreeProven,
            ),
        )
        .profile_requirement();
    assert_eq!(
        policy,
        ProfileRequirement::Required(RequirementReason::AuthorIdentity)
    );
}

#[test]
fn pull_rebase_autostash_can_create_an_ambient_commit_for_ff_only_pull() {
    let (_directory, consumer) = pull_fixture();
    success(&consumer, &["config", "merge.autoStash", "false"]);
    success(&consumer, &["config", "pull.rebase", "true"]);
    success(&consumer, &["config", "rebase.autoStash", "true"]);

    let pull = git(&consumer, &["pull", "--ff-only"]);
    let oid = created_autostash_oid(&pull);
    let author = success(&consumer, &["show", "-s", "--format=%an <%ae>", &oid]);
    assert_eq!(
        String::from_utf8_lossy(&author.stdout).trim(),
        "Wrong Ambient <wrong@example.test>"
    );
    assert_eq!(
        requirement(&["pull", "--ff-only"], PROVEN, MAY_CREATE, PROVEN),
        ProfileRequirement::Required(RequirementReason::AuthorIdentity)
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
    assert_eq!(
        requirement(&["tag", "v1"], PROVEN, PROVEN, MAY_CREATE,),
        ProfileRequirement::Required(RequirementReason::SigningIdentity)
    );
}
