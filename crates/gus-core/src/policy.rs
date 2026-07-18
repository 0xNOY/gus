use crate::model::{
    IdentityCreationEvidence, InvocationContext, Operation, ProfileRequirement, RequirementReason,
    ResolvedEndpoint, ResolvedInvocation, Transport,
};

pub(crate) fn unresolved_profile_requirement(context: &InvocationContext) -> ProfileRequirement {
    let invocation = context.normalized();
    if invocation.issue.is_some() {
        return required(RequirementReason::AmbiguousInvocation);
    }
    if has_unsafe_runtime_config(context) {
        return required(RequirementReason::AmbiguousConfiguration);
    }

    match invocation.operation {
        Operation::ReadOnly | Operation::WorkingTree | Operation::ConfigRead => {
            ProfileRequirement::NotRequired
        }
        Operation::Fetch
        | Operation::Clone
        | Operation::LsRemote
        | Operation::Pull {
            ff_only_candidate: true,
        } => required(RequirementReason::UnresolvedTransport),
        Operation::LightweightTagCandidate | Operation::SignedTag => {
            required(RequirementReason::SigningIdentity)
        }
        Operation::Pull {
            ff_only_candidate: false,
        }
        | Operation::Commit
        | Operation::CommitTree
        | Operation::Merge { .. }
        | Operation::HistoryRewrite
        | Operation::Stash
        | Operation::AnnotatedTag => required(RequirementReason::AuthorIdentity),
        Operation::Push => required(RequirementReason::PublishAuthentication),
        Operation::ConfigWriteOrUnknown => required(RequirementReason::AmbiguousConfiguration),
        Operation::Unknown => required(RequirementReason::UnknownOrExternalCommand),
    }
}

pub(crate) fn resolved_profile_requirement(context: &ResolvedInvocation) -> ProfileRequirement {
    let invocation = context.invocation();
    if invocation.normalized().issue.is_some() {
        return required(RequirementReason::AmbiguousInvocation);
    }
    if has_unsafe_runtime_config(invocation) {
        return required(RequirementReason::AmbiguousConfiguration);
    }

    let config = context.evidence().effective_config();
    match invocation.operation() {
        Operation::ReadOnly | Operation::WorkingTree | Operation::ConfigRead => {
            ProfileRequirement::NotRequired
        }
        Operation::Fetch | Operation::Clone | Operation::LsRemote => {
            remote_read(context.evidence().endpoints())
        }
        Operation::Pull {
            ff_only_candidate: true,
        } if config.pull_ff_only() == IdentityCreationEvidence::IdentityFreeProven => {
            remote_read(context.evidence().endpoints())
        }
        Operation::Merge {
            ff_only_candidate: true,
        } if config.merge_ff_only() == IdentityCreationEvidence::IdentityFreeProven => {
            ProfileRequirement::NotRequired
        }
        Operation::LightweightTagCandidate
            if config.lightweight_tag() == IdentityCreationEvidence::IdentityFreeProven =>
        {
            ProfileRequirement::NotRequired
        }
        Operation::LightweightTagCandidate | Operation::SignedTag => {
            required(RequirementReason::SigningIdentity)
        }
        Operation::Pull { .. }
        | Operation::Commit
        | Operation::CommitTree
        | Operation::Merge { .. }
        | Operation::HistoryRewrite
        | Operation::Stash
        | Operation::AnnotatedTag => required(RequirementReason::AuthorIdentity),
        Operation::Push => required(RequirementReason::PublishAuthentication),
        Operation::ConfigWriteOrUnknown => required(RequirementReason::AmbiguousConfiguration),
        Operation::Unknown => required(RequirementReason::UnknownOrExternalCommand),
    }
}

fn has_unsafe_runtime_config(context: &InvocationContext) -> bool {
    let global = &context.normalized().global;
    global
        .config_overrides
        .iter()
        .any(|config| !is_harmless_config(&config.name))
        || global
            .config_env_overrides
            .iter()
            .any(|config| !is_harmless_config(&config.name))
}

fn is_harmless_config(name: &str) -> bool {
    // This intentionally starts with one narrow presentation-only key. The
    // allowlist may grow only with Git-version fixtures proving that a value
    // cannot select an executable, identity, hook, endpoint, or credential.
    name.eq_ignore_ascii_case("color.ui")
}

fn remote_read(endpoints: &[ResolvedEndpoint]) -> ProfileRequirement {
    if endpoints.is_empty()
        || endpoints
            .iter()
            .any(|endpoint| endpoint.transport() == Transport::Unknown)
    {
        return required(RequirementReason::UnresolvedTransport);
    }
    if endpoints
        .iter()
        .any(|endpoint| endpoint.transport() == Transport::Ssh)
    {
        return required(RequirementReason::SshTransport);
    }
    if endpoints
        .iter()
        .any(|endpoint| endpoint.transport() == Transport::Http)
    {
        ProfileRequirement::Deferred(RequirementReason::HttpCredential)
    } else {
        ProfileRequirement::NotRequired
    }
}

const fn required(reason: RequirementReason) -> ProfileRequirement {
    ProfileRequirement::Required(reason)
}

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};

    use super::*;
    use crate::{
        ConfigEnvOverride, ConfigOverride, EffectiveConfigEvidence, EndpointRole, ParseIssue,
        ResolvedEndpoint, SnapshotGenerations,
    };

    const PROVEN: IdentityCreationEvidence = IdentityCreationEvidence::IdentityFreeProven;
    const MAY_CREATE: IdentityCreationEvidence = IdentityCreationEvidence::MayCreateOrUnresolved;

    fn generations() -> SnapshotGenerations {
        SnapshotGenerations::new(1, 1).expect("non-zero fixture generations")
    }

    fn resolved(
        args: &[&str],
        transport: Transport,
        integration: IdentityCreationEvidence,
        tag: IdentityCreationEvidence,
    ) -> ProfileRequirement {
        InvocationContext::parse(args)
            .begin_resolution([1; 32], [2; 32], Some([3; 32]), generations())
            .resolve(
                vec![ResolvedEndpoint::new(
                    EndpointRole::Fetch,
                    transport,
                    [1; 32],
                )],
                EffectiveConfigEvidence::new(integration, integration, tag),
            )
            .profile_requirement()
    }

    #[test]
    fn command_classification_is_conservative_before_resolution() {
        let cases: &[(&[&str], Operation, ProfileRequirement)] = &[
            (
                &["status"],
                Operation::ReadOnly,
                ProfileRequirement::NotRequired,
            ),
            (
                &["commit", "-m", "message"],
                Operation::Commit,
                required(RequirementReason::AuthorIdentity),
            ),
            (
                &["tag", "v1"],
                Operation::LightweightTagCandidate,
                required(RequirementReason::SigningIdentity),
            ),
            (
                &["push", "origin", "main"],
                Operation::Push,
                required(RequirementReason::PublishAuthentication),
            ),
            (
                &["co", "main"],
                Operation::Unknown,
                required(RequirementReason::UnknownOrExternalCommand),
            ),
        ];
        for (args, operation, expected) in cases {
            let context = InvocationContext::parse(*args);
            assert_eq!(context.operation(), *operation, "args: {args:?}");
            assert_eq!(context.profile_requirement(), *expected, "args: {args:?}");
        }
    }

    #[test]
    fn raw_url_never_bypasses_effective_resolution() {
        for command in ["fetch", "clone", "ls-remote"] {
            let args = [command, "https://example.test/repository.git"];
            let unresolved = InvocationContext::parse(args);
            assert_eq!(
                unresolved.profile_requirement(),
                required(RequirementReason::UnresolvedTransport)
            );
            assert_eq!(
                resolved(&args, Transport::Http, PROVEN, PROVEN,),
                ProfileRequirement::Deferred(RequirementReason::HttpCredential)
            );
            assert_eq!(
                resolved(&args, Transport::Ssh, PROVEN, PROVEN,),
                required(RequirementReason::SshTransport)
            );
        }
    }

    #[test]
    fn every_effective_endpoint_participates_in_remote_policy() {
        let context = InvocationContext::parse(["fetch", "--multiple", "public", "private"]);
        let resolved = context
            .begin_resolution([1; 32], [2; 32], Some([3; 32]), generations())
            .resolve(
                vec![
                    ResolvedEndpoint::new(EndpointRole::Fetch, Transport::Http, [1; 32]),
                    ResolvedEndpoint::new(EndpointRole::Fetch, Transport::Ssh, [2; 32]),
                ],
                EffectiveConfigEvidence::conservative(),
            );
        assert_eq!(
            resolved.profile_requirement(),
            required(RequirementReason::SshTransport)
        );
    }

    #[test]
    fn resolution_request_binds_invocation_repository_config_and_head() {
        let status = InvocationContext::parse(["status"]).begin_resolution(
            [1; 32],
            [2; 32],
            Some([3; 32]),
            generations(),
        );
        let status_binding = status.binding();
        let different_invocation = InvocationContext::parse(["status", "--short"])
            .begin_resolution([1; 32], [2; 32], Some([3; 32]), generations())
            .binding();
        let different_repository = InvocationContext::parse(["status"])
            .begin_resolution([9; 32], [2; 32], Some([3; 32]), generations())
            .binding();

        assert_ne!(
            status_binding.invocation_digest(),
            different_invocation.invocation_digest()
        );
        assert_ne!(
            status_binding.repository_identity(),
            different_repository.repository_identity()
        );
        assert_eq!(status_binding.config_snapshot_digest(), [2; 32]);
        assert_eq!(status_binding.head_state_digest(), Some([3; 32]));

        let resolved = status.resolve(Vec::new(), EffectiveConfigEvidence::conservative());
        assert_eq!(resolved.evidence().binding(), status_binding);
    }

    #[test]
    fn fast_forward_operations_require_effective_autostash_proof() {
        for args in [
            &["merge", "--ff-only", "topic"][..],
            &["pull", "--ff-only", "origin", "main"][..],
        ] {
            assert_ne!(
                resolved(args, Transport::Local, MAY_CREATE, PROVEN,),
                ProfileRequirement::NotRequired
            );
            assert_eq!(
                resolved(args, Transport::Local, PROVEN, PROVEN,),
                ProfileRequirement::NotRequired
            );
        }
        assert_eq!(
            resolved(
                &["merge", "--ff-only", "--autostash", "topic"],
                Transport::Local,
                PROVEN,
                PROVEN,
            ),
            required(RequirementReason::AuthorIdentity)
        );
        assert_eq!(
            resolved(
                &["merge", "--ff-only", "--definitely-unknown", "topic"],
                Transport::Local,
                PROVEN,
                PROVEN,
            ),
            required(RequirementReason::AuthorIdentity)
        );
    }

    #[test]
    fn lightweight_tag_requires_effective_signing_proof() {
        assert_eq!(
            resolved(&["tag", "v1"], Transport::Local, PROVEN, PROVEN,),
            ProfileRequirement::NotRequired
        );
        assert_eq!(
            resolved(&["tag", "v1"], Transport::Local, PROVEN, MAY_CREATE,),
            required(RequirementReason::SigningIdentity)
        );
    }

    #[test]
    fn global_options_are_normalized_but_runtime_config_is_conservative() {
        let context = InvocationContext::parse([
            "-C",
            "workspace",
            "-C",
            "nested",
            "--git-dir=.git",
            "--work-tree",
            ".",
            "-c",
            "color.ui=false",
            "--config-env=http.proxy=GUS_TEST_PROXY",
            "status",
        ]);
        let global = &context.normalized().global;
        assert_eq!(global.directory_changes, ["workspace", "nested"]);
        assert_eq!(global.git_dir.as_deref(), Some(OsStr::new(".git")));
        assert_eq!(global.work_tree.as_deref(), Some(OsStr::new(".")));
        assert_eq!(
            global.config_overrides,
            [ConfigOverride {
                name: "color.ui".into(),
                value: OsString::from("false"),
            }]
        );
        assert_eq!(
            global.config_env_overrides,
            [ConfigEnvOverride {
                name: "http.proxy".into(),
                environment_variable: "GUS_TEST_PROXY".into(),
            }]
        );
        assert_eq!(
            context.profile_requirement(),
            required(RequirementReason::AmbiguousConfiguration)
        );
    }

    #[test]
    fn presentation_only_runtime_config_preserves_the_base_policy() {
        for args in [
            &["-c", "color.ui=false", "status"][..],
            &["--config-env=color.ui=GUS_TEST_COLOR", "status"][..],
        ] {
            assert_eq!(
                InvocationContext::parse(args).profile_requirement(),
                ProfileRequirement::NotRequired,
                "args: {args:?}"
            );
        }
        for args in [
            &["-c", "alias.co=commit", "status"][..],
            &["-c", "credential.helper=ambient", "status"][..],
        ] {
            assert_eq!(
                InvocationContext::parse(args).profile_requirement(),
                required(RequirementReason::AmbiguousConfiguration),
                "args: {args:?}"
            );
        }
    }

    #[test]
    fn malformed_or_unknown_global_options_fail_closed() {
        let cases: &[(&[&str], ParseIssue)] = &[
            (&[], ParseIssue::EmptyInvocation),
            (&["-C"], ParseIssue::MissingOptionValue),
            (&["--git-dir="], ParseIssue::MalformedOptionValue),
            (&["-c", "alias.co"], ParseIssue::MalformedOptionValue),
            (
                &["--config-env=user.name=NOT-VALID"],
                ParseIssue::MalformedOptionValue,
            ),
            (&["-Ccombined", "status"], ParseIssue::UnknownGlobalOption),
        ];
        for (args, issue) in cases {
            let context = InvocationContext::parse(*args);
            assert_eq!(context.normalized().issue, Some(*issue), "args: {args:?}");
            assert_eq!(
                context.profile_requirement(),
                required(RequirementReason::AmbiguousInvocation),
                "args: {args:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_positional_argument_is_preserved_losslessly() {
        use std::os::unix::ffi::OsStringExt;

        let path = OsString::from_vec(vec![b'p', 0x80, b't', b'h']);
        let context = InvocationContext::parse([OsString::from("status"), path.clone()]);
        assert_eq!(context.normalized().raw_args[1], path);
        assert_eq!(context.normalized().command_args[0], path);
        assert_eq!(
            context.profile_requirement(),
            ProfileRequirement::NotRequired
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_pull_argument_cannot_be_ignored_for_ff_only() {
        use std::os::unix::ffi::OsStringExt;

        let unknown_option = OsString::from_vec(vec![b'-', 0x80]);
        let context = InvocationContext::parse([
            OsString::from("pull"),
            unknown_option,
            OsString::from("--ff-only"),
            OsString::from("origin"),
        ]);
        assert_eq!(
            context.operation(),
            Operation::Pull {
                ff_only_candidate: false
            }
        );
        assert_eq!(
            context.profile_requirement(),
            required(RequirementReason::AuthorIdentity)
        );
    }

    #[cfg(windows)]
    #[test]
    fn ill_formed_wide_positional_argument_is_preserved_losslessly() {
        use std::os::windows::ffi::OsStringExt;

        let path = OsString::from_wide(&[u16::from(b'p'), 0xD800, u16::from(b'h')]);
        let context = InvocationContext::parse([OsString::from("status"), path.clone()]);
        assert_eq!(context.normalized().raw_args[1], path);
        assert_eq!(context.normalized().command_args[0], path);
        assert_eq!(
            context.profile_requirement(),
            ProfileRequirement::NotRequired
        );
    }
}
