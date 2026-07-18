use crate::model::{
    HttpPreflightDisposition, IdentityCreationEvidence, InvocationContext, Operation,
    ProfileRequirement, RequirementReason, ResolutionEvidence, ResolvedInvocation, Transport,
};

pub(crate) fn unresolved_profile_requirement(context: &InvocationContext) -> ProfileRequirement {
    let invocation = context.normalized();
    if invocation.issue.is_some() {
        return required(RequirementReason::AmbiguousInvocation);
    }
    if has_unsafe_runtime_config(context, false) {
        return required(RequirementReason::AmbiguousConfiguration);
    }

    match invocation.operation {
        Operation::Informational
        | Operation::ReadOnly
        | Operation::WorkingTree
        | Operation::ConfigRead => ProfileRequirement::NotRequired,
        Operation::Fetch
        | Operation::Clone
        | Operation::LsRemote
        | Operation::Pull {
            ff_only_candidate: true,
            ..
        } => required(RequirementReason::UnresolvedTransport),
        Operation::LightweightTagCandidate | Operation::SignedTag => {
            required(RequirementReason::SigningIdentity)
        }
        Operation::Pull {
            ff_only_candidate: false,
            ..
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
    if let Some(requirement) = unsupported_http_preflight(context.evidence()) {
        return requirement;
    }
    if has_unsafe_runtime_config(invocation, true) {
        return required(RequirementReason::AmbiguousConfiguration);
    }

    let config = context.evidence().effective_config();
    match invocation.operation() {
        Operation::Informational
        | Operation::ReadOnly
        | Operation::WorkingTree
        | Operation::ConfigRead => ProfileRequirement::NotRequired,
        Operation::Fetch | Operation::Clone | Operation::LsRemote => {
            remote_read(context.evidence())
        }
        Operation::Pull {
            ff_only_candidate: true,
            ..
        } if config.pull_ff_only() == IdentityCreationEvidence::IdentityFreeProven => {
            remote_read(context.evidence())
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

fn has_unsafe_runtime_config(context: &InvocationContext, resolved: bool) -> bool {
    let global = &context.normalized().global;
    global.exec_path.is_some()
        || global.config_overrides.iter().any(|config| {
            !(is_harmless_config(&config.name)
                || resolved && is_http_preflight_config(&config.name))
        })
        || global.config_env_overrides.iter().any(|config| {
            !(is_harmless_config(&config.name)
                || resolved && is_http_preflight_config(&config.name))
        })
}

fn is_http_preflight_config(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name == "http.proxy"
        || name == "http.proxyauthmethod"
        || name == "http.sslcert"
        || name == "http.sslkey"
        || (name.starts_with("http.")
            && (config_key_suffix_is(&name, "proxy")
                || config_key_suffix_is(&name, "sslcert")
                || config_key_suffix_is(&name, "sslkey")
                || name.starts_with("http.proxyssl")))
        || (name.starts_with("remote.") && config_key_suffix_is(&name, "proxy"))
}

fn config_key_suffix_is(name: &str, expected: &str) -> bool {
    name.rsplit('.').next() == Some(expected)
}

fn is_harmless_config(name: &str) -> bool {
    // This intentionally starts with one narrow presentation-only key. The
    // allowlist may grow only with Git-version fixtures proving that a value
    // cannot select an executable, identity, hook, endpoint, or credential.
    name.eq_ignore_ascii_case("color.ui")
}

fn unsupported_http_preflight(evidence: &ResolutionEvidence) -> Option<ProfileRequirement> {
    if evidence
        .http_preflight()
        .iter()
        .any(|item| item.disposition() == HttpPreflightDisposition::ProxyTransport)
    {
        return Some(unsupported(RequirementReason::ProxyTransport));
    }
    if evidence.http_preflight().iter().any(|item| {
        matches!(
            item.disposition(),
            HttpPreflightDisposition::PreHandshakeIdentity | HttpPreflightDisposition::Unresolved
        )
    }) {
        return Some(unsupported(RequirementReason::PreHandshakeHttpIdentity));
    }
    None
}

fn remote_read(evidence: &ResolutionEvidence) -> ProfileRequirement {
    let endpoints = evidence.endpoints();
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

const fn unsupported(reason: RequirementReason) -> ProfileRequirement {
    ProfileRequirement::Unsupported(reason)
}

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};

    use super::*;
    use crate::{
        ConfigEnvOverride, ConfigOverride, EndpointRole, ParseIssue, ResolutionError,
        SnapshotGenerations,
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
        let invocation = InvocationContext::parse(args);
        let needs_fetch_endpoint = matches!(
            invocation.operation(),
            Operation::Fetch | Operation::Clone | Operation::LsRemote | Operation::Pull { .. }
        );
        let request =
            invocation.begin_resolution([1; 32], [8; 32], [2; 32], Some([3; 32]), generations());
        let endpoints = if needs_fetch_endpoint {
            vec![request.bind_endpoint(EndpointRole::Fetch, transport, [1; 32])]
        } else {
            Vec::new()
        };
        let http_preflight = if needs_fetch_endpoint && transport == Transport::Http {
            vec![request.bind_http_preflight(
                EndpointRole::Fetch,
                [1; 32],
                HttpPreflightDisposition::HelperCompatible,
            )]
        } else {
            Vec::new()
        };
        let config = request.bind_effective_config(integration, integration, tag);
        request
            .resolve(endpoints, config, http_preflight)
            .expect("valid bound test evidence")
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
    fn ide_discovery_and_background_reads_never_select_a_profile() {
        let cases: &[&[&str]] = &[
            &["--version"],
            &["-h"],
            &["--help"],
            &["--exec-path"],
            &["version"],
            &["version", "--build-options"],
            &["help"],
            &["help", "commit"],
            &["for-each-ref", "--format=%(refname)"],
            &["symbolic-ref", "--short", "HEAD"],
            &["remote", "--verbose"],
            &["branch", "--show-current"],
            &["stash", "list"],
            &["stash", "show", "stash@{0}"],
            &["init", "repository"],
            &["--no-optional-locks", "status"],
            &["--namespace=ide-session", "status"],
        ];
        for args in cases {
            assert_eq!(
                InvocationContext::parse(*args).profile_requirement(),
                ProfileRequirement::NotRequired,
                "args: {args:?}"
            );
        }
        assert_eq!(
            InvocationContext::parse(["stash", "push"]).profile_requirement(),
            required(RequirementReason::AuthorIdentity)
        );
        assert_eq!(
            InvocationContext::parse(["version", "--unknown"]).profile_requirement(),
            required(RequirementReason::UnknownOrExternalCommand)
        );
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
        let request =
            context.begin_resolution([1; 32], [8; 32], [2; 32], Some([3; 32]), generations());
        let endpoints = vec![
            request.bind_endpoint(EndpointRole::Fetch, Transport::Http, [1; 32]),
            request.bind_endpoint(EndpointRole::Fetch, Transport::Ssh, [2; 32]),
        ];
        let config = request.bind_effective_config(MAY_CREATE, MAY_CREATE, MAY_CREATE);
        let http_preflight = vec![request.bind_http_preflight(
            EndpointRole::Fetch,
            [1; 32],
            HttpPreflightDisposition::HelperCompatible,
        )];
        let resolved = request
            .resolve(endpoints, config, http_preflight)
            .expect("matching endpoint evidence");
        assert_eq!(
            resolved.profile_requirement(),
            required(RequirementReason::SshTransport)
        );
    }

    #[test]
    fn recursive_submodule_endpoints_are_bound_and_participate_in_policy() {
        let fetch = InvocationContext::parse(["fetch", "--recurse-submodules", "origin"])
            .begin_resolution([1; 32], [8; 32], [2; 32], Some([3; 32]), generations());
        let fetch_endpoints = vec![
            fetch.bind_endpoint(EndpointRole::Fetch, Transport::Local, [4; 32]),
            fetch.bind_endpoint(EndpointRole::Submodule, Transport::Ssh, [5; 32]),
        ];
        let fetch_config = fetch.bind_effective_config(MAY_CREATE, MAY_CREATE, MAY_CREATE);
        let fetch = fetch
            .resolve(fetch_endpoints, fetch_config, Vec::new())
            .expect("fetch and submodule endpoints are compatible");
        assert_eq!(
            fetch.profile_requirement(),
            required(RequirementReason::SshTransport)
        );

        let push = InvocationContext::parse(["push", "--recurse-submodules=on-demand", "origin"])
            .begin_resolution([1; 32], [8; 32], [2; 32], Some([3; 32]), generations());
        let push_endpoints = vec![
            push.bind_endpoint(EndpointRole::Push, Transport::Http, [4; 32]),
            push.bind_endpoint(EndpointRole::Submodule, Transport::Ssh, [5; 32]),
        ];
        let push_config = push.bind_effective_config(MAY_CREATE, MAY_CREATE, MAY_CREATE);
        let push_preflight = vec![push.bind_http_preflight(
            EndpointRole::Push,
            [4; 32],
            HttpPreflightDisposition::HelperCompatible,
        )];
        let push = push
            .resolve(push_endpoints, push_config, push_preflight)
            .expect("push and submodule endpoints are compatible");
        assert_eq!(
            push.profile_requirement(),
            required(RequirementReason::PublishAuthentication)
        );
    }

    #[test]
    fn resolution_request_binds_invocation_repository_config_and_head() {
        let status = InvocationContext::parse(["status"]).begin_resolution(
            [1; 32],
            [8; 32],
            [2; 32],
            Some([3; 32]),
            generations(),
        );
        let status_binding = status.binding();
        let different_invocation = InvocationContext::parse(["status", "--short"])
            .begin_resolution([1; 32], [8; 32], [2; 32], Some([3; 32]), generations())
            .binding();
        let different_repository = InvocationContext::parse(["status"])
            .begin_resolution([9; 32], [8; 32], [2; 32], Some([3; 32]), generations())
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
        assert_eq!(status_binding.git_semantics_digest(), [8; 32]);
        assert_eq!(status_binding.head_state_digest(), Some([3; 32]));

        let config = status.bind_effective_config(MAY_CREATE, MAY_CREATE, MAY_CREATE);
        let resolved = status
            .resolve(Vec::new(), config, Vec::new())
            .expect("matching bound evidence");
        assert_eq!(resolved.evidence().binding(), status_binding);
    }

    #[test]
    fn resolver_rejects_cross_request_missing_head_and_wrong_endpoint_role() {
        let request_a = InvocationContext::parse(["fetch", "origin"]).begin_resolution(
            [1; 32],
            [8; 32],
            [2; 32],
            Some([3; 32]),
            generations(),
        );
        let endpoint_a = request_a.bind_endpoint(EndpointRole::Fetch, Transport::Http, [4; 32]);
        let config_a = request_a.bind_effective_config(MAY_CREATE, MAY_CREATE, MAY_CREATE);
        let request_b = InvocationContext::parse(["fetch", "origin"]).begin_resolution(
            [9; 32],
            [8; 32],
            [2; 32],
            Some([3; 32]),
            generations(),
        );
        assert_eq!(
            request_b.resolve(vec![endpoint_a], config_a, Vec::new()),
            Err(ResolutionError::BindingMismatch)
        );

        let no_head = InvocationContext::parse(["merge", "--ff-only", "topic"]).begin_resolution(
            [1; 32],
            [8; 32],
            [2; 32],
            None,
            generations(),
        );
        let identity_free = no_head.bind_effective_config(PROVEN, MAY_CREATE, MAY_CREATE);
        assert_eq!(
            no_head.resolve(Vec::new(), identity_free, Vec::new()),
            Err(ResolutionError::HeadStateRequired)
        );

        let wrong_generation = SnapshotGenerations::new(1, 2).expect("valid generations");
        let generation_a = InvocationContext::parse(["fetch", "origin"]).begin_resolution(
            [1; 32],
            [8; 32],
            [2; 32],
            Some([3; 32]),
            generations(),
        );
        let config_generation_a =
            generation_a.bind_effective_config(MAY_CREATE, MAY_CREATE, MAY_CREATE);
        let generation_b = InvocationContext::parse(["fetch", "origin"]).begin_resolution(
            [1; 32],
            [8; 32],
            [2; 32],
            Some([3; 32]),
            wrong_generation,
        );
        let endpoint_generation_b =
            generation_b.bind_endpoint(EndpointRole::Fetch, Transport::Http, [4; 32]);
        assert_eq!(
            generation_b.resolve(vec![endpoint_generation_b], config_generation_a, Vec::new(),),
            Err(ResolutionError::BindingMismatch)
        );

        let fetch = InvocationContext::parse(["fetch", "origin"]).begin_resolution(
            [1; 32],
            [8; 32],
            [2; 32],
            Some([3; 32]),
            generations(),
        );
        let push_only = fetch.bind_endpoint(EndpointRole::Push, Transport::Ssh, [4; 32]);
        let config = fetch.bind_effective_config(MAY_CREATE, MAY_CREATE, MAY_CREATE);
        assert_eq!(
            fetch.resolve(vec![push_only], config, Vec::new()),
            Err(ResolutionError::EndpointSetMismatch)
        );
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
            "--namespace=tenant",
            "-c",
            "color.ui=false",
            "--config-env=http.proxy=GUS_TEST_PROXY",
            "status",
        ]);
        let global = &context.normalized().global;
        assert_eq!(global.directory_changes, ["workspace", "nested"]);
        assert_eq!(global.git_dir.as_deref(), Some(OsStr::new(".git")));
        assert_eq!(global.work_tree.as_deref(), Some(OsStr::new(".")));
        assert_eq!(global.namespace.as_deref(), Some(OsStr::new("tenant")));
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
                ff_only_candidate: false,
                rebase: crate::CliBooleanOverride::Unspecified,
                autostash: crate::CliBooleanOverride::Unspecified,
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
