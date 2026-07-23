//! Policy routing for the transparent GUS Git shim.
//!
//! This crate does not locate or start real Git. Its admission values are
//! deliberately non-constructible by callers and own the invocation that was
//! classified. A later execution layer must still turn an admission into a
//! short-lived plan bound to a verified real-Git handle and revalidated
//! repository/config generations.

use std::ffi::OsStr;

use gus_core::{
    GitResolver, InvocationContext, Operation, ProfileRequirement, RequirementReason,
    ResolutionError, ResolutionIntent, ResolutionTarget, ResolvedInvocation, ResolverSnapshot,
};
pub use gus_ipc::OperationPresentation;
use gus_profile::{PersonIdentity, Profile};

/// A losslessly parsed invocation entering the Git shim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShimInvocation {
    invocation: Box<InvocationContext>,
}

impl ShimInvocation {
    /// Parses arguments following the shim executable name.
    pub fn parse<I, S>(args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        Self {
            invocation: Box::new(InvocationContext::parse(args)),
        }
    }

    /// Returns the lossless syntactic invocation.
    #[must_use]
    pub fn invocation(&self) -> &InvocationContext {
        &self.invocation
    }

    /// Consumes the invocation and chooses its first trusted processing stage.
    #[must_use]
    pub fn route(self) -> InitialRoute {
        let requirement = self.invocation.profile_requirement();
        match initial_action(requirement) {
            InitialAction::Forward => InitialRoute::Forward(LocalPolicyAdmission {
                invocation: self.invocation,
            }),
            InitialAction::Resolve => InitialRoute::Resolve(ResolutionRequired {
                invocation: self.invocation,
            }),
            InitialAction::Reject(reason) => {
                InitialRoute::Reject(PreflightRejection::unresolved(*self.invocation, reason))
            }
        }
    }
}

/// The first policy route selected without reading Git configuration.
#[derive(Debug)]
pub enum InitialRoute {
    /// The syntactic operation needs no profile or endpoint resolution.
    Forward(LocalPolicyAdmission),
    /// Trusted Git/config/remote resolution must run before a decision.
    Resolve(ResolutionRequired),
    /// Profile selection cannot make this invocation safe.
    Reject(PreflightRejection),
}

/// Syntactic admission for a local operation that needs no selected profile.
///
/// This is not process-launch authority. The execution layer must still bind
/// the invocation to verified real Git and install the neutral identity and
/// credential boundaries before spawning it.
#[derive(Debug)]
pub struct LocalPolicyAdmission {
    invocation: Box<InvocationContext>,
}

impl LocalPolicyAdmission {
    /// Returns the admitted syntactic invocation.
    #[must_use]
    pub fn invocation(&self) -> &InvocationContext {
        &self.invocation
    }

    /// Returns the display-only operation category.
    #[must_use]
    pub fn presentation(&self) -> OperationPresentation {
        operation_presentation(self.invocation.operation())
    }

    /// Consumes this admission and returns the exact argv it admitted.
    ///
    /// Execution layers should use this method instead of retaining a second
    /// caller-owned argv copy beside the policy decision.
    #[must_use]
    pub fn into_arguments(self) -> Vec<std::ffi::OsString> {
        (*self.invocation).into_raw_args()
    }
}

/// An invocation that needs trusted repository/config/endpoint evidence.
#[derive(Debug)]
pub struct ResolutionRequired {
    invocation: Box<InvocationContext>,
}

impl ResolutionRequired {
    /// Returns the invocation for which a snapshot must be captured.
    #[must_use]
    pub fn invocation(&self) -> &InvocationContext {
        &self.invocation
    }

    /// Returns the display-only operation category.
    #[must_use]
    pub fn presentation(&self) -> OperationPresentation {
        operation_presentation(self.invocation.operation())
    }

    /// Starts one snapshot capture and consumes this request instance.
    ///
    /// # Errors
    ///
    /// Returns an error without issuing an intent if a unique request nonce
    /// cannot be obtained from the operating system.
    pub fn begin_capture(self) -> Result<(ResolutionCapture, ResolutionIntent), ResolutionError> {
        let (target, intent) = (*self.invocation).begin_resolution_capture()?;
        Ok((ResolutionCapture { target }, intent))
    }

    /// Selects an externally requested profile for an operation whose initial
    /// policy already proves that only author/committer identity is required.
    ///
    /// Operations that still need repository, transport, or signing evidence
    /// must continue through [`Self::begin_capture`].
    ///
    /// # Errors
    ///
    /// Rejects invalid profiles and every unresolved requirement other than a
    /// direct author identity requirement.
    pub fn select_explicit_profile(
        self,
        profile: &Profile,
    ) -> Result<ExplicitProfileAdmission, ExplicitProfileError> {
        profile.validate()?;
        if self.invocation.operation() != Operation::Commit
            || self.invocation.profile_requirement()
                != ProfileRequirement::Required(RequirementReason::AuthorIdentity)
        {
            return Err(ExplicitProfileError::ResolutionRequired);
        }
        if profile.signing.is_some() {
            return Err(ExplicitProfileError::SigningUnsupported);
        }
        let global = &self.invocation.normalized().global;
        if !global.directory_changes.is_empty()
            || global.git_dir.is_some()
            || global.work_tree.is_some()
            || global.namespace.is_some()
            || global.exec_path.is_some()
            || !global.config_overrides.is_empty()
            || !global.config_env_overrides.is_empty()
        {
            return Err(ExplicitProfileError::UnsupportedInvocation);
        }
        if !plain_commit_arguments(&self.invocation.normalized().command_args) {
            return Err(ExplicitProfileError::UnsupportedInvocation);
        }
        Ok(ExplicitProfileAdmission {
            arguments: self.invocation.into_raw_args(),
            author: profile.author.clone(),
            committer: profile.committer.clone(),
        })
    }
}

/// Execution inputs admitted for one external profile override.
#[derive(Debug)]
pub struct ExplicitProfileAdmission {
    arguments: Vec<std::ffi::OsString>,
    author: PersonIdentity,
    committer: PersonIdentity,
}

impl ExplicitProfileAdmission {
    /// Consumes the admission into the exact argv and immutable identities
    /// validated by [`ResolutionRequired::select_explicit_profile`].
    #[must_use]
    pub fn into_execution(self) -> (Vec<std::ffi::OsString>, PersonIdentity, PersonIdentity) {
        (self.arguments, self.author, self.committer)
    }
}

/// Failure to turn an external profile override into execution authority.
#[derive(Debug, thiserror::Error)]
pub enum ExplicitProfileError {
    #[error("the selected profile is invalid: {0}")]
    InvalidProfile(#[from] gus_profile::ValidationError),
    #[error("the invocation still requires trusted repository or transport resolution")]
    ResolutionRequired,
    #[error("this build supports explicit profiles only for a plain unsigned commit")]
    UnsupportedInvocation,
    #[error("commit signing for an explicit profile is not implemented in this build")]
    SigningUnsupported,
}

fn plain_commit_arguments(arguments: &[std::ffi::OsString]) -> bool {
    let mut index = 0;
    while index < arguments.len() {
        let Some(argument) = arguments[index].to_str() else {
            return false;
        };
        if argument == "--" {
            return true;
        }
        if matches!(argument, "-m" | "--message") {
            index += 1;
            if index == arguments.len() {
                return false;
            }
        } else if !(matches!(
            argument,
            "-q" | "--quiet"
                | "-a"
                | "--all"
                | "--allow-empty"
                | "--allow-empty-message"
                | "--no-verify"
                | "--dry-run"
        ) || argument.starts_with("-m") && argument.len() > 2
            || argument.starts_with("--message="))
            && argument.starts_with('-')
        {
            return false;
        }
        index += 1;
    }
    true
}

/// A single in-progress capture retaining the exact invocation request nonce.
#[derive(Debug)]
pub struct ResolutionCapture {
    target: ResolutionTarget,
}

impl ResolutionCapture {
    /// Returns the invocation being captured.
    #[must_use]
    pub fn invocation(&self) -> &InvocationContext {
        self.target.invocation()
    }

    /// Consumes this capture and binds its trusted snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when the snapshot belongs to another request, is
    /// incomplete, invalid, or has incompatible endpoint evidence.
    pub fn resolve(self, snapshot: ResolverSnapshot) -> Result<ResolvedRoute, ResolutionError> {
        let resolved = GitResolver.resolve(self.target, snapshot)?;
        Ok(route_resolved(resolved))
    }
}

/// The route selected after trusted Git/config/endpoint resolution.
#[derive(Debug)]
pub enum ResolvedRoute {
    /// Real Git may start within the indicated credential boundary.
    Forward(ResolvedForwardAdmission),
    /// A profile must be selected before real Git starts.
    Select(ProfileSelectionRequired),
    /// The resolved operation is unsupported or remains ambiguous.
    Reject(PreflightRejection),
}

/// Credential behavior installed around an admitted real-Git process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialBoundaryMode {
    /// Credential access is denied; no profile is selected.
    NoCredentialAccess,
    /// HTTP may proceed anonymously and request a profile only after a real
    /// origin authentication challenge reaches the GUS credential helper.
    DeferredHttpSelection,
}

/// A resolved admission that still requires an execution-plan lease.
#[derive(Debug)]
pub struct ResolvedForwardAdmission {
    invocation: Box<ResolvedInvocation>,
    credential_mode: CredentialBoundaryMode,
}

impl ResolvedForwardAdmission {
    /// Returns the invocation and immutable resolver evidence.
    #[must_use]
    pub fn invocation(&self) -> &ResolvedInvocation {
        &self.invocation
    }

    /// Returns the credential-helper boundary required for execution.
    #[must_use]
    pub const fn credential_mode(&self) -> CredentialBoundaryMode {
        self.credential_mode
    }

    /// Returns the display-only operation category.
    #[must_use]
    pub fn presentation(&self) -> OperationPresentation {
        operation_presentation(self.invocation.invocation().operation())
    }
}

/// An invocation for which broker-mediated profile selection is necessary.
#[derive(Debug)]
pub struct ProfileSelectionRequired {
    invocation: Box<ResolvedInvocation>,
    reason: RequirementReason,
}

impl ProfileSelectionRequired {
    fn resolved(invocation: ResolvedInvocation, reason: RequirementReason) -> Self {
        Self {
            invocation: Box::new(invocation),
            reason,
        }
    }

    /// Returns the policy reason shown to the selection provider.
    #[must_use]
    pub const fn reason(&self) -> RequirementReason {
        self.reason
    }

    /// Returns the invocation and immutable resolver evidence.
    #[must_use]
    pub fn invocation(&self) -> &ResolvedInvocation {
        &self.invocation
    }

    /// Returns the display-only operation category.
    #[must_use]
    pub fn presentation(&self) -> OperationPresentation {
        operation_presentation(self.invocation.invocation().operation())
    }
}

/// A fail-closed decision made before real Git starts.
#[derive(Debug)]
pub struct PreflightRejection {
    subject: PolicySubject,
    reason: RequirementReason,
}

impl PreflightRejection {
    fn unresolved(invocation: InvocationContext, reason: RequirementReason) -> Self {
        Self {
            subject: PolicySubject::Unresolved(Box::new(invocation)),
            reason,
        }
    }

    fn resolved(invocation: ResolvedInvocation, reason: RequirementReason) -> Self {
        Self {
            subject: PolicySubject::Resolved(Box::new(invocation)),
            reason,
        }
    }

    /// Returns the reason selection cannot safely admit the invocation.
    #[must_use]
    pub const fn reason(&self) -> RequirementReason {
        self.reason
    }

    /// Returns the parsed invocation for diagnostics.
    #[must_use]
    pub fn invocation(&self) -> &InvocationContext {
        self.subject.invocation()
    }

    /// Reports whether trusted resolver evidence was attached before rejection.
    #[must_use]
    pub const fn has_resolution_evidence(&self) -> bool {
        self.subject.has_resolution_evidence()
    }

    /// Returns the display-only operation category.
    #[must_use]
    pub fn presentation(&self) -> OperationPresentation {
        operation_presentation(self.invocation().operation())
    }
}

#[derive(Debug)]
enum PolicySubject {
    Unresolved(Box<InvocationContext>),
    Resolved(Box<ResolvedInvocation>),
}

impl PolicySubject {
    fn invocation(&self) -> &InvocationContext {
        match self {
            Self::Unresolved(invocation) => invocation,
            Self::Resolved(invocation) => invocation.invocation(),
        }
    }

    const fn has_resolution_evidence(&self) -> bool {
        matches!(self, Self::Resolved(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InitialAction {
    Forward,
    Resolve,
    Reject(RequirementReason),
}

const fn initial_action(requirement: ProfileRequirement) -> InitialAction {
    match requirement {
        ProfileRequirement::NotRequired => InitialAction::Forward,
        ProfileRequirement::Deferred(reason) => initial_required_action(reason, true),
        ProfileRequirement::Required(reason) => initial_required_action(reason, false),
        ProfileRequirement::Unsupported(reason) => InitialAction::Reject(reason),
    }
}

const fn initial_required_action(reason: RequirementReason, deferred: bool) -> InitialAction {
    if deferred
        || selection_reason(reason)
        || matches!(
            reason,
            RequirementReason::UnresolvedTransport | RequirementReason::UnresolvedIdentityCreation
        )
    {
        InitialAction::Resolve
    } else {
        InitialAction::Reject(reason)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolvedAction {
    Forward(CredentialBoundaryMode),
    Select(RequirementReason),
    Reject(RequirementReason),
}

const fn resolved_action(requirement: ProfileRequirement) -> ResolvedAction {
    match requirement {
        ProfileRequirement::NotRequired => {
            ResolvedAction::Forward(CredentialBoundaryMode::NoCredentialAccess)
        }
        ProfileRequirement::Deferred(RequirementReason::HttpCredential) => {
            ResolvedAction::Forward(CredentialBoundaryMode::DeferredHttpSelection)
        }
        ProfileRequirement::Required(reason) if selection_reason(reason) => {
            ResolvedAction::Select(reason)
        }
        ProfileRequirement::Deferred(reason)
        | ProfileRequirement::Required(reason)
        | ProfileRequirement::Unsupported(reason) => ResolvedAction::Reject(reason),
    }
}

fn route_resolved(invocation: ResolvedInvocation) -> ResolvedRoute {
    match resolved_action(invocation.profile_requirement()) {
        ResolvedAction::Forward(credential_mode) => {
            ResolvedRoute::Forward(ResolvedForwardAdmission {
                invocation: Box::new(invocation),
                credential_mode,
            })
        }
        ResolvedAction::Select(reason) => {
            ResolvedRoute::Select(ProfileSelectionRequired::resolved(invocation, reason))
        }
        ResolvedAction::Reject(reason) => {
            ResolvedRoute::Reject(PreflightRejection::resolved(invocation, reason))
        }
    }
}

const fn selection_reason(reason: RequirementReason) -> bool {
    matches!(
        reason,
        RequirementReason::AuthorIdentity
            | RequirementReason::SigningIdentity
            | RequirementReason::SshTransport
            | RequirementReason::HttpCredential
            | RequirementReason::PublishAuthentication
    )
}

/// Maps authoritative core policy operations to display-only IPC categories.
#[must_use]
pub const fn operation_presentation(operation: Operation) -> OperationPresentation {
    match operation {
        Operation::Informational | Operation::ReadOnly | Operation::ConfigRead => {
            OperationPresentation::LocalRead
        }
        Operation::WorkingTree => OperationPresentation::WorktreeMutation,
        Operation::Commit | Operation::CommitTree => OperationPresentation::Commit,
        Operation::LightweightTagCandidate | Operation::AnnotatedTag | Operation::SignedTag => {
            OperationPresentation::Tag
        }
        Operation::HistoryRewrite | Operation::Stash => OperationPresentation::HistoryRewrite,
        Operation::Merge { .. } | Operation::Pull { .. } => OperationPresentation::Merge,
        Operation::Fetch | Operation::Clone | Operation::LsRemote => {
            OperationPresentation::RemoteRead
        }
        Operation::Push => OperationPresentation::Push,
        Operation::ConfigWriteOrUnknown | Operation::Unknown => {
            OperationPresentation::UnknownProtected
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gus_core::{
        EffectiveConfigEntry, EndpointObservation, EndpointRole, SnapshotGenerations, Transport,
        VerifiedGitSemantics,
    };

    fn route(args: &[&str]) -> InitialRoute {
        ShimInvocation::parse(args).route()
    }

    fn begin_capture(resolution: ResolutionRequired) -> (ResolutionCapture, ResolutionIntent) {
        resolution.begin_capture().expect("unique fixture capture")
    }

    fn endpoint_snapshot(
        intent: ResolutionIntent,
        role: EndpointRole,
        transport: Transport,
    ) -> ResolverSnapshot {
        let semantics = VerifiedGitSemantics::from_version_output([8; 32], "git version 2.39.0")
            .expect("valid supported Git fixture");
        ResolverSnapshot::new(
            intent,
            [1; 32],
            semantics,
            Some([3; 32]),
            SnapshotGenerations::new(1, 1).expect("non-zero generations"),
            Some("main".to_owned()),
            Vec::new(),
            vec![EndpointObservation::new(role, transport, [2; 32])],
            Vec::new(),
        )
        .expect("valid remote snapshot")
    }

    fn local_snapshot(
        intent: ResolutionIntent,
        config_entries: Vec<EffectiveConfigEntry>,
    ) -> ResolverSnapshot {
        let semantics = VerifiedGitSemantics::from_version_output([8; 32], "git version 2.39.0")
            .expect("valid supported Git fixture");
        ResolverSnapshot::new(
            intent,
            [1; 32],
            semantics,
            Some([3; 32]),
            SnapshotGenerations::new(1, 1).expect("non-zero generations"),
            Some("main".to_owned()),
            config_entries,
            Vec::new(),
            Vec::new(),
        )
        .expect("valid local snapshot")
    }

    #[test]
    fn identity_free_syntactic_operations_forward_without_selection() {
        for args in [
            ["status"].as_slice(),
            ["checkout", "main"].as_slice(),
            ["--version"].as_slice(),
            ["remote", "get-url", "origin"].as_slice(),
            ["config", "--local", "--get", "remote.origin.url"].as_slice(),
            ["worktree", "list", "--porcelain"].as_slice(),
            ["submodule", "status", "--recursive"].as_slice(),
        ] {
            let InitialRoute::Forward(admission) = route(args) else {
                panic!("expected local admission for {args:?}");
            };
            assert_eq!(
                admission.presentation(),
                operation_presentation(admission.invocation().operation())
            );
        }
    }

    #[test]
    fn remote_reads_require_resolution_before_admission() {
        for args in [
            ["fetch"].as_slice(),
            ["clone", "https://example.invalid/repo"].as_slice(),
            ["ls-remote", "origin"].as_slice(),
        ] {
            assert!(matches!(route(args), InitialRoute::Resolve(_)), "{args:?}");
        }
    }

    #[test]
    fn identity_and_publish_operations_resolve_before_selection() {
        for args in [
            ["commit", "-m", "message"].as_slice(),
            ["tag", "-s", "v1"].as_slice(),
            ["push", "origin", "main"].as_slice(),
        ] {
            assert!(matches!(route(args), InitialRoute::Resolve(_)), "{args:?}");
        }

        let cases = [
            (
                ["commit", "-m", "message"].as_slice(),
                RequirementReason::AuthorIdentity,
            ),
            (
                ["tag", "-s", "v1"].as_slice(),
                RequirementReason::SigningIdentity,
            ),
        ];
        for (args, expected) in cases {
            let InitialRoute::Resolve(resolution) = route(args) else {
                panic!("protected operation must resolve for {args:?}");
            };
            let (capture, intent) = begin_capture(resolution);
            let ResolvedRoute::Select(selection) = capture
                .resolve(local_snapshot(intent, Vec::new()))
                .expect("valid protected local resolution")
            else {
                panic!("protected operation must select for {args:?}");
            };
            assert_eq!(selection.reason(), expected);
            let _ = selection.invocation().evidence();
        }

        let InitialRoute::Resolve(resolution) = route(&["push", "origin", "main"]) else {
            panic!("push must resolve");
        };
        let (capture, intent) = begin_capture(resolution);
        let ResolvedRoute::Select(selection) = capture
            .resolve(endpoint_snapshot(
                intent,
                EndpointRole::Push,
                Transport::Local,
            ))
            .expect("valid local push resolution")
        else {
            panic!("publish operation must select");
        };
        assert_eq!(selection.reason(), RequirementReason::PublishAuthentication);
        let _ = selection.invocation().evidence();
    }

    #[test]
    fn conditional_identity_creation_resolves_before_prompting() {
        for args in [
            ["tag", "v1"].as_slice(),
            ["merge", "--ff-only", "topic"].as_slice(),
        ] {
            assert!(matches!(route(args), InitialRoute::Resolve(_)), "{args:?}");
        }
    }

    #[test]
    fn identity_free_config_evidence_avoids_selection() {
        for args in [
            ["tag", "v1"].as_slice(),
            ["merge", "--ff-only", "topic"].as_slice(),
        ] {
            let InitialRoute::Resolve(resolution) = route(args) else {
                panic!("conditional operation must resolve for {args:?}");
            };
            let (capture, intent) = begin_capture(resolution);
            let ResolvedRoute::Forward(admission) = capture
                .resolve(local_snapshot(intent, Vec::new()))
                .expect("valid identity-free resolution")
            else {
                panic!("identity-free evidence must avoid selection for {args:?}");
            };
            assert_eq!(
                admission.credential_mode(),
                CredentialBoundaryMode::NoCredentialAccess
            );
        }
    }

    #[test]
    fn signing_config_promotes_lightweight_tag_to_selection() {
        let InitialRoute::Resolve(resolution) = route(&["tag", "v1"]) else {
            panic!("lightweight tag must resolve");
        };
        let config = vec![EffectiveConfigEntry::new(
            "tag.gpgSign".to_owned(),
            "true".into(),
        )];
        let (capture, intent) = begin_capture(resolution);
        let ResolvedRoute::Select(selection) = capture
            .resolve(local_snapshot(intent, config))
            .expect("valid signing resolution")
        else {
            panic!("effective signing must select a profile");
        };
        assert_eq!(selection.reason(), RequirementReason::SigningIdentity);
        let _ = selection.invocation().evidence();
    }

    #[test]
    fn ambiguity_and_unknown_commands_reject_instead_of_prompting() {
        let cases = [
            (
                ["config", "user.name", "wrong"].as_slice(),
                RequirementReason::AmbiguousConfiguration,
            ),
            (
                ["external-command"].as_slice(),
                RequirementReason::UnknownOrExternalCommand,
            ),
            (
                ["--git-dir"].as_slice(),
                RequirementReason::AmbiguousInvocation,
            ),
        ];
        for (args, expected) in cases {
            let InitialRoute::Reject(rejection) = route(args) else {
                panic!("expected rejection for {args:?}");
            };
            assert_eq!(rejection.reason(), expected);
            assert!(!rejection.has_resolution_evidence());
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_invocation_rejects_before_real_git() {
        use std::os::unix::ffi::OsStringExt;

        let invalid = std::ffi::OsString::from_vec(vec![0xff]);
        let InitialRoute::Reject(rejection) = ShimInvocation::parse([invalid]).route() else {
            panic!("invalid encoding must reject");
        };
        assert_eq!(rejection.reason(), RequirementReason::AmbiguousInvocation);
    }

    #[cfg(windows)]
    #[test]
    fn unpaired_utf16_invocation_rejects_before_real_git() {
        use std::os::windows::ffi::OsStringExt;

        let invalid = std::ffi::OsString::from_wide(&[0xd800]);
        let InitialRoute::Reject(rejection) = ShimInvocation::parse([invalid]).route() else {
            panic!("invalid encoding must reject");
        };
        assert_eq!(rejection.reason(), RequirementReason::AmbiguousInvocation);
    }

    #[cfg(windows)]
    #[test]
    fn unpaired_utf16_positional_argument_forwards_losslessly() {
        use std::os::windows::ffi::OsStringExt;

        let path = std::ffi::OsString::from_wide(&[u16::from(b'p'), 0xd800, u16::from(b'h')]);
        let invocation = ShimInvocation::parse([std::ffi::OsString::from("status"), path.clone()]);
        let InitialRoute::Forward(admission) = invocation.route() else {
            panic!("status path must forward");
        };
        assert_eq!(admission.invocation().normalized().raw_args[1], path);
    }

    #[test]
    fn resolved_local_remote_read_forwards_without_credentials() {
        let InitialRoute::Resolve(resolution) = route(&["fetch"]) else {
            panic!("fetch must resolve");
        };
        let (capture, intent) = begin_capture(resolution);
        let ResolvedRoute::Forward(admission) = capture
            .resolve(endpoint_snapshot(
                intent,
                EndpointRole::Fetch,
                Transport::Local,
            ))
            .expect("valid local resolution")
        else {
            panic!("local fetch must forward");
        };
        assert_eq!(
            admission.credential_mode(),
            CredentialBoundaryMode::NoCredentialAccess
        );
    }

    #[test]
    fn resolved_ssh_remote_read_requests_selection() {
        let InitialRoute::Resolve(resolution) = route(&["fetch"]) else {
            panic!("fetch must resolve");
        };
        let (capture, intent) = begin_capture(resolution);
        let ResolvedRoute::Select(selection) = capture
            .resolve(endpoint_snapshot(
                intent,
                EndpointRole::Fetch,
                Transport::Ssh,
            ))
            .expect("valid SSH resolution")
        else {
            panic!("SSH fetch must select a profile");
        };
        assert_eq!(selection.reason(), RequirementReason::SshTransport);
        let _ = selection.invocation().evidence();
    }

    #[test]
    fn resolved_unknown_push_transport_rejects_without_prompting() {
        let InitialRoute::Resolve(resolution) = route(&["push", "origin", "main"]) else {
            panic!("push must resolve");
        };
        let (capture, intent) = begin_capture(resolution);
        let ResolvedRoute::Reject(rejection) = capture
            .resolve(endpoint_snapshot(
                intent,
                EndpointRole::Push,
                Transport::Unknown,
            ))
            .expect("unknown transport is conservative policy evidence")
        else {
            panic!("unknown push transport must reject");
        };
        assert_eq!(rejection.reason(), RequirementReason::UnresolvedTransport);
        assert!(rejection.has_resolution_evidence());
    }

    #[test]
    fn resolver_snapshot_cannot_be_reused_for_another_invocation() {
        for other in [
            ["fetch", "other"].as_slice(),
            ["-C", "other", "fetch", "origin"].as_slice(),
            ["--namespace=other", "fetch", "origin"].as_slice(),
        ] {
            let InitialRoute::Resolve(resolution) = route(&["fetch", "origin"]) else {
                panic!("fetch must resolve");
            };
            let (capture, _) = begin_capture(resolution);
            let InitialRoute::Resolve(other_resolution) = route(other) else {
                panic!("other remote read must resolve");
            };
            let (_, wrong_intent) = begin_capture(other_resolution);
            let result = capture.resolve(endpoint_snapshot(
                wrong_intent,
                EndpointRole::Fetch,
                Transport::Ssh,
            ));
            assert!(
                matches!(result, Err(ResolutionError::BindingMismatch)),
                "other invocation {other:?} must not reuse the snapshot"
            );
        }
    }

    #[test]
    fn resolver_snapshot_cannot_cross_identical_concurrent_requests() {
        let InitialRoute::Resolve(first) = route(&["fetch", "origin"]) else {
            panic!("fetch must resolve");
        };
        let InitialRoute::Resolve(second) = route(&["fetch", "origin"]) else {
            panic!("fetch must resolve");
        };
        let (first_capture, _) = begin_capture(first);
        let (_, second_intent) = begin_capture(second);
        let result = first_capture.resolve(endpoint_snapshot(
            second_intent,
            EndpointRole::Fetch,
            Transport::Ssh,
        ));
        assert!(matches!(result, Err(ResolutionError::BindingMismatch)));
    }

    #[test]
    fn deferred_http_is_the_only_deferred_forward_route() {
        assert_eq!(
            resolved_action(ProfileRequirement::Deferred(
                RequirementReason::HttpCredential
            )),
            ResolvedAction::Forward(CredentialBoundaryMode::DeferredHttpSelection)
        );
        assert_eq!(
            resolved_action(ProfileRequirement::Deferred(
                RequirementReason::ProxyTransport
            )),
            ResolvedAction::Reject(RequirementReason::ProxyTransport)
        );
    }

    #[test]
    fn presentation_mapping_covers_every_operation_family() {
        let cases = [
            (Operation::Informational, OperationPresentation::LocalRead),
            (Operation::ReadOnly, OperationPresentation::LocalRead),
            (Operation::ConfigRead, OperationPresentation::LocalRead),
            (
                Operation::WorkingTree,
                OperationPresentation::WorktreeMutation,
            ),
            (Operation::Commit, OperationPresentation::Commit),
            (Operation::CommitTree, OperationPresentation::Commit),
            (
                Operation::LightweightTagCandidate,
                OperationPresentation::Tag,
            ),
            (Operation::AnnotatedTag, OperationPresentation::Tag),
            (Operation::SignedTag, OperationPresentation::Tag),
            (
                Operation::HistoryRewrite,
                OperationPresentation::HistoryRewrite,
            ),
            (Operation::Stash, OperationPresentation::HistoryRewrite),
            (
                Operation::Merge {
                    ff_only_candidate: false,
                },
                OperationPresentation::Merge,
            ),
            (
                Operation::Pull {
                    ff_only_candidate: false,
                    rebase: gus_core::CliBooleanOverride::Unspecified,
                    autostash: gus_core::CliBooleanOverride::Unspecified,
                },
                OperationPresentation::Merge,
            ),
            (Operation::Fetch, OperationPresentation::RemoteRead),
            (Operation::Clone, OperationPresentation::RemoteRead),
            (Operation::LsRemote, OperationPresentation::RemoteRead),
            (Operation::Push, OperationPresentation::Push),
            (
                Operation::ConfigWriteOrUnknown,
                OperationPresentation::UnknownProtected,
            ),
            (Operation::Unknown, OperationPresentation::UnknownProtected),
        ];
        for (operation, expected) in cases {
            assert_eq!(operation_presentation(operation), expected);
        }
    }
}
