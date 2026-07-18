use std::ffi::{OsStr, OsString};

use sha2::{Digest, Sha256};

use crate::model::{
    EndpointRole, IdentityCreationEvidence, InvocationContext, ResolutionError, ResolvedInvocation,
    SnapshotGenerations, Transport,
};

/// One effective Git configuration record in the order returned by the fixed
/// real-Git resolver. Includes and worktree configuration must already have
/// been expanded by Git.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveConfigEntry {
    name: String,
    value: OsString,
}

impl EffectiveConfigEntry {
    #[must_use]
    pub fn new(name: String, value: OsString) -> Self {
        Self { name, value }
    }
}

/// Raw endpoint observation produced while resolving remotes and submodules.
/// It is not policy evidence until [`GitResolver`] binds it to a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointObservation {
    role: EndpointRole,
    transport: Transport,
    identity_digest: [u8; 32],
}

/// Git behavior family for which the resolver's effective-config rules have
/// been verified by executable fixtures. Minor versions are admitted only by
/// an explicit entry here; an unknown version never inherits a nearby rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitSemanticRuleset {
    Git2_39,
    Git2_55,
    Unsupported,
}

/// Identity and semantic version of the fixed real Git selected by the
/// platform resolver. The digest binds proofs to both the executable identity
/// and the complete, non-lossy `git --version` observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGitSemantics {
    executable_identity: [u8; 32],
    version_output: String,
    ruleset: GitSemanticRuleset,
    digest: [u8; 32],
}

impl VerifiedGitSemantics {
    /// Creates semantics from a version observation made through the same
    /// verified executable handle represented by `executable_identity`.
    ///
    /// # Errors
    ///
    /// Rejects a missing executable identity or malformed Git version output.
    pub fn from_version_output(
        executable_identity: [u8; 32],
        version_output: &str,
    ) -> Result<Self, ResolutionError> {
        if executable_identity == [0; 32] {
            return Err(ResolutionError::InvalidSnapshot);
        }
        let version_output = version_output.trim();
        let version = version_output
            .strip_prefix("git version ")
            .and_then(|remainder| remainder.split_ascii_whitespace().next())
            .ok_or(ResolutionError::InvalidSnapshot)?;
        let mut components = version.split('.');
        let major = components
            .next()
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or(ResolutionError::InvalidSnapshot)?;
        let minor = components
            .next()
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or(ResolutionError::InvalidSnapshot)?;
        if components.next().is_none() {
            return Err(ResolutionError::InvalidSnapshot);
        }
        let ruleset = match (major, minor) {
            (2, 39) => GitSemanticRuleset::Git2_39,
            (2, 55) => GitSemanticRuleset::Git2_55,
            _ => GitSemanticRuleset::Unsupported,
        };
        let mut digest = Sha256::new();
        digest.update(b"gus.git-semantics.v1\0");
        digest.update(executable_identity);
        digest.update((version_output.len() as u64).to_le_bytes());
        digest.update(version_output.as_bytes());
        digest.update([match ruleset {
            GitSemanticRuleset::Git2_39 => 1,
            GitSemanticRuleset::Git2_55 => 2,
            GitSemanticRuleset::Unsupported => 0,
        }]);
        Ok(Self {
            executable_identity,
            version_output: version_output.to_owned(),
            ruleset,
            digest: digest.finalize().into(),
        })
    }

    #[must_use]
    pub const fn executable_identity(&self) -> [u8; 32] {
        self.executable_identity
    }

    #[must_use]
    pub fn version_output(&self) -> &str {
        &self.version_output
    }

    #[must_use]
    pub const fn ruleset(&self) -> GitSemanticRuleset {
        self.ruleset
    }

    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    const fn supports_identity_proofs(&self) -> bool {
        !matches!(self.ruleset, GitSemanticRuleset::Unsupported)
    }
}

impl EndpointObservation {
    #[must_use]
    pub const fn new(role: EndpointRole, transport: Transport, identity_digest: [u8; 32]) -> Self {
        Self {
            role,
            transport,
            identity_digest,
        }
    }
}

/// Inputs captured atomically by the filesystem/config resolver. The config
/// digest is computed here rather than accepted from a caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverSnapshot {
    repository_identity: [u8; 32],
    git_semantics: VerifiedGitSemantics,
    head_state_digest: Option<[u8; 32]>,
    generations: SnapshotGenerations,
    current_branch: Option<String>,
    config_entries: Vec<EffectiveConfigEntry>,
    config_snapshot_digest: [u8; 32],
    endpoints: Vec<EndpointObservation>,
}

impl ResolverSnapshot {
    /// Creates a snapshot from raw observations. Identity digests must be
    /// produced from open handles by the platform resolver.
    ///
    /// # Errors
    ///
    /// Rejects zero repository/endpoint identities, which represent missing
    /// observations rather than a valid snapshot.
    pub fn new(
        repository_identity: [u8; 32],
        git_semantics: VerifiedGitSemantics,
        head_state_digest: Option<[u8; 32]>,
        generations: SnapshotGenerations,
        current_branch: Option<String>,
        config_entries: Vec<EffectiveConfigEntry>,
        endpoints: Vec<EndpointObservation>,
    ) -> Result<Self, ResolutionError> {
        if repository_identity == [0; 32]
            || endpoints
                .iter()
                .any(|endpoint| endpoint.identity_digest == [0; 32])
        {
            return Err(ResolutionError::InvalidSnapshot);
        }
        let config_snapshot_digest = digest_config(current_branch.as_deref(), &config_entries);
        Ok(Self {
            repository_identity,
            git_semantics,
            head_state_digest,
            generations,
            current_branch,
            config_entries,
            config_snapshot_digest,
            endpoints,
        })
    }
}

/// Sealed policy-evidence producer. Callers provide raw effective Git records;
/// they cannot directly construct an identity-free proof.
#[derive(Debug, Default, Clone, Copy)]
pub struct GitResolver;

impl GitResolver {
    /// Binds a parsed invocation and a complete snapshot, derives aggregate
    /// identity-creation evidence, and validates endpoint completeness.
    ///
    /// # Errors
    ///
    /// Returns [`ResolutionError`] for cross-snapshot evidence, missing HEAD
    /// state required by an identity-free integration, or incompatible
    /// endpoint roles/counts.
    pub fn resolve(
        self,
        invocation: InvocationContext,
        snapshot: ResolverSnapshot,
    ) -> Result<ResolvedInvocation, ResolutionError> {
        let config = EffectiveFacts::from_snapshot(&snapshot);
        let request = invocation.begin_resolution(
            snapshot.repository_identity,
            snapshot.git_semantics.digest(),
            snapshot.config_snapshot_digest,
            snapshot.head_state_digest,
            snapshot.generations,
        );
        let endpoints = snapshot
            .endpoints
            .into_iter()
            .map(|endpoint| {
                request.bind_endpoint(endpoint.role, endpoint.transport, endpoint.identity_digest)
            })
            .collect();
        let effective_config = request.bind_effective_config(
            config.merge_ff_only,
            config.pull_ff_only,
            config.lightweight_tag,
        );
        request.resolve(endpoints, effective_config)
    }
}

#[derive(Debug, Clone, Copy)]
struct EffectiveFacts {
    merge_ff_only: IdentityCreationEvidence,
    pull_ff_only: IdentityCreationEvidence,
    lightweight_tag: IdentityCreationEvidence,
}

impl EffectiveFacts {
    fn from_snapshot(snapshot: &ResolverSnapshot) -> Self {
        if !snapshot.git_semantics.supports_identity_proofs() {
            return Self {
                merge_ff_only: IdentityCreationEvidence::MayCreateOrUnresolved,
                pull_ff_only: IdentityCreationEvidence::MayCreateOrUnresolved,
                lightweight_tag: IdentityCreationEvidence::MayCreateOrUnresolved,
            };
        }
        let config = ConfigView::new(snapshot);
        let merge_options_safe = config.branch_merge_options_are_identity_free();
        let merge_autostash = config.boolean("merge.autostash");
        let merge_ff_only = evidence(merge_options_safe && merge_autostash.is_disabled());

        let rebase = config.pull_uses_rebase();
        let pull_autostash = match snapshot.git_semantics.ruleset() {
            // Git 2.39 has no pull.autoStash key. Treating an ignored false
            // value as authoritative could hide merge.autoStash=true.
            GitSemanticRuleset::Git2_39 => ParsedBoolean::Unset,
            GitSemanticRuleset::Git2_55 => config.boolean("pull.autostash"),
            GitSemanticRuleset::Unsupported => unreachable!("handled above"),
        };
        let effective_pull_autostash = if !pull_autostash.is_unset() {
            pull_autostash
        } else if rebase == ParsedBoolean::Enabled {
            config.boolean("rebase.autostash")
        } else if rebase == ParsedBoolean::Disabled {
            merge_autostash
        } else {
            ParsedBoolean::Invalid
        };
        let pull_options_safe = if rebase == ParsedBoolean::Enabled {
            true
        } else if rebase == ParsedBoolean::Disabled {
            merge_options_safe
        } else {
            false
        };
        let pull_ff_only = evidence(pull_options_safe && effective_pull_autostash.is_disabled());

        let lightweight_tag = evidence(config.boolean("tag.gpgsign").is_disabled());
        Self {
            merge_ff_only,
            pull_ff_only,
            lightweight_tag,
        }
    }
}

const fn evidence(identity_free: bool) -> IdentityCreationEvidence {
    if identity_free {
        IdentityCreationEvidence::IdentityFreeProven
    } else {
        IdentityCreationEvidence::MayCreateOrUnresolved
    }
}

struct ConfigView<'a> {
    branch: Option<&'a str>,
    entries: &'a [EffectiveConfigEntry],
}

impl<'a> ConfigView<'a> {
    fn new(snapshot: &'a ResolverSnapshot) -> Self {
        Self {
            branch: snapshot.current_branch.as_deref(),
            entries: &snapshot.config_entries,
        }
    }

    fn values(&self, name: &str) -> impl DoubleEndedIterator<Item = &OsStr> {
        self.entries
            .iter()
            .filter(move |entry| entry.name.eq_ignore_ascii_case(name))
            .map(|entry| entry.value.as_os_str())
    }

    fn boolean(&self, name: &str) -> ParsedBoolean {
        self.values(name)
            .next_back()
            .map_or(ParsedBoolean::Unset, parse_boolean)
    }

    fn pull_uses_rebase(&self) -> ParsedBoolean {
        if self.branch.is_some() {
            let branch_value = self.branch_boolean("rebase");
            if !branch_value.is_unset() {
                return branch_value;
            }
        }
        self.boolean("pull.rebase")
            .with_unset_default(ParsedBoolean::Disabled)
    }

    fn branch_merge_options_are_identity_free(&self) -> bool {
        if self.branch.is_none() {
            return false;
        }
        self.branch_values("mergeoptions").all(safe_merge_options)
    }

    fn branch_boolean(&self, key: &str) -> ParsedBoolean {
        self.branch_values(key)
            .next_back()
            .map_or(ParsedBoolean::Unset, parse_boolean)
    }

    fn branch_values(&self, key: &str) -> impl DoubleEndedIterator<Item = &OsStr> {
        let branch = self.branch;
        self.entries.iter().filter_map(move |entry| {
            let (section, remainder) = entry.name.split_once('.')?;
            let (subsection, entry_key) = remainder.rsplit_once('.')?;
            (section.eq_ignore_ascii_case("branch")
                && branch == Some(subsection)
                && entry_key.eq_ignore_ascii_case(key))
            .then_some(entry.value.as_os_str())
        })
    }
}

fn safe_merge_options(value: &OsStr) -> bool {
    let Some(value) = value.to_str() else {
        return false;
    };
    if value.trim().is_empty() {
        return false;
    }
    value.split_ascii_whitespace().all(|option| {
        matches!(
            option,
            "--ff-only"
                | "--no-autostash"
                | "--stat"
                | "--no-stat"
                | "--compact-summary"
                | "--no-compact-summary"
                | "--quiet"
                | "-q"
                | "--verbose"
                | "-v"
        )
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParsedBoolean {
    Unset,
    Enabled,
    Disabled,
    Invalid,
}

impl ParsedBoolean {
    const fn is_unset(self) -> bool {
        matches!(self, Self::Unset)
    }

    const fn is_disabled(self) -> bool {
        matches!(self, Self::Unset | Self::Disabled)
    }

    const fn with_unset_default(self, default: Self) -> Self {
        if self.is_unset() { default } else { self }
    }
}

fn parse_boolean(value: &OsStr) -> ParsedBoolean {
    let Some(value) = value.to_str() else {
        return ParsedBoolean::Invalid;
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "true" | "yes" | "on" | "1" | "merges" | "interactive" => ParsedBoolean::Enabled,
        "false" | "no" | "off" | "0" => ParsedBoolean::Disabled,
        _ => ParsedBoolean::Invalid,
    }
}

fn digest_config(branch: Option<&str>, entries: &[EffectiveConfigEntry]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"gus.effective-config.v1\0");
    if let Some(branch) = branch {
        digest.update((branch.len() as u64).to_le_bytes());
        digest.update(branch.as_bytes());
    } else {
        digest.update(0_u64.to_le_bytes());
    }
    for entry in entries {
        digest.update((entry.name.len() as u64).to_le_bytes());
        digest.update(entry.name.as_bytes());
        let value = entry.value.as_os_str().as_encoded_bytes();
        digest.update((value.len() as u64).to_le_bytes());
        digest.update(value);
    }
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProfileRequirement, RequirementReason};

    fn generations() -> SnapshotGenerations {
        SnapshotGenerations::new(1, 1).expect("valid generations")
    }

    fn entry(name: &str, value: &str) -> EffectiveConfigEntry {
        EffectiveConfigEntry::new(name.to_owned(), value.into())
    }

    fn semantics(version: &str) -> VerifiedGitSemantics {
        VerifiedGitSemantics::from_version_output([8; 32], version)
            .expect("valid fixture Git semantics")
    }

    fn resolve_pull_with_version(
        version: &str,
        branch: Option<&str>,
        head: Option<[u8; 32]>,
        entries: Vec<EffectiveConfigEntry>,
    ) -> ProfileRequirement {
        let snapshot = ResolverSnapshot::new(
            [1; 32],
            semantics(version),
            head,
            generations(),
            branch.map(str::to_owned),
            entries,
            vec![EndpointObservation::new(
                EndpointRole::Fetch,
                Transport::Local,
                [2; 32],
            )],
        )
        .expect("valid snapshot");
        GitResolver
            .resolve(InvocationContext::parse(["pull", "--ff-only"]), snapshot)
            .expect("valid resolution")
            .profile_requirement()
    }

    fn resolve_pull(
        branch: Option<&str>,
        head: Option<[u8; 32]>,
        entries: Vec<EffectiveConfigEntry>,
    ) -> ProfileRequirement {
        resolve_pull_with_version("git version 2.55.0", branch, head, entries)
    }

    #[test]
    fn branch_subsection_matching_is_case_sensitive() {
        let requirement = resolve_pull(
            Some("foo"),
            Some([3; 32]),
            vec![
                entry("branch.Foo.rebase", "true"),
                entry("pull.rebase", "false"),
                entry("merge.autoStash", "true"),
                entry("rebase.autoStash", "false"),
            ],
        );
        assert_eq!(
            requirement,
            ProfileRequirement::Required(RequirementReason::AuthorIdentity)
        );
    }

    #[test]
    fn detached_head_and_empty_merge_options_never_produce_identity_free_proof() {
        let detached = resolve_pull(
            None,
            Some([3; 32]),
            vec![
                entry("pull.rebase", "false"),
                entry("merge.autoStash", "false"),
            ],
        );
        assert_eq!(
            detached,
            ProfileRequirement::Required(RequirementReason::AuthorIdentity)
        );

        let empty_options = resolve_pull(
            Some("main"),
            Some([3; 32]),
            vec![
                entry("pull.rebase", "false"),
                entry("merge.autoStash", "false"),
                entry("branch.main.mergeOptions", ""),
            ],
        );
        assert_eq!(
            empty_options,
            ProfileRequirement::Required(RequirementReason::AuthorIdentity)
        );
    }

    #[test]
    fn identity_proofs_are_available_only_for_explicit_git_rulesets() {
        for version in ["git version 2.39.5", "git version 2.55.0.windows.1"] {
            let semantics = semantics(version);
            assert_ne!(semantics.ruleset(), GitSemanticRuleset::Unsupported);
            let snapshot = ResolverSnapshot::new(
                [1; 32],
                semantics,
                Some([3; 32]),
                generations(),
                Some("main".to_owned()),
                vec![
                    entry("pull.rebase", "false"),
                    entry("merge.autoStash", "false"),
                ],
                vec![EndpointObservation::new(
                    EndpointRole::Fetch,
                    Transport::Local,
                    [2; 32],
                )],
            )
            .expect("valid supported snapshot");
            let requirement = GitResolver
                .resolve(InvocationContext::parse(["pull", "--ff-only"]), snapshot)
                .expect("valid resolution")
                .profile_requirement();
            assert_eq!(requirement, ProfileRequirement::NotRequired, "{version}");
        }

        let unsupported = ResolverSnapshot::new(
            [1; 32],
            semantics("git version 2.54.3"),
            Some([3; 32]),
            generations(),
            Some("main".to_owned()),
            vec![
                entry("pull.rebase", "false"),
                entry("merge.autoStash", "false"),
            ],
            vec![EndpointObservation::new(
                EndpointRole::Fetch,
                Transport::Local,
                [2; 32],
            )],
        )
        .expect("unsupported versions still form conservative snapshots");
        let requirement = GitResolver
            .resolve(InvocationContext::parse(["pull", "--ff-only"]), unsupported)
            .expect("unsupported semantics fail closed in policy")
            .profile_requirement();
        assert_eq!(
            requirement,
            ProfileRequirement::Required(RequirementReason::AuthorIdentity)
        );
    }

    #[test]
    fn pull_autostash_precedence_is_ruleset_specific() {
        let entries = || {
            vec![
                entry("pull.rebase", "false"),
                entry("pull.autoStash", "false"),
                entry("merge.autoStash", "true"),
            ]
        };
        assert_eq!(
            resolve_pull_with_version("git version 2.39.5", Some("main"), Some([3; 32]), entries(),),
            ProfileRequirement::Required(RequirementReason::AuthorIdentity),
            "Git 2.39 ignores pull.autoStash and inherits merge.autoStash"
        );
        assert_eq!(
            resolve_pull_with_version("git version 2.55.0", Some("main"), Some([3; 32]), entries(),),
            ProfileRequirement::NotRequired,
            "Git 2.55 pull.autoStash overrides merge.autoStash"
        );
    }

    #[test]
    fn semantics_digest_changes_with_executable_or_version() {
        let base = semantics("git version 2.55.0");
        let other_version = semantics("git version 2.55.1");
        let other_executable =
            VerifiedGitSemantics::from_version_output([9; 32], "git version 2.55.0")
                .expect("valid fixture Git semantics");
        assert_ne!(base.digest(), other_version.digest());
        assert_ne!(base.digest(), other_executable.digest());
    }
}
