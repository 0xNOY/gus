use std::{collections::BTreeMap, fmt, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::validation::{ValidationError, has_forbidden_control};

pub const PROFILE_SET_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProfileId(String);

impl ProfileId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ProfileId {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let valid = !value.is_empty()
            && value.len() <= 64
            && value.as_bytes()[0].is_ascii_alphanumeric()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
        if valid {
            Ok(Self(value))
        } else {
            Err(ValidationError::InvalidProfileId)
        }
    }
}

impl From<ProfileId> for String {
    fn from(value: ProfileId) -> Self {
        value.0
    }
}

impl fmt::Display for ProfileId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonIdentity {
    name: String,
    email: String,
}

impl PersonIdentity {
    /// Creates a Git person identity after validating its serialized form.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidName`] or
    /// [`ValidationError::InvalidEmail`] when an identity cannot be represented
    /// safely and unambiguously.
    pub fn new(name: String, email: String) -> Result<Self, ValidationError> {
        if name.is_empty()
            || name.chars().count() > 256
            || has_forbidden_control(&name)
            || name.contains(['<', '>'])
        {
            return Err(ValidationError::InvalidName);
        }
        let mut parts = email.split('@');
        let local = parts.next().unwrap_or_default();
        let domain = parts.next().unwrap_or_default();
        if local.is_empty()
            || domain.is_empty()
            || parts.next().is_some()
            || email.len() > 320
            || has_forbidden_control(&email)
            || email.contains(['<', '>', ' '])
        {
            return Err(ValidationError::InvalidEmail);
        }
        Ok(Self { name, email })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn email(&self) -> &str {
        &self.email
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutableRef {
    pub path: PathBuf,
    #[serde(default)]
    pub arguments: Vec<String>,
    pub sha256: Option<String>,
}

impl ExecutableRef {
    /// Validates arguments that will later be passed directly to a process.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidExecutableArgument`] for control
    /// characters. This does not resolve or trust the executable path.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self
            .arguments
            .iter()
            .any(|argument| has_forbidden_control(argument))
        {
            return Err(ValidationError::InvalidExecutableArgument);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigningFormat {
    OpenPgp,
    Ssh,
    X509,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigningPolicy {
    Required,
    Optional,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningIdentity {
    pub format: SigningFormat,
    pub key_reference: String,
    pub program: Option<ExecutableRef>,
    pub commit_policy: SigningPolicy,
    pub tag_policy: SigningPolicy,
}

impl SigningIdentity {
    /// Validates signing configuration without accessing the filesystem.
    ///
    /// # Errors
    ///
    /// Returns a [`ValidationError`] for an empty/control-containing key
    /// reference or invalid managed program arguments.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.key_reference.is_empty() || has_forbidden_control(&self.key_reference) {
            return Err(ValidationError::InvalidExecutableArgument);
        }
        if let Some(program) = &self.program {
            program.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SshIdentitySource {
    PrivateKey {
        path: PathBuf,
        certificate: Option<PathBuf>,
    },
    DedicatedAgent {
        endpoint: PathBuf,
        public_key_fingerprint: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshIdentity {
    pub source: SshIdentitySource,
    pub proxy_jump: Option<String>,
    pub known_hosts_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialProtocol {
    Http,
    Https,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CredentialBackend {
    ManagedExecutable { executable: ExecutableRef },
    SecretStore { service: String, account: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialBinding {
    pub protocol: CredentialProtocol,
    pub host: String,
    pub port: Option<u16>,
    pub path_prefix: Option<String>,
    pub username: String,
    pub backend: CredentialBackend,
}

impl CredentialBinding {
    /// Validates a profile-scoped HTTP credential context.
    ///
    /// # Errors
    ///
    /// Returns a [`ValidationError`] when the host, path, username, or managed
    /// backend arguments are unsafe or ambiguous.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.host.is_empty()
            || self.host.chars().any(char::is_whitespace)
            || has_forbidden_control(&self.host)
        {
            return Err(ValidationError::InvalidCredentialHost);
        }
        if self
            .path_prefix
            .as_ref()
            .is_some_and(|path| !path.starts_with('/') || has_forbidden_control(path))
        {
            return Err(ValidationError::InvalidCredentialPath);
        }
        if self.username.is_empty() || has_forbidden_control(&self.username) {
            return Err(ValidationError::InvalidCredentialUsername);
        }
        if let CredentialBackend::ManagedExecutable { executable } = &self.backend {
            executable.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpIdentity {
    #[serde(default)]
    pub bindings: Vec<CredentialBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub id: ProfileId,
    pub author: PersonIdentity,
    pub committer: PersonIdentity,
    pub signing: Option<SigningIdentity>,
    pub ssh_transport: Option<SshIdentity>,
    pub http: Option<HttpIdentity>,
    pub generation: u64,
}

impl Profile {
    /// Validates fields whose invariants span a complete profile.
    ///
    /// # Errors
    ///
    /// Returns a [`ValidationError`] for generation zero or invalid nested
    /// signing and credential identities.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.generation == 0 {
            return Err(ValidationError::InvalidProfileGeneration);
        }
        if let Some(signing) = &self.signing {
            signing.validate()?;
        }
        if let Some(http) = &self.http {
            for binding in &http.bindings {
                binding.validate()?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileSet {
    pub version: u32,
    pub generation: u64,
    #[serde(default)]
    pub profiles: BTreeMap<ProfileId, Profile>,
}

impl Default for ProfileSet {
    fn default() -> Self {
        Self {
            version: PROFILE_SET_VERSION,
            generation: 1,
            profiles: BTreeMap::new(),
        }
    }
}

impl ProfileSet {
    /// Validates versioning, map keys, and all contained profiles.
    ///
    /// # Errors
    ///
    /// Returns a [`ValidationError`] for unsupported versions, key/id
    /// mismatches, or an invalid contained profile.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.version != PROFILE_SET_VERSION {
            return Err(ValidationError::UnsupportedProfileSetVersion(self.version));
        }
        for (id, profile) in &self.profiles {
            if id != &profile.id {
                return Err(ValidationError::ProfileKeyMismatch {
                    map_key: id.to_string(),
                    profile_id: profile.id.to_string(),
                });
            }
            profile.validate()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> ProfileId {
        ProfileId::try_from(value.to_owned()).expect("valid test id")
    }

    fn person() -> PersonIdentity {
        PersonIdentity::new("Work User".into(), "work@example.test".into()).expect("valid person")
    }

    fn profile(profile_id: ProfileId) -> Profile {
        Profile {
            id: profile_id,
            author: person(),
            committer: person(),
            signing: None,
            ssh_transport: None,
            http: None,
            generation: 1,
        }
    }

    #[test]
    fn profile_id_rejects_shell_and_path_syntax() {
        for invalid in ["", "-leading", "with space", "work;cmd", "../work", "仕事"] {
            assert_eq!(
                ProfileId::try_from(invalid.to_owned()),
                Err(ValidationError::InvalidProfileId),
                "value: {invalid:?}"
            );
        }
        assert_eq!(id("work.example_1").as_str(), "work.example_1");
    }

    #[test]
    fn person_identity_rejects_git_identity_delimiters_and_controls() {
        for name in ["", "A <B>", "line\nbreak"] {
            assert_eq!(
                PersonIdentity::new(name.into(), "a@example.test".into()),
                Err(ValidationError::InvalidName)
            );
        }
        for email in [
            "missing-at",
            "a@@example.test",
            "a b@example.test",
            "a@x\n.test",
        ] {
            assert_eq!(
                PersonIdentity::new("User".into(), email.into()),
                Err(ValidationError::InvalidEmail)
            );
        }
    }

    #[test]
    fn transport_signing_and_http_are_distinct_after_round_trip() {
        let profile_id = id("work");
        let value = Profile {
            id: profile_id.clone(),
            author: person(),
            committer: person(),
            signing: Some(SigningIdentity {
                format: SigningFormat::Ssh,
                key_reference: "SHA256:signing".into(),
                program: Some(ExecutableRef {
                    path: "/usr/bin/ssh-keygen".into(),
                    arguments: Vec::new(),
                    sha256: Some("00".repeat(32)),
                }),
                commit_policy: SigningPolicy::Required,
                tag_policy: SigningPolicy::Required,
            }),
            ssh_transport: Some(SshIdentity {
                source: SshIdentitySource::PrivateKey {
                    path: "/keys/transport".into(),
                    certificate: None,
                },
                proxy_jump: None,
                known_hosts_file: Some("/keys/known_hosts".into()),
            }),
            http: Some(HttpIdentity {
                bindings: vec![CredentialBinding {
                    protocol: CredentialProtocol::Https,
                    host: "git.example.test".into(),
                    port: None,
                    path_prefix: Some("/team/".into()),
                    username: "work-user".into(),
                    backend: CredentialBackend::SecretStore {
                        service: "gus".into(),
                        account: "work".into(),
                    },
                }],
            }),
            generation: 7,
        };
        let mut set = ProfileSet::default();
        set.profiles.insert(profile_id, value);
        set.validate().expect("valid profile set");

        let encoded = toml::to_string(&set).expect("serialize profile set");
        let decoded: ProfileSet = toml::from_str(&encoded).expect("deserialize profile set");
        assert_eq!(decoded, set);
        decoded.validate().expect("round-tripped set remains valid");
    }

    #[test]
    fn profile_set_rejects_mismatched_map_key() {
        let mut set = ProfileSet::default();
        set.profiles.insert(id("map-key"), profile(id("embedded")));
        assert_eq!(
            set.validate(),
            Err(ValidationError::ProfileKeyMismatch {
                map_key: "map-key".into(),
                profile_id: "embedded".into(),
            })
        );
    }
}
