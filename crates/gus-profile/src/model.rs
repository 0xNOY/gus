use std::{collections::BTreeMap, fmt, net::IpAddr, path::PathBuf, str::FromStr};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl TryFrom<String> for Sha256Digest {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ValidationError::InvalidSha256Digest);
        }
        let mut digest = [0; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = hex_nibble(pair[0]).ok_or(ValidationError::InvalidSha256Digest)?;
            let low = hex_nibble(pair[1]).ok_or(ValidationError::InvalidSha256Digest)?;
            digest[index] = (high << 4) | low;
        }
        Ok(Self(digest))
    }
}

impl From<Sha256Digest> for String {
    fn from(value: Sha256Digest) -> Self {
        let mut encoded = String::with_capacity(64);
        for byte in value.0 {
            use std::fmt::Write as _;
            write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
        }
        encoded
    }
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutableRef {
    pub path: PathBuf,
    #[serde(default)]
    pub arguments: Vec<String>,
    pub sha256: Sha256Digest,
}

impl ExecutableRef {
    /// Validates arguments that will later be passed directly to a process.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidExecutableArgument`] for control
    /// characters. This does not resolve or trust the executable path.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if !self.path.is_absolute() {
            return Err(ValidationError::InvalidExecutablePath);
        }
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
        public_key_fingerprint: SshFingerprint,
    },
    DedicatedAgent {
        endpoint: PathBuf,
        public_key_fingerprint: SshFingerprint,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SshFingerprint(String);

impl SshFingerprint {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SshFingerprint {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let payload = value.strip_prefix("SHA256:").unwrap_or_default();
        if payload.len() != 43
            || !payload
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
        {
            return Err(ValidationError::InvalidSshFingerprint);
        }
        Ok(Self(value))
    }
}

impl From<SshFingerprint> for String {
    fn from(value: SshFingerprint) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyJump {
    pub host: CredentialHost,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub host_key_fingerprint: SshFingerprint,
}

impl ProxyJump {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.port == Some(0)
            || self.user.as_ref().is_some_and(|user| {
                user.is_empty()
                    || user.len() > 255
                    || !user.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
            })
        {
            return Err(ValidationError::InvalidProxyJump);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshIdentity {
    pub source: SshIdentitySource,
    pub proxy_jump: Option<ProxyJump>,
    pub known_hosts_file: Option<PathBuf>,
}

impl SshIdentity {
    /// Validates SSH references before any managed OpenSSH configuration is
    /// rendered.
    ///
    /// # Errors
    ///
    /// Rejects relative/empty paths, invalid agent fingerprints, and invalid
    /// structured proxy-hop data.
    pub fn validate(&self) -> Result<(), ValidationError> {
        let paths_are_absolute = match &self.source {
            SshIdentitySource::PrivateKey {
                path, certificate, ..
            } => {
                path.is_absolute()
                    && certificate
                        .as_ref()
                        .is_none_or(|certificate| certificate.is_absolute())
            }
            SshIdentitySource::DedicatedAgent { endpoint, .. } => endpoint.is_absolute(),
        };
        if !paths_are_absolute
            || !self
                .known_hosts_file
                .as_ref()
                .is_some_and(|path| path.is_absolute())
        {
            return Err(ValidationError::InvalidSshPath);
        }
        if let Some(proxy_jump) = &self.proxy_jump {
            proxy_jump.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CredentialHost(String);

impl CredentialHost {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CredentialHost {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let canonical = if let Ok(address) = IpAddr::from_str(&value) {
            address.to_string()
        } else {
            let value = value
                .strip_suffix('.')
                .unwrap_or(&value)
                .to_ascii_lowercase();
            let valid = !value.is_empty()
                && value.len() <= 253
                && value.is_ascii()
                && value.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && label.as_bytes()[0].is_ascii_alphanumeric()
                        && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                        && label
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                });
            if !valid {
                return Err(ValidationError::InvalidCredentialHost);
            }
            value
        };
        Ok(Self(canonical))
    }
}

impl From<CredentialHost> for String {
    fn from(value: CredentialHost) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CredentialPathPrefix(String);

impl CredentialPathPrefix {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn component_prefix_of(&self, path: &Self) -> bool {
        self.0 == "/"
            || self.0 == path.0
            || path
                .0
                .strip_prefix(&self.0)
                .is_some_and(|suffix| suffix.starts_with('/'))
    }
}

impl TryFrom<String> for CredentialPathPrefix {
    type Error = ValidationError;

    fn try_from(mut value: String) -> Result<Self, Self::Error> {
        if value.len() > 4096
            || !value.starts_with('/')
            || value.contains(['\\', '?', '#', '%'])
            || has_forbidden_control(&value)
            || value
                .split('/')
                .skip(1)
                .any(|part| part.is_empty() || matches!(part, "." | ".."))
        {
            if value == "/" {
                return Ok(Self(value));
            }
            return Err(ValidationError::InvalidCredentialPath);
        }
        while value.len() > 1 && value.ends_with('/') {
            value.pop();
        }
        Ok(Self(value))
    }
}

impl From<CredentialPathPrefix> for String {
    fn from(value: CredentialPathPrefix) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialProtocol {
    Http,
    Https,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalCredentialRequest {
    protocol: CredentialProtocol,
    host: CredentialHost,
    port: u16,
    path: CredentialPathPrefix,
    username: Option<String>,
}

impl CanonicalCredentialRequest {
    #[must_use]
    pub const fn protocol(&self) -> CredentialProtocol {
        self.protocol
    }

    #[must_use]
    pub fn host(&self) -> &CredentialHost {
        &self.host
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    #[must_use]
    pub fn path(&self) -> &CredentialPathPrefix {
        &self.path
    }

    #[must_use]
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// Canonicalizes an endpoint-capability context whose host and port are
    /// already structurally separated and whose path is absolute.
    ///
    /// # Errors
    ///
    /// Rejects ambiguous hosts/paths, port zero, and invalid usernames.
    pub fn from_endpoint(
        protocol: CredentialProtocol,
        host: String,
        port: Option<u16>,
        path: String,
        username: Option<String>,
    ) -> Result<Self, ValidationError> {
        let host = CredentialHost::try_from(host)?;
        let path = CredentialPathPrefix::try_from(path)?;
        let port = match port {
            Some(0) => return Err(ValidationError::InvalidCredentialHost),
            Some(port) => port,
            None => match protocol {
                CredentialProtocol::Http => 80,
                CredentialProtocol::Https => 443,
            },
        };
        if username.as_ref().is_some_and(|username| {
            username.is_empty() || username.len() > 255 || has_forbidden_control(username)
        }) {
            return Err(ValidationError::InvalidCredentialUsername);
        }
        Ok(Self {
            protocol,
            host,
            port,
            path,
            username,
        })
    }

    /// Parses Git credential protocol fields, including `host=host:port`,
    /// bracketed IPv6, and paths without a leading slash, into the same form
    /// used by endpoint capabilities.
    ///
    /// # Errors
    ///
    /// Rejects malformed brackets/ports and any host, path, or username that
    /// cannot be represented canonically.
    pub fn from_git_protocol(
        protocol: CredentialProtocol,
        host_field: &str,
        path_field: Option<String>,
        username: Option<String>,
    ) -> Result<Self, ValidationError> {
        let (host, port) = split_git_host_port(host_field)?;
        let mut path = path_field.unwrap_or_else(|| "/".to_owned());
        if path.is_empty() {
            path.push('/');
        } else if !path.starts_with('/') {
            path.insert(0, '/');
        }
        Self::from_endpoint(protocol, host, port, path, username)
    }
}

fn split_git_host_port(value: &str) -> Result<(String, Option<u16>), ValidationError> {
    if let Some(bracketed) = value.strip_prefix('[') {
        let (host, suffix) = bracketed
            .split_once(']')
            .ok_or(ValidationError::InvalidCredentialHost)?;
        let port = if suffix.is_empty() {
            None
        } else {
            Some(
                suffix
                    .strip_prefix(':')
                    .ok_or(ValidationError::InvalidCredentialHost)?
                    .parse()
                    .map_err(|_| ValidationError::InvalidCredentialHost)?,
            )
        };
        return Ok((host.to_owned(), port));
    }
    if IpAddr::from_str(value).is_ok() {
        return Ok((value.to_owned(), None));
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if host.contains(':') {
            return Err(ValidationError::InvalidCredentialHost);
        }
        let port = port
            .parse()
            .map_err(|_| ValidationError::InvalidCredentialHost)?;
        return Ok((host.to_owned(), Some(port)));
    }
    Ok((value.to_owned(), None))
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
    pub host: CredentialHost,
    pub port: Option<u16>,
    pub path_prefix: Option<CredentialPathPrefix>,
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
        if self.port == Some(0) {
            return Err(ValidationError::InvalidCredentialHost);
        }
        if self.username.is_empty()
            || self.username.len() > 255
            || has_forbidden_control(&self.username)
        {
            return Err(ValidationError::InvalidCredentialUsername);
        }
        match &self.backend {
            CredentialBackend::ManagedExecutable { executable } => executable.validate()?,
            CredentialBackend::SecretStore { service, account }
                if service.is_empty()
                    || account.is_empty()
                    || has_forbidden_control(service)
                    || has_forbidden_control(account) =>
            {
                return Err(ValidationError::InvalidSecretStoreReference);
            }
            CredentialBackend::SecretStore { .. } => {}
        }
        Ok(())
    }

    fn effective_port(&self) -> u16 {
        match self.port {
            Some(port) => port,
            None => match self.protocol {
                CredentialProtocol::Http => 80,
                CredentialProtocol::Https => 443,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpIdentity {
    #[serde(default)]
    pub bindings: Vec<CredentialBinding>,
}

impl HttpIdentity {
    /// Validates every canonical binding and rejects equal-precedence scopes.
    /// Overlapping component prefixes are allowed and use longest-prefix
    /// selection.
    ///
    /// # Errors
    ///
    /// Returns a [`ValidationError`] for an invalid binding or duplicate
    /// canonical protocol/host/port/path scope.
    pub fn validate(&self) -> Result<(), ValidationError> {
        for (index, binding) in self.bindings.iter().enumerate() {
            binding.validate()?;
            for other in &self.bindings[index + 1..] {
                if binding.protocol == other.protocol
                    && binding.host == other.host
                    && binding.effective_port() == other.effective_port()
                    && binding.path_prefix == other.path_prefix
                {
                    return Err(ValidationError::DuplicateCredentialBinding);
                }
            }
        }
        Ok(())
    }

    /// Selects a binding using exact protocol/host/default-normalized port and
    /// longest component-prefix path matching.
    ///
    /// # Errors
    ///
    /// Returns an error if the profile contains invalid or duplicate scopes.
    pub fn select_binding(
        &self,
        request: &CanonicalCredentialRequest,
    ) -> Result<Option<&CredentialBinding>, ValidationError> {
        self.validate()?;
        Ok(self
            .bindings
            .iter()
            .filter(|binding| {
                binding.protocol == request.protocol
                    && binding.host == request.host
                    && binding.effective_port() == request.port
                    && binding
                        .path_prefix
                        .as_ref()
                        .is_none_or(|prefix| prefix.component_prefix_of(&request.path))
                    && request
                        .username
                        .as_ref()
                        .is_none_or(|username| binding.username == *username)
            })
            .max_by_key(|binding| {
                binding
                    .path_prefix
                    .as_ref()
                    .map_or(0, |prefix| prefix.as_str().len())
            }))
    }
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
        if let Some(ssh_transport) = &self.ssh_transport {
            ssh_transport.validate()?;
        }
        if let Some(http) = &self.http {
            http.validate()?;
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
        if self.generation == 0 {
            return Err(ValidationError::InvalidProfileSetGeneration);
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

    fn digest() -> Sha256Digest {
        Sha256Digest::try_from("00".repeat(32)).expect("valid digest")
    }

    fn host(value: &str) -> CredentialHost {
        CredentialHost::try_from(value.to_owned()).expect("valid host")
    }

    fn path(value: &str) -> CredentialPathPrefix {
        CredentialPathPrefix::try_from(value.to_owned()).expect("valid path")
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
                    sha256: digest(),
                }),
                commit_policy: SigningPolicy::Required,
                tag_policy: SigningPolicy::Required,
            }),
            ssh_transport: Some(SshIdentity {
                source: SshIdentitySource::PrivateKey {
                    path: "/keys/transport".into(),
                    certificate: None,
                    public_key_fingerprint: SshFingerprint::try_from(format!(
                        "SHA256:{}",
                        "A".repeat(43)
                    ))
                    .expect("valid fingerprint"),
                },
                proxy_jump: None,
                known_hosts_file: Some("/keys/known_hosts".into()),
            }),
            http: Some(HttpIdentity {
                bindings: vec![CredentialBinding {
                    protocol: CredentialProtocol::Https,
                    host: host("git.example.test"),
                    port: None,
                    path_prefix: Some(path("/team")),
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

    #[test]
    fn executable_ssh_and_set_generations_are_validated() {
        let executable = ExecutableRef {
            path: "relative/helper".into(),
            arguments: Vec::new(),
            sha256: digest(),
        };
        assert_eq!(
            executable.validate(),
            Err(ValidationError::InvalidExecutablePath)
        );
        assert_eq!(
            Sha256Digest::try_from("xyz".to_owned()),
            Err(ValidationError::InvalidSha256Digest)
        );
        assert_eq!(
            SshFingerprint::try_from(String::new()),
            Err(ValidationError::InvalidSshFingerprint)
        );

        let mut value = profile(id("ssh"));
        value.ssh_transport = Some(SshIdentity {
            source: SshIdentitySource::PrivateKey {
                path: "relative-key".into(),
                certificate: None,
                public_key_fingerprint: SshFingerprint::try_from(format!(
                    "SHA256:{}",
                    "A".repeat(43)
                ))
                .expect("valid fingerprint"),
            },
            proxy_jump: None,
            known_hosts_file: Some("relative-known-hosts".into()),
        });
        assert_eq!(value.validate(), Err(ValidationError::InvalidSshPath));

        let set = ProfileSet {
            generation: 0,
            ..ProfileSet::default()
        };
        assert_eq!(
            set.validate(),
            Err(ValidationError::InvalidProfileSetGeneration)
        );
    }

    #[test]
    fn credential_host_and_path_inputs_are_canonical() {
        let canonical_host = host("Git.Example.Test.");
        assert_eq!(canonical_host.as_str(), "git.example.test");
        for invalid in [
            "https://example.test",
            "user@example.test",
            "example.test/path",
            "example.test:443",
        ] {
            assert_eq!(
                CredentialHost::try_from(invalid.to_owned()),
                Err(ValidationError::InvalidCredentialHost)
            );
        }
        for invalid in [
            "team",
            "/team/%2e%2e/admin",
            "/team/../admin",
            "/team-evil?",
        ] {
            assert_eq!(
                CredentialPathPrefix::try_from(invalid.to_owned()),
                Err(ValidationError::InvalidCredentialPath)
            );
        }
    }

    #[test]
    fn http_bindings_use_longest_component_prefix() {
        let canonical_host = host("git.example.test");
        let identity = HttpIdentity {
            bindings: vec![
                CredentialBinding {
                    protocol: CredentialProtocol::Https,
                    host: canonical_host.clone(),
                    port: None,
                    path_prefix: Some(path("/team")),
                    username: "team".into(),
                    backend: CredentialBackend::SecretStore {
                        service: "gus".into(),
                        account: "team".into(),
                    },
                },
                CredentialBinding {
                    protocol: CredentialProtocol::Https,
                    host: canonical_host.clone(),
                    port: Some(443),
                    path_prefix: Some(path("/team/admin")),
                    username: "admin".into(),
                    backend: CredentialBackend::SecretStore {
                        service: "gus".into(),
                        account: "admin".into(),
                    },
                },
            ],
        };
        identity
            .validate()
            .expect("overlapping prefixes are deterministic");
        let selected = identity
            .select_binding(
                &CanonicalCredentialRequest::from_git_protocol(
                    CredentialProtocol::Https,
                    &format!("{}:443", canonical_host.as_str()),
                    Some("team/admin/repository".into()),
                    Some("admin".into()),
                )
                .expect("canonical request"),
            )
            .expect("valid identity")
            .expect("matching binding");
        assert_eq!(selected.username, "admin");
        assert!(
            identity
                .select_binding(
                    &CanonicalCredentialRequest::from_git_protocol(
                        CredentialProtocol::Https,
                        canonical_host.as_str(),
                        Some("team-evil".into()),
                        None,
                    )
                    .expect("canonical request"),
                )
                .expect("valid identity")
                .is_none()
        );
        assert!(
            identity
                .select_binding(
                    &CanonicalCredentialRequest::from_git_protocol(
                        CredentialProtocol::Https,
                        canonical_host.as_str(),
                        Some("team/admin/repository".into()),
                        Some("different-user".into()),
                    )
                    .expect("canonical request"),
                )
                .expect("valid identity")
                .is_none()
        );

        let mut duplicate = identity;
        duplicate.bindings.push(CredentialBinding {
            protocol: CredentialProtocol::Https,
            host: canonical_host,
            port: Some(443),
            path_prefix: Some(path("/team")),
            username: "duplicate".into(),
            backend: CredentialBackend::SecretStore {
                service: "gus".into(),
                account: "duplicate".into(),
            },
        });
        assert_eq!(
            duplicate.validate(),
            Err(ValidationError::DuplicateCredentialBinding)
        );

        let ipv6 = CanonicalCredentialRequest::from_git_protocol(
            CredentialProtocol::Https,
            "[2001:db8::1]:8443",
            Some("repository.git".into()),
            None,
        )
        .expect("bracketed IPv6 credential context");
        assert_eq!(ipv6.host.as_str(), "2001:db8::1");
        assert_eq!(ipv6.port, 8443);
        assert_eq!(ipv6.path.as_str(), "/repository.git");
    }
}
