use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ValidationError {
    #[error(
        "profile id must be 1-64 ASCII characters and use only letters, digits, '.', '_' or '-'"
    )]
    InvalidProfileId,
    #[error(
        "identity name must be non-empty, at most 256 characters, and contain no control or '<'/'>' characters"
    )]
    InvalidName,
    #[error("identity email must be a single-line address with one '@' and no angle brackets")]
    InvalidEmail,
    #[error("credential host must be a non-empty DNS name or address without control characters")]
    InvalidCredentialHost,
    #[error("credential path prefix must start with '/' and contain no control characters")]
    InvalidCredentialPath,
    #[error("credential username must be non-empty and contain no control characters")]
    InvalidCredentialUsername,
    #[error("executable argument contains a NUL or control character")]
    InvalidExecutableArgument,
    #[error("profile map key '{map_key}' does not match embedded id '{profile_id}'")]
    ProfileKeyMismatch { map_key: String, profile_id: String },
    #[error("profile generation must be greater than zero")]
    InvalidProfileGeneration,
    #[error("profile set version {0} is not supported")]
    UnsupportedProfileSetVersion(u32),
}

pub(crate) fn has_forbidden_control(value: &str) -> bool {
    value.chars().any(char::is_control)
}
