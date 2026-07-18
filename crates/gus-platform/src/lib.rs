//! Native operating-system observations used to derive GUS session identity.
//!
//! Values in this crate are evidence produced by an operating-system backend,
//! not claims accepted from IPC, environment variables, or command-line
//! arguments. Their constructors are deliberately private. The identities are
//! suitable for equality and hashing, but they do not make processes sharing
//! one OS user into mutually distrustful security principals.

use std::{fmt, num::NonZeroU32, num::NonZeroU64};

use sha2::{Digest, Sha256};
use thiserror::Error;

#[cfg(target_os = "linux")]
mod linux;

const IDENTITY_DIGEST_BYTES: usize = 32;

/// Operating-system family that produced an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PlatformFamily {
    Linux,
    MacOs,
    FreeBsd,
    Windows,
    Other,
}

/// Opaque identity for one local OS user.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct OsUserIdentity {
    family: PlatformFamily,
    digest: [u8; IDENTITY_DIGEST_BYTES],
}

impl OsUserIdentity {
    #[must_use]
    pub const fn family(self) -> PlatformFamily {
        self.family
    }

    fn from_native_bytes(family: PlatformFamily, native: &[u8]) -> Self {
        Self {
            family,
            digest: identity_digest(b"gus.platform.user.v1", family, native),
        }
    }
}

impl fmt::Debug for OsUserIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OsUserIdentity")
            .field("family", &self.family)
            .field("opaque", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Opaque identity for one host boot. It prevents process start counters from
/// being reused across a reboot.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BootIdentity([u8; IDENTITY_DIGEST_BYTES]);

impl BootIdentity {
    fn from_native_bytes(family: PlatformFamily, native: &[u8]) -> Self {
        Self(identity_digest(b"gus.platform.boot.v1", family, native))
    }
}

impl fmt::Debug for BootIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BootIdentity([REDACTED])")
    }
}

/// Identity of a process that remains stable across PID reuse.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessIdentity {
    boot: BootIdentity,
    pid: NonZeroU32,
    start_time: NonZeroU64,
    user: OsUserIdentity,
}

impl ProcessIdentity {
    #[must_use]
    pub const fn pid(self) -> NonZeroU32 {
        self.pid
    }

    #[must_use]
    pub const fn start_time(self) -> NonZeroU64 {
        self.start_time
    }

    #[must_use]
    pub const fn user(self) -> OsUserIdentity {
        self.user
    }

    #[must_use]
    pub const fn boot(self) -> BootIdentity {
        self.boot
    }

    const fn from_observation(
        boot: BootIdentity,
        pid: NonZeroU32,
        start_time: NonZeroU64,
        user: OsUserIdentity,
    ) -> Self {
        Self {
            boot,
            pid,
            start_time,
            user,
        }
    }
}

impl fmt::Debug for ProcessIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessIdentity")
            .field("pid", &self.pid)
            .field("start_time", &self.start_time)
            .field("boot", &self.boot)
            .field("user", &self.user)
            .finish()
    }
}

/// Opaque identity for a controlling terminal or console.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TerminalIdentity {
    family: PlatformFamily,
    digest: [u8; IDENTITY_DIGEST_BYTES],
}

impl TerminalIdentity {
    #[must_use]
    pub const fn family(self) -> PlatformFamily {
        self.family
    }

    fn from_native_bytes(family: PlatformFamily, native: &[u8]) -> Self {
        Self {
            family,
            digest: identity_digest(b"gus.platform.terminal.v1", family, native),
        }
    }
}

impl fmt::Debug for TerminalIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TerminalIdentity")
            .field("family", &self.family)
            .field("opaque", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// A controlling-terminal session anchored to its live session leader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TerminalSessionIdentity {
    terminal: TerminalIdentity,
    session_leader: ProcessIdentity,
}

impl TerminalSessionIdentity {
    #[must_use]
    pub const fn terminal(self) -> TerminalIdentity {
        self.terminal
    }

    #[must_use]
    pub const fn session_leader(self) -> ProcessIdentity {
        self.session_leader
    }

    const fn from_observation(terminal: TerminalIdentity, session_leader: ProcessIdentity) -> Self {
        Self {
            terminal,
            session_leader,
        }
    }
}

/// OS-derived facts for the process which invoked GUS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LocalSessionObservation {
    caller: ProcessIdentity,
    parent_pid: Option<NonZeroU32>,
    terminal: Option<TerminalSessionIdentity>,
}

impl LocalSessionObservation {
    #[must_use]
    pub const fn caller(self) -> ProcessIdentity {
        self.caller
    }

    #[must_use]
    pub const fn parent_pid(self) -> Option<NonZeroU32> {
        self.parent_pid
    }

    #[must_use]
    pub const fn terminal(self) -> Option<TerminalSessionIdentity> {
        self.terminal
    }

    #[must_use]
    pub const fn has_controlling_terminal(self) -> bool {
        self.terminal.is_some()
    }

    const fn from_observation(
        caller: ProcessIdentity,
        parent_pid: Option<NonZeroU32>,
        terminal: Option<TerminalSessionIdentity>,
    ) -> Self {
        Self {
            caller,
            parent_pid,
            terminal,
        }
    }
}

/// Native observer for the current GUS process.
#[derive(Debug, Default, Clone, Copy)]
pub struct CurrentSessionObserver;

impl CurrentSessionObserver {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Observes the current process and its controlling-terminal anchor.
    ///
    /// # Errors
    ///
    /// Fails closed if the backend is unavailable, kernel data is malformed,
    /// the process changes during observation, or a terminal session leader
    /// cannot be bound to the same user and terminal.
    pub fn observe(self) -> Result<LocalSessionObservation, ObservationError> {
        #[cfg(target_os = "linux")]
        {
            linux::observe_current()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(ObservationError::UnsupportedPlatform)
        }
    }
}

/// Bounded native resource consulted during observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ObservationResource {
    BootIdentity,
    CallerProcess,
    CallerUser,
    SessionLeaderProcess,
    SessionLeaderUser,
}

impl fmt::Display for ObservationResource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::BootIdentity => "boot identity",
            Self::CallerProcess => "caller process",
            Self::CallerUser => "caller user",
            Self::SessionLeaderProcess => "session leader process",
            Self::SessionLeaderUser => "session leader user",
        };
        formatter.write_str(name)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ObservationError {
    #[error("native session observation is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("failed to read {resource}: {kind:?}")]
    Read {
        resource: ObservationResource,
        kind: std::io::ErrorKind,
    },
    #[error("{resource} exceeded its native size bound")]
    Oversized { resource: ObservationResource },
    #[error("{resource} had a malformed native representation")]
    Malformed { resource: ObservationResource },
    #[error("caller process changed during observation")]
    ProcessChanged,
    #[error("session leader changed during observation")]
    SessionLeaderChanged,
    #[error("controlling terminal is not bound to the observed user and session leader")]
    SessionLeaderBindingMismatch,
}

fn identity_digest(
    domain: &[u8],
    family: PlatformFamily,
    native: &[u8],
) -> [u8; IDENTITY_DIGEST_BYTES] {
    let family_tag: &[u8] = match family {
        PlatformFamily::Linux => b"linux",
        PlatformFamily::MacOs => b"macos",
        PlatformFamily::FreeBsd => b"freebsd",
        PlatformFamily::Windows => b"windows",
        PlatformFamily::Other => b"other",
    };
    let mut hasher = Sha256::new();
    hasher.update(
        u64::try_from(domain.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(domain);
    hasher.update(
        u64::try_from(family_tag.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(family_tag);
    hasher.update(
        u64::try_from(native.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(native);
    hasher.finalize().into()
}
