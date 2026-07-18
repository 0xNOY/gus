//! Native operating-system observations used to derive GUS session identity.
//!
//! Values in this crate are evidence produced by an operating-system backend,
//! not claims accepted from IPC, environment variables, or command-line
//! arguments. Their constructors are deliberately private. The identities are
//! suitable for equality and hashing, but they do not make processes sharing
//! one OS user into mutually distrustful security principals.
//! FreeBSD observations are scoped to one prison: the kernel reports the
//! observer's current prison as JID zero, so brokers, sockets, and stored
//! session authority must never be shared across prison boundaries.

use std::{fmt, num::NonZeroU32, num::NonZeroU64};

#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows"
))]
use sha2::{Digest, Sha256};
use thiserror::Error;

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod bsd;
#[cfg(any(target_os = "macos", target_os = "freebsd", test))]
mod bsd_model;
#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(any(target_os = "windows", test))]
mod windows_model;

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

/// Opaque identity for one local OS user in this observer's native isolation
/// boundary.
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

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows",
        test
    ))]
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

/// Opaque identity for the native time domain of a process start value.
///
/// Linux and FreeBSD bind a host boot ID to boot-relative process time.
/// Platforms whose process creation time has an absolute epoch bind that epoch
/// instead. Consumers compare this value together with `start_time` and never
/// interpret either field in isolation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessTimeDomainIdentity([u8; IDENTITY_DIGEST_BYTES]);

impl ProcessTimeDomainIdentity {
    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows",
        test
    ))]
    fn from_native_bytes(family: PlatformFamily, native: &[u8]) -> Self {
        Self(identity_digest(
            b"gus.platform.process-time-domain.v1",
            family,
            native,
        ))
    }
}

impl fmt::Debug for ProcessTimeDomainIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProcessTimeDomainIdentity([REDACTED])")
    }
}

/// Identity of a process that remains stable across PID reuse.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessIdentity {
    time_domain: ProcessTimeDomainIdentity,
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
    pub const fn time_domain(self) -> ProcessTimeDomainIdentity {
        self.time_domain
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows",
        test
    ))]
    const fn from_observation(
        time_domain: ProcessTimeDomainIdentity,
        pid: NonZeroU32,
        start_time: NonZeroU64,
        user: OsUserIdentity,
    ) -> Self {
        Self {
            time_domain,
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
            .field("time_domain", &self.time_domain)
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

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows",
        test
    ))]
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

/// A terminal or console session anchored to its live native root process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TerminalSessionIdentity {
    terminal: TerminalIdentity,
    anchor_process: ProcessIdentity,
}

impl TerminalSessionIdentity {
    #[must_use]
    pub const fn terminal(self) -> TerminalIdentity {
        self.terminal
    }

    #[must_use]
    pub const fn anchor_process(self) -> ProcessIdentity {
        self.anchor_process
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows",
        test
    ))]
    const fn from_observation(terminal: TerminalIdentity, anchor_process: ProcessIdentity) -> Self {
        Self {
            terminal,
            anchor_process,
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
    pub const fn terminal_session(self) -> Option<TerminalSessionIdentity> {
        self.terminal
    }

    #[must_use]
    pub const fn has_terminal_session(self) -> bool {
        self.terminal.is_some()
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows",
        test
    ))]
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

    /// Observes the current process and its native terminal-session anchor.
    ///
    /// # Errors
    ///
    /// Fails closed if the backend is unavailable, kernel data is malformed,
    /// the process changes during observation, or a terminal anchor cannot be
    /// bound to the same user and terminal session.
    pub fn observe(self) -> Result<LocalSessionObservation, ObservationError> {
        #[cfg(target_os = "linux")]
        {
            linux::observe_current()
        }
        #[cfg(target_os = "windows")]
        {
            windows::observe_current()
        }
        #[cfg(target_os = "macos")]
        {
            macos::observe_current()
        }
        #[cfg(target_os = "freebsd")]
        {
            freebsd::observe_current()
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "freebsd",
            target_os = "windows"
        )))]
        {
            Err(ObservationError::UnsupportedPlatform)
        }
    }
}

/// Bounded native resource consulted during observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ObservationResource {
    ProcessTimeDomain,
    CallerProcess,
    CallerUser,
    ProcessAncestry,
    TerminalSession,
    TerminalAnchorProcess,
    TerminalAnchorUser,
}

impl fmt::Display for ObservationResource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::ProcessTimeDomain => "process time domain",
            Self::CallerProcess => "caller process",
            Self::CallerUser => "caller user",
            Self::ProcessAncestry => "process ancestry",
            Self::TerminalSession => "terminal session",
            Self::TerminalAnchorProcess => "terminal anchor process",
            Self::TerminalAnchorUser => "terminal anchor user",
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
    #[error("terminal anchor changed during observation")]
    TerminalAnchorChanged,
    #[error("terminal is not bound to the observed user and anchor process")]
    TerminalBindingMismatch,
}

#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows",
    test
))]
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
