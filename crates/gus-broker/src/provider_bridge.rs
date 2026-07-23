#[cfg(unix)]
use std::{
    io::{self, Read as _, Write as _},
    os::{fd::AsRawFd as _, unix::ffi::OsStrExt as _},
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
    thread,
    time::Duration,
};

#[cfg(unix)]
use gus_broker::connect_published_provider;

#[cfg(unix)]
const IO_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(unix)]
const RELAY_BUFFER_BYTES: usize = 16 * 1024;
#[cfg(unix)]
const BROKER_START_ATTEMPTS: usize = 100;

#[cfg(unix)]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("gus-provider-bridge: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!("gus-provider-bridge: this build does not support a native provider transport");
    std::process::ExitCode::FAILURE
}

#[cfg(unix)]
fn run() -> Result<(), BridgeError> {
    let runtime_directory = parse_runtime_directory(std::env::args_os())?;
    let mut broker = connect_or_start_broker(&runtime_directory)?;
    relay(&mut broker)
}

#[cfg(unix)]
fn connect_or_start_broker(
    runtime_directory: &Path,
) -> Result<gus_platform::AuthenticatedUnixStream, BridgeError> {
    if let Ok(stream) = connect_published_provider(runtime_directory, IO_TIMEOUT, IO_TIMEOUT) {
        return Ok(stream);
    }
    let executable = std::env::current_exe().map_err(|_| BridgeError::BrokerUnavailable)?;
    let broker = executable
        .parent()
        .map(|parent| parent.join("gus-broker"))
        .ok_or(BridgeError::BrokerUnavailable)?;
    Command::new(broker)
        .env("GUS_RUNTIME_DIR", runtime_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| BridgeError::BrokerUnavailable)?;
    for _ in 0..BROKER_START_ATTEMPTS {
        if let Ok(stream) = connect_published_provider(runtime_directory, IO_TIMEOUT, IO_TIMEOUT) {
            return Ok(stream);
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(BridgeError::BrokerUnavailable)
}

#[cfg(unix)]
fn parse_runtime_directory(
    mut arguments: impl Iterator<Item = std::ffi::OsString>,
) -> Result<PathBuf, BridgeError> {
    let _program = arguments.next().ok_or(BridgeError::InvalidArguments)?;
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--runtime-dir")) {
        return Err(BridgeError::InvalidArguments);
    }
    let directory = arguments.next().ok_or(BridgeError::InvalidArguments)?;
    if arguments.next().is_some()
        || directory.as_bytes().is_empty()
        || !Path::new(&directory).is_absolute()
    {
        return Err(BridgeError::InvalidArguments);
    }
    Ok(directory.into())
}

#[cfg(unix)]
fn relay(stream: &mut gus_platform::AuthenticatedUnixStream) -> Result<(), BridgeError> {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    let mut buffer = [0_u8; RELAY_BUFFER_BYTES];
    loop {
        let mut descriptors = [
            libc::pollfd {
                fd: libc::STDIN_FILENO,
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            },
            libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            },
        ];
        // SAFETY: `descriptors` is writable storage for two poll records.
        let ready = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                libc::nfds_t::try_from(descriptors.len()).map_err(|_| BridgeError::RelayFailed)?,
                -1,
            )
        };
        if ready == -1 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(BridgeError::RelayFailed);
        }
        if descriptors[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            let count = input
                .read(&mut buffer)
                .map_err(|_| BridgeError::RelayFailed)?;
            if count == 0 {
                return Ok(());
            }
            stream
                .write_all(&buffer[..count])
                .map_err(|_| BridgeError::RelayFailed)?;
            stream.flush().map_err(|_| BridgeError::RelayFailed)?;
        }
        if descriptors[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            let count = stream
                .read(&mut buffer)
                .map_err(|_| BridgeError::RelayFailed)?;
            if count == 0 {
                return Ok(());
            }
            output
                .write_all(&buffer[..count])
                .map_err(|_| BridgeError::RelayFailed)?;
            output.flush().map_err(|_| BridgeError::RelayFailed)?;
        }
        if descriptors
            .iter()
            .any(|descriptor| descriptor.revents & (libc::POLLERR | libc::POLLNVAL) != 0)
        {
            return Err(BridgeError::RelayFailed);
        }
    }
}

#[cfg(unix)]
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
enum BridgeError {
    #[error("usage: gus-provider-bridge --runtime-dir <absolute-directory>")]
    InvalidArguments,
    #[error("the published GUS broker is unavailable or unauthenticated")]
    BrokerUnavailable,
    #[error("the provider relay failed closed")]
    RelayFailed,
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn runtime_directory_is_exact_and_absolute() {
        assert_eq!(
            parse_runtime_directory(
                ["bridge", "--runtime-dir", "/tmp/gus"]
                    .into_iter()
                    .map(std::ffi::OsString::from)
            ),
            Ok(PathBuf::from("/tmp/gus"))
        );
        for arguments in [
            vec!["bridge"],
            vec!["bridge", "--runtime-dir"],
            vec!["bridge", "--runtime-dir", "relative"],
            vec!["bridge", "--runtime-dir", "/tmp/gus", "extra"],
        ] {
            assert_eq!(
                parse_runtime_directory(arguments.into_iter().map(std::ffi::OsString::from)),
                Err(BridgeError::InvalidArguments)
            );
        }
    }
}
