use std::process::ExitCode;

#[cfg(target_os = "linux")]
use std::{
    fs::OpenOptions,
    io::Read as _,
    os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
use gus_broker::{
    PendingUnixClient, ProviderCommandOutcome, PublishedUnixProviderEndpoint,
    UnixProviderConnection, observe_linux_shim,
};
#[cfg(target_os = "linux")]
use gus_ipc::{
    BrokerError, BrokerShimMessage, Digest32, ErrorCode, ErrorDetail, ErrorPhase, Generation,
    ProfilePresentation, ProviderDecision, ProviderStatusSnapshot, RepositoryPresentation,
    RequestId, ResolvedSelection, ScopePresentation, SelectionPrompt, SelectionScopePresentation,
    ShimRequest, ShimResponseFrame,
};
#[cfg(target_os = "linux")]
use gus_platform::{ProcessIdentity, observe_process_parent};
#[cfg(target_os = "linux")]
use gus_profile::{Profile, ProfileId, ProfileSet};
#[cfg(target_os = "linux")]
use sha2::{Digest as _, Sha256};

#[cfg(target_os = "linux")]
const IO_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(target_os = "linux")]
const SELECTION_TIMEOUT: Duration = Duration::from_secs(60);
#[cfg(target_os = "linux")]
const HEARTBEAT_INTERVAL_MILLIS: u32 = 30_000;
#[cfg(target_os = "linux")]
const MAX_PROFILE_STORE_BYTES: u64 = 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_PROVIDER_WORK: usize = 64;

fn main() -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        match run_linux() {
            Ok(never) => match never {},
            Err(error) => {
                eprintln!("GUS_E_BROKER_UNAVAILABLE: {error}");
                ExitCode::from(75)
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("GUS_E_PLATFORM_UNSUPPORTED: the broker daemon currently requires Linux");
        ExitCode::from(126)
    }
}

#[cfg(target_os = "linux")]
fn run_linux() -> Result<std::convert::Infallible, String> {
    let runtime = runtime_directory()?;
    ensure_private_directory(&runtime)?;
    let endpoint = PublishedUnixProviderEndpoint::bind(&runtime, IO_TIMEOUT, IO_TIMEOUT)
        .map_err(|error| error.to_string())?;
    let registry = Arc::new(Mutex::new(Vec::<ProviderHandle>::new()));
    let generations = Arc::new(AtomicU64::new(1));

    loop {
        match endpoint.accept_client() {
            Ok(PendingUnixClient::Provider(provider)) => {
                let peer = provider.peer_identity();
                let Ok((observed, anchor)) = observe_process_parent(peer.pid()) else {
                    continue;
                };
                if observed != peer {
                    continue;
                }
                let provider_generation = next_generation(&generations)?;
                let Ok(connection) = provider.admit(
                    &[],
                    Generation::new(1).map_err(|error| error.to_string())?,
                    provider_generation,
                    HEARTBEAT_INTERVAL_MILLIS,
                ) else {
                    continue;
                };
                let (sender, receiver) = mpsc::sync_channel(MAX_PROVIDER_WORK);
                let alive = Arc::new(AtomicBool::new(true));
                registry
                    .lock()
                    .map_err(|_| "provider registry was poisoned".to_owned())?
                    .push(ProviderHandle {
                        anchor,
                        sender,
                        alive: Arc::clone(&alive),
                    });
                let generations = Arc::clone(&generations);
                thread::spawn(move || {
                    provider_loop(connection, receiver, generations);
                    alive.store(false, Ordering::Release);
                });
            }
            Ok(PendingUnixClient::Shim(shim)) => {
                let registry = Arc::clone(&registry);
                thread::spawn(move || handle_shim(shim, &registry));
            }
            Err(error) => eprintln!("GUS broker rejected a client: {error}"),
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct ProviderHandle {
    anchor: ProcessIdentity,
    sender: mpsc::SyncSender<ProviderWork>,
    alive: Arc<AtomicBool>,
}

#[cfg(target_os = "linux")]
struct ProviderWork {
    repository: Digest32,
    repository_label: String,
    operation: gus_ipc::OperationPresentation,
    profiles: Vec<Profile>,
    explicit_profile: Option<ProfileId>,
    deadline: Instant,
    active: Arc<AtomicBool>,
    reply: mpsc::SyncSender<Result<SelectedProfile, SelectionFailure>>,
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct SelectedProfile {
    id: ProfileId,
    profile_generation: u64,
    profile_digest: Digest32,
    session_generation: u64,
}

#[cfg(target_os = "linux")]
struct PendingPrompt {
    request_id: gus_ipc::RequestId,
    profiles: Vec<Profile>,
    waiters: Vec<SelectionWaiter>,
}

#[cfg(target_os = "linux")]
struct SelectionWaiter {
    deadline: Instant,
    active: Arc<AtomicBool>,
    reply: mpsc::SyncSender<Result<SelectedProfile, SelectionFailure>>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum SelectionFailure {
    Cancelled,
    Unavailable,
    TimedOut,
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_lines)]
fn handle_shim(
    shim: gus_broker::PendingUnixShimRequest,
    registry: &Arc<Mutex<Vec<ProviderHandle>>>,
) {
    let request_id = shim.request().request_id();
    let ShimRequest::ResolveSelection(request) = shim.request().message() else {
        respond_error(shim, request_id, ErrorCode::GusEInternal);
        return;
    };
    let operation = request.operation();
    let explicit_profile = request.explicit_profile().cloned();
    let Ok((observed, anchor)) = observe_process_parent(shim.peer_identity().pid()) else {
        respond_error(shim, request_id, ErrorCode::GusEProviderUnavailable);
        return;
    };
    if observed != shim.peer_identity() {
        respond_error(shim, request_id, ErrorCode::GusEProviderUnavailable);
        return;
    }
    let Ok(evidence) = observe_linux_shim(shim.peer_identity()) else {
        respond_error(shim, request_id, ErrorCode::GusEShimUnverified);
        return;
    };
    if evidence.repository().identity() != request.repository_identity()
        || evidence.plan_digest() != request.plan_digest()
    {
        respond_error(shim, request_id, ErrorCode::GusEShimUnverified);
        return;
    }
    let repository = evidence.repository().identity();
    let repository_label = evidence.repository().label().to_owned();
    let Ok(profile_set) = load_profile_set() else {
        respond_error(shim, request_id, ErrorCode::GusEProfileInvalid);
        return;
    };
    let profiles = profile_set.profiles.into_values().collect::<Vec<_>>();
    let providers = registry
        .lock()
        .ok()
        .map(|mut providers| {
            providers.retain(|provider| provider.alive.load(Ordering::Acquire));
            providers
                .iter()
                .rev()
                .filter(|provider| provider.anchor == anchor)
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if providers.is_empty() {
        respond_error(shim, request_id, ErrorCode::GusEProviderUnavailable);
        return;
    }
    let (reply, result) = mpsc::sync_channel(1);
    let active = Arc::new(AtomicBool::new(true));
    let deadline = Instant::now() + SELECTION_TIMEOUT;
    let mut reply = Some(reply);
    let mut sent = false;
    for provider in providers {
        let work = ProviderWork {
            repository,
            repository_label: repository_label.clone(),
            operation,
            profiles: profiles.clone(),
            explicit_profile: explicit_profile.clone(),
            deadline,
            active: Arc::clone(&active),
            reply: reply
                .take()
                .expect("reply is retained until one send succeeds"),
        };
        match provider.sender.try_send(work) {
            Ok(()) => {
                sent = true;
                break;
            }
            Err(mpsc::TrySendError::Disconnected(work)) => reply = Some(work.reply),
            Err(mpsc::TrySendError::Full(_)) => {
                active.store(false, Ordering::Release);
                respond_error(shim, request_id, ErrorCode::GusEBrokerCapacity);
                return;
            }
        }
    }
    if !sent {
        respond_error(shim, request_id, ErrorCode::GusEProviderUnavailable);
        return;
    }
    let selected = loop {
        if !shim.peer_is_live() {
            active.store(false, Ordering::Release);
            return;
        }
        let now = Instant::now();
        if now >= deadline {
            active.store(false, Ordering::Release);
            respond_error(shim, request_id, ErrorCode::GusESelectionTimeout);
            return;
        }
        let wait = deadline
            .saturating_duration_since(now)
            .min(Duration::from_millis(50));
        match result.recv_timeout(wait) {
            Ok(Ok(selected)) => break selected,
            Ok(Err(SelectionFailure::Cancelled)) => {
                active.store(false, Ordering::Release);
                respond_error(shim, request_id, ErrorCode::GusESelectionCancelled);
                return;
            }
            Ok(Err(SelectionFailure::TimedOut)) => {
                active.store(false, Ordering::Release);
                respond_error(shim, request_id, ErrorCode::GusESelectionTimeout);
                return;
            }
            Ok(Err(SelectionFailure::Unavailable)) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                active.store(false, Ordering::Release);
                respond_error(shim, request_id, ErrorCode::GusEProviderUnavailable);
                return;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    active.store(false, Ordering::Release);
    let Ok(profile_generation) = Generation::new(selected.profile_generation) else {
        return;
    };
    let Ok(session_generation) = Generation::new(selected.session_generation) else {
        return;
    };
    let Ok(resolved) = ResolvedSelection::new(
        selected.id,
        profile_generation,
        selected.profile_digest,
        session_generation,
    ) else {
        return;
    };
    let Ok(response) =
        ShimResponseFrame::response(request_id, BrokerShimMessage::Resolved(resolved))
    else {
        return;
    };
    let _ = shim.respond(&response);
}

#[cfg(target_os = "linux")]
fn respond_error(shim: gus_broker::PendingUnixShimRequest, request_id: RequestId, code: ErrorCode) {
    let Ok(diagnostic_id) = RequestId::generate() else {
        return;
    };
    let Ok(error) = BrokerError::new(
        code,
        ErrorPhase::Preflight,
        diagnostic_id,
        ErrorDetail::None,
    ) else {
        return;
    };
    let Ok(response) = ShimResponseFrame::response(request_id, BrokerShimMessage::Error(error))
    else {
        return;
    };
    let _ = shim.respond(&response);
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_lines, clippy::needless_pass_by_value)]
fn provider_loop(
    mut connection: UnixProviderConnection,
    receiver: mpsc::Receiver<ProviderWork>,
    generations: Arc<AtomicU64>,
) {
    let mut repositories = Vec::new();
    let mut selected: Option<SelectedProfile> = None;
    let mut pending: Option<PendingPrompt> = None;
    loop {
        if connection.expire_heartbeat(Instant::now()).is_some() {
            break;
        }
        match connection.try_handle_next(&repositories) {
            Ok(Some(ProviderCommandOutcome::StatusSubscribed { .. })) => {
                let Ok(snapshot) = ProviderStatusSnapshot::new(
                    connection.registration_id(),
                    connection.provider_generation(),
                    Vec::new(),
                ) else {
                    break;
                };
                if connection.send_status(snapshot, Instant::now()).is_err() {
                    break;
                }
            }
            Ok(Some(ProviderCommandOutcome::SelectionDecided { response, decision })) => {
                let Some(mut prompt) = pending.take() else {
                    break;
                };
                if response.request_id() != prompt.request_id {
                    complete_waiters(&mut prompt.waiters, &Err(SelectionFailure::Unavailable));
                    break;
                }
                prune_waiters(&mut prompt.waiters, Instant::now());
                if prompt.waiters.is_empty() {
                    continue;
                }
                let result = match decision {
                    ProviderDecision::Selected(id) => prompt
                        .profiles
                        .iter()
                        .find(|profile| profile.id == id)
                        .and_then(|profile| {
                            let session_generation = next_generation(&generations).ok()?.get();
                            let profile_digest =
                                Digest32::from_bytes(profile.content_digest().ok()?);
                            Some(SelectedProfile {
                                id,
                                profile_generation: profile.generation,
                                profile_digest,
                                session_generation,
                            })
                        })
                        .ok_or(SelectionFailure::Unavailable),
                    ProviderDecision::Cancelled => Err(SelectionFailure::Cancelled),
                    ProviderDecision::Unavailable => Err(SelectionFailure::Unavailable),
                };
                if let Ok(value) = &result {
                    selected = Some(value.clone());
                }
                complete_waiters(&mut prompt.waiters, &result);
            }
            Ok(Some(_) | None) => {}
            Err(_) => break,
        }
        loop {
            let work = match receiver.try_recv() {
                Ok(work) => work,
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    if let Some(prompt) = pending.as_mut() {
                        complete_waiters(&mut prompt.waiters, &Err(SelectionFailure::Unavailable));
                    }
                    let _ = connection.shutdown();
                    return;
                }
            };
            if !work.active.load(Ordering::Acquire) || Instant::now() >= work.deadline {
                let _ = work.reply.send(Err(SelectionFailure::TimedOut));
                continue;
            }
            if let Some(selection) = resolve_existing_selection(&work, selected.as_ref()) {
                let _ = work.reply.send(Ok(selection));
                continue;
            }
            if let Some(prompt) = pending.as_mut() {
                if prompt.profiles == work.profiles {
                    prompt.waiters.push(waiter_from(work));
                } else {
                    let _ = work.reply.send(Err(SelectionFailure::Unavailable));
                }
                continue;
            }
            match start_prompt(&mut connection, &mut repositories, work, &generations) {
                Ok(prompt) => pending = Some(prompt),
                Err(work) => {
                    let _ = work.reply.send(Err(SelectionFailure::Unavailable));
                    break;
                }
            }
        }
        if let Some(prompt) = pending.as_mut() {
            prune_waiters(&mut prompt.waiters, Instant::now());
            if prompt.waiters.is_empty() {
                let _ = connection.abandon_prompt(prompt.request_id);
                pending = None;
                continue;
            }
            let expired = connection
                .expire_prompts(Instant::now())
                .is_ok_and(|expired| expired.contains(&prompt.request_id));
            if expired {
                let mut prompt = pending.take().expect("pending prompt exists");
                complete_waiters(&mut prompt.waiters, &Err(SelectionFailure::TimedOut));
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    if let Some(mut prompt) = pending.take() {
        complete_waiters(&mut prompt.waiters, &Err(SelectionFailure::Unavailable));
    }
    let _ = connection.shutdown();
}

#[cfg(target_os = "linux")]
fn start_prompt(
    connection: &mut UnixProviderConnection,
    repositories: &mut Vec<Digest32>,
    work: ProviderWork,
    generations: &AtomicU64,
) -> Result<PendingPrompt, Box<ProviderWork>> {
    repositories.clear();
    repositories.push(work.repository);
    let Ok(membership_generation) = next_generation(generations) else {
        return Err(Box::new(work));
    };
    if connection
        .replace_authorized_repositories(repositories, membership_generation, Instant::now())
        .is_err()
    {
        return Err(Box::new(work));
    }
    let Ok(prompt) = make_prompt(connection, &work, next_generation(generations).ok()) else {
        return Err(Box::new(work));
    };
    let Ok(sent) = connection.send_prompt(prompt, Instant::now()) else {
        return Err(Box::new(work));
    };
    let profiles = work.profiles.clone();
    Ok(PendingPrompt {
        request_id: sent.request_id,
        profiles,
        waiters: vec![waiter_from(work)],
    })
}

#[cfg(target_os = "linux")]
fn waiter_from(work: ProviderWork) -> SelectionWaiter {
    SelectionWaiter {
        deadline: work.deadline,
        active: work.active,
        reply: work.reply,
    }
}

#[cfg(target_os = "linux")]
fn prune_waiters(waiters: &mut Vec<SelectionWaiter>, now: Instant) {
    waiters.retain(|waiter| {
        if !waiter.active.load(Ordering::Acquire) {
            return false;
        }
        if now >= waiter.deadline {
            waiter.active.store(false, Ordering::Release);
            let _ = waiter.reply.send(Err(SelectionFailure::TimedOut));
            return false;
        }
        true
    });
}

#[cfg(target_os = "linux")]
fn complete_waiters(
    waiters: &mut Vec<SelectionWaiter>,
    result: &Result<SelectedProfile, SelectionFailure>,
) {
    for waiter in waiters.drain(..) {
        if waiter.active.swap(false, Ordering::AcqRel) {
            let _ = waiter.reply.send(result.clone());
        }
    }
}

#[cfg(target_os = "linux")]
fn resolve_existing_selection(
    work: &ProviderWork,
    selected: Option<&SelectedProfile>,
) -> Option<SelectedProfile> {
    if let Some(requested) = work.explicit_profile.as_ref() {
        let profile = work
            .profiles
            .iter()
            .find(|profile| &profile.id == requested)?;
        return Some(SelectedProfile {
            id: profile.id.clone(),
            profile_generation: profile.generation,
            profile_digest: Digest32::from_bytes(profile.content_digest().ok()?),
            session_generation: selected.map_or(1, |value| value.session_generation),
        });
    }
    let selected = selected?;
    let profile = work
        .profiles
        .iter()
        .find(|profile| profile.id == selected.id)?;
    let digest = Digest32::from_bytes(profile.content_digest().ok()?);
    (profile.generation == selected.profile_generation && digest == selected.profile_digest)
        .then(|| selected.clone())
}

#[cfg(target_os = "linux")]
fn make_prompt(
    connection: &UnixProviderConnection,
    work: &ProviderWork,
    selection_generation: Option<Generation>,
) -> Result<SelectionPrompt, ()> {
    let selection_generation = selection_generation.ok_or(())?;
    let scope_digest = digest_scope(connection.registration_id());
    let scope = ScopePresentation::new(
        SelectionScopePresentation::IdeWindow,
        scope_digest,
        "VS Code window".to_owned(),
    )
    .map_err(|_| ())?;
    let repository = RepositoryPresentation::new(work.repository, work.repository_label.clone())
        .or_else(|_| RepositoryPresentation::new(work.repository, "Git repository".to_owned()))
        .map_err(|_| ())?;
    let profiles = work
        .profiles
        .iter()
        .map(|profile| {
            ProfilePresentation::new(
                profile.id.clone(),
                profile.author.name().to_owned(),
                Some(profile.author.email().to_owned()),
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ())?;
    SelectionPrompt::new(
        connection.registration_id(),
        connection.provider_generation(),
        selection_generation,
        scope,
        repository,
        work.operation,
        profiles,
        u32::try_from(SELECTION_TIMEOUT.as_millis()).map_err(|_| ())?,
    )
    .map_err(|_| ())
}

#[cfg(target_os = "linux")]
fn digest_scope(request_id: gus_ipc::RequestId) -> Digest32 {
    let mut digest = Sha256::new();
    digest.update(b"gus.provider-scope.v1\0");
    digest.update(request_id.as_bytes());
    Digest32::from_bytes(digest.finalize().into())
}

#[cfg(target_os = "linux")]
fn next_generation(counter: &AtomicU64) -> Result<Generation, String> {
    let value = counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| "broker generation counter was exhausted".to_owned())?;
    Generation::new(value).map_err(|error| error.to_string())
}

#[cfg(target_os = "linux")]
fn runtime_directory() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("GUS_RUNTIME_DIR") {
        let path = PathBuf::from(path);
        return path
            .is_absolute()
            .then_some(path)
            .ok_or_else(|| "GUS_RUNTIME_DIR must be absolute".to_owned());
    }
    if let Some(path) = std::env::var_os("XDG_RUNTIME_DIR") {
        let path = PathBuf::from(path);
        return path
            .is_absolute()
            .then(|| path.join("gus"))
            .ok_or_else(|| "XDG_RUNTIME_DIR must be absolute".to_owned());
    }
    // SAFETY: `geteuid` has no preconditions.
    Ok(PathBuf::from(format!("/tmp/gus-{}", unsafe {
        libc::geteuid()
    })))
}

#[cfg(target_os = "linux")]
fn ensure_private_directory(path: &Path) -> Result<(), String> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    // SAFETY: `geteuid` has no preconditions.
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(format!(
            "{} is not an owner-private directory",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn load_profile_set() -> Result<ProfileSet, String> {
    let path = profile_store_path()?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .map_err(|error| format!("cannot securely open {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    // SAFETY: `geteuid` has no preconditions.
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        return Err("profile store permissions are unsafe".to_owned());
    }
    let mut bytes = Vec::new();
    file.take(MAX_PROFILE_STORE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_PROFILE_STORE_BYTES {
        return Err("profile store exceeds 1 MiB".to_owned());
    }
    let profiles: ProfileSet = toml::from_str(
        std::str::from_utf8(&bytes).map_err(|_| "profile store is not UTF-8".to_owned())?,
    )
    .map_err(|error| error.to_string())?;
    profiles.validate().map_err(|error| error.to_string())?;
    Ok(profiles)
}

#[cfg(target_os = "linux")]
fn profile_store_path() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("GUS_PROFILE_STORE") {
        let path = PathBuf::from(path);
        return path
            .is_absolute()
            .then_some(path)
            .ok_or_else(|| "GUS_PROFILE_STORE must be absolute".to_owned());
    }
    if let Some(path) = std::env::var_os("XDG_CONFIG_HOME") {
        let path = PathBuf::from(path);
        return path
            .is_absolute()
            .then(|| path.join("gus/profiles.toml"))
            .ok_or_else(|| "XDG_CONFIG_HOME must be absolute".to_owned());
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .map(|path| path.join(".config/gus/profiles.toml"))
        .ok_or_else(|| "profile store location is unavailable".to_owned())
}
