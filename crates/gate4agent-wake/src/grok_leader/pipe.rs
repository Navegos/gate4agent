//! Grok home, the leader socket path, and the Windows pipe name.
//!
//! The hash must match `xai-grok-shell`'s `pipe_leaf_name`: SipHash-1-3 with
//! the keys shipped in that file, then `Path::hash`. The keys are not a
//! secret. They exist so the name does not move when Rust changes
//! `DefaultHasher`. `Path::hash` itself is still std's component hash, so
//! this name matches a grok binary built with a compatible std.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::wake_error::{classify, ProviderError, WakeClass};

/// Fixed SipHash-1-3 keys from grok `leader/transport.rs`. Do not change.
const PIPE_KEY_0: u64 = 0x6772_6f6b_6c65_6164;
const PIPE_KEY_1: u64 = 0x6572_5f70_6970_6521;

#[derive(Debug, Error)]
pub enum PushError {
    #[error("leader-absent")]
    LeaderAbsent,
    #[error("leader-not-ready")]
    LeaderNotReady,
    #[error("leader-protocol: {0}")]
    Protocol(String),
    #[error("session-load-failed: {0}")]
    SessionLoadFailed(String),
    #[error("prompt-failed: {0}")]
    PromptFailed(String),
    #[error("frame-too-large")]
    FrameTooLarge,
}

impl PushError {
    /// The class of this failure. A provider error's codes travel in its text as tags
    /// (`[code=..] [vendor=..] [http=..]`, see [`crate::wake_error::code_tags`]), so this reads
    /// them back; a leader that is absent or starting is `host_down`, a session that does not
    /// load and says nothing more is `session_gone`.
    pub fn class(&self) -> WakeClass {
        self.provider_error().class
    }

    /// The provider error behind this failure, as far as the error itself carries it (the
    /// `_detailed` push functions return the one read from the JSON-RPC error directly).
    pub fn provider_error(&self) -> ProviderError {
        let plain = |class| ProviderError { class, rpc_code: None, vendor_code: None, http_status: None, retry_after_s: None, message: self.to_string() };
        let read = |text: &str, otherwise: WakeClass| {
            let mut e = classify(rpc_code_in(text), None, text);
            if e.class == WakeClass::Other {
                e.class = otherwise;
            }
            e
        };
        match self {
            PushError::LeaderAbsent | PushError::LeaderNotReady => plain(WakeClass::HostDown),
            PushError::FrameTooLarge => plain(WakeClass::Context),
            PushError::Protocol(text) => read(text, WakeClass::HostDown),
            PushError::SessionLoadFailed(text) => read(text, WakeClass::SessionGone),
            PushError::PromptFailed(text) => read(text, WakeClass::Other),
        }
    }
}

/// The `[code=N]` tag of a flattened provider error.
fn rpc_code_in(text: &str) -> Option<i64> {
    let at = text.find("[code=")? + "[code=".len();
    let rest = &text[at..];
    rest[..rest.find(']')?].parse().ok()
}

/// A failed push with the provider error it came from, when there was one: the codes and the
/// class as the leader's JSON-RPC error carried them (returned by the `_detailed` functions;
/// the plain ones return [`PushFailure::error`] only).
#[derive(Debug, Error)]
#[error("{error}")]
pub struct PushFailure {
    #[source]
    pub error: PushError,
    pub provider: Option<ProviderError>,
}

impl PushFailure {
    /// The class: the provider error's when there is one, else the [`PushError`]'s.
    pub fn class(&self) -> WakeClass {
        self.provider.as_ref().map_or_else(|| self.error.class(), |p| p.class)
    }
}

impl From<PushError> for PushFailure {
    fn from(error: PushError) -> Self {
        PushFailure { error, provider: None }
    }
}

/// `$GROK_HOME` verbatim when set, otherwise `<home>/.grok` with the home
/// canonicalized through `dunce` (no `\\?\` prefix). Matches grok's
/// `grok_home_in`.
pub fn grok_home() -> Option<PathBuf> {
    if let Some(env) = std::env::var_os("GROK_HOME").filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(env));
    }
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .filter(|value| !value.is_empty())?;
    let home = PathBuf::from(home);
    Some(dunce::canonicalize(&home).unwrap_or(home).join(".grok"))
}

/// `GROK_LEADER_SOCKET` when set, otherwise `<grok_home>/leader.sock`.
/// A non-default relay suffix (`leader-<hash>.sock`) is not derived here:
/// `DefaultHasher` is not stable. Set the env var for that socket.
pub fn leader_socket(grok_home: &Path, override_socket: Option<&OsStr>) -> PathBuf {
    if let Some(over) = override_socket.filter(|value| !value.is_empty()) {
        return PathBuf::from(over);
    }
    grok_home.join("leader.sock")
}

pub fn leader_pipe_name(sock: &Path) -> String {
    use std::hash::{Hash, Hasher};

    use siphasher::sip::SipHasher13;

    let mut hasher = SipHasher13::new_with_keys(PIPE_KEY_0, PIPE_KEY_1);
    sock.hash(&mut hasher);
    format!("grok-leader-{:016x}", hasher.finish())
}

#[cfg(windows)]
pub fn leader_pipe_os_path(sock: &Path) -> PathBuf {
    PathBuf::from(format!(r"\\.\pipe\{}", leader_pipe_name(sock)))
}

/// Non-connecting probe. On Windows `WaitNamedPipeW` does not take a server
/// instance. A connecting open would be accepted as a phantom client.
pub fn leader_is_listening(sock: &Path) -> bool {
    #[cfg(windows)]
    {
        windows_pipe_ready(&leader_pipe_os_path(sock))
    }
    #[cfg(not(windows))]
    {
        unix_socket_ready(sock)
    }
}

#[cfg(windows)]
fn windows_pipe_ready(pipe: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "kernel32")]
    extern "system" {
        fn WaitNamedPipeW(name: *const u16, timeout_ms: u32) -> i32;
        fn GetLastError() -> u32;
    }

    const ERROR_FILE_NOT_FOUND: u32 = 2;
    let mut wide: Vec<u16> = pipe.as_os_str().encode_wide().collect();
    wide.push(0);
    let ready = unsafe { WaitNamedPipeW(wide.as_ptr(), 1) };
    if ready != 0 {
        return true;
    }
    let err = unsafe { GetLastError() };
    err != ERROR_FILE_NOT_FOUND
}

#[cfg(not(windows))]
fn unix_socket_ready(sock: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::metadata(sock).is_ok_and(|meta| meta.file_type().is_socket())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_name_is_stable_and_shaped() {
        let sock = Path::new(r"C:\grok\leader.sock");
        let once = leader_pipe_name(sock);
        let twice = leader_pipe_name(sock);
        assert_eq!(once, twice);
        assert!(once.starts_with("grok-leader-"));
        assert_eq!(once.len(), "grok-leader-".len() + 16);
        assert!(once.bytes().skip("grok-leader-".len()).all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn a_different_path_hashes_differently() {
        let home = leader_pipe_name(Path::new(r"C:\grok\leader.sock"));
        let other = leader_pipe_name(Path::new(r"C:\grok\leader-other.sock"));
        assert_ne!(home, other);
    }

    #[test]
    fn socket_override_replaces_the_default() {
        let home = Path::new(r"C:\grok");
        assert_eq!(leader_socket(home, None), home.join("leader.sock"));
        assert_eq!(
            leader_socket(home, Some(OsStr::new(r"D:\custom.sock"))),
            PathBuf::from(r"D:\custom.sock")
        );
        assert_eq!(leader_socket(home, Some(OsStr::new(""))), home.join("leader.sock"));
    }
}

#[cfg(test)]
mod class_tests {
    use super::*;

    #[test]
    fn push_errors_have_a_class() {
        assert_eq!(PushError::LeaderAbsent.class(), WakeClass::HostDown);
        assert_eq!(PushError::LeaderNotReady.class(), WakeClass::HostDown);
        assert_eq!(PushError::FrameTooLarge.class(), WakeClass::Context);
        assert_eq!(PushError::Protocol("leader-shutdown".into()).class(), WakeClass::HostDown);
        assert_eq!(PushError::Protocol("something odd".into()).class(), WakeClass::HostDown);
        assert_eq!(PushError::SessionLoadFailed("no record".into()).class(), WakeClass::SessionGone);
        assert_eq!(PushError::SessionLoadFailed("Request failed (402): balance exhausted".into()).class(), WakeClass::Exhausted);
        assert_eq!(PushError::PromptFailed("Request failed (402): Grok Build usage balance exhausted".into()).class(), WakeClass::Exhausted);
        assert_eq!(PushError::PromptFailed("failed [code=-32603] [vendor=50150]".into()).provider_error().rpc_code, Some(-32603));
        assert_eq!(PushError::PromptFailed("failed [code=-32603] [vendor=50150]".into()).class(), WakeClass::RateLimited);
        let plain: PushFailure = PushError::LeaderAbsent.into();
        assert_eq!((plain.class(), plain.provider), (WakeClass::HostDown, None));
    }
}
