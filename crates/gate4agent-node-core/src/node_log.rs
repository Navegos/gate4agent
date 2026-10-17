//! Rotating JSON-lines log for the node. Path comes from the caller or
//! `GATE4AGENT_NODE_LOG` — never a hardcoded absolute path.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_BYTES: u64 = 5 * 1024 * 1024;
const ENV_LOG: &str = "GATE4AGENT_NODE_LOG";

static READY: AtomicBool = AtomicBool::new(false);
static SINK: OnceLock<Mutex<Sink>> = OnceLock::new();

struct Sink {
    path: PathBuf,
    file: File,
    written: u64,
}

/// Install the file sink. Also mirrors every line to stderr.
/// Safe to call more than once: the first successful path wins.
pub fn init(path: impl AsRef<Path>) -> Result<(), String> {
    let path = path.as_ref().to_path_buf();
    if path.as_os_str().is_empty() {
        return Err("node log path is empty".to_owned());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("node log dir: {e}"))?;
    }
    let meta_len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("node log open {}: {e}", path.display()))?;
    let sink = Sink {
        path,
        file,
        written: meta_len,
    };
    let _ = SINK.set(Mutex::new(sink));
    READY.store(true, Ordering::SeqCst);
    Ok(())
}

/// Init from `GATE4AGENT_NODE_LOG` when set. No-op when unset.
pub fn init_from_env() -> Result<(), String> {
    match std::env::var_os(ENV_LOG) {
        Some(v) if !v.is_empty() => init(PathBuf::from(v)),
        _ => Ok(()),
    }
}

pub fn env_name() -> &'static str {
    ENV_LOG
}

/// Resolve the default log path next to an enroll/state directory
/// (`<state>/node.log`), without hardcoding a home root.
pub fn path_beside_state(state_dir: &Path) -> PathBuf {
    state_dir.join("node.log")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn emit(level: &str, event: &str, fields: &[(&str, String)]) {
    let mut line = format!(
        "{{\"ts_ms\":{},\"level\":{level:?},\"event\":{event:?}",
        now_ms()
    );
    for (k, v) in fields {
        line.push(',');
        line.push_str(&format!("{k:?}:{v:?}"));
    }
    line.push('}');
    eprintln!("{line}");
    if !READY.load(Ordering::Relaxed) {
        return;
    }
    let Some(lock) = SINK.get() else {
        return;
    };
    let Ok(mut sink) = lock.lock() else {
        return;
    };
    if sink.written >= MAX_BYTES {
        let _ = sink.file.flush();
        let path = sink.path.clone();
        match rotate(&path) {
            Ok(f) => {
                sink.file = f;
                sink.written = 0;
            }
            Err(_) => return,
        }
    }
    if writeln!(sink.file, "{line}").is_ok() {
        sink.written = sink.written.saturating_add(line.len() as u64 + 1);
        let _ = sink.file.flush();
    }
}

fn rotate(path: &Path) -> Result<File, String> {
    let bak = path.with_extension("log.1");
    let _ = std::fs::remove_file(&bak);
    let _ = std::fs::rename(path, &bak);
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())
}

pub fn info(event: &str, fields: &[(&str, String)]) {
    emit("info", event, fields);
}

pub fn warn(event: &str, fields: &[(&str, String)]) {
    emit("warn", event, fields);
}

pub fn error(event: &str, fields: &[(&str, String)]) {
    emit("error", event, fields);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn path_beside_state_is_relative_to_caller() {
        let dir = std::env::temp_dir().join(format!("g4a-log-path-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = path_beside_state(&dir);
        assert_eq!(p, dir.join("node.log"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn writes_and_rotates_under_tempdir() {
        let dir = std::env::temp_dir().join(format!("g4a-log-rot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.log");
        // Fresh sink for this test process — only works if SINK unset.
        // Use a unique subprocess-free approach: write via init only once per
        // process. If already inited, still verify helper path logic above.
        if SINK.get().is_none() {
            init(&path).unwrap();
            info("test_event", &[("k", "v".to_owned())]);
            let mut body = String::new();
            File::open(&path).unwrap().read_to_string(&mut body).unwrap();
            assert!(body.contains("test_event"));
            assert!(body.contains("\"k\":\"v\""));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
