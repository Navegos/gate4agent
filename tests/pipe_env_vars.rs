//! `SessionConfig.env_vars` reaches the headless pipe child (#97).
//!
//! The pipe child inherits the host environment and every configured pair is
//! applied on top of it, so a matching key overrides the inherited value.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use gate4agent::core::types::SessionConfig;
use gate4agent::pipe::{PipeProcessOptions, PipeSession};
use gate4agent::CliTool;
use gate4agent_types::{LaunchSpec, PipePromptDelivery};

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "g4a-pipe-env-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn wait_for_file(path: &Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(text) = std::fs::read_to_string(path) {
            if text.ends_with('\n') {
                return text;
            }
        }
        assert!(Instant::now() < deadline, "child never wrote {}", path.display());
        std::thread::sleep(Duration::from_millis(20));
    }
}

const DUMP: &str = r#"printf '%s|%s|%s\n' "$G4A_PIPE_ENV" "$G4A_PIPE_OVERRIDE" "${HOME:+host-home}" > "$G4A_PIPE_OUT""#;

#[tokio::test]
async fn pipe_session_spawn_applies_session_config_env_vars() {
    let dir = scratch_dir("spawn");
    // Fake `codex` on a PATH that only the configured env provides, so the
    // test also proves the env is applied before the program is resolved.
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let fake = bin.join("codex");
    std::fs::write(&fake, format!("#!/bin/sh\n{DUMP}\n")).unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let out = dir.join("env.txt");

    std::env::set_var("G4A_PIPE_OVERRIDE", "from-host");
    let host_path = std::env::var("PATH").unwrap_or_default();
    let config = SessionConfig {
        tool: CliTool::Codex,
        working_dir: dir.clone(),
        env_vars: vec![
            ("PATH".into(), format!("{}:{host_path}", bin.display())),
            ("G4A_PIPE_ENV".into(), "from-config".into()),
            ("G4A_PIPE_OVERRIDE".into(), "from-config".into()),
            ("G4A_PIPE_OUT".into(), out.display().to_string()),
        ],
        name: None,
    };
    let session = PipeSession::spawn(config, "hello", PipeProcessOptions::default())
        .await
        .expect("spawn fake codex");
    let text = wait_for_file(&out);
    drop(session);
    assert_eq!(text, "from-config|from-config|host-home\n");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn pipe_session_spawn_with_launch_applies_session_config_env_vars() {
    let dir = scratch_dir("launch");
    let out = dir.join("env.txt");
    let launch = LaunchSpec {
        program: "sh".into(),
        fixed_args: vec!["-c".into(), DUMP.into()],
    };
    let config = SessionConfig {
        tool: CliTool::Codex,
        working_dir: dir.clone(),
        env_vars: vec![
            ("G4A_PIPE_ENV".into(), "from-launch-config".into()),
            ("G4A_PIPE_OVERRIDE".into(), "x".into()),
            ("G4A_PIPE_OUT".into(), out.display().to_string()),
        ],
        name: None,
    };
    let session = PipeSession::spawn_with_launch(config, "", &launch, PipePromptDelivery::None)
        .await
        .expect("spawn sh");
    let text = wait_for_file(&out);
    drop(session);
    assert_eq!(text, "from-launch-config|x|host-home\n");
    let _ = std::fs::remove_dir_all(&dir);
}
