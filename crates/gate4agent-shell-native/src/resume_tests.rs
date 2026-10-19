use super::*;
use gate4agent_types::{LaunchSpec, ProviderSessionKey, SessionGeneration, TerminalSize};

// No vendor process or provider state: the fixture validates the wire contract.
const FIXTURE: &str = r#"
import json, sys
mode = sys.argv[1]
def send(value):
    print(json.dumps(value), flush=True)
for line in sys.stdin:
    request = json.loads(line)
    method = request['method']
    result = {}
    if method == 'initialize':
        result = {'agentCapabilities': {'loadSession': mode not in ('unsupported', 'modern')}}
        if mode == 'modern': result['agentCapabilities']['sessionCapabilities'] = {'resume': {}}
    elif method == 'session/new':
        assert request['params']['mcpServers'][0]['name'] == 'fixture-mailbox'
        result = {'sessionId': 'temporary-thread', 'modes': {'currentModeId': 'agent-full-access', 'availableModes': [{'id':'agent-full-access','name':'Default'}]}}
    elif method == 'session/load':
        assert request['params']['sessionId'] == 'prior-thread'
        if mode == 'refused':
            send({'jsonrpc':'2.0','id':request['id'],'error':{'code':-32000,'message':'fixture load refused'}})
            continue
        send({'jsonrpc':'2.0','method':'session/update','params':{'sessionId':'prior-thread','update':{'sessionUpdate':'agent_message_chunk','content':{'type':'text','text':'replayed history'}}}})
        result = {'sessionId': 'prior-thread', 'modes': {'currentModeId': 'agent-full-access', 'availableModes': [{'id':'agent-full-access','name':'Default'}]}}
    if 'id' in request:
        send({'jsonrpc':'2.0','id':request['id'],'result':result})
"#;

async fn resume(mode: &str) -> (NativeEffectShell, NativeSessionKey, ControlObservation) {
    let agent_id = AgentId::new("codex").unwrap();
    let mut spec = gate4agent_catalog::builtin_registry()
        .get(&agent_id)
        .unwrap()
        .clone();
    spec.capabilities
        .transports
        .acp
        .as_mut()
        .unwrap()
        .launch_override = Some(LaunchSpec {
        program: if cfg!(windows) { "python" } else { "python3" }.into(),
        fixed_args: vec!["-u".into(), "-c".into(), FIXTURE.into(), mode.into()],
    });
    let mut shell = NativeEffectShell::new(gate4agent_catalog::AgentRegistry::new([spec]).unwrap());
    let key = NativeSessionKey {
        instance_id: AgentInstanceId(71),
        generation: SessionGeneration(1),
    };
    let mut policy = ProviderRuntimePolicy::none();
    policy.provider_session_identity = true;
    let effect = EffectEnvelope {
        operation_id: OperationId(1),
        instance_id: key.instance_id,
        generation: key.generation,
        effect: ControlEffect::SpawnResume {
            agent_id,
            transport: TransportKind::Acp,
            runtime_policy: policy,
            provider_session: ProviderSessionIdentity {
                key: ProviderSessionKey::SessionId,
                id: "prior-thread".into(),
                transcript_path: None,
            },
            request: ResumeLaunchRequest {
                working_directory: std::env::current_dir()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
                terminal_size: TerminalSize {
                    rows: 24,
                    columns: 80,
                },
                initial_prompt: None,
            },
        },
    };
    let mcp = McpServerSpec::new("fixture-mailbox", "fixture-mcp".into(), vec![], vec![]).unwrap();
    let result = shell
        .execute_with_launch_context(
            effect,
            vec![],
            vec![],
            OneShotSessionPersistence::Ephemeral,
            Some(mcp),
        )
        .await;
    (shell, key, result.observation)
}

#[tokio::test]
async fn acp_resume_preserves_loaded_identity_replay_and_mcp() {
    let (mut shell, key, result) = resume("supported").await;
    assert!(
        matches!(result, ControlObservation::Spawned { .. }),
        "{result:?}"
    );
    let session = &shell.acp_sessions.get(&key).unwrap().session;
    assert_eq!(
        session.provider_reported_session_id().await.as_deref(),
        Some("prior-thread")
    );
    let events = shell.collect_provider_events();
    assert!(events.iter().any(|e| matches!(&e.observation, ControlObservation::ProviderEvent { event: ProviderEvent::SessionIdentityObserved { identity }, .. } if identity.id == "prior-thread")), "{events:?}");
    assert!(events.iter().any(|e| matches!(&e.observation, ControlObservation::ProviderEvent { event: ProviderEvent::Text { text, .. }, .. } if text == "replayed history")), "{events:?}");
    shell.stop_native(key, true).await;
}

#[tokio::test]
async fn acp_resume_without_load_capability_leaves_no_fresh_runtime() {
    let (shell, _, result) = resume("unsupported").await;
    assert!(
        matches!(result, ControlObservation::SpawnFailed { ref message } if message.contains("session/load unsupported")),
        "{result:?}"
    );
    assert!(shell.acp_sessions.is_empty());
}

#[tokio::test]
async fn acp_resume_load_refusal_leaves_no_fresh_runtime() {
    let (shell, _, result) = resume("refused").await;
    assert!(
        matches!(result, ControlObservation::SpawnFailed { ref message } if message.contains("fixture load refused")),
        "{result:?}"
    );
    assert!(shell.acp_sessions.is_empty());
}

#[tokio::test]
async fn acp_resume_forwards_mcp_with_modern_resume_capability() {
    // The fixture rejects session/new unless the MCP overlay survived SpawnResume.
    let (mut shell, key, result) = resume("modern").await;
    assert!(
        matches!(result, ControlObservation::Spawned { .. }),
        "{result:?}"
    );
    let session = &shell.acp_sessions.get(&key).unwrap().session;
    assert_eq!(
        session.capability_names(),
        vec!["sessionCapabilities.resume"]
    );
    assert_eq!(
        session.acp_session_id().await.as_deref(),
        Some("prior-thread")
    );
    shell.stop_native(key, true).await;
}
