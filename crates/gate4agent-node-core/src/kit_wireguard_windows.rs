//! Windows node↔C2 tunnel.
//!
//! Placement is decided by facts about the interface that carries traffic to
//! the C2 public endpoint (ifType / hardware / split defaults), not by adapter
//! names. A foreign tunnel → userspace WG inside it (no adapter). A physical
//! path → WinTun host route, with a userspace fallback when elevation is missing.
//!
//! There is no default route and no edit of any other adapter.

#[path = "kit_wireguard_inside.rs"]
mod inside;

use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::os::windows::io::AsRawSocket;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use windows_sys::Win32::Foundation::{GetLastError, HMODULE};
use windows_sys::Win32::Networking::WinSock::{setsockopt, IPPROTO_IP, IP_UNICAST_IF, SOCKET};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

use crate::kit_wireguard::{NodeWgPeerConfig, NodeWgPeerError};
use crate::kit_wireguard_placement::{
    decide, parse_route_facts, Placement, RouteFact,
};

const RING: u32 = 0x20000;
const MTU: u16 = 1280;

pub(crate) fn peer_prefix(peer: IpAddr) -> String {
    match peer {
        IpAddr::V4(ip) => format!("{ip}/32"),
        IpAddr::V6(ip) => format!("{ip}/128"),
    }
}

pub(crate) fn env_nested_forced() -> bool {
    match std::env::var("GATE4AGENT_WG_NESTED") {
        Ok(v) => matches!(v.trim(), "1" | "true" | "TRUE" | "yes" | "YES"),
        _ => false,
    }
}

pub(crate) fn connect_inside(addr: SocketAddr) -> std::io::Result<Option<std::net::TcpStream>> {
    inside::connect(addr)
}

pub(crate) fn bring_up(config: &NodeWgPeerConfig) -> Result<(), NodeWgPeerError> {
    let config = config.clone();
    std::thread::Builder::new()
        .name("wg-supervisor".to_owned())
        .spawn(move || supervisor_loop(config))
        .map_err(|error| NodeWgPeerError::Setup(format!("wireguard supervisor: {error}")))?;
    Ok(())
}

fn log_stats() {
    use crate::node_log;
    use crate::wg_status;
    let st = wg_status::WgStatus::snapshot();
    node_log::info(
        "wg_stats",
        &[
            ("udp_out", st.udp_out.to_string()),
            ("udp_in", st.udp_in.to_string()),
            ("send_fail", st.send_fail.to_string()),
            ("last_err", st.last_err.to_string()),
            ("session", if st.handshake_age_secs.is_some() { "1" } else { "0" }.into()),
            (
                "handshake_age_secs",
                st.handshake_age_secs
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "none".into()),
            ),
            ("state", st.state),
        ],
    );
}

fn supervisor_loop(config: NodeWgPeerConfig) {
    use crate::node_log;
    use crate::wg_status;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    let _ = node_log::init_from_env();
    let mut ever_nested = env_nested_forced();
    let mut backoff = Duration::from_secs(1);
    let mut live_stop: Option<Arc<AtomicBool>> = None;
    let mut live_if: Option<u32> = None;
    let mut last_key = String::new();
    let handshake_limit = Duration::from_secs(60);
    let endpoint = config.peer_endpoint;

    loop {
        let routes = match endpoint {
            Some(ep) => read_endpoint_routes(ep).unwrap_or_else(|error| {
                node_log::warn("wg_classify_failed", &[("error", error)]);
                Vec::new()
            }),
            None => {
                node_log::warn("wg_classify_failed", &[("error", "no peer endpoint".into())]);
                Vec::new()
            }
        };
        if routes.iter().any(|r| crate::kit_wireguard_placement::tunnel_reason(r).is_some()) {
            ever_nested = true;
        }
        if env_nested_forced() {
            ever_nested = true;
        }
        let decision = decide(&routes, ever_nested);
        let key = match &decision.placement {
            Placement::Open => format!("open:{}", decision.reason),
            Placement::WaitExitTun => format!("wait:{}", decision.reason),
            Placement::InsideExisting { if_index, alias, .. } => {
                format!("inside:{if_index}:{alias}:{}", decision.reason)
            }
        };
        if key != last_key {
            for r in &routes {
                node_log::info(
                    "wg_classify_route",
                    &[
                        ("if_index", r.if_index.to_string()),
                        ("prefix", r.prefix.clone()),
                        ("metric", r.metric.to_string()),
                        ("if_type", r.if_type.to_string()),
                        (
                            "hardware",
                            r.hardware.map(|b| b.to_string()).unwrap_or_else(|| "none".into()),
                        ),
                        (
                            "virtual",
                            r.is_virtual.map(|b| b.to_string()).unwrap_or_else(|| "none".into()),
                        ),
                        ("media", r.media.clone()),
                        ("alias", r.alias.clone()),
                        ("desc", r.desc.clone()),
                    ],
                );
            }
            let mut fields = vec![
                ("placement", match &decision.placement {
                    Placement::Open => "open".into(),
                    Placement::WaitExitTun => "wait_exit_tun".into(),
                    Placement::InsideExisting { .. } => "inside-existing".into(),
                }),
                ("reason", decision.reason.clone()),
                ("nested", ever_nested.to_string()),
            ];
            if let Some(r) = &decision.route {
                fields.push(("deciding_prefix", r.prefix.clone()));
                fields.push(("deciding_if", r.if_index.to_string()));
                fields.push(("deciding_if_type", r.if_type.to_string()));
                fields.push(("alias", r.alias.clone()));
                fields.push(("desc", r.desc.clone()));
            }
            node_log::info("wg_classify", &fields);
            last_key = key;
        }

        match decision.placement {
            Placement::WaitExitTun => {
                wg_status::set_waiting();
                if let Some(stop) = live_stop.take() {
                    stop.store(true, Ordering::SeqCst);
                    live_if = None;
                    node_log::warn("wg_pump_stopped", &[("reason", "exit_tun_gone".into())]);
                }
                log_stats();
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(Duration::from_secs(30));
                last_key.clear();
                continue;
            }
            Placement::InsideExisting { if_index, alias, desc } => {
                let need_start = live_stop.as_ref().map_or(true, |s| s.load(Ordering::SeqCst));
                let if_changed = live_if.map(|v| v != if_index).unwrap_or(true);
                let stale = {
                    let st = wg_status::WgStatus::snapshot();
                    match st.handshake_age_secs {
                        None => live_stop.is_some(),
                        Some(age) => age >= handshake_limit.as_secs(),
                    }
                };
                if need_start || if_changed || stale {
                    if let Some(stop) = live_stop.take() {
                        stop.store(true, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(200));
                    }
                    let reason = if if_changed && live_if.is_some() {
                        "if_index_changed"
                    } else if stale {
                        "handshake_stale"
                    } else {
                        "start"
                    };
                    if reason != "start" {
                        wg_status::set_rebinding();
                        wg_status::bump_rebind();
                        node_log::warn(
                            "wg_rebind",
                            &[
                                ("old_if", live_if.unwrap_or(0).to_string()),
                                ("new_if", if_index.to_string()),
                                ("alias", alias.clone()),
                                ("reason", reason.into()),
                            ],
                        );
                    }
                    // Let the OS pick the exit interface: sticky IP_UNICAST_IF
                    // breaks when the outer VPN recreates its adapter.
                    match start_inside(&config, None, &alias, &desc) {
                        Ok(stop) => {
                            live_stop = Some(stop);
                            live_if = Some(if_index);
                            wg_status::set_exit_if(if_index);
                            wg_status::set_up();
                            backoff = Duration::from_secs(1);
                            node_log::info(
                                "wg_bring_up_ok",
                                &[
                                    ("variant", "inside-existing".into()),
                                    ("if_index", if_index.to_string()),
                                    ("bind", "os-route".into()),
                                    ("alias", alias.clone()),
                                ],
                            );
                        }
                        Err(error) => {
                            wg_status::set_down();
                            live_if = None;
                            last_key.clear();
                            node_log::error(
                                "wg_bring_up_err",
                                &[("variant", "inside-existing".into()), ("error", error)],
                            );
                            log_stats();
                            std::thread::sleep(backoff);
                            backoff = (backoff * 2).min(Duration::from_secs(30));
                            continue;
                        }
                    }
                }
            }
            Placement::Open => {
                if live_stop.as_ref().map_or(true, |s| s.load(Ordering::SeqCst)) {
                    if let Some(stop) = live_stop.take() {
                        stop.store(true, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(200));
                    }
                    match start_open_or_userspace(&config) {
                        Ok((stop, variant)) => {
                            live_stop = Some(stop);
                            live_if = None;
                            wg_status::set_up();
                            backoff = Duration::from_secs(1);
                            node_log::info("wg_bring_up_ok", &[("variant", variant)]);
                        }
                        Err(error) => {
                            wg_status::set_down();
                            last_key.clear();
                            node_log::error(
                                "wg_bring_up_err",
                                &[("variant", "open".into()), ("error", error)],
                            );
                            log_stats();
                            std::thread::sleep(backoff);
                            backoff = (backoff * 2).min(Duration::from_secs(30));
                            continue;
                        }
                    }
                }
            }
        }

        std::thread::sleep(Duration::from_secs(5));
        log_stats();
    }
}

fn start_inside(
    config: &NodeWgPeerConfig,
    exit_if: Option<u32>,
    alias: &str,
    _desc: &str,
) -> Result<std::sync::Arc<std::sync::atomic::AtomicBool>, String> {
    let (secret, peer_key) = load_keys(&config.private_key_path, &config.peer_public_key)?;
    crate::node_log::info(
        "wg_start_inside",
        &[
            ("exit", alias.to_owned()),
            (
                "if_index",
                exit_if.map(|v| v.to_string()).unwrap_or_else(|| "os-route".into()),
            ),
            ("adapter", "none".into()),
        ],
    );
    inside::start(config, secret, peer_key, exit_if)
}

/// Prefer WinTun; on elevation / create failure fall back to userspace (no adapter).
fn start_open_or_userspace(
    config: &NodeWgPeerConfig,
) -> Result<(std::sync::Arc<std::sync::atomic::AtomicBool>, String), String> {
    match start_open(config) {
        Ok(stop) => Ok((stop, "open".into())),
        Err(error) => {
            let elev = error.contains("(5)")
                || error.to_ascii_lowercase().contains("elevation")
                || error.to_ascii_lowercase().contains("access is denied")
                || error.to_ascii_lowercase().contains("wintun create");
            if elev {
                crate::node_log::warn(
                    "wg_open_fallback_userspace",
                    &[("error", error)],
                );
                let stop = start_inside(config, None, "os-route", "")?;
                Ok((stop, "open-userspace-fallback".into()))
            } else {
                Err(error)
            }
        }
    }
}

fn start_open(config: &NodeWgPeerConfig) -> Result<std::sync::Arc<std::sync::atomic::AtomicBool>, String> {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    let (secret, peer_key) = load_keys(&config.private_key_path, &config.peer_public_key)?;
    let mut live = LiveTun::open(&config.interface_name)?;
    assign_host_route(
        &config.interface_name,
        config.local_tunnel_address,
        config.peer_tunnel_address,
    )?;
    let udp = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, config.listen_port)))
        .map_err(|error| format!("udp bind: {error}"))?;
    udp.set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(|error| format!("udp timeout: {error}"))?;
    let index = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(1);
    let tunn = Tunn::new(
        secret,
        peer_key,
        None,
        (config.persistent_keepalive_secs > 0).then_some(config.persistent_keepalive_secs),
        index,
        None,
    );
    let endpoint = config.peer_endpoint;
    live.session = unsafe { (live.api.start)(live.adapter, RING) };
    if live.session.is_null() {
        let err = unsafe { GetLastError() };
        drop(live);
        return Err(format!("wintun session failed ({err})"));
    }
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);
    let iface = config.interface_name.clone();
    std::thread::Builder::new()
        .name(format!("{iface}-wg"))
        .spawn(move || pump(live, tunn, udp, endpoint, stop_thread))
        .map_err(|error| format!("wireguard thread: {error}"))?;
    Ok(stop)
}


fn assign_host_route(iface: &str, local: IpAddr, peer: IpAddr) -> Result<(), String> {
    match (local, peer) {
        (IpAddr::V4(local), IpAddr::V4(peer)) => {
            run_netsh(&[
                "interface",
                "ipv4",
                "set",
                "address",
                &format!("name={iface}"),
                "source=static",
                &format!("address={local}"),
                "mask=255.255.255.255",
                "gateway=none",
            ])?;
            let _ = run_netsh(&[
                "interface",
                "ipv4",
                "set",
                "subinterface",
                iface,
                &format!("mtu={MTU}"),
                "store=active",
            ]);
            let prefix = format!("{peer}/32");
            let _ = run_netsh(&[
                "interface",
                "ipv4",
                "delete",
                "route",
                &format!("prefix={prefix}"),
                &format!("interface={iface}"),
                "store=active",
            ]);
            run_netsh(&[
                "interface",
                "ipv4",
                "add",
                "route",
                &format!("prefix={prefix}"),
                &format!("interface={iface}"),
                "metric=0",
                "store=active",
            ])?;
            // `set address` resets the interface metric. Set it last, or the
            // other tun's copy of the same /32 ties and wins.
            run_netsh(&[
                "interface",
                "ipv4",
                "set",
                "interface",
                &format!("name={iface}"),
                "metric=1",
            ])?;
            Ok(())
        }
        (IpAddr::V6(local), IpAddr::V6(peer)) => {
            run_netsh(&[
                "interface",
                "ipv6",
                "set",
                "address",
                &format!("interface={iface}"),
                &format!("address={local}"),
            ])?;
            let prefix = format!("{peer}/128");
            run_netsh(&[
                "interface",
                "ipv6",
                "add",
                "route",
                &format!("prefix={prefix}"),
                &format!("interface={iface}"),
                "metric=0",
                "store=active",
            ])?;
            Ok(())
        }
        _ => Err("tunnel addresses are not the same family".to_owned()),
    }
}

fn run_netsh(args: &[&str]) -> Result<(), String> {
    if args.iter().any(|arg| arg.contains("0.0.0.0/0") || arg.contains("::/0")) {
        return Err("refusing a default route".to_owned());
    }
    let output = Command::new("netsh").args(args).output().map_err(|error| error.to_string())?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(format!("netsh {} failed: {stderr} {stdout}", args.join(" ")))
}

fn bind_v4_exit(udp: &UdpSocket, if_index: u32) -> Result<(), String> {
    let sock = udp.as_raw_socket() as SOCKET;
    let value = if_index.to_be();
    let rc = unsafe {
        setsockopt(
            sock,
            IPPROTO_IP,
            IP_UNICAST_IF,
            &value as *const u32 as *const u8,
            4,
        )
    };
    if rc != 0 {
        return Err(format!("handshake egress to existing tun if {if_index} failed ({rc})"));
    }
    Ok(())
}

/// Routes that can carry packets to `endpoint`, with adapter facts.
/// Written by PowerShell into a UTF-8 temp file (avoids the UTF-16 pipe trap).
fn read_endpoint_routes(endpoint: SocketAddr) -> Result<Vec<RouteFact>, String> {
    let host = match endpoint.ip() {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => ip.to_string(),
    };
    let out_path = std::env::temp_dir().join(format!(
        "g4a-wg-routes-{}-{}.tsv",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let out_ps = out_path.display().to_string().replace('\'', "''");
    let script = endpoint_route_script(&host, &out_ps);
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        let err = stdout_text(&output.stderr);
        let _ = std::fs::remove_file(&out_path);
        return Err(err.trim().to_owned());
    }
    let bytes = std::fs::read(&out_path).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&out_path);
    let text = String::from_utf8_lossy(&bytes).into_owned();
    Ok(parse_route_facts(&text))
}

fn endpoint_route_script(host: &str, out_ps: &str) -> String {
    let host = host.replace('\'', "''");
    format!(
        r#"$ErrorActionPreference = 'SilentlyContinue'
$dest = '{host}'
$out = '{out}'
$utf8 = New-Object System.Text.UTF8Encoding $false
$rows = New-Object System.Collections.Generic.List[string]
function Emit($r) {{
  if ($null -eq $r) {{ return }}
  $idx = [int]$r.InterfaceIndex
  $prefix = [string]$r.DestinationPrefix
  $metric = [int]$r.RouteMetric
  $a = Get-NetAdapter -InterfaceIndex $idx -IncludeHidden -ErrorAction SilentlyContinue
  $ifType = 0; $hw = ''; $virt = ''; $media = ''; $alias = '-'; $desc = '-'
  if ($null -ne $a) {{
    try {{ $ifType = [int]$a.InterfaceType }} catch {{}}
    if ($null -ne $a.HardwareInterface) {{ $hw = if ($a.HardwareInterface) {{ 'True' }} else {{ 'False' }} }}
    try {{ if ($null -ne $a.Virtual) {{ $virt = if ($a.Virtual) {{ 'True' }} else {{ 'False' }} }} }} catch {{}}
    try {{ $media = [string]$a.MediaType }} catch {{}}
    $alias = [string]$a.InterfaceAlias
    $desc = [string]$a.InterfaceDescription
  }} else {{
    $alias = [string]$r.InterfaceAlias
    if ([string]::IsNullOrWhiteSpace($alias)) {{ $alias = '-' }}
  }}
  if ($alias -match '[	
]') {{ $alias = '-' }}
  if ($desc -match '[	
]') {{ $desc = '-' }}
  if ($media -match '[	
]') {{ $media = '-' }}
  $rows.Add(('{{0}}{{9}}{{1}}{{9}}{{2}}{{9}}{{3}}{{9}}{{4}}{{9}}{{5}}{{9}}{{6}}{{9}}{{7}}{{9}}{{8}}' -f $idx, $prefix, $metric, $ifType, $hw, $virt, $media, $alias, $desc, [char]9))
}}
Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "$dest/32" -ErrorAction SilentlyContinue | ForEach-Object {{ Emit $_ }}
try {{
  $best = Find-NetRoute -RemoteIPAddress $dest -ErrorAction SilentlyContinue
  if ($null -ne $best) {{
    $br = @($best)[0]
    $idx = [int]$br.InterfaceIndex
    if ($idx -gt 0) {{
      $a = Get-NetAdapter -InterfaceIndex $idx -IncludeHidden -ErrorAction SilentlyContinue
      $fake = [pscustomobject]@{{ InterfaceIndex = $idx; DestinationPrefix = "$dest/32"; RouteMetric = 0; InterfaceAlias = $(if ($a) {{ $a.InterfaceAlias }} else {{ '-' }}) }}
      Emit $fake
    }}
  }}
}} catch {{}}
Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | ForEach-Object {{ Emit $_ }}
Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/1' | ForEach-Object {{ Emit $_ }}
Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '128.0.0.0/1' | ForEach-Object {{ Emit $_ }}
[IO.File]::WriteAllLines($out, $rows.ToArray(), $utf8)
"#,
        host = host,
        out = out_ps,
    )
}

fn stdout_text(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && (bytes.starts_with(&[0xFF, 0xFE]) || bytes[1] == 0) {
        let start = if bytes.starts_with(&[0xFF, 0xFE]) { 2 } else { 0 };
        let units: Vec<u16> = bytes[start..]
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    String::from_utf8_lossy(bytes).into_owned()
}

fn load_keys(path: &Path, peer_b64: &str) -> Result<(StaticSecret, PublicKey), String> {
    let text = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    let ours = decode_key(text.trim())?;
    let peer = decode_key(peer_b64.trim())?;
    Ok((StaticSecret::from(ours), PublicKey::from(peer)))
}

fn decode_key(text: &str) -> Result<[u8; 32], String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(text))
        .map_err(|error| format!("wireguard key: {error}"))?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("wireguard key is {} bytes", bytes.len()))?;
    Ok(array)
}

type CreateAdapter = unsafe extern "system" fn(*const u16, *const u16, *const u8) -> *mut core::ffi::c_void;
type CloseAdapter = unsafe extern "system" fn(*mut core::ffi::c_void);
type OpenAdapter = unsafe extern "system" fn(*const u16) -> *mut core::ffi::c_void;
type StartSession = unsafe extern "system" fn(*mut core::ffi::c_void, u32) -> *mut core::ffi::c_void;
type EndSession = unsafe extern "system" fn(*mut core::ffi::c_void);
type ReceivePacket = unsafe extern "system" fn(*mut core::ffi::c_void, *mut u32) -> *mut u8;
type ReleaseReceive = unsafe extern "system" fn(*mut core::ffi::c_void, *const u8);
type AllocateSend = unsafe extern "system" fn(*mut core::ffi::c_void, u32) -> *mut u8;
type SendPacket = unsafe extern "system" fn(*mut core::ffi::c_void, *const u8);

struct TunApi {
    create: CreateAdapter,
    close: CloseAdapter,
    open: OpenAdapter,
    start: StartSession,
    end: EndSession,
    recv: ReceivePacket,
    release: ReleaseReceive,
    alloc: AllocateSend,
    send: SendPacket,
}

struct LiveTun {
    api: TunApi,
    adapter: *mut core::ffi::c_void,
    session: *mut core::ffi::c_void,
}

unsafe impl Send for LiveTun {}

impl Drop for LiveTun {
    fn drop(&mut self) {
        unsafe {
            if !self.session.is_null() {
                (self.api.end)(self.session);
                self.session = std::ptr::null_mut();
            }
            if !self.adapter.is_null() {
                (self.api.close)(self.adapter);
                self.adapter = std::ptr::null_mut();
            }
        }
    }
}

impl LiveTun {
    fn open(name: &str) -> Result<Self, String> {
        let api = load_api()?;
        let name_w = wide(name);
        let kind = wide("Hatchery");
        unsafe {
            let existing = (api.open)(name_w.as_ptr());
            if !existing.is_null() {
                (api.close)(existing);
            }
            let adapter = (api.create)(name_w.as_ptr(), kind.as_ptr(), std::ptr::null());
            if adapter.is_null() {
                let err = GetLastError();
                let hint = if err == 5 {
                    " (the process needs elevation, same as Linux CAP_NET_ADMIN)"
                } else {
                    ""
                };
                return Err(format!("wintun create {name} failed ({err}){hint}"));
            }
            Ok(Self {
                api,
                adapter,
                session: std::ptr::null_mut(),
            })
        }
    }

    fn try_recv(&self) -> Option<Vec<u8>> {
        let mut size = 0u32;
        unsafe {
            let ptr = (self.api.recv)(self.session, &mut size);
            if ptr.is_null() || size == 0 || size > 2048 {
                if !ptr.is_null() {
                    (self.api.release)(self.session, ptr);
                }
                return None;
            }
            let packet = std::slice::from_raw_parts(ptr, size as usize).to_vec();
            (self.api.release)(self.session, ptr);
            Some(packet)
        }
    }

    fn send(&self, packet: &[u8]) {
        if packet.is_empty() || packet.len() > 2048 {
            return;
        }
        unsafe {
            let dst = (self.api.alloc)(self.session, packet.len() as u32);
            if dst.is_null() {
                return;
            }
            std::ptr::copy_nonoverlapping(packet.as_ptr(), dst, packet.len());
            (self.api.send)(self.session, dst);
        }
    }
}

fn load_api() -> Result<TunApi, String> {
    let path = find_dll()?;
    let wide_path = wide(&path);
    unsafe {
        let lib = LoadLibraryW(wide_path.as_ptr());
        if lib.is_null() {
            return Err(format!("LoadLibrary {path} failed ({})", GetLastError()));
        }
        Ok(TunApi {
            create: sym(lib, "WintunCreateAdapter")?,
            close: sym(lib, "WintunCloseAdapter")?,
            open: sym(lib, "WintunOpenAdapter")?,
            start: sym(lib, "WintunStartSession")?,
            end: sym(lib, "WintunEndSession")?,
            recv: sym(lib, "WintunReceivePacket")?,
            release: sym(lib, "WintunReleaseReceivePacket")?,
            alloc: sym(lib, "WintunAllocateSendPacket")?,
            send: sym(lib, "WintunSendPacket")?,
        })
    }
}

fn find_dll() -> Result<String, String> {
    let mut candidates = Vec::new();
    if let Some(from_env) = std::env::var_os("HATCHERY_WINTUN_DLL") {
        candidates.push(std::path::PathBuf::from(from_env));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("wintun.dll"));
        }
    }
    if let Some(programs) = std::env::var_os("ProgramFiles") {
        let root = std::path::PathBuf::from(programs);
        candidates.push(root.join("WireGuard").join("wintun.dll"));
    }
    for path in &candidates {
        if path.is_file() {
            return Ok(path.display().to_string());
        }
    }
    Err("wintun.dll not found next to the exe or in HATCHERY_WINTUN_DLL".to_owned())
}

unsafe fn sym<T>(lib: HMODULE, name: &str) -> Result<T, String> {
    let c = CString::new(name).map_err(|error| error.to_string())?;
    let far = GetProcAddress(lib, c.as_ptr() as *const u8).ok_or_else(|| format!("wintun.dll missing {name}"))?;
    Ok(std::mem::transmute_copy(&far))
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn pump(
    live: LiveTun,
    mut tunn: Tunn,
    udp: UdpSocket,
    endpoint: Option<SocketAddr>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::atomic::Ordering;
    let mut net_buf = [0u8; 2048];
    let mut tun_buf = [0u8; 2048];
    let mut udp_out = 0u64;
    let mut udp_in = 0u64;
    let mut send_fail = 0u64;
    let mut last_err = 0i32;
    let mut reported = std::time::Instant::now();
    loop {
        if stop.load(Ordering::SeqCst) {
            crate::wg_status::set_down();
            return;
        }
        if let Some(dst) = endpoint {
            match tunn.update_timers(&mut net_buf) {
                TunnResult::WriteToNetwork(packet) if dst.port() != 0 => {
                    match udp.send_to(packet, dst) {
                        Ok(_) => udp_out += 1,
                        Err(e) => {
                            send_fail += 1;
                            last_err = e.raw_os_error().unwrap_or(1);
                        }
                    }
                }
                _ => {}
            }
        }
        if let Some(packet) = live.try_recv() {
            send_network(&udp, endpoint.unwrap_or(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))), {
                // unwrap_or is only used when endpoint is None; encapsulate still returns WriteToNetwork
                // and send_network drops a send to port 0.
                tunn.encapsulate(&packet, &mut net_buf)
            });
        }
        let mut recvd = [0u8; 2048];
        match udp.recv_from(&mut recvd) {
            Ok((n, src)) => {
                let mut datagram = recvd[..n].to_vec();
                loop {
                    let outcome = tunn.decapsulate(
                        Some(src.ip()),
                        &datagram,
                        &mut tun_buf,
                    );
                    datagram.clear();
                    match outcome {
                        TunnResult::WriteToNetwork(packet) => {
                            let copy = packet.to_vec();
                            let _ = udp.send_to(&copy, src);
                        }
                        TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                            udp_in = udp_in.saturating_add(1);
                            live.send(packet);
                        }
                        TunnResult::Done | TunnResult::Err(_) => break,
                    }
                }
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
        if reported.elapsed() >= Duration::from_secs(5) {
            let age = tunn.time_since_last_handshake().map(|d| d.as_secs());
            crate::wg_status::publish_stats(udp_out, udp_in, send_fail, last_err, age);
            if age.is_some() {
                crate::wg_status::set_up();
            }
            reported = std::time::Instant::now();
        }
    }
}

fn send_network(udp: &UdpSocket, dst: SocketAddr, result: TunnResult<'_>) {
    if dst.port() == 0 {
        return;
    }
    if let TunnResult::WriteToNetwork(packet) = result {
        let _ = udp.send_to(packet, dst);
    }
}

