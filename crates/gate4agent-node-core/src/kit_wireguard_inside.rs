//! In-process WireGuard (boringtun + smoltcp). No system TUN, no routes, no
//! elevation. Ciphertext leaves on a normal UDP socket; the OS routes it.
//! TCP to the configured peer tunnel address is terminated in this process
//! and exposed to callers via [`connect`].

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant as StdInstant};

use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};

use crate::kit_wireguard::{NodeWgPeerConfig, NodeWgPeerError};

struct Gate {
    peer: IpAddr,
    jobs: SyncSender<Job>,
}

struct Job {
    port: u16,
    listener: TcpListener,
}

static GATE: Mutex<Option<Gate>> = Mutex::new(None);

/// Idle time before the inner (in-tunnel) TCP socket sends a keepalive.
const INNER_KEEPALIVE: smoltcp::time::Duration = smoltcp::time::Duration::from_secs(15);
/// Unacked time after which the inner TCP socket is reset.
const INNER_TIMEOUT: smoltcp::time::Duration = smoltcp::time::Duration::from_secs(45);
/// Recreate the UDP socket + initiation when the handshake is this old.
const HANDSHAKE_STALE: Duration = Duration::from_secs(180);
/// First handshake must arrive within this time after session start.
const FIRST_HANDSHAKE: Duration = Duration::from_secs(60);
/// A tunnel that received any datagram within this window is alive.
const RX_QUIET: Duration = Duration::from_secs(60);

/// Self-heal decision. Rekey happens every 120 s, so handshake age up to
/// REJECT_AFTER_TIME (180 s) is normal; also require recent inbound silence.
pub(crate) fn rebind_reason(
    handshake_age_secs: Option<u64>,
    since_start: Duration,
    since_rx: Duration,
) -> Option<&'static str> {
    if since_rx < RX_QUIET {
        return None;
    }
    match handshake_age_secs {
        Some(age) if age >= HANDSHAKE_STALE.as_secs() => Some("handshake_stale"),
        Some(_) => None,
        None if since_start >= FIRST_HANDSHAKE => Some("handshake_timeout"),
        None => None,
    }
}

/// Dial `addr` through the in-process tunnel when it matches the peer.
/// Returns `Ok(None)` when no session is up or the address is not the peer.
pub(super) fn connect(addr: SocketAddr) -> std::io::Result<Option<TcpStream>> {
    let guard = GATE
        .lock()
        .map_err(|_| std::io::Error::other("wireguard gate lock"))?;
    let Some(gate) = guard.as_ref() else {
        return Ok(None);
    };
    if addr.ip() != gate.peer {
        return Ok(None);
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let local = listener.local_addr()?;
    gate.jobs
        .send(Job {
            port: addr.port(),
            listener,
        })
        .map_err(|_| std::io::Error::other("wireguard session is gone"))?;
    drop(guard);
    let stream = TcpStream::connect_timeout(&local, Duration::from_secs(20))?;
    stream.set_nodelay(true)?;
    Ok(Some(stream))
}

/// Spawn the forever supervisor: userspace pump with self-heal on stale handshake.
pub(super) fn bring_up(config: &NodeWgPeerConfig) -> Result<(), NodeWgPeerError> {
    let config = config.clone();
    std::thread::Builder::new()
        .name("wg-supervisor".to_owned())
        .spawn(move || supervisor_loop(config))
        .map_err(|error| NodeWgPeerError::Setup(format!("wireguard supervisor: {error}")))?;
    Ok(())
}

fn supervisor_loop(config: NodeWgPeerConfig) {
    use crate::node_log;
    use crate::wg_status;

    let _ = node_log::init_from_env();
    let mut backoff = Duration::from_secs(1);
    let mut live_stop: Option<Arc<AtomicBool>> = None;
    let mut session_started: Option<StdInstant> = None;
    let mut last_rx = StdInstant::now();
    let mut last_udp_in = 0u64;

    loop {
        let st = wg_status::WgStatus::snapshot();
        // Only an established-but-old handshake is "stale". A missing
        // handshake means we are still waiting — give it HANDSHAKE_STALE
        // from session start before recreating the UDP socket.
        if st.udp_in != last_udp_in {
            last_udp_in = st.udp_in;
            last_rx = StdInstant::now();
        }
        let reason = session_started.and_then(|start| {
            rebind_reason(st.handshake_age_secs, start.elapsed(), last_rx.elapsed())
        });
        let stale = reason.is_some();
        let need_start = live_stop
            .as_ref()
            .map_or(true, |s| s.load(Ordering::SeqCst));

        if need_start || stale {
            if let Some(stop) = live_stop.take() {
                stop.store(true, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(250));
            }
            session_started = None;
            if stale && !need_start {
                wg_status::set_rebinding();
                wg_status::bump_rebind();
                let reason = reason.unwrap_or("handshake_stale");
                node_log::warn("wg_rebind", &[("reason", reason.into())]);
            }
            match start_session(&config) {
                Ok(stop) => {
                    live_stop = Some(stop);
                    session_started = Some(StdInstant::now());
                    last_rx = StdInstant::now();
                    last_udp_in = 0;
                    wg_status::set_up();
                    backoff = Duration::from_secs(1);
                    node_log::info(
                        "wg_bring_up_ok",
                        &[("variant", "userspace".into())],
                    );
                }
                Err(error) => {
                    wg_status::set_down();
                    node_log::error(
                        "wg_bring_up_err",
                        &[("variant", "userspace".into()), ("error", error)],
                    );
                    log_stats();
                    std::thread::sleep(backoff);
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                    continue;
                }
            }
        }

        log_stats();
        std::thread::sleep(Duration::from_secs(5));
    }
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
            (
                "session",
                if st.handshake_age_secs.is_some() {
                    "1"
                } else {
                    "0"
                }
                .into(),
            ),
            (
                "handshake_age_secs",
                st.handshake_age_secs
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "none".into()),
            ),
            ("state", st.state),
            ("rebind_count", st.rebind_count.to_string()),
        ],
    );
}

fn start_session(config: &NodeWgPeerConfig) -> Result<Arc<AtomicBool>, String> {
    let (secret, peer_key) = load_keys(&config.private_key_path, &config.peer_public_key)?;
    start(config, secret, peer_key)
}

fn start(
    config: &NodeWgPeerConfig,
    secret: StaticSecret,
    peer_key: PublicKey,
) -> Result<Arc<AtomicBool>, String> {
    let IpAddr::V4(local) = config.local_tunnel_address else {
        return Err("userspace tunnel is ipv4 only".to_owned());
    };
    let IpAddr::V4(peer) = config.peer_tunnel_address else {
        return Err("userspace tunnel is ipv4 only".to_owned());
    };
    let endpoint = config
        .peer_endpoint
        .ok_or_else(|| "userspace tunnel needs the peer endpoint".to_owned())?;
    let udp = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, config.listen_port)))
        .map_err(|error| format!("udp bind: {error}"))?;
    udp.set_read_timeout(Some(Duration::from_millis(50)))
        .map_err(|error| format!("udp timeout: {error}"))?;
    let index = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(1);
    let keepalive = if config.persistent_keepalive_secs > 0 {
        Some(config.persistent_keepalive_secs)
    } else {
        Some(25)
    };
    let tunn = Tunn::new(secret, peer_key, None, keepalive, index, None);
    let (tx, rx) = sync_channel(8);
    let gate = Gate {
        peer: config.peer_tunnel_address,
        jobs: tx,
    };
    {
        let mut slot = GATE.lock().map_err(|_| "wireguard gate lock".to_owned())?;
        *slot = Some(gate);
    }
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);
    std::thread::Builder::new()
        .name("wg-userspace".to_owned())
        .spawn(move || pump(local, peer, endpoint, udp, tunn, rx, stop_thread))
        .map_err(|error| format!("wireguard thread: {error}"))?;
    Ok(stop)
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

struct Link {
    handle: smoltcp::iface::SocketHandle,
    local: TcpStream,
    to_wg: VecDeque<u8>,
    to_local: VecDeque<u8>,
    opened: StdInstant,
}

struct IpDev {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

struct DevRx(Vec<u8>);

impl RxToken for DevRx {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.0)
    }
}

struct DevTx<'a>(&'a mut VecDeque<Vec<u8>>);

impl TxToken for DevTx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let out = f(&mut buf);
        self.0.push_back(buf);
        out
    }
}

impl Device for IpDev {
    type RxToken<'a> = DevRx;
    type TxToken<'a> = DevTx<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((DevRx(packet), DevTx(&mut self.tx)))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(DevTx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1280;
        caps
    }
}

fn pump(
    local: Ipv4Addr,
    peer: Ipv4Addr,
    endpoint: SocketAddr,
    udp: UdpSocket,
    mut tunn: Tunn,
    jobs: std::sync::mpsc::Receiver<Job>,
    stop: Arc<AtomicBool>,
) {
    let mut device = IpDev {
        rx: VecDeque::new(),
        tx: VecDeque::new(),
    };
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = 0xC2_5A_11;
    let mut iface = Interface::new(config, &mut device, Instant::now());
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(local.into()), 32));
    });
    let _ = iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::from(peer));
    let mut sockets = SocketSet::new(vec![]);
    let mut links: Vec<Link> = Vec::new();
    let mut pending: VecDeque<Job> = VecDeque::new();
    let mut next_port: u16 = 20_000;
    let mut net_buf = [0u8; 2048];
    let mut tun_buf = [0u8; 2048];
    let mut udp_out = 0u64;
    let mut udp_in = 0u64;
    let mut send_fail = 0u64;
    let mut last_err = 0i32;
    let mut reported = StdInstant::now();
    note_send(
        &mut udp_out,
        &mut send_fail,
        &mut last_err,
        send_out(
            &udp,
            endpoint,
            tunn.format_handshake_initiation(&mut net_buf, false),
        ),
    );
    loop {
        if stop.load(Ordering::SeqCst) {
            if let Ok(mut slot) = GATE.lock() {
                *slot = None;
            }
            crate::wg_status::set_down();
            return;
        }
        loop {
            match jobs.try_recv() {
                Ok(job) => pending.push_back(job),
                Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
            }
        }
        note_send(
            &mut udp_out,
            &mut send_fail,
            &mut last_err,
            send_out(&udp, endpoint, tunn.update_timers(&mut net_buf)),
        );
        let mut recvd = [0u8; 2048];
        match udp.recv_from(&mut recvd) {
            Ok((n, src)) => {
                udp_in = udp_in.saturating_add(1);
                let mut datagram = recvd[..n].to_vec();
                loop {
                    let outcome = tunn.decapsulate(Some(src.ip()), &datagram, &mut tun_buf);
                    datagram.clear();
                    match outcome {
                        TunnResult::WriteToNetwork(packet) => {
                            let copy = packet.to_vec();
                            note_send(
                                &mut udp_out,
                                &mut send_fail,
                                &mut last_err,
                                match udp.send_to(&copy, src) {
                                    Ok(_) => 1,
                                    Err(error) => -error.raw_os_error().unwrap_or(1),
                                },
                            );
                        }
                        TunnResult::WriteToTunnelV4(packet, _)
                        | TunnResult::WriteToTunnelV6(packet, _) => {
                            device.rx.push_back(packet.to_vec());
                        }
                        TunnResult::Done | TunnResult::Err(_) => break,
                    }
                }
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
        while let Some(job) = pending.pop_front() {
            match job.listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(true);
                    let _ = stream.set_nodelay(true);
                    let handle = sockets.add(tcp::Socket::new(
                        tcp::SocketBuffer::new(vec![0u8; 65_535]),
                        tcp::SocketBuffer::new(vec![0u8; 65_535]),
                    ));
                    let local_port = next_port;
                    next_port = next_port.wrapping_add(1).max(20_000);
                    let connected = {
                        let socket = sockets.get_mut::<tcp::Socket>(handle);
                        socket.set_keep_alive(Some(INNER_KEEPALIVE));
                        socket.set_timeout(Some(INNER_TIMEOUT));
                        socket
                            .connect(
                                iface.context(),
                                (IpAddress::Ipv4(peer.into()), job.port),
                                local_port,
                            )
                            .is_ok()
                    };
                    if connected {
                        links.push(Link {
                            handle,
                            local: stream,
                            to_wg: VecDeque::new(),
                            to_local: VecDeque::new(),
                            opened: StdInstant::now(),
                        });
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    pending.push_front(job);
                    break;
                }
                Err(_) => {}
            }
        }
        let _ = iface.poll(Instant::now(), &mut device, &mut sockets);
        while let Some(packet) = device.tx.pop_front() {
            note_send(
                &mut udp_out,
                &mut send_fail,
                &mut last_err,
                send_out(&udp, endpoint, tunn.encapsulate(&packet, &mut net_buf)),
            );
        }
        if reported.elapsed() >= Duration::from_secs(5) {
            if tunn.time_since_last_handshake().is_none() {
                note_send(
                    &mut udp_out,
                    &mut send_fail,
                    &mut last_err,
                    send_out(
                        &udp,
                        endpoint,
                        tunn.format_handshake_initiation(&mut net_buf, true),
                    ),
                );
            }
            let age = tunn.time_since_last_handshake().map(|d| d.as_secs());
            crate::wg_status::publish_stats(udp_out, udp_in, send_fail, last_err, age);
            if age.is_some() {
                crate::wg_status::set_up();
            }
            reported = StdInstant::now();
        }
        let mut keep = Vec::new();
        for mut link in links.drain(..) {
            let mut tmp = [0u8; 1500];
            if link.to_wg.len() < 1_048_576 {
                match link.local.read(&mut tmp) {
                    Ok(0) => {
                        sockets.get_mut::<tcp::Socket>(link.handle).close();
                    }
                    Ok(n) => link.to_wg.extend(tmp[..n].iter().copied()),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => {
                        sockets.get_mut::<tcp::Socket>(link.handle).abort();
                        continue;
                    }
                }
            }
            {
                let socket = sockets.get_mut::<tcp::Socket>(link.handle);
                if socket.may_send() && !link.to_wg.is_empty() {
                    let buf: Vec<u8> = link.to_wg.iter().copied().take(2048).collect();
                    if let Ok(n) = socket.send_slice(&buf) {
                        link.to_wg.drain(..n);
                    }
                }
                if socket.may_recv() {
                    if let Ok(n) = socket.recv_slice(&mut tmp) {
                        link.to_local.extend(tmp[..n].iter().copied());
                    }
                }
                if link.opened.elapsed() > Duration::from_secs(20)
                    && !socket.may_send()
                    && link.to_local.is_empty()
                {
                    socket.abort();
                    continue;
                }
                if !socket.is_active() && link.to_local.is_empty() && link.to_wg.is_empty() {
                    continue;
                }
            }
            if !link.to_local.is_empty() {
                let buf: Vec<u8> = link.to_local.iter().copied().collect();
                match link.local.write(&buf) {
                    Ok(0) => {
                        sockets.get_mut::<tcp::Socket>(link.handle).abort();
                        continue;
                    }
                    Ok(n) => {
                        link.to_local.drain(..n);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => {
                        sockets.get_mut::<tcp::Socket>(link.handle).abort();
                        continue;
                    }
                }
            }
            keep.push(link);
        }
        links = keep;
        let _ = local;
    }
}

fn note_send(udp_out: &mut u64, send_fail: &mut u64, last_err: &mut i32, rc: i32) {
    if rc > 0 {
        *udp_out = udp_out.saturating_add(1);
    } else if rc < 0 {
        *send_fail = send_fail.saturating_add(1);
        *last_err = -rc;
    }
}

fn send_out(udp: &UdpSocket, dst: SocketAddr, result: TunnResult<'_>) -> i32 {
    if dst.port() == 0 {
        return 0;
    }
    if let TunnResult::WriteToNetwork(packet) = result {
        return match udp.send_to(packet, dst) {
            Ok(_) => 1,
            Err(error) => -error.raw_os_error().unwrap_or(1),
        };
    }
    0
}

#[cfg(test)]
mod tests {
    use super::rebind_reason;
    use std::time::Duration;
    const S: fn(u64) -> Duration = Duration::from_secs;

    #[test]
    fn rekey_window_is_not_stale() {
        assert_eq!(rebind_reason(Some(130), S(600), S(120)), None);
        assert_eq!(rebind_reason(Some(179), S(600), S(120)), None);
    }

    #[test]
    fn recent_rx_keeps_tunnel_even_if_handshake_old() {
        assert_eq!(rebind_reason(Some(400), S(600), S(10)), None);
        assert_eq!(rebind_reason(None, S(600), S(10)), None);
    }

    #[test]
    fn old_handshake_and_silence_rebinds() {
        assert_eq!(rebind_reason(Some(180), S(600), S(60)), Some("handshake_stale"));
    }

    #[test]
    fn first_handshake_timeout() {
        assert_eq!(rebind_reason(None, S(30), S(90)), None);
        assert_eq!(rebind_reason(None, S(60), S(60)), Some("handshake_timeout"));
    }
}
