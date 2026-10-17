//! Process-wide WireGuard health for `/health` and logs. No secrets.

use std::sync::atomic::{AtomicI32, AtomicU64, AtomicU8, Ordering};

/// 0=off 1=down 2=waiting_exit_tun 3=up 4=rebinding
const ST_OFF: u8 = 0;
const ST_DOWN: u8 = 1;
const ST_WAIT: u8 = 2;
const ST_UP: u8 = 3;
const ST_REBIND: u8 = 4;

static STATE: AtomicU8 = AtomicU8::new(ST_OFF);
static HANDSHAKE_AGE_SECS: AtomicU64 = AtomicU64::new(u64::MAX);
static UDP_OUT: AtomicU64 = AtomicU64::new(0);
static UDP_IN: AtomicU64 = AtomicU64::new(0);
static SEND_FAIL: AtomicU64 = AtomicU64::new(0);
static LAST_ERR: AtomicI32 = AtomicI32::new(0);
static EXIT_IF: AtomicU64 = AtomicU64::new(0);
static REBIND_COUNT: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WgStatus {
    pub state: String,
    pub exit_if_index: Option<u32>,
    pub handshake_age_secs: Option<u64>,
    pub udp_out: u64,
    pub udp_in: u64,
    pub send_fail: u64,
    pub last_err: i32,
    pub rebind_count: u64,
}

impl WgStatus {
    pub fn snapshot() -> Self {
        let state = match STATE.load(Ordering::Relaxed) {
            ST_DOWN => "down",
            ST_WAIT => "waiting_exit_tun",
            ST_UP => "up",
            ST_REBIND => "rebinding",
            _ => "off",
        };
        let age = HANDSHAKE_AGE_SECS.load(Ordering::Relaxed);
        let ifx = EXIT_IF.load(Ordering::Relaxed);
        Self {
            state: state.to_owned(),
            exit_if_index: if ifx == 0 {
                None
            } else {
                Some(ifx as u32)
            },
            handshake_age_secs: if age == u64::MAX { None } else { Some(age) },
            udp_out: UDP_OUT.load(Ordering::Relaxed),
            udp_in: UDP_IN.load(Ordering::Relaxed),
            send_fail: SEND_FAIL.load(Ordering::Relaxed),
            last_err: LAST_ERR.load(Ordering::Relaxed),
            rebind_count: REBIND_COUNT.load(Ordering::Relaxed),
        }
    }
}

pub(crate) fn set_off() {
    STATE.store(ST_OFF, Ordering::Relaxed);
}

pub(crate) fn set_down() {
    STATE.store(ST_DOWN, Ordering::Relaxed);
    HANDSHAKE_AGE_SECS.store(u64::MAX, Ordering::Relaxed);
}

pub(crate) fn set_waiting() {
    STATE.store(ST_WAIT, Ordering::Relaxed);
}

pub(crate) fn set_up() {
    STATE.store(ST_UP, Ordering::Relaxed);
}

pub(crate) fn set_rebinding() {
    STATE.store(ST_REBIND, Ordering::Relaxed);
}

pub(crate) fn set_exit_if(if_index: u32) {
    EXIT_IF.store(u64::from(if_index), Ordering::Relaxed);
}

pub(crate) fn bump_rebind() {
    REBIND_COUNT.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn publish_stats(
    udp_out: u64,
    udp_in: u64,
    send_fail: u64,
    last_err: i32,
    handshake_age_secs: Option<u64>,
) {
    UDP_OUT.store(udp_out, Ordering::Relaxed);
    UDP_IN.store(udp_in, Ordering::Relaxed);
    SEND_FAIL.store(send_fail, Ordering::Relaxed);
    LAST_ERR.store(last_err, Ordering::Relaxed);
    HANDSHAKE_AGE_SECS.store(handshake_age_secs.unwrap_or(u64::MAX), Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_roundtrip_states() {
        set_down();
        assert_eq!(WgStatus::snapshot().state, "down");
        set_waiting();
        assert_eq!(WgStatus::snapshot().state, "waiting_exit_tun");
        set_up();
        publish_stats(3, 2, 1, -5, Some(12));
        set_exit_if(40);
        bump_rebind();
        let s = WgStatus::snapshot();
        assert_eq!(s.state, "up");
        assert_eq!(s.udp_out, 3);
        assert_eq!(s.udp_in, 2);
        assert_eq!(s.send_fail, 1);
        assert_eq!(s.last_err, -5);
        assert_eq!(s.handshake_age_secs, Some(12));
        assert_eq!(s.exit_if_index, Some(40));
        assert!(s.rebind_count >= 1);
        set_off();
    }
}
