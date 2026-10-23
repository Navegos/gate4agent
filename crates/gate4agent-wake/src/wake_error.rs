//! Classes of a failed wake (a letter that could not be put into a session as a turn), from
//! the provider's error: its JSON-RPC `error.code` and `error.data`, a vendor code, an HTTP
//! status, a `Retry-After`, and as the last resort its words.
//!
//! The class decides what the host does next: `exhausted` waits for the limit to reset,
//! `rate_limited` / `overloaded` / `host_down` / `busy` retry, the rest go to a person. The
//! code and the status are kept beside the class ([`ProviderError`]), never flattened into
//! text only.
//!
//! Order of signals: a known vendor code (MiniMax `mcode`: 42212 / 50110 = usage spent,
//! 50111 / 50150 = the provider rate-limits), then the HTTP status, then phrases.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// What a failed wake means for the host.
///
/// 0.6: mark this `#[non_exhaustive]` (a new class must not break a host's `match`); not done in
/// 0.5.x, where it would be a breaking change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WakeClass {
    /// Usage balance, quota or plan spent (HTTP 402, mcode 42212 / 50110): no retry before the
    /// limit resets.
    Exhausted,
    /// Too many requests (HTTP 429, mcode 50111 / 50150): retry after `Retry-After` or a backoff.
    RateLimited,
    /// The provider failed or is overloaded (5xx, 529, a dropped stream): retry with a backoff.
    Overloaded,
    /// Not signed in or the credential was refused (401 / 403): no retry; a login is needed.
    Auth,
    /// The provider session is gone (not found, cannot be loaded): no retry.
    SessionGone,
    /// The host process is not there or not ready (no leader socket, leader starting, timeout).
    HostDown,
    /// The session already runs a turn: queue the letter, do not report it.
    Busy,
    /// The prompt does not fit the context (413, context length): no retry.
    Context,
    /// None of the above.
    Other,
}

impl WakeClass {
    pub fn as_str(self) -> &'static str {
        match self {
            WakeClass::Exhausted => "exhausted",
            WakeClass::RateLimited => "rate_limited",
            WakeClass::Overloaded => "overloaded",
            WakeClass::Auth => "auth",
            WakeClass::SessionGone => "session_gone",
            WakeClass::HostDown => "host_down",
            WakeClass::Busy => "busy",
            WakeClass::Context => "context",
            WakeClass::Other => "other",
        }
    }

    /// Worth trying again later without anyone acting.
    pub fn retryable(self) -> bool {
        matches!(self, WakeClass::RateLimited | WakeClass::Overloaded | WakeClass::HostDown | WakeClass::Busy)
    }
}

impl std::fmt::Display for WakeClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A provider error with everything it carried: the class and the codes, not only the words.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderError {
    pub class: WakeClass,
    /// The JSON-RPC `error.code` (ACP), when the error came as a JSON-RPC error.
    pub rpc_code: Option<i64>,
    /// A vendor error code (MiniMax `mcode` 42212, ...) from `error.code`, `error.data` or the
    /// text (`(code 42212)`).
    pub vendor_code: Option<i64>,
    /// The HTTP status the provider answered with, from `error.data` or the text.
    pub http_status: Option<u16>,
    /// Seconds to wait, when the error says so.
    pub retry_after_s: Option<u64>,
    /// The provider's words (`error.message`), clipped.
    pub message: String,
}

/// MiniMax Code (`mcode`) vendor codes: usage (Token Plan) spent.
pub const MCODE_EXHAUSTED: &[i64] = &[42212, 50110];
/// MiniMax Code (`mcode`) vendor codes: "The model provider is rate limiting requests."
pub const MCODE_RATE_LIMITED: &[i64] = &[50111, 50150];

/// Longest message kept in a [`ProviderError`].
pub const MAX_MESSAGE: usize = 180;

fn vendor_class(code: i64) -> Option<WakeClass> {
    if MCODE_EXHAUSTED.contains(&code) {
        Some(WakeClass::Exhausted)
    } else if MCODE_RATE_LIMITED.contains(&code) {
        Some(WakeClass::RateLimited)
    } else {
        None
    }
}

fn status_class(status: u16) -> Option<WakeClass> {
    Some(match status {
        402 => WakeClass::Exhausted,
        429 => WakeClass::RateLimited,
        401 | 403 => WakeClass::Auth,
        404 | 410 => WakeClass::SessionGone,
        409 => WakeClass::Busy,
        413 => WakeClass::Context,
        500..=599 => WakeClass::Overloaded,
        _ => return None,
    })
}

/// JSON-RPC 2.0 reserves -32768..=-32000 for the protocol; any other `error.code` may be the
/// vendor's own.
fn is_protocol_code(code: i64) -> bool {
    (-32768..=-32000).contains(&code)
}

/// Classify one provider error from its JSON-RPC code, its `error.data` and its text.
pub fn classify(rpc_code: Option<i64>, data: Option<&Value>, text: &str) -> ProviderError {
    let vendor_code = rpc_code
        .filter(|c| !is_protocol_code(*c) && vendor_class(*c).is_some())
        .or_else(|| data.and_then(vendor_code_in_data))
        .or_else(|| vendor_code_in(text));
    let http_status = data.and_then(status_in_data).or_else(|| http_status_in(text));
    let retry_after_s = data.and_then(retry_after_in_data).or_else(|| retry_after_in(text));
    let class = vendor_code
        .and_then(vendor_class)
        .or_else(|| http_status.and_then(status_class))
        .unwrap_or_else(|| class_of_text(text));
    ProviderError { class, rpc_code, vendor_code, http_status, retry_after_s, message: clip(text) }
}

/// Classify a JSON-RPC `error` object (`{code, message, data}`).
pub fn classify_rpc_error(error: &Value) -> ProviderError {
    let text = error.get("message").and_then(Value::as_str).unwrap_or("error");
    classify(error.get("code").and_then(Value::as_i64), error.get("data"), text)
}

fn clip(text: &str) -> String {
    text.chars().take(MAX_MESSAGE).collect()
}

fn num(v: &Value) -> Option<i64> {
    v.as_i64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

/// A known vendor code in `error.data`: `code`, `vendor_code`, `error_code`, `status_code` (some
/// vendors put theirs there), or the same one level down in `error`.
fn vendor_code_in_data(data: &Value) -> Option<i64> {
    let here = ["vendor_code", "code", "error_code", "status_code", "base_resp_code"]
        .iter()
        .filter_map(|k| data.get(*k).and_then(num))
        .find(|c| vendor_class(*c).is_some());
    here.or_else(|| data.get("error").filter(|e| e.is_object()).and_then(vendor_code_in_data))
        .or_else(|| data.get("base_resp").and_then(|b| b.get("status_code")).and_then(num).filter(|c| vendor_class(*c).is_some()))
}

fn status_in_data(data: &Value) -> Option<u16> {
    ["http_status", "status", "statusCode", "status_code"]
        .iter()
        .filter_map(|k| data.get(*k).and_then(num))
        .find(|c| (400..600).contains(c))
        .map(|c| c as u16)
        .or_else(|| data.get("error").filter(|e| e.is_object()).and_then(status_in_data))
}

fn retry_after_in_data(data: &Value) -> Option<u64> {
    if let Some(s) = ["retry_after", "retry_after_s", "retryAfter"].iter().find_map(|k| data.get(*k).and_then(num)) {
        return u64::try_from(s).ok();
    }
    ["retry_after_ms", "retryAfterMs"].iter().find_map(|k| data.get(*k).and_then(num)).and_then(|ms| u64::try_from(ms).ok()).map(|ms| ms.div_ceil(1000))
}

/// A known vendor code written as an error code in the text: `(code 42212)`, `code: 50150`,
/// `code=42212`, `[vendor=42212]`, `(42212)`, `error 50111`. A bare number elsewhere (a port,
/// a byte count) is not one.
pub fn vendor_code_in(text: &str) -> Option<i64> {
    let t = text.to_ascii_lowercase();
    let b = t.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_digit() || (i > 0 && b[i - 1].is_ascii_alphanumeric()) {
            i += 1;
            continue;
        }
        let end = (i..b.len()).find(|&j| !b[j].is_ascii_digit()).unwrap_or(b.len());
        let before = t[..i].trim_end_matches([' ', ':', '=']);
        let marked = before.ends_with("code") || before.ends_with("vendor") || before.ends_with("error") || (before.ends_with('(') && b.get(end) == Some(&b')'));
        if marked {
            if let Ok(code) = t[i..end].parse::<i64>() {
                if vendor_class(code).is_some() {
                    return Some(code);
                }
            }
        }
        i = end;
    }
    None
}

/// An HTTP status written in an error text: `Request failed (402)`, `status 429`, `HTTP 503`,
/// `returned 500`, `code 401`, `[http=402]`. Only 4xx and 5xx count.
pub fn http_status_in(text: &str) -> Option<u16> {
    let t = text.to_ascii_lowercase();
    let three = |s: &str| -> Option<u16> {
        let d: String = s.chars().take_while(char::is_ascii_digit).collect();
        (d.len() == 3).then(|| d.parse::<u16>().ok()).flatten().filter(|c| (400..600).contains(c))
    };
    for marker in ["[http=", "failed (", "status code ", "status: ", "status ", "http/1.1 ", "http/2 ", "http ", "returned ", "code ", "error ("] {
        let mut from = 0;
        while let Some(i) = t[from..].find(marker) {
            let at = from + i + marker.len();
            if let Some(c) = three(&t[at..]) {
                return Some(c);
            }
            from = at;
        }
    }
    None
}

/// Seconds from `Retry-After: N`, `retry after Ns` or `retry in N` in an error text.
pub fn retry_after_in(text: &str) -> Option<u64> {
    let t = text.to_ascii_lowercase();
    for marker in ["retry-after:", "retry-after", "retry after", "retry in"] {
        if let Some(i) = t.find(marker) {
            let rest = t[i + marker.len()..].trim_start_matches([' ', ':', '=']);
            let d: String = rest.chars().take_while(char::is_ascii_digit).collect();
            if let Ok(n) = d.parse::<u64>() {
                return Some(n);
            }
        }
    }
    None
}

fn class_of_text(text: &str) -> WakeClass {
    let t = text.to_ascii_lowercase();
    let has = |phrases: &[&str]| phrases.iter().any(|p| t.contains(p));
    // Most specific first.
    if has(&["prompt too long", "prompt is too long", "context length", "context window", "maximum context", "too many tokens", "context_length_exceeded"]) {
        WakeClass::Context
    } else if has(&["usage balance exhausted", "usage limit reached", "usage limit", "weekly limit", "quota exceeded", "insufficient_quota", "insufficient credits", "credit balance", "out of credits", "balance exhausted", "payment required"]) {
        WakeClass::Exhausted
    } else if has(&["rate limit", "rate_limit", "ratelimit", "too many requests", "rate limiting requests", "retry-after", "retry after"]) {
        WakeClass::RateLimited
    } else if has(&["overloaded", "server error", "internal error", "bad gateway", "service unavailable", "gateway timeout", "stream ended", "stream closed unexpectedly", "connection reset"]) {
        WakeClass::Overloaded
    } else if has(&["unauthorized", "forbidden", "auth_required", "authentication", "not logged in", "log in", "login", "sign in", "token expired", "invalid api key", "api key"]) {
        WakeClass::Auth
    } else if has(&["session not found", "no such session", "unknown session", "session does not exist", "session-load-failed"]) {
        WakeClass::SessionGone
    } else if has(&["already running", "turn in progress", "prompt in progress", "session is busy", "busy"]) {
        WakeClass::Busy
    } else if has(&["leader-absent", "leader_starting", "leader-not-ready", "leader-shutdown", "connection refused", "broken pipe", "no such file", "timeout", "timed out"]) {
        WakeClass::HostDown
    } else {
        WakeClass::Other
    }
}

/// The codes of `e` as text tags appended to a flattened error string (`[code=-32603]
/// [vendor=42212] [http=402]`), so the codes survive in a `String`-only error too; both
/// [`vendor_code_in`] and [`http_status_in`] read them back.
pub fn code_tags(e: &ProviderError) -> String {
    let mut out = String::new();
    if let Some(c) = e.rpc_code {
        out.push_str(&format!(" [code={c}]"));
    }
    if let Some(c) = e.vendor_code {
        out.push_str(&format!(" [vendor={c}]"));
    }
    if let Some(s) = e.http_status {
        out.push_str(&format!(" [http={s}]"));
    }
    if let Some(s) = e.retry_after_s {
        out.push_str(&format!(" [retry-after={s}]"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_grok_402_of_the_incident_is_exhausted() {
        let e = classify(Some(-32603), None, "Request failed (402): Grok Build usage balance exhausted");
        assert_eq!((e.class, e.http_status, e.rpc_code, e.class.retryable()), (WakeClass::Exhausted, Some(402), Some(-32603), false));
        assert_eq!(classify(None, None, "weekly limit reached, resets Oct 23").class, WakeClass::Exhausted);
    }

    #[test]
    fn mcode_vendor_codes_decide_first() {
        for (code, class) in [(42212, WakeClass::Exhausted), (50110, WakeClass::Exhausted), (50111, WakeClass::RateLimited), (50150, WakeClass::RateLimited)] {
            // As the JSON-RPC code itself, in error.data, and written in the text.
            assert_eq!(classify_rpc_error(&json!({"code": code, "message": "request failed"})).class, class, "{code} as error.code");
            let e = classify_rpc_error(&json!({"code": -32603, "message": "internal error", "data": {"code": code}}));
            assert_eq!((e.class, e.vendor_code, e.rpc_code), (class, Some(code), Some(-32603)), "{code} in data");
            assert_eq!(classify(None, None, &format!("API error (code {code}): upstream")).class, class, "{code} in text");
        }
        // The vendor code beats a status that says otherwise.
        assert_eq!(classify(None, Some(&json!({"status": 500, "base_resp": {"status_code": 42212}})), "x").class, WakeClass::Exhausted);
        assert_eq!(classify(None, None, "Usage limit reached.").class, WakeClass::Exhausted);
        assert_eq!(classify(None, None, "The model provider is rate limiting requests.").class, WakeClass::RateLimited);
    }

    #[test]
    fn bare_numbers_are_not_codes() {
        assert_eq!(vendor_code_in("listening on port 42212"), None);
        assert_eq!(vendor_code_in("wrote 150110 bytes"), None);
        assert_eq!(vendor_code_in("code 142212"), None);
        assert_eq!(vendor_code_in("error (50150)"), Some(50150));
        assert_eq!(classify(None, None, "failed (200)").class, WakeClass::Other, "2xx is no error class");
        assert_eq!(classify(Some(-32602), None, "invalid params").vendor_code, None, "a protocol code is never the vendor's");
    }

    #[test]
    fn statuses_decide_before_phrases() {
        assert_eq!(classify(None, Some(&json!({"http_status": 429})), "whatever").class, WakeClass::RateLimited);
        assert_eq!(classify(None, None, "HTTP 503 Service Unavailable").class, WakeClass::Overloaded);
        assert_eq!(classify(None, None, "status 529").class, WakeClass::Overloaded);
        assert_eq!(classify(None, None, "Request failed (401): token expired").class, WakeClass::Auth);
        assert_eq!(classify(None, None, "request returned 413").class, WakeClass::Context);
        assert_eq!(classify(None, Some(&json!({"error": {"status": 402}})), "x").http_status, Some(402));
    }

    #[test]
    fn retry_after_from_data_or_text() {
        let e = classify(None, None, "Rate limit exceeded. Retry-After: 30");
        assert_eq!((e.class, e.retry_after_s), (WakeClass::RateLimited, Some(30)));
        assert_eq!(classify(None, Some(&json!({"retry_after_ms": 1500})), "x").retry_after_s, Some(2));
        assert_eq!(classify(None, Some(&json!({"retry_after": "12"})), "x").retry_after_s, Some(12));
    }

    #[test]
    fn phrases_without_a_code() {
        assert_eq!(classify(None, None, "Overloaded").class, WakeClass::Overloaded);
        assert_eq!(classify(None, None, "prompt is too long: 210000 tokens > 200000 maximum").class, WakeClass::Context);
        assert_eq!(classify(None, None, "Please sign in to continue").class, WakeClass::Auth);
        assert_eq!(classify(None, None, "Session not found").class, WakeClass::SessionGone);
        assert_eq!(classify(None, None, "a turn in progress").class, WakeClass::Busy);
        assert_eq!(classify(None, None, "something odd").class, WakeClass::Other);
    }

    #[test]
    fn tags_carry_the_codes_through_a_string() {
        let e = classify_rpc_error(&json!({"code": -32603, "message": "Request failed", "data": {"code": 42212, "http_status": 402, "retry_after": 60}}));
        let flat = format!("{}{}", e.message, code_tags(&e));
        assert_eq!(flat, "Request failed [code=-32603] [vendor=42212] [http=402] [retry-after=60]");
        let back = classify(None, None, &flat);
        assert_eq!((back.class, back.vendor_code, back.http_status, back.retry_after_s), (WakeClass::Exhausted, Some(42212), Some(402), Some(60)));
    }

    #[test]
    fn messages_are_clipped_and_classes_serialize_as_names() {
        assert_eq!(classify(None, None, &"x".repeat(500)).message.chars().count(), MAX_MESSAGE);
        assert_eq!(serde_json::to_value(WakeClass::RateLimited).unwrap(), json!("rate_limited"));
        assert!(WakeClass::HostDown.retryable() && !WakeClass::Exhausted.retryable() && !WakeClass::Auth.retryable());
    }
}
