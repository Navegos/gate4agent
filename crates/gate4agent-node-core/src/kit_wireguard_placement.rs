//! WireGuard placement on Windows, decided by facts about the interface that
//! carries traffic to the C2 endpoint (not by adapter names).
//! Pure logic; tested on every target.

/// IANA ifType values that mean "not a physical NIC".
const IFTYPE_PROP_VIRTUAL: u32 = 53;
const IFTYPE_TUNNEL: u32 = 131;
const IFTYPE_PPP: u32 = 23;
const IFTYPE_SOFTWARE_LOOPBACK: u32 = 24;
const IFTYPE_ETHERNET: u32 = 6;
const IFTYPE_WIFI: u32 = 71;

/// Name fragments used only as a secondary hint.
const NAME_HINTS: [&str; 8] = [
    "wintun", "wireguard", "tun", "tap", "vpn", "tunnel", "virtual", "ppp",
];

/// One route candidate toward the C2 endpoint with facts about its interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteFact {
    pub if_index: u32,
    /// Destination prefix of the route, e.g. `0.0.0.0/0`, `0.0.0.0/1`, `x.x.x.x/32`.
    pub prefix: String,
    pub metric: u32,
    /// IANA ifType (`InterfaceType` of Get-NetAdapter / `InterfaceType` of MIB). 0 = unknown.
    pub if_type: u32,
    /// `HardwareInterface` of Get-NetAdapter. `None` = no adapter object (hidden/virtual driver).
    pub hardware: Option<bool>,
    /// `Virtual` of Get-NetAdapter, when present.
    pub is_virtual: Option<bool>,
    pub media: String,
    pub alias: String,
    pub desc: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Placement {
    /// Traffic to C2 leaves through a physical adapter: a dedicated adapter may be created.
    Open,
    /// Traffic to C2 already rides another tunnel: run WG in userspace inside it, no adapter.
    InsideExisting { if_index: u32, alias: String, desc: String },
    /// Nested mode is locked but no tunnel carries traffic right now: wait.
    WaitExitTun,
}

/// Why the decision was made (logged verbatim).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub placement: Placement,
    pub reason: String,
    pub route: Option<RouteFact>,
}

/// Prefix length of `a.b.c.d/n`; unparseable = 0.
pub fn prefix_len(prefix: &str) -> u8 {
    prefix
        .rsplit_once('/')
        .and_then(|(_, n)| n.trim().parse::<u8>().ok())
        .unwrap_or(0)
}

/// `0.0.0.0/1` or `128.0.0.0/1` (typical VPN split-default).
pub fn is_split_default(prefix: &str) -> bool {
    let p = prefix.trim();
    p == "0.0.0.0/1" || p == "128.0.0.0/1"
}

/// Most specific route wins; ties broken by lowest metric.
pub fn decisive_route(routes: &[RouteFact]) -> Option<&RouteFact> {
    routes
        .iter()
        .max_by(|a, b| {
            prefix_len(&a.prefix)
                .cmp(&prefix_len(&b.prefix))
                .then_with(|| b.metric.cmp(&a.metric))
        })
}

/// Facts that make an interface a tunnel. Returns the reason when it is one.
pub fn tunnel_reason(route: &RouteFact) -> Option<String> {
    match route.if_type {
        IFTYPE_PROP_VIRTUAL => return Some("if_type=53 propVirtual".into()),
        IFTYPE_TUNNEL => return Some("if_type=131 tunnel".into()),
        IFTYPE_PPP => return Some("if_type=23 ppp".into()),
        _ => {}
    }
    if route.hardware == Some(false) {
        return Some("hardware_interface=false".into());
    }
    if route.is_virtual == Some(true) {
        return Some("virtual=true".into());
    }
    if route.hardware.is_none() && route.if_type != IFTYPE_SOFTWARE_LOOPBACK {
        return Some("no physical adapter object".into());
    }
    if is_split_default(&route.prefix) {
        return Some(format!("split default route {}", route.prefix));
    }
    let media = route.media.to_ascii_lowercase();
    if !media.is_empty()
        && media != "802.3"
        && (media.contains("tunnel") || (media.contains("ip") && !media.contains("802")))
    {
        return Some(format!("media={}", route.media));
    }
    let blob = format!("{} {}", route.alias, route.desc).to_ascii_lowercase();
    if route.if_type != IFTYPE_ETHERNET && route.if_type != IFTYPE_WIFI {
        if let Some(hint) = NAME_HINTS.iter().find(|h| blob.contains(*h)) {
            return Some(format!("name hint '{hint}'"));
        }
    }
    None
}

pub fn decide(routes: &[RouteFact], nested_locked: bool) -> Decision {
    let Some(route) = decisive_route(routes) else {
        return Decision {
            placement: if nested_locked { Placement::WaitExitTun } else { Placement::Open },
            reason: "no route to endpoint".into(),
            route: None,
        };
    };
    if let Some(why) = tunnel_reason(route) {
        return Decision {
            placement: Placement::InsideExisting {
                if_index: route.if_index,
                alias: route.alias.clone(),
                desc: route.desc.clone(),
            },
            reason: format!("tunnel: {why}"),
            route: Some(route.clone()),
        };
    }
    // A tunnel anywhere in the list that is not decisive still means a VPN is
    // around; with nested locked we wait for it instead of opening our own.
    if nested_locked {
        return Decision {
            placement: Placement::WaitExitTun,
            reason: "nested locked; decisive route is physical".into(),
            route: Some(route.clone()),
        };
    }
    Decision {
        placement: Placement::Open,
        reason: "physical: route to endpoint via hardware adapter".into(),
        route: Some(route.clone()),
    }
}

pub fn opens_adapter(placement: &Placement) -> bool {
    matches!(placement, Placement::Open)
}

fn opt_bool(s: &str) -> Option<bool> {
    match s.trim() {
        "1" | "True" | "true" => Some(true),
        "0" | "False" | "false" => Some(false),
        _ => None,
    }
}

/// Parse tab-separated lines:
/// `if_index \t prefix \t metric \t if_type \t hardware \t virtual \t media \t alias \t desc`
pub fn parse_route_facts(text: &str) -> Vec<RouteFact> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim_end_matches(['\r', '\n']);
            if line.trim().is_empty() {
                return None;
            }
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() < 9 {
                return None;
            }
            Some(RouteFact {
                if_index: f[0].trim().parse().ok()?,
                prefix: f[1].trim().to_owned(),
                metric: f[2].trim().parse().unwrap_or(u32::MAX),
                if_type: f[3].trim().parse().unwrap_or(0),
                hardware: opt_bool(f[4]),
                is_virtual: opt_bool(f[5]),
                media: f[6].trim().to_owned(),
                alias: f[7].trim().to_owned(),
                desc: f[8].trim().to_owned(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact(if_index: u32, prefix: &str, metric: u32, if_type: u32, hw: Option<bool>, alias: &str) -> RouteFact {
        RouteFact {
            if_index,
            prefix: prefix.into(),
            metric,
            if_type,
            hardware: hw,
            is_virtual: None,
            media: String::new(),
            alias: alias.into(),
            desc: "adapter".into(),
        }
    }

    #[test]
    fn unknown_vpn_name_with_virtual_iftype_is_inside() {
        let routes = [
            fact(12, "0.0.0.0/0", 25, IFTYPE_ETHERNET, Some(true), "Ethernet"),
            fact(30, "0.0.0.0/0", 1, IFTYPE_PROP_VIRTUAL, Some(false), "Zebra Link"),
        ];
        let d = decide(&routes, false);
        assert!(matches!(d.placement, Placement::InsideExisting { if_index: 30, .. }), "{d:?}");
    }

    #[test]
    fn split_default_beats_physical_default() {
        let routes = [
            fact(12, "0.0.0.0/0", 25, IFTYPE_ETHERNET, Some(true), "Ethernet"),
            fact(30, "0.0.0.0/1", 5, 0, Some(true), "Unnamed"),
        ];
        let d = decide(&routes, false);
        assert!(matches!(d.placement, Placement::InsideExisting { if_index: 30, .. }), "{d:?}");
        assert!(d.reason.contains("split"), "{}", d.reason);
    }

    #[test]
    fn host_route_is_most_specific() {
        let routes = [
            fact(30, "0.0.0.0/1", 5, IFTYPE_TUNNEL, Some(false), "Tun"),
            fact(12, "198.51.100.7/32", 25, IFTYPE_ETHERNET, Some(true), "Ethernet"),
        ];
        let d = decide(&routes, false);
        assert_eq!(d.placement, Placement::Open, "{d:?}");
    }

    #[test]
    fn physical_only_opens_or_waits_when_nested() {
        let routes = [fact(12, "0.0.0.0/0", 25, IFTYPE_ETHERNET, Some(true), "Ethernet")];
        assert_eq!(decide(&routes, false).placement, Placement::Open);
        assert_eq!(decide(&routes, true).placement, Placement::WaitExitTun);
    }

    #[test]
    fn missing_adapter_object_counts_as_virtual() {
        let routes = [fact(44, "0.0.0.0/0", 1, 0, None, "x")];
        assert!(matches!(decide(&routes, false).placement, Placement::InsideExisting { .. }));
    }

    #[test]
    fn name_is_only_a_hint_for_unknown_type() {
        let mut f = fact(9, "0.0.0.0/0", 1, IFTYPE_ETHERNET, Some(true), "My VPN");
        assert_eq!(tunnel_reason(&f), None);
        f.if_type = 0;
        assert!(tunnel_reason(&f).unwrap().contains("name hint"));
    }

    #[test]
    fn no_route_waits_when_nested() {
        assert_eq!(decide(&[], true).placement, Placement::WaitExitTun);
        assert_eq!(decide(&[], false).placement, Placement::Open);
    }

    #[test]
    fn parses_tab_separated_facts_with_utf8_alias() {
        let text = "30\t0.0.0.0/1\t5\t53\tFalse\tTrue\t\tТуннель 1\tSome Adapter\r\n12\t0.0.0.0/0\t25\t6\tTrue\tFalse\t802.3\tEthernet\tNIC\n";
        let r = parse_route_facts(text);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].alias, "Туннель 1");
        assert_eq!(r[0].hardware, Some(false));
        assert_eq!(r[0].is_virtual, Some(true));
        assert_eq!(r[1].if_type, 6);
        assert!(matches!(decide(&r, false).placement, Placement::InsideExisting { if_index: 30, .. }));
    }

    #[test]
    fn opens_adapter_only_for_open() {
        assert!(opens_adapter(&Placement::Open));
        assert!(!opens_adapter(&Placement::WaitExitTun));
    }
}
