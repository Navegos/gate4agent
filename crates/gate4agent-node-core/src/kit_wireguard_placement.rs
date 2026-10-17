//! Default-route classification for Windows WireGuard placement.
//! Pure logic, tested on every target.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefaultRoute {
    pub if_index: u32,
    pub metric: u32,
    pub tun: bool,
    pub alias: String,
    pub desc: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Placement {
    Open,
    InsideExisting { if_index: u32, alias: String, desc: String },
    WaitExitTun,
}

pub fn nested_locked(env_nested: bool, routes: &[DefaultRoute], ever_nested: bool) -> bool {
    env_nested || ever_nested || routes.iter().any(|r| r.tun)
}

pub fn classify(routes: &[DefaultRoute], nested: bool) -> Placement {
    let best = routes.iter().min_by_key(|route| route.metric);
    match best {
        Some(best) if best.tun => Placement::InsideExisting {
            if_index: best.if_index,
            alias: best.alias.clone(),
            desc: best.desc.clone(),
        },
        Some(_) | None if nested => Placement::WaitExitTun,
        Some(_) | None => Placement::Open,
    }
}

pub fn opens_adapter(placement: &Placement) -> bool {
    matches!(placement, Placement::Open)
}

pub fn parse_route_lines(text: &str) -> Vec<DefaultRoute> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            let (head, desc) = match line.split_once('\t') {
                Some((h, d)) => (h, d.trim().to_owned()),
                None => (line, "-".to_owned()),
            };
            let mut parts = head.split_whitespace();
            let if_index = parts.next()?.parse().ok()?;
            let metric = parts.next()?.parse().ok()?;
            let tun = parts.next()? == "1";
            let alias = {
                let rest: Vec<&str> = parts.collect();
                if rest.is_empty() {
                    "-".to_owned()
                } else {
                    rest.join(" ")
                }
            };
            Some(DefaultRoute {
                if_index,
                metric,
                tun,
                alias,
                desc: if desc.is_empty() { "-".to_owned() } else { desc },
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(if_index: u32, metric: u32, tun: bool, alias: &str) -> DefaultRoute {
        DefaultRoute {
            if_index,
            metric,
            tun,
            alias: alias.to_owned(),
            desc: "-".to_owned(),
        }
    }

    #[test]
    fn classify_opens_when_not_nested_and_default_is_not_tun() {
        assert_eq!(classify(&[route(5, 25, false, "eth0")], false), Placement::Open);
    }

    #[test]
    fn classify_waits_when_nested_and_default_is_not_tun() {
        assert_eq!(classify(&[route(5, 25, false, "eth0")], true), Placement::WaitExitTun);
        assert!(nested_locked(false, &[route(5, 25, false, "eth0")], true));
    }

    #[test]
    fn classify_uses_lowest_metric_tun() {
        let routes = [route(12, 256, false, "eth0"), route(40, 0, true, "tun0")];
        assert_eq!(
            classify(&routes, false),
            Placement::InsideExisting {
                if_index: 40,
                alias: "tun0".to_owned(),
                desc: "-".to_owned(),
            }
        );
        assert!(nested_locked(false, &routes, false));
    }

    #[test]
    fn nested_locked_by_env_or_any_tun() {
        assert!(nested_locked(true, &[], false));
        assert!(!nested_locked(false, &[route(1, 1, false, "eth")], false));
        assert!(nested_locked(false, &[route(1, 1, true, "tun")], false));
    }

    #[test]
    fn opens_adapter_only_for_open() {
        assert!(opens_adapter(&Placement::Open));
        assert!(!opens_adapter(&Placement::WaitExitTun));
        assert!(!opens_adapter(&Placement::InsideExisting {
            if_index: 1,
            alias: "t".into(),
            desc: "d".into(),
        }));
    }

    #[test]
    fn route_lines_parse_alias_and_desc() {
        let routes = parse_route_lines("15 0 1 nic 2\tWireGuard Tunnel\n9 256 0 nic0\n");
        assert_eq!(routes[0].alias, "nic 2");
        assert_eq!(routes[0].desc, "WireGuard Tunnel");
        assert!(routes[0].tun);
        assert!(!routes[1].tun);
        assert_eq!(routes[1].desc, "-");
    }
}
