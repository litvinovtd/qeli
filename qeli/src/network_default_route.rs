//! Shared Linux default-route selection for client gateway and server WAN setup.
//! An ECMP hash result for one destination never authorizes a single-uplink plan.

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DefaultDevice {
    Missing,
    Selected(String),
    Ambiguous,
}

impl DefaultDevice {
    #[cfg(any(feature = "client", test))]
    pub(crate) fn selected(self) -> Option<String> {
        match self {
            Self::Selected(device) => Some(device),
            Self::Missing | Self::Ambiguous => None,
        }
    }
}

/// `ip route show default` is not priority-ordered. A multipath route is
/// printed as a `default` header followed by indented `nexthop` lines; equal
/// metric routes can also select different devices. Both need more than one
/// WAN rule, which this name-based exit backend does not install atomically.
pub(crate) fn preferred_default_device(output: &str) -> DefaultDevice {
    let mut routes: Vec<(u32, Vec<String>)> = Vec::new();
    let mut current = None;
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        match fields.first().copied() {
            Some("default") => {
                let metric = match fields.iter().position(|field| *field == "metric") {
                    Some(index) => fields.get(index + 1).and_then(|s| s.parse::<u32>().ok()),
                    None => Some(0),
                };
                let Some(metric) = metric else {
                    current = None;
                    continue;
                };
                routes.push((metric, dev_tokens(&fields)));
                current = Some(routes.len() - 1);
            }
            Some("nexthop") => {
                if let Some(index) = current {
                    routes[index].1.extend(dev_tokens(&fields));
                }
            }
            _ => current = None,
        }
    }
    let Some(best_metric) = routes
        .iter()
        .filter(|(_, devices)| !devices.is_empty())
        .map(|(metric, _)| *metric)
        .min()
    else {
        return DefaultDevice::Missing;
    };
    let mut selected: Option<String> = None;
    for (_, devices) in routes.iter().filter(|(metric, _)| *metric == best_metric) {
        for device in devices {
            match &selected {
                Some(previous) if previous != device => return DefaultDevice::Ambiguous,
                None => selected = Some(device.clone()),
                _ => {}
            }
        }
    }
    selected.map_or(DefaultDevice::Missing, DefaultDevice::Selected)
}

fn dev_tokens(fields: &[&str]) -> Vec<String> {
    fields
        .windows(2)
        .filter(|pair| pair[0] == "dev")
        .map(|pair| pair[1].to_string())
        .collect()
}
