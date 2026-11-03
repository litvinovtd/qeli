//! Read-only WAN discovery and selection of remembered cleanup targets.
use crate::network_default_route::{preferred_default_device, DefaultDevice};
use std::io;
use std::process::Output;

pub(super) fn detect_wan(ctx: &super::Context) -> Option<String> {
    detect_wan_with(false, |args| ctx.ip(args))
}

pub(super) fn detect_wan_ipv6(ctx: &super::Context) -> Option<String> {
    select_wan_ipv6(ctx).selected()
}

pub(super) fn select_wan_ipv6(ctx: &super::Context) -> DefaultDevice {
    detect_wan_selection_with(true, |args| ctx.ip(args))
}

/// Prefer the default route itself; route-get remains the fallback when no
/// usable default route was reported. An ambiguous best route must not fall
/// back to a single destination-specific ECMP hash choice.
fn detect_wan_with(ipv6: bool, run: impl FnMut(&[&str]) -> io::Result<Output>) -> Option<String> {
    detect_wan_selection_with(ipv6, run).selected()
}

fn detect_wan_selection_with(
    ipv6: bool,
    mut run: impl FnMut(&[&str]) -> io::Result<Output>,
) -> DefaultDevice {
    let (show, lookup): (&[&str], &[&str]) = if ipv6 {
        (
            &["-6", "route", "show", "default"],
            &["-6", "route", "get", "2606:4700:4700::1111"],
        )
    } else {
        (&["route", "show", "default"], &["route", "get", "1.1.1.1"])
    };
    if let Ok(out) = run(show) {
        if out.status.success() {
            match preferred_default_device(&String::from_utf8_lossy(&out.stdout)) {
                DefaultDevice::Selected(device) => return DefaultDevice::Selected(device),
                DefaultDevice::Ambiguous => return DefaultDevice::Ambiguous,
                DefaultDevice::Missing => {}
            }
        }
    }
    let Ok(out) = run(lookup) else {
        return DefaultDevice::Missing;
    };
    if !out.status.success() {
        return DefaultDevice::Missing;
    }
    dev_token(&String::from_utf8_lossy(&out.stdout))
        .map_or(DefaultDevice::Missing, DefaultDevice::Selected)
}

fn dev_token(line: &str) -> Option<String> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    tokens
        .iter()
        .position(|&token| token == "dev")
        .and_then(|index| tokens.get(index + 1))
        .map(|device| device.to_string())
}

#[cfg(test)]
#[path = "wan/tests.rs"]
mod tests;
