//! Generation-scoped platform path updates and transactional path commands.
//!
//! This module is deliberately control-plane only. A completed transaction records that a
//! future transport proved a candidate and that the platform committed its temporary rules;
//! it never swaps the live socket, TUN/TAP, `NetworkPlan` or packet pumps by itself.

use super::{CoreError, MAX_PLAN_STRING_BYTES};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::time::Instant;

pub const MAX_PATH_UPDATE_BYTES: usize = 64 * 1024;
pub const MAX_PATH_LOCAL_ADDRESSES: usize = 16;
pub const MAX_PATH_RESOLUTIONS: usize = 16;
pub const MAX_PATH_TTL_SECS: u32 = 7 * 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathUpdateReason {
    NetworkChanged,
    DefaultRouteChanged,
    Wake,
    SameNetworkNatFailure,
    ManualProbe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PathUpdateFlags {
    #[serde(default)]
    pub default_route_changed: bool,
    #[serde(default)]
    pub wake: bool,
    #[serde(default)]
    pub same_network_nat_failure: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathResolution {
    /// Literal A/AAAA result resolved through the selected physical network.
    pub address: String,
    /// Remaining DNS lifetime when the update crosses the ABI. Zero means no caching.
    pub ttl_secs: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathUpdate {
    /// Active `NetworkPlan`/runtime generation. An old generation is always rejected.
    pub generation: u64,
    /// Monotonic platform sequence within one generation, used for idempotency.
    pub update_id: u64,
    pub platform_path_id: String,
    pub reason: PathUpdateReason,
    /// Stable opaque physical-network token, if the platform exposes one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_token: Option<String>,
    /// One-based OS interface index, if a stable network token is unavailable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface_index: Option<u32>,
    /// Literal addresses currently usable as candidate source addresses.
    pub local_addresses: Vec<String>,
    /// Bounded A/AAAA answers obtained through this exact physical path.
    pub resolved_addresses: Vec<PathResolution>,
    #[serde(default)]
    pub flags: PathUpdateFlags,
}

impl PathUpdate {
    pub(crate) fn parse(input: &str) -> Result<Self, CoreError> {
        if input.len() > MAX_PATH_UPDATE_BYTES {
            return Err(CoreError::InvalidArgument(format!(
                "path update is {} bytes; maximum is {MAX_PATH_UPDATE_BYTES}",
                input.len()
            )));
        }
        let update: Self = serde_json::from_str(input)
            .map_err(|error| CoreError::InvalidArgument(format!("invalid path update: {error}")))?;
        update.validate()?;
        Ok(update)
    }

    pub(crate) fn validate(&self) -> Result<(), CoreError> {
        if self.generation == 0 || self.update_id == 0 {
            return Err(CoreError::InvalidArgument(
                "path generation and update_id must be non-zero".into(),
            ));
        }
        validate_identifier("platform path id", &self.platform_path_id)?;
        if let Some(token) = &self.network_token {
            validate_identifier("physical network token", token)?;
        }
        if self.network_token.is_none() && self.interface_index.is_none() {
            return Err(CoreError::InvalidArgument(
                "path update requires a physical network token or interface index".into(),
            ));
        }
        if self.interface_index == Some(0) {
            return Err(CoreError::InvalidArgument(
                "path interface index must be non-zero".into(),
            ));
        }
        let missing_reason_flag = match self.reason {
            PathUpdateReason::DefaultRouteChanged => !self.flags.default_route_changed,
            PathUpdateReason::Wake => !self.flags.wake,
            PathUpdateReason::SameNetworkNatFailure => !self.flags.same_network_nat_failure,
            PathUpdateReason::NetworkChanged | PathUpdateReason::ManualProbe => false,
        };
        if missing_reason_flag {
            return Err(CoreError::InvalidArgument(format!(
                "path update reason {:?} requires its matching flag",
                self.reason
            )));
        }
        if self.local_addresses.is_empty() || self.local_addresses.len() > MAX_PATH_LOCAL_ADDRESSES
        {
            return Err(CoreError::InvalidArgument(format!(
                "path update must contain 1..={MAX_PATH_LOCAL_ADDRESSES} local addresses"
            )));
        }
        if self.resolved_addresses.is_empty()
            || self.resolved_addresses.len() > MAX_PATH_RESOLUTIONS
        {
            return Err(CoreError::InvalidArgument(format!(
                "path update must contain 1..={MAX_PATH_RESOLUTIONS} resolved addresses"
            )));
        }

        let mut local = BTreeSet::new();
        for value in &self.local_addresses {
            if value.len() > MAX_PLAN_STRING_BYTES {
                return Err(CoreError::InvalidArgument(
                    "path local address is too long".into(),
                ));
            }
            let address: IpAddr = value.parse().map_err(|_| {
                CoreError::InvalidArgument(format!("invalid path local address '{value}'"))
            })?;
            if is_unusable_path_address(address) {
                return Err(CoreError::InvalidArgument(format!(
                    "path local address '{value}' is not usable"
                )));
            }
            if !local.insert(address) {
                return Err(CoreError::InvalidArgument(format!(
                    "duplicate path local address '{value}'"
                )));
            }
        }

        let mut resolved = BTreeSet::new();
        for value in &self.resolved_addresses {
            if value.address.len() > MAX_PLAN_STRING_BYTES {
                return Err(CoreError::InvalidArgument(
                    "resolved path address is too long".into(),
                ));
            }
            let address: IpAddr = value.address.parse().map_err(|_| {
                CoreError::InvalidArgument(format!(
                    "invalid resolved path address '{}'",
                    value.address
                ))
            })?;
            if is_unusable_path_address(address) {
                return Err(CoreError::InvalidArgument(format!(
                    "resolved path address '{}' is not usable",
                    value.address
                )));
            }
            if value.ttl_secs > MAX_PATH_TTL_SECS {
                return Err(CoreError::InvalidArgument(format!(
                    "resolved path TTL {} exceeds {MAX_PATH_TTL_SECS}",
                    value.ttl_secs
                )));
            }
            if !resolved.insert(address) {
                return Err(CoreError::InvalidArgument(format!(
                    "duplicate resolved path address '{}'",
                    value.address
                )));
            }
        }
        if self.compatible_resolved_addresses().is_empty() {
            return Err(CoreError::InvalidArgument(
                "path update has no resolved address compatible with a local address family".into(),
            ));
        }
        Ok(())
    }

    /// Preserve DNS/platform order while excluding carrier families that this physical path
    /// cannot source. Platform adapters may report dual-stack DNS on an IPv4-only or IPv6-only
    /// link; trying the incompatible first answer would turn a usable handover into a fallback.
    pub(crate) fn compatible_resolved_addresses(&self) -> Vec<IpAddr> {
        let mut local_families = [false; 2];
        for address in self
            .local_addresses
            .iter()
            .filter_map(|value| value.parse::<IpAddr>().ok())
        {
            local_families[if address.is_ipv6() { 1 } else { 0 }] = true;
        }
        self.resolved_addresses
            .iter()
            .filter_map(|value| value.address.parse::<IpAddr>().ok())
            .filter(|address| local_families[if address.is_ipv6() { 1 } else { 0 }])
            .collect()
    }
}

fn is_unusable_path_address(address: IpAddr) -> bool {
    address.is_unspecified()
        || address.is_multicast()
        || address.is_loopback()
        || matches!(address, IpAddr::V4(value) if value.is_broadcast())
}

fn validate_identifier(label: &str, value: &str) -> Result<(), CoreError> {
    if value.is_empty()
        || value.len() > MAX_PLAN_STRING_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(CoreError::InvalidArgument(format!(
            "{label} must be 1..={MAX_PLAN_STRING_BYTES} UTF-8 bytes without control characters"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathCommandAction {
    PreparePath,
    BindSocket,
    CommitPath,
    AbortPath,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PathCommand {
    pub generation: u64,
    pub candidate_id: u64,
    pub action: PathCommandAction,
    pub path: PathUpdate,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socket_fd: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathCandidatePhase {
    Preparing,
    Prepared,
    Binding,
    Bound,
    Committing,
    Aborting,
}

/// Immutable transport view of a platform-prepared candidate. The transport may borrow this
/// snapshot only to create and validate the exact socket identified by `candidate_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreparedPathCandidate {
    pub candidate_id: u64,
    pub update: PathUpdate,
}

pub(crate) struct PathCandidate {
    pub candidate_id: u64,
    pub update: PathUpdate,
    pub phase: PathCandidatePhase,
    pub pending_sequence: Option<u64>,
    pub started_at: Instant,
    pub failure_recorded: bool,
}

impl PathCandidate {
    pub(crate) fn command(
        &self,
        action: PathCommandAction,
        socket_fd: Option<i64>,
        reason: Option<String>,
    ) -> PathCommand {
        PathCommand {
            generation: self.update.generation,
            candidate_id: self.candidate_id,
            action,
            path: self.update.clone(),
            socket_fd,
            reason,
        }
    }
}

pub(crate) struct QueuedPathCandidate {
    pub candidate_id: u64,
    pub update: PathUpdate,
}
