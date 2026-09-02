package com.qeli

import com.qeli.model.VpnConfig

/**
 * Everything that affects the Android-owned TUN. Transport-only facts and the native
 * generation are deliberately absent: a full reconnect may attach a new Rust generation to
 * the same kernel interface only when this value is unchanged.
 */
internal data class AndroidTunPlanFingerprint(
    val familyMode: String,
    val addresses: List<String>,
    val mtu: Int,
    val routes: List<String>,
    val pushedRoutes: List<String>,
    val dnsServers: List<String>,
    val fullTunnel: Boolean,
    val killSwitch: Boolean,
    val allowIpv4Leak: Boolean,
    val allowIpv6Leak: Boolean,
    val dnsMode: String,
    val excludedRoutes: List<String>,
    val allowLan: Boolean,
    val appsMode: String,
    val apps: List<String>,
    val modernRouteExclusionApi: Boolean,
)

internal fun androidTunPlanFingerprint(
    config: VpnConfig,
    plan: TransportCoreNetworkPlan,
    effectiveAllowLan: Boolean,
    sdkInt: Int,
): AndroidTunPlanFingerprint = AndroidTunPlanFingerprint(
    familyMode = plan.familyMode,
    addresses = plan.addresses.map {
        "${it.family}:${it.address}/${it.prefixLength}@${it.onLinkPrefixLength}:${it.gateway.orEmpty()}"
    }.sorted(),
    mtu = plan.mtu,
    routes = plan.routes.map { "${it.cidr}:${it.gateway}:${it.metric}" }.sorted(),
    pushedRoutes = plan.pushedRoutes.sorted(),
    dnsServers = plan.dnsServers.map { "${it.address}:${it.port}" }.sorted(),
    fullTunnel = plan.fullTunnel,
    killSwitch = plan.killSwitch,
    allowIpv4Leak = plan.allowIpv4Leak,
    allowIpv6Leak = plan.allowIpv6Leak,
    dnsMode = config.dnsMode,
    excludedRoutes = config.excludeRoutes.sorted(),
    allowLan = effectiveAllowLan,
    appsMode = config.appsMode,
    apps = config.apps.sorted(),
    modernRouteExclusionApi = sdkInt >= 33,
)
