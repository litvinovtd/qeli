#!/usr/bin/env python3

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import build_native_libs_p4 as desktop
import build_mac_universal as macpack


class NativeRecipeTests(unittest.TestCase):
    def test_release_server_requires_jemalloc_but_client_builds_stay_isolated(self):
        root = Path(__file__).resolve().parents[1]
        main = (root / "qeli/src/main.rs").read_text(encoding="utf-8")
        makefile = (root / "qeli/debian/Makefile").read_text(encoding="utf-8")
        workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        lab_gate = (root / "scripts/lab_build_jemalloc.py").read_text(
            encoding="utf-8"
        )
        keenetic_gate = (root / "scripts/keenetic_verify.py").read_text(
            encoding="utf-8"
        )

        error = "release qeli server builds require --features jemalloc"
        self.assertIn('not(debug_assertions)', main)
        self.assertIn('not(feature = "jemalloc")', main)
        self.assertIn(f'compile_error!("{error}")', main)

        self.assertNotIn("CARGO_FEATURES", makefile)
        self.assertIn(
            "cargo build --locked --release --features jemalloc --bin $(PACKAGE_NAME)",
            makefile,
        )
        self.assertIn(
            "cargo zigbuild --locked --release --features jemalloc --bin $(PACKAGE_NAME)",
            makefile,
        )

        self.assertIn("cargo check --locked --release --bin qeli", workflow)
        self.assertIn(error, workflow)
        self.assertIn(
            "cargo build --locked --bin qeli --release --features jemalloc",
            workflow,
        )
        self.assertIn("guard_ok = rc2 != 0", lab_gate)
        self.assertIn(error, lab_gate)
        self.assertIn(
            "cargo build --release --features jemalloc --bin qeli", keenetic_gate
        )
        self.assertIn("server_build=", keenetic_gate)


    def test_macos_install_name_does_not_contain_build_pass_path(self):
        flags = desktop.macos_rust_flags()
        self.assertIn("-install_name,@rpath/libqeli.dylib", flags)
        self.assertNotIn("-no_uuid", flags)
        self.assertNotIn("desktop-a", flags)
        self.assertNotIn("desktop-b", flags)

    def test_independent_artifacts_still_have_distinct_storage(self):
        first = desktop.artifact_path("a", desktop.MAC_TARGET, "libqeli.dylib")
        second = desktop.artifact_path("b", desktop.MAC_TARGET, "libqeli.dylib")
        self.assertNotEqual(first, second)

    def test_rcodesign_textual_error_is_not_accepted_with_zero_exit(self):
        class FakeClient:
            def checked(self, _command, _label):
                return "normalized"

            def run(self, _command):
                return "Error: invalid signature", 0

        with self.assertRaisesRegex(RuntimeError, "rcodesign sign failed"):
            desktop.normalize_and_sign_macos(FakeClient(), "/tmp/libqeli.dylib", "a")

    def test_apk_rebuild_uses_strict_shared_lab_connection(self):
        source = (Path(__file__).parent / "rebuild_apk.py").read_text(encoding="utf-8")
        self.assertIn("from native_lab import connect_lab", source)
        self.assertIn("apksigner} verify", source)
        self.assertIn("pull_verified_artifact", source)
        self.assertIn("shutil.copy2(cur, prev)", source)
        self.assertNotIn("os.replace(cur, prev)", source)
        self.assertNotIn("AutoAddPolicy", source)

    def test_macos_packaging_uses_checked_shared_lab_connection(self):
        source = (Path(__file__).parent / "build_mac_universal.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("from native_lab import connect_lab", source)
        self.assertIn("print-signature-info", source)
        self.assertIn("pull_verified_artifact", source)
        self.assertNotIn("AutoAddPolicy", source)

    def test_macos_packaging_batches_signing_and_accepts_adhoc_runtime_flag(self):
        self.assertIn("print-signature-info", macpack.REMOTE_SIGN_PY)
        self.assertIn('"CodeSignatureFlags(ADHOC"', macpack.REMOTE_SIGN_PY)
        source = Path(macpack.__file__).read_text(encoding="utf-8")
        self.assertIn("python3 sign_app.py", source)
        self.assertIn("remote_sha256(c, cached) != expected", source)

    def test_android_e2e_uses_current_abi_strict_ssh_and_exact_restore(self):
        source = (Path(__file__).parent / "e2e_final.py").read_text(encoding="utf-8")
        self.assertIn("from lab_common import LAB_CLI, LAB_SRV, connect", source)
        self.assertIn("Shared native transport active: ABI 0x1000a", source)
        self.assertIn("original_server_bytes", source)
        self.assertNotIn("AutoAddPolicy", source)

    def test_installer_formats_ipv6_authorities_and_public_panel_bind(self):
        root = Path(__file__).parent.parent
        source = (root / "install-qeli-server.sh").read_text(encoding="utf-8")
        self.assertIn('PUBLIC_AUTHORITY_HOST="[${PUBLIC_HOST}]"', source)
        self.assertIn('PUBLIC_PANEL_BIND="::"', source)
        self.assertIn('if [ -s /proc/net/if_inet6 ]; then', source)
        self.assertIn('ENABLE_IPV6_LISTENER=1', source)
        self.assertIn('listen = [::]:${PORT}', source)
        self.assertIn("qeli makes\n# that socket V6ONLY", source)
        self.assertIn(
            'apply_mss_clamp iptables PREROUTING "$MSS_INPUT_RULE" IPv4 server-to-client 1240',
            source,
        )
        self.assertIn(
            'apply_mss_clamp iptables OUTPUT "$MSS_RULE" IPv4 client-to-server 1240',
            source,
        )
        self.assertIn(
            'apply_mss_clamp ip6tables PREROUTING "$MSS6_INPUT_RULE" IPv6 server-to-client 1220',
            source,
        )
        self.assertIn(
            'apply_mss_clamp ip6tables OUTPUT "$MSS6_RULE" IPv6 client-to-server 1220',
            source,
        )
        self.assertIn('/etc/iptables/rules.v6', source)
        self.assertIn(
            'persist_new_ruleset iptables-save iptables-restore /etc/iptables/rules.v4 IPv4', source
        )
        self.assertIn(
            'persist_new_ruleset ip6tables-save ip6tables-restore /etc/iptables/rules.v6 IPv6', source
        )
        self.assertNotIn('iptables-save > /etc/iptables/rules.v4', source)
        self.assertNotIn('ip6tables-save > /etc/iptables/rules.v6', source)
        self.assertIn('ln "$tmp" "$destination"', source)
        self.assertIn('[ ! -s "$tmp" ]', source)
        self.assertIn('"$restore_cmd" --test <"$tmp"', source)
        self.assertNotIn('\n    netfilter-persistent save', source)
        self.assertIn('MSS_LAST_ADDED=0', source)
        self.assertEqual(source.count('record_mss_clamp "'), 4)
        self.assertIn('[ "$MSS_ADDED" = "1" ] || [ "$MSS6_ADDED" = "1" ]', source)
        self.assertIn('[ "$ENABLE_IPV6_LISTENER" = "1" ]', source)
        self.assertIn('--host "${PUBLIC_AUTHORITY_HOST}:${PORT}"', source)

        for helper_name in ("prod_tcp_tune.py", "fix_prod_firewall.py"):
            helper = (root / "scripts" / helper_name).read_text(encoding="utf-8")
            self.assertIn("rules.v4.qeli.XXXXXX", helper)
            self.assertIn("iptables-restore --test", helper)
            self.assertIn('mv -f \\"$tmp\\" /etc/iptables/rules.v4; then :;', helper)
            self.assertIn('rm -f \\"$tmp\\"', helper)

    def test_desktop_ipv6_merge_keeps_persist_tun_plan_guard(self):
        root = Path(__file__).parent.parent
        for relative in (
            "qeli-win/QeliWin/Vpn/VpnTunnel.cs",
            "qeli-mac/QeliMac/Vpn/VpnTunnel.cs",
        ):
            source = (root / relative).read_text(encoding="utf-8")
            self.assertIn(
                "protected override bool SupportsPlanReplacementGuard => true;",
                source,
                relative,
            )
            self.assertIn(
                "protected override ulong NativeIpv6Capabilities(VpnConfig config)",
                source,
                relative,
            )

    def test_authoritative_session_teardown_joins_admission_transaction(self):
        root = Path(__file__).parent.parent
        cases = (
            (
                "qeli/src/server/handler.rs",
                "if was_last {",
                "profile.pool.lock().await.release",
            ),
            (
                "qeli/src/server/control.rs",
                "async fn kick_user_on_profile",
                "profile.pool.lock().await.release",
            ),
            (
                "qeli/src/server/mod.rs",
                "for (pname, ip, session_id) in to_kick",
                "profile.pool.lock().await.release",
            ),
        )
        for relative, start_marker, release_marker in cases:
            source = (root / relative).read_text(encoding="utf-8")
            start = source.index(start_marker)
            release = source.index(release_marker, start)
            admission = source.index("profile.admission.lock().await", start, release)
            iroute = source.index("program_client_subnet_route(", admission, release)
            self.assertLess(admission, release, relative)
            self.assertLess(iroute, release, relative)

        handler = (root / "qeli/src/server/handler.rs").read_text(encoding="utf-8")
        route_programmer = handler.split(
            "pub(crate) async fn program_client_subnet_route", 1
        )[1].split("fn client_subnet_is_default", 1)[0]
        self.assertIn("tokio::time::timeout", route_programmer)
        self.assertIn("kill_on_drop(true)", route_programmer)

    def test_failed_tcp_and_udp_admission_release_restored_device_lease(self):
        root = Path(__file__).parent.parent
        for relative in (
            "qeli/src/server/handler.rs",
            "qeli/src/server/udp_handler.rs",
        ):
            source = (root / relative).read_text(encoding="utf-8")
            error_check = source.index("if result.is_err()")
            release = source.index("pool.release(&dkey)", error_check)
            self.assertLess(error_check, release, relative)

    def test_udp_idle_reaper_joins_admission_before_releasing_device_lease(self):
        root = Path(__file__).parent.parent
        source = (root / "qeli/src/server/udp_handler.rs").read_text(encoding="utf-8")
        start = source.index("for (device_key, client_ip, session_id) in to_release")
        release = source.index("profile.pool.lock().await.release(&device_key)", start)
        admission = source.index("profile.admission.lock().await", start, release)
        iroute = source.index("program_client_subnet_route(", release)
        guard_drop = source.index("drop(admission_guard)", iroute)
        self.assertLess(admission, release)
        self.assertLess(iroute, guard_drop)
        self.assertNotIn("spawn_client_route_teardown", source)

    def test_mobile_connection_properties_use_the_live_generation_snapshot(self):
        root = Path(__file__).parent.parent

        android_service = (root / "qeli-android/app/src/main/kotlin/com/qeli/QeliService.kt").read_text(
            encoding="utf-8"
        )
        android_view = (root / "qeli-android/app/src/main/kotlin/com/qeli/MainActivity.kt").read_text(
            encoding="utf-8"
        )
        self.assertIn("liveConnectionProperties = connectedConfig?.let", android_service)
        self.assertIn("liveConnectionProperties = null", android_service)
        self.assertIn("VpnServiceImpl.liveConnectionProperties", android_view)
        self.assertNotIn("ProtectionSummary.of(cfg, globalAllowLan())", android_view)

        ios_project = (root / "qeli-ios/project.yml").read_text(encoding="utf-8")
        packet_tunnel = ios_project.split("  QeliPacketTunnel:", 1)[1].split(
            "  QeliWidgets:", 1
        )[0]
        self.assertNotIn("- Model/Protection.swift", packet_tunnel)

        ios_engine = (root / "qeli-ios/QeliPacketTunnel/QeliNativeTunnelEngine.swift").read_text(
            encoding="utf-8"
        )
        ios_view = (root / "qeli-ios/QeliIOS/Views/ConnectionView.swift").read_text(
            encoding="utf-8"
        )
        ios_model = (root / "qeli-ios/QeliIOS/AppModel.swift").read_text(encoding="utf-8")
        self.assertIn("snapshot.liveConnectionProperties = liveConnectionProperties", ios_engine)
        self.assertIn("snapshot.liveConnectionProperties = nil", ios_engine)
        self.assertIn("model.tunnelSnapshot.liveConnectionProperties", ios_view)
        self.assertNotIn("VPNConfig(parsing: $0.configText)", ios_view)
        self.assertIn("updateCheckGeneration &+= 1", ios_model)
        self.assertIn("if updateCheckGeneration == generation", ios_model)
        self.assertIn("automaticUpdateChecked = false", ios_model)

    def test_ios_retained_wire_primitives_are_test_only(self):
        root = Path(__file__).parent.parent
        ios_project = (root / "qeli-ios/project.yml").read_text(encoding="utf-8")
        app_target = ios_project.split("  QeliIOS:", 1)[1].split(
            "  QeliPacketTunnel:", 1
        )[0]
        test_target = ios_project.split("  QeliIOSTests:", 1)[1].split(
            "schemes:", 1
        )[0]
        self.assertIn("- Protocol", app_target)
        self.assertIn("- path: QeliCore/Protocol", test_target)

        protocol_dir = root / "qeli-ios/QeliCore/Protocol"
        for source in protocol_dir.glob("*.swift"):
            self.assertIn(
                "@testable import QeliIOS",
                source.read_text(encoding="utf-8"),
                source.name,
            )

    def test_mobile_update_requests_cannot_migrate_to_the_physical_network(self):
        root = Path(__file__).parent.parent
        android_checker = (
            root / "qeli-android/app/src/main/kotlin/com/qeli/UpdateChecker.kt"
        ).read_text(encoding="utf-8")
        android_view = (
            root / "qeli-android/app/src/main/kotlin/com/qeli/MainActivity.kt"
        ).read_text(encoding="utf-8")
        self.assertIn("vpnNetwork.openConnection(URL(RELEASES))", android_checker)
        self.assertNotIn("URL(RELEASES).openConnection()", android_checker)
        self.assertIn("manager.allNetworks.filter", android_view)
        self.assertEqual(android_view.count("UpdateChecker.check(rawVersionName(), vpnNetwork)"), 2)
        self.assertIn("Revoking the opt-in also revokes an already-running request", android_view)

        ios_model = (root / "qeli-ios/QeliIOS/AppModel.swift").read_text(encoding="utf-8")
        disconnect = ios_model.split("private func disconnectManually() async", 1)[1].split(
            "func ping(_ profile: Profile)", 1
        )[0]
        self.assertIn("try await tunnelManager.updateOnDemand", disconnect)
        self.assertIn("await cancelUpdateCheckBeforeTunnelTeardown()", disconnect)
        self.assertIn("tunnelManager.disconnect()", disconnect)
        self.assertNotIn("profile.configText", disconnect)
        self.assertIn("await task?.value", ios_model)
        self.assertIn("Turning the opt-in off revokes an in-flight", ios_model)
        self.assertIn("updateChecksSuspendedForTunnelTeardown", ios_model)
        ios_checker = (root / "qeli-ios/QeliIOS/Support/UpdateChecker.swift").read_text(
            encoding="utf-8"
        )
        self.assertIn("waitsForConnectivity = false", ios_checker)
        self.assertIn("multipathServiceType = .none", ios_checker)
        run_probe = ios_model.split("private func runProbe(_ profile: Profile) async", 1)[1].split(
            "func pingAll()", 1
        )[0]
        self.assertIn("tunnelSnapshot.tunnelGateway", run_probe)
        self.assertIn("toTransportCoreINI()", run_probe)
        self.assertNotIn("gateway(forClientAddress:", run_probe)

        ios_manager = (root / "qeli-ios/QeliCore/VPN/TunnelManager.swift").read_text(
            encoding="utf-8"
        )
        stop = ios_manager.split("func disconnect()", 1)[1].split(
            "func refreshSnapshot()", 1
        )[0]
        self.assertLess(stop.index("publish(value)"), stop.index("stopVPNTunnel()"))

    def test_client_subnet_admission_is_non_destructive_and_fail_closed(self):
        root = Path(__file__).parent.parent
        handler = (root / "qeli/src/server/handler.rs").read_text(encoding="utf-8")
        programmer = handler.split("async fn program_client_subnet_route_inner", 1)[1].split(
            "fn client_subnet_is_default", 1
        )[0]
        self.assertIn("query_client_subnet_routes(cidr).await?", programmer)
        self.assertIn('let action = if add { "add" } else { "del" };', programmer)
        self.assertNotIn('if add { "replace" }', programmer)
        self.assertIn("refusing to replace or adopt unowned host route", programmer)
        self.assertIn("adopting existing qeli-owned route", programmer)
        self.assertIn("CLIENT_SUBNET_ROUTE_METRIC", handler)
        self.assertIn('"metric",', handler)
        self.assertIn("route_lines_are_owned_by_qeli", programmer)
        self.assertIn("rollback also failed", programmer)
        self.assertIn("cannot install client_subnet", handler)

        udp = (root / "qeli/src/server/udp_handler.rs").read_text(encoding="utf-8")
        self.assertIn("UDP: refusing client", udp)
        self.assertIn("installed_iroutes.iter().rev()", udp)

        users = (root / "qeli/src/config/users.rs").read_text(encoding="utf-8")
        self.assertIn("MAX_CLIENT_SUBNETS_PER_USER", users)
        self.assertIn("client_subnet has {} entries; maximum is {}", users)

    def test_openwrt_renders_ipv6_and_dns_as_unambiguous_flat_ini_keys(self):
        root = Path(__file__).parent.parent
        defaults = (root / "qeli-openwrt/files/qeli.config").read_text(encoding="utf-8")
        init = (root / "qeli-openwrt/files/qeli.init").read_text(encoding="utf-8")
        luci = (
            root
            / "qeli-openwrt/luci-app-qeli/htdocs/luci-static/resources/view/qeli/config.js"
        ).read_text(encoding="utf-8")

        self.assertIn("option ipv6 'auto'", defaults)
        self.assertIn("option dns 'off'", defaults)
        self.assertIn("list dns_servers '1.1.1.1'", defaults)
        self.assertIn("config_list_foreach main dns_servers append_dns_server", init)
        self.assertIn('ini_kv dns "$dns_mode"', init)
        self.assertIn('ini_kv dns_servers "$dns_servers"', init)
        self.assertIn('ini_kv ipv6 "$ipv6"', init)
        self.assertIn("form.ListValue, 'dns'", luci)
        self.assertIn("form.DynamicList, 'dns_servers'", luci)
        self.assertIn("mtu >= 576 && mtu <= 16638", luci)

    def test_keenetic_attach_recipe_transfers_both_families_and_mtu_without_loop(self):
        hook = (
            Path(__file__).parent.parent / "release/keenetic/opkgtun/010-qeli.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("s/^ipv4=", hook)
        self.assertIn("s/^ipv6=", hook)
        self.assertIn("s/^mtu=", hook)
        self.assertIn('ipv6 address $IP6', hook)
        self.assertIn('ip mtu $MTU', hook)
        self.assertNotIn('ipv6 force-default', hook)
        self.assertNotIn('ip route default $NDM_IF', hook)

    def test_installer_selects_and_verifies_the_host_deb_architecture(self):
        source = (Path(__file__).parent.parent / "install-qeli-server.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('HOST_DEB_ARCH="$(dpkg --print-architecture)"', source)
        self.assertIn('endswith("_" + $arch + ".deb")', source)
        self.assertIn('dpkg-deb -f "$TMP_DEB" Architecture', source)
        self.assertIn('"$HOST_DEB_ARCH"|all', source)

    def test_release_checksum_is_lf_only_and_installer_handles_crlf_defensively(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            asset_dir = Path(tmp)
            (asset_dir / "qeli.deb").write_bytes(b"release payload")
            subprocess.run(
                [sys.executable, str(root / "scripts/gen_checksums.py"), str(asset_dir)],
                check=True,
                capture_output=True,
                text=True,
            )
            sums = (asset_dir / "SHA256SUMS").read_bytes()
            self.assertIn(b"  qeli.deb\n", sums)
            self.assertNotIn(b"\r", sums)

        installer = (root / "install-qeli-server.sh").read_text(encoding="utf-8")
        self.assertIn('sub(/\\r$/, "", $2)', installer)
        self.assertEqual(installer.count("_checksum_for \"$"), 2)

        workflow = (root / ".github/workflows/release-attest.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("grep -q $'\\r' SHA256SUMS", workflow)

    def test_installer_strictly_validates_the_final_mutated_config_before_restart(self):
        source = (Path(__file__).parent.parent / "install-qeli-server.sh").read_text(
            encoding="utf-8"
        )
        validation = source.index('qeli check-config --config "$CONF"')
        restart = source.index("systemctl restart qeli")
        self.assertLess(validation, restart)
        self.assertIn("final configuration validation failed", source)

    def test_config_matrix_uses_strict_server_client_and_users_validation(self):
        source = (Path(__file__).parent / "config_functest.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('CFG.glob("server*.conf")', source)
        self.assertIn('CFG.glob("client*.conf")', source)
        self.assertIn("check-config --client", source)
        self.assertIn('users_remote = "/tmp/pv-users.conf"', source)
        self.assertNotIn("timeout 3", source)
        self.assertNotIn("pkill -9 -x qeli", source)
        self.assertIn("SERVER_PID", source)
        self.assertIn("client_active_units", source)
        self.assertIn("nohup setsid", source)
        self.assertIn(r'kill -TERM -- \"-$p\"', source)
        self.assertIn(r'kill -KILL -- \"-$p\"', source)
        self.assertIn(r'readlink -f \"/proc/$p/exe\"', source)
        self.assertIn(r'[ \"$pgid\" = \"$p\" ]', source)

        main_source = (Path(__file__).parent.parent / "qeli/src/main.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn("server::load_users_db(&cfg).map_err", main_source)
        self.assertNotIn("valid empty first install", main_source)

        multiprofile = (Path(__file__).parent / "pool2_multiprofile.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("client_active_units", multiprofile)
        self.assertIn("nohup setsid", multiprofile)
        self.assertIn(r'kill -TERM -- \"-$p\"', multiprofile)
        self.assertIn(r'kill -KILL -- \"-$p\"', multiprofile)
        self.assertIn(r'readlink -f \"/proc/$p/exe\"', multiprofile)
        self.assertIn(r'[ \"$pgid\" = \"$p\" ]', multiprofile)

    def test_linux_matrix_uses_the_configured_management_route_end_to_end(self):
        source = (Path(__file__).parent / "e2e_linux_prod_matrix.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('MGMT_IP_ROUTE = "ip -6 route"', source)
        self.assertIn("f\"{MGMT_IP_ROUTE} show {shlex.quote(MGMT_ROUTE_PREFIX)}\"", source)
        self.assertIn("f\"{MGMT_IP_ROUTE} add {MGMT_ROUTE_COMMAND}\"", source)
        self.assertIn("f\"{MGMT_IP_ROUTE} del {MGMT_ROUTE_COMMAND}", source)

    def test_active_release_scenarios_are_checkout_and_tool_path_neutral(self):
        root = Path(__file__).resolve().parents[1]
        forbidden_checkout = "C:" + "\\Users\\" + "litvi"
        for recipe in (root / "scripts").glob("*.py"):
            source = recipe.read_text(encoding="utf-8")
            self.assertNotIn(forbidden_checkout, source, str(recipe.relative_to(root)))
        android = (root / "scripts/e2e_android_prod_lifecycle.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('os.environ.get("QELI_ADB"', android)
        self.assertIn("command -v {quoted}", android)
        self.assertNotIn('shutil.which("adb")', android)

    def test_installer_e2e_fails_closed_on_any_red_case(self):
        source = (Path(__file__).parent / "pool0b_installer_full.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('and A["panel"]', source)
        self.assertIn('and A["panel_bind"]', source)
        self.assertIn('and A["version"]', source)
        self.assertIn('if passed != len(results):', source)
        self.assertIn('raise RuntimeError("one or more installer scenarios failed")', source)
        self.assertIn("def dns_resolves", source)
        self.assertNotIn("| head -1 || echo FAIL", source)

    def test_android_native_recipe_requires_the_cancellable_probe_exports(self):
        source = (Path(__file__).parent / "build_android_so_11.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('jni.strip() != "19"', source)

    def test_lab_gate_syncs_integration_tests_and_their_release_fixture(self):
        source = (Path(__file__).parent / "lab_sync_build.py").read_text(encoding="utf-8")
        self.assertIn('"tests"', source)
        self.assertIn('"release", "reality-tls", "server-reality.conf"', source)
        self.assertIn('"/opt/release/reality-tls/server-reality.conf"', source)

    def test_native_client_recipes_do_not_enable_the_server_stack(self):
        recipes = [
            Path(desktop.__file__),
            Path(__file__).parent / "build_android_so_11.py",
            Path(__file__).parent / "build_so_aes.py",
            Path(__file__).parent.parent / "qeli-mac" / "build_dylib.sh",
        ]
        for recipe in recipes:
            source = recipe.read_text(encoding="utf-8")
            self.assertIn(
                "--no-default-features",
                source,
                f"{recipe.name} must build only the shared client transport",
            )

    def test_keenetic_recipes_resolve_the_current_checkout(self):
        for name in ("build_keenetic.py", "keenetic_verify.py"):
            source = (Path(__file__).parent / name).read_text(encoding="utf-8")
            self.assertIn("Path(__file__).resolve().parents[1]", source, name)
            self.assertNotIn("C:" + "\\Users\\" + "litvi", source, name)

    def test_retired_root_ssh_scenarios_exit_before_network_or_mutation(self):
        root = Path(__file__).parent.parent
        retired = [
            "scripts/add-dpd-config.py",
            "scripts/add-hash-command.py",
            "scripts/add-hash-command-v2.py",
            "scripts/capture-handshake.py",
            "scripts/create-multi-interface-config.py",
            "scripts/create-multi-interface-server.py",
            "scripts/deploy-and-build.py",
            "scripts/deploy-and-build-final.py",
            "scripts/deploy_audit_fixes.py",
            "scripts/deploy_prod_0712.py",
            "scripts/deploy_prod_073.py",
            "scripts/deploy_prod_dev0711.py",
            "scripts/deploy_to_server.py",
            "scripts/generate-hash.py",
            "scripts/generate-hash-v2.py",
            "scripts/gen_reality_link.py",
            "scripts/gen_share_link.py",
            "scripts/gen-hash-rust.py",
            "scripts/implement-dpd-client.py",
            "scripts/implement-dpd-server.py",
            "scripts/install-argon2.py",
            "scripts/rebuild-and-test.py",
            "scripts/rebuild-both.py",
            "scripts/setup-client.py",
            "scripts/setup_reality_tls.py",
            "scripts/setup-multi-interface.py",
            "scripts/sync-config-and-rebuild.py",
            "scripts/update-client-binary.py",
            "scripts/update-server-dpd-config.py",
            "scripts/verify-dpd-file.py",
            "scripts/finish_deploy.py",
        ]
        retired += [
            str(path.relative_to(root)).replace("\\", "/")
            for path in (root / "test").iterdir()
            if path.suffix == ".py"
        ]
        for relative in retired:
            source = (root / relative).read_text(encoding="utf-8")
            guard = source.find("raise SystemExit")
            dangerous = min(
                (pos for marker in ("paramiko", "ssh.connect", "exec_command", "subprocess")
                 if (pos := source.find(marker)) >= 0),
                default=len(source),
            )
            self.assertGreaterEqual(guard, 0, f"{relative} has no retirement guard")
            self.assertLess(guard, dangerous, f"{relative} can act before its retirement guard")

        for path in (root / "test").glob("*.sh"):
            source = path.read_text(encoding="utf-8")
            self.assertIn("RETIRED:", source, path.name)
            dangerous = min(
                (pos for marker in ("ssh ", "scp ", "systemctl")
                 if (pos := source.find(marker)) >= 0),
                default=len(source),
            )
            self.assertLess(source.find("exit 1"), dangerous, path.name)

    def test_tracked_python_scenarios_never_silently_trust_a_new_ssh_host(self):
        root = Path(__file__).resolve().parents[1]
        tracked = subprocess.run(
            [
                "git",
                "-c",
                f"safe.directory={root.as_posix()}",
                "ls-files",
                "scripts/*.py",
                "scripts/**/*.py",
            ],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        for relative in tracked:
            path = root / relative
            if path.resolve() == Path(__file__).resolve():
                continue  # assertions below name the forbidden policy but never execute SSH
            if path.name == "ssh_hostkey.py":
                continue  # the one explicit QELI_LAB_TRUST_NEW_HOST opt-in lives here
            source = path.read_text(encoding="utf-8")
            self.assertNotIn("AutoAddPolicy", source, str(path))


if __name__ == "__main__":
    unittest.main()
