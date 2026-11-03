#!/usr/bin/env python3
"""Fail closed when an iOS IPA cannot run Qeli's Packet Tunnel Provider.

A generic sideloading signature may make the container UI launch while silently dropping
Network Extension, App Group or shared-Keychain capabilities. This verifier first checks the
portable archive contract on every OS and, on macOS, also verifies the signatures and their
effective entitlements with Apple's ``codesign`` tool.
"""
from __future__ import annotations

import argparse
import plistlib
import re
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

TEAM_KEYCHAIN_GROUP = re.compile(r"^[A-Z0-9]{10}\..+\.shared$")
MAX_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
NETWORK_EXTENSION_KEY = "com.apple.developer.networking.networkextension"
APP_GROUP_KEY = "com.apple.security.application-groups"
KEYCHAIN_GROUP_KEY = "keychain-access-groups"
APPLICATION_ID_KEY = "application-identifier"
TEAM_ID_KEY = "com.apple.developer.team-identifier"


def _string_list(value: Any) -> list[str]:
    """Return only a real plist array of strings; scalars must fail closed."""
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return []
    return value


def _plist(archive: zipfile.ZipFile, name: str, errors: list[str]) -> dict[str, Any]:
    try:
        value = plistlib.loads(archive.read(name))
    except (KeyError, plistlib.InvalidFileException, ValueError) as error:
        errors.append(f"cannot read {name}: {error}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{name}: plist root is not a dictionary")
        return {}
    return value


def _embedded_profile(
    archive: zipfile.ZipFile, name: str, errors: list[str]
) -> dict[str, Any]:
    try:
        data = archive.read(name)
    except KeyError:
        errors.append(f"{name}: embedded.mobileprovision is missing")
        return {}
    # A mobileprovision is CMS SignedData whose payload is normally an XML plist. Parsing
    # that embedded plist is portable; macOS additionally verifies the enclosing code
    # signatures below, so this is not treated as cryptographic verification on its own.
    starts = [offset for token in (b"<?xml", b"<plist") if (offset := data.find(token)) >= 0]
    start = min(starts) if starts else -1
    end = data.rfind(b"</plist>")
    if start < 0 or end < start:
        errors.append(f"{name}: provisioning profile payload is not a readable plist")
        return {}
    try:
        value = plistlib.loads(data[start : end + len(b"</plist>")])
    except (plistlib.InvalidFileException, ValueError) as error:
        errors.append(f"{name}: cannot parse provisioning profile: {error}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{name}: provisioning profile root is not a dictionary")
        return {}
    return value


def _validate_profile(
    profile_name: str,
    profile: dict[str, Any],
    *,
    bundle_id: str,
    app_group: str,
    keychain_group: str,
    needs_vpn: bool,
    needs_keychain: bool,
    expected_team: str,
    errors: list[str],
) -> None:
    if not profile:
        return
    expiration = profile.get("ExpirationDate")
    if not isinstance(expiration, datetime):
        errors.append(f"{profile_name}: provisioning profile expiration is missing")
    else:
        expiry = expiration if expiration.tzinfo else expiration.replace(tzinfo=timezone.utc)
        if expiry <= datetime.now(timezone.utc):
            errors.append(f"{profile_name}: provisioning profile has expired")
    teams = profile.get("TeamIdentifier", [])
    if not isinstance(teams, list) or expected_team not in teams:
        errors.append(f"{profile_name}: provisioning TeamIdentifier does not match {expected_team}")
    entitlements = profile.get("Entitlements")
    if not isinstance(entitlements, dict):
        errors.append(f"{profile_name}: provisioning entitlements are missing")
        return
    if entitlements.get(TEAM_ID_KEY) != expected_team:
        errors.append(f"{profile_name}: provisioning Team ID entitlement does not match")
    expected_application_id = f"{expected_team}.{bundle_id}"
    if entitlements.get(APPLICATION_ID_KEY) != expected_application_id:
        errors.append(
            f"{profile_name}: provisioning App ID must be {expected_application_id}"
        )
    prefixes = profile.get("ApplicationIdentifierPrefix", [])
    if not isinstance(prefixes, list) or expected_team not in prefixes:
        errors.append(f"{profile_name}: provisioning App ID prefix does not match")
    if app_group not in _string_list(entitlements.get(APP_GROUP_KEY)):
        errors.append(f"{profile_name}: provisioning App Group entitlement is missing")
    if needs_vpn and "packet-tunnel-provider" not in _string_list(
        entitlements.get(NETWORK_EXTENSION_KEY)
    ):
        errors.append(f"{profile_name}: provisioning packet-tunnel entitlement is missing")
    if needs_keychain and keychain_group not in _string_list(
        entitlements.get(KEYCHAIN_GROUP_KEY)
    ):
        errors.append(f"{profile_name}: provisioning shared-Keychain entitlement is missing")

def validate_archive(path: Path) -> tuple[list[str], dict[str, str]]:
    errors: list[str] = []
    facts: dict[str, str] = {}
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as error:
        return [f"cannot open IPA {path}: {error}"], facts

    with archive:
        infos = archive.infolist()
        names = [item.filename for item in infos]
        if len(names) != len(set(names)):
            errors.append("IPA contains duplicate archive paths")
        if sum(item.file_size for item in infos) > MAX_UNCOMPRESSED_BYTES:
            errors.append("IPA uncompressed size exceeds the 512 MiB verification budget")

        main_infos = [
            name for name in names
            if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", name)
        ]
        if len(main_infos) != 1:
            errors.append(f"expected one container app, found {len(main_infos)}")
            return errors, facts
        main_info_name = main_infos[0]
        main_root = main_info_name.removesuffix("Info.plist")
        main = _plist(archive, main_info_name, errors)
        bundle_id = main.get("CFBundleIdentifier")
        tunnel_id = main.get("QeliPacketTunnelBundleIdentifier")
        app_group = main.get("QeliAppGroup")
        keychain_group = main.get("QeliKeychainAccessGroup")
        facts.update(
            main_root=main_root,
            bundle_id=str(bundle_id or ""),
            tunnel_id=str(tunnel_id or ""),
            app_group=str(app_group or ""),
            keychain_group=str(keychain_group or ""),
        )
        if not isinstance(bundle_id, str) or not bundle_id:
            errors.append("container CFBundleIdentifier is missing")
        if not isinstance(tunnel_id, str) or not tunnel_id:
            errors.append("QeliPacketTunnelBundleIdentifier is missing")
        if not isinstance(app_group, str) or not app_group.startswith("group."):
            errors.append("QeliAppGroup is missing or invalid")
        if not isinstance(keychain_group, str) or not TEAM_KEYCHAIN_GROUP.fullmatch(keychain_group):
            errors.append(
                "QeliKeychainAccessGroup lacks the ten-character Apple Team/AppIdentifier prefix"
            )

        extension_infos = [
            name for name in names
            if name.startswith(main_root + "PlugIns/")
            and re.fullmatch(re.escape(main_root) + r"PlugIns/[^/]+\.appex/Info\.plist", name)
        ]
        extensions: list[tuple[str, dict[str, Any]]] = []
        for info_name in extension_infos:
            extensions.append((info_name.removesuffix("Info.plist"), _plist(archive, info_name, errors)))
        tunnel = next(
            ((root, info) for root, info in extensions if info.get("CFBundleIdentifier") == tunnel_id),
            None,
        )
        if tunnel is None:
            errors.append(f"Packet Tunnel extension {tunnel_id!r} is missing")
        else:
            facts["tunnel_root"] = tunnel[0]
            extension_point = tunnel[1].get("NSExtension", {}).get("NSExtensionPointIdentifier")
            if extension_point != "com.apple.networkextension.packet-tunnel":
                errors.append("Packet Tunnel extension point is missing or invalid")
            if tunnel[1].get("QeliAppGroup") != app_group:
                errors.append("container and Packet Tunnel App Group values differ")
            if tunnel[1].get("QeliKeychainAccessGroup") != keychain_group:
                errors.append("container and Packet Tunnel Keychain Group values differ")

        widget = next(
            (
                (root, info)
                for root, info in extensions
                if info.get("NSExtension", {}).get("NSExtensionPointIdentifier")
                == "com.apple.widgetkit-extension"
            ),
            None,
        )
        if widget is None:
            errors.append("WidgetKit extension is missing")
        else:
            facts["widget_root"] = widget[0]
            if widget[1].get("QeliAppGroup") != app_group:
                errors.append("container and Widget App Group values differ")

        components: list[tuple[str, str, dict[str, Any], bool, bool]] = [
            ("main_root", main_root, main, True, True)
        ]
        if tunnel is not None:
            components.append(("tunnel_root", tunnel[0], tunnel[1], True, True))
        if widget is not None:
            components.append(("widget_root", widget[0], widget[1], False, False))

        expected_team = keychain_group.split(".", 1)[0] if isinstance(keychain_group, str) else ""
        for root_key, root, info, needs_vpn, needs_keychain in components:
            component_bundle_id = info.get("CFBundleIdentifier")
            facts[root_key + "_bundle_id"] = str(component_bundle_id or "")
            profile_name = root + "embedded.mobileprovision"
            profile = _embedded_profile(archive, profile_name, errors)
            if isinstance(component_bundle_id, str) and component_bundle_id and expected_team:
                _validate_profile(
                    profile_name,
                    profile,
                    bundle_id=component_bundle_id,
                    app_group=str(app_group or ""),
                    keychain_group=str(keychain_group or ""),
                    needs_vpn=needs_vpn,
                    needs_keychain=needs_keychain,
                    expected_team=expected_team,
                    errors=errors,
                )
            if root + "_CodeSignature/CodeResources" not in names:
                errors.append(f"{root}: code signature is missing")
        if not expected_team:
            errors.append("cannot derive Apple Team ID from QeliKeychainAccessGroup")
    return errors, facts


def _safe_extract(path: Path, destination: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        for item in archive.infolist():
            parts = PurePosixPath(item.filename).parts
            if not parts or any(part in ("", ".", "..") for part in parts):
                raise ValueError(f"unsafe IPA path {item.filename!r}")
            target = destination.joinpath(*parts).resolve()
            if destination.resolve() not in target.parents and target != destination.resolve():
                raise ValueError(f"unsafe IPA path {item.filename!r}")
        archive.extractall(destination)


def _signed_entitlements(bundle: Path) -> tuple[dict[str, Any], str | None]:
    try:
        process = subprocess.run(
            ["codesign", "-d", "--entitlements", ":-", str(bundle)],
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {}, f"cannot read signed entitlements for {bundle.name}: {error}"
    output = process.stdout + process.stderr
    start, end = output.find(b"<?xml"), output.rfind(b"</plist>")
    if process.returncode != 0 or start < 0 or end < start:
        detail = output.decode("utf-8", "replace").strip()
        return {}, f"cannot read signed entitlements for {bundle.name}: {detail}"
    try:
        value = plistlib.loads(output[start : end + len(b"</plist>")])
    except plistlib.InvalidFileException as error:
        return {}, f"cannot parse signed entitlements for {bundle.name}: {error}"
    return value if isinstance(value, dict) else {}, None


def validate_signatures(path: Path, facts: dict[str, str]) -> list[str]:
    if sys.platform != "darwin":
        return ["full codesign/entitlement verification must run on macOS"]
    errors: list[str] = []
    with tempfile.TemporaryDirectory(prefix="qeli-ios-verify-") as directory:
        root = Path(directory)
        try:
            _safe_extract(path, root)
        except (OSError, ValueError, zipfile.BadZipFile) as error:
            return [f"cannot safely extract IPA: {error}"]
        main_bundle = root.joinpath(*PurePosixPath(facts["main_root"].rstrip("/")).parts)
        verify = subprocess.run(
            ["codesign", "--verify", "--deep", "--strict", str(main_bundle)],
            capture_output=True,
            text=True,
        )
        if verify.returncode != 0:
            errors.append(f"codesign verification failed: {(verify.stderr or verify.stdout).strip()}")

        expected_group = facts["app_group"]
        expected_keychain = facts["keychain_group"]
        expected_team = expected_keychain.split(".", 1)[0]
        for root_key, needs_vpn, needs_keychain in (
            ("main_root", True, True),
            ("tunnel_root", True, True),
            ("widget_root", False, False),
        ):
            archive_root = facts.get(root_key)
            if not archive_root:
                continue
            bundle = root.joinpath(*PurePosixPath(archive_root.rstrip("/")).parts)
            entitlements, error = _signed_entitlements(bundle)
            if error:
                errors.append(error)
                continue
            if expected_group not in _string_list(entitlements.get(APP_GROUP_KEY)):
                errors.append(f"{bundle.name}: signed App Group entitlement is missing")
            if needs_vpn and "packet-tunnel-provider" not in _string_list(
                entitlements.get(NETWORK_EXTENSION_KEY)
            ):
                errors.append(f"{bundle.name}: signed packet-tunnel-provider entitlement is missing")
            if needs_keychain and expected_keychain not in _string_list(
                entitlements.get(KEYCHAIN_GROUP_KEY)
            ):
                errors.append(f"{bundle.name}: signed shared-Keychain entitlement is missing")
            expected_bundle_id = facts.get(root_key + "_bundle_id", "")
            expected_application_id = f"{expected_team}.{expected_bundle_id}"
            if entitlements.get(TEAM_ID_KEY) != expected_team:
                errors.append(f"{bundle.name}: signed Team ID entitlement does not match")
            if entitlements.get(APPLICATION_ID_KEY) != expected_application_id:
                errors.append(
                    f"{bundle.name}: signed App ID must be {expected_application_id}"
                )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ipa", type=Path)
    parser.add_argument(
        "--structural-only",
        action="store_true",
        help="skip Apple's cryptographic codesign verification (diagnostics only, never release evidence)",
    )
    args = parser.parse_args()
    errors, facts = validate_archive(args.ipa)
    if not errors and not args.structural_only:
        errors.extend(validate_signatures(args.ipa, facts))
    if errors:
        print("FAIL: iOS IPA is not a releasable Qeli VPN package", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    qualifier = "structural checks" if args.structural_only else "signatures and entitlements"
    print(f"PASS: iOS IPA {qualifier} verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
