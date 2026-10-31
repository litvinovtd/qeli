"""Guard the remaining list/optional/map and user/group INI reference defaults.

Reader coverage is source review, not execution of Rust. The independent lab
matrix uses the real CLI to check admission and diagnostic boundaries.
"""
import re
import unittest

import test_server_config_defaults as scalar

ROOT = scalar.ROOT


def reader_keys():
    result = {}
    for root, function in (("profile", "profile_from"), ("auth", "auth_from"),
                           ("web", "web_from"), ("logging", "logging_from"),
                           ("user", "user_from"), ("group", "group_from")):
        body = re.search(r"fn " + function + r"\([^\{]+\{(.*?)^\}",
                         scalar.reader, re.M | re.S)[1]
        keys = set(re.findall(
            r'\bs\s*\.\s*(?:get|list|all|entries_with_prefix|str_or|bool_or|parse_or|contains_key)'
            r'\(\s*"([^"]+)"', body, re.S))
        keys.update(re.findall(r'opt_parse\(s,\s*"([^"]+)"', body))
        if "routes_from(s)" in body:
            # The helper reads the repeatable key for both profile and user.
            keys.add("route")
        result[root] = keys
    return result


# Values not covered by the scalar assignment guard. Paths resolve their real
# serde functions through the same source reader, including nonempty list defaults.
PROFILE_FIELDS = {
    "identity_key": "identity_key", "listen": "bind.listen",
    "tun.ipv6_address": "tun.ipv6_address", "pool.exclude": "pool.exclude",
    "pool.reservation.": "pool.static_reservations", "pool.ipv6.cidr": "pool.ipv6.cidr",
    "pool.ipv6.exclude": "pool.ipv6.exclude", "pool.ipv6.reservation.": "pool.ipv6.static_reservations",
    "route": "routing.advertised_routes", "dns.listen_ipv6": "dns.listen_ipv6",
    "dns.upstream": "dns.upstream", "dns.blocklist": "dns.blocklist",
    "dns.push_servers": "dns.push_servers", "dhcp.pool_start": "dhcp.pool_start",
    "dhcp.pool_end": "dhcp.pool_end", "obf.tls.reality_proxy.short_ids": "obfuscation.tls.reality_proxy.short_ids",
    "obf.traffic_normalization.round_sizes": "obfuscation.traffic_normalization.round_sizes",
    "obf.recordizer.policy": "obfuscation.recordizer.policy",
    "obf.recordizer.batch.mode": "obfuscation.recordizer.batch.mode",
}


def remaining_defaults():
    defaults = {"profile." + key: scalar.walk("ProfileConfig", path.split("."))
                for key, path in PROFILE_FIELDS.items()}
    for key in ("allowed_ips", "allowed_origins", "trusted_proxies"):
        defaults["web." + key] = scalar.walk("WebConfig", [key])
    defaults["logging.file"] = scalar.walk("LoggingConfig", ["file"])
    body = re.search(r"fn user_from\([^\{]+\{(.*?)^\}", scalar.reader, re.M | re.S)[1]
    literal_values = dict(re.findall(
        r's\.(?:str_or|bool_or|parse_or)\("([^"]+)",\s*(""|true|false|[0-9]+)\)', body))
    for key in reader_keys()["user"]:
        defaults["user." + key] = scalar.value(literal_values[key]) if key in literal_values else ""
    for key in reader_keys()["group"]:
        defaults["group." + key] = ""  # All three fields are optional; absence means None.
    return defaults


def reference_defaults(text):
    root = "profile"
    active = False
    skip = False
    result = {}
    for line in text.splitlines():
        if line.startswith("## "):
            active = False
            skip = "Client:" in line or "Клиент:" in line
            root = ("web" if "[web]" in line else "auth" if "[auth]" in line else
                    "logging" if line in ("## Logging", "## Логирование") else "profile")
        if line.startswith("**"):
            if "[user:<name>]" in line:
                root = "user"
            elif "[group:<name>]" in line:
                root = "group"
        if not line.startswith("|"):
            active = False
            continue
        cells = [cell.strip() for cell in re.split(r"(?<!\\)\|", line.strip("|"))]
        if len(cells) > 1 and cells[1] in ("Default", "Умолч.", "По умолчанию", "Дефолт"):
            active = True
            continue
        if not active or skip:
            continue
        keys = []
        for token in re.findall(r"`([^`]+)`", cells[0]):
            token = re.sub(r"<[^>]+>", "", token)
            if not re.fullmatch(r"[a-z][a-z0-9_.]*", token):
                continue
            if "." not in token and keys and "." in keys[-1]:
                token = keys[-1].rsplit(".", 1)[0] + "." + token
            keys.append(token)
        if not keys:
            continue
        tokens = re.findall(r"`([^`]+)`", cells[1])
        if cells[1].startswith(("empty", "пуст", "(none)", "нет", "—")):
            values = [""] * len(keys)
        else:
            values = [token.strip('"').replace("[]", "").replace("{}", "") for token in tokens]
            if len(values) == 1:
                values *= len(keys)
        if len(values) != len(keys):
            continue
        for key, value in zip(keys, values):
            result.setdefault(root + "." + key, set()).add(value.replace(" ", ""))
    return result


class ServerCollectionDocumentationTests(unittest.TestCase):
    def test_complete_reader_key_inventory_has_reference_defaults(self):
        keys = {root + "." + key for root, values in reader_keys().items() for key in values}
        self.assertEqual(len(keys), 177, "review coverage when reader keys change")
        defaults = remaining_defaults()
        # The sole consumed obsolete setting warns and has no operational default.
        self.assertEqual(set(scalar.inventory) | set(defaults) | {"profile.tun.netmask"}, keys)
        self.assertEqual(len(defaults), 42)
        self.assertEqual(defaults["profile.obf.recordizer.batch.mode"], "timed")
        for lang in ("ru", "eng"):
            documented = reference_defaults((ROOT / f"docs/{lang}/manuals/CONFIG.md").read_text(encoding="utf-8"))
            for key, value in defaults.items():
                with self.subTest(lang=lang, key=key):
                    self.assertEqual(documented.get(key), {value.replace(" ", "")})


if __name__ == "__main__":
    unittest.main()
