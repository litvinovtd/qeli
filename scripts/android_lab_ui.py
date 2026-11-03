#!/usr/bin/env python3
"""Observed English Android VPN Settings controls for disposable private-lab AVDs."""
import re
import subprocess
import time
import xml.etree.ElementTree as ET


def wait_until(predicate, message, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate(): return
        time.sleep(.25)
    raise AssertionError(message)


class AndroidVpnSettings:
    def __init__(self, arun, evidence, result, label, prefix=""):
        self.arun, self.evidence, self.result = arun, evidence, result
        self.label, self.prefix, self.sequence = label, prefix, 0

    def ui(self, label):
        self.sequence += 1
        # Shell-owned temporary storage avoids early-boot external-storage publication.
        remote = f"/data/local/tmp/q29-{self.prefix}vpn-ui-{self.sequence:02}.xml"
        diagnostic = []
        for attempt in range(3):
            try:
                proc = self.arun("shell", "uiautomator", "dump", remote, timeout=15, check=False)
                diagnostic.append(f"attempt={attempt + 1} rc={proc.returncode}\n{proc.stdout}{proc.stderr}")
                value = self.arun("shell", "cat", remote, check=False)
                if value.returncode == 0:
                    tree = ET.fromstring(value.stdout)
                    waiting = next((n for n in tree.iter('node') if n.get('resource-id') == 'android:id/aerr_wait'), None)
                    if waiting is not None:
                        # A system ANR can interrupt any transition, including a
                        # Settings switch. Preserve its XML before bounded Wait.
                        (self.evidence / f"{self.prefix}ui-{self.sequence:02}-{label}-attempt{attempt + 1}-anr.xml").write_text(value.stdout)
                        self.result.setdefault('ui_anr_waits', []).append(dict(label=label,sequence=self.sequence,attempt=attempt + 1))
                        self.tap(waiting)
                        time.sleep(.5)
                        continue
                    (self.evidence / f"{self.prefix}ui-{self.sequence:02}-{label}.xml").write_text(value.stdout)
                    return tree
                diagnostic.append(value.stderr)
            except subprocess.TimeoutExpired:
                diagnostic.append(f"attempt={attempt + 1} dump timed out after15s")
            finally:
                (self.evidence / f"{self.prefix}ui-{self.sequence:02}-{label}-dump.log").write_text("\n".join(diagnostic))
            time.sleep(.5)
        raise AssertionError("uiautomator did not produce a fresh XML after3 attempts; dump diagnostics retained")

    def tap(self, node):
        coords = [int(v) for v in re.findall(r"[0-9]+", node.attrib["bounds"])]
        assert len(coords) == 4 and coords[2] > coords[0] and coords[3] > coords[1]
        self.arun("shell", "input", "tap", str((coords[0] + coords[2]) // 2), str((coords[1] + coords[3]) // 2))

    @staticmethod
    def text_node(tree, text):
        return next((n for n in tree.iter("node") if n.get("text", "").lower() == text.lower()), None)

    @staticmethod
    def gear(node):
        return node.get("package") == "com.android.settings" and (node.get("resource-id", "").endswith("settings_button") or node.get("content-desc", "").lower() == "settings")

    def open(self):
        self.arun("shell", "am", "start", "-a", "android.settings.VPN_SETTINGS")
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            tree = self.ui("vpn-list")
            waiting = next((n for n in tree.iter("node") if n.get("resource-id") == "android:id/aerr_wait"), None)
            if waiting is not None:
                self.result.setdefault("system_ui_anr_waits", []).append(dict(prefix=self.prefix, sequence=self.sequence))
                self.tap(waiting); continue
            battery_title = self.text_node(tree, "Let app always run in background?")
            if battery_title is not None:
                assert any(n.get("text", "").startswith("Allowing " + self.label + " to always run in the background")
                           for n in tree.iter("node")), "unexpected background-permission requester"
                deny = self.text_node(tree, "DENY")
                assert deny is not None, "background-permission DENY control absent"
                self.result.setdefault("battery_exemption_denied", []).append(dict(provider=self.label, sequence=self.sequence))
                self.tap(deny)
                self.arun("shell", "am", "start", "-a", "android.settings.VPN_SETTINGS")
                continue
            management = self.text_node(tree, "Always-on VPN") is not None and self.text_node(tree, "Forget VPN") is not None
            if management:
                if any(n.get("content-desc") == self.label or n.get("text") == self.label for n in tree.iter("node")):
                    return tree
                up = next((n for n in tree.iter("node") if n.get("content-desc") == "Navigate up"), None)
                assert up is not None, "wrong provider management screen has no navigation control"
                self.tap(up); continue
            if not any(n.get("package") == "com.android.settings" for n in tree.iter("node")):
                self.arun("shell", "am", "start", "-a", "android.settings.VPN_SETTINGS")
                continue
            label = next((n for n in tree.iter("node") if n.get("text") == self.label and n.get("package") == "com.android.settings"), None)
            if label is not None:
                parents = {child: parent for parent in tree.iter() for child in parent}
                row = label
                while row in parents:
                    row = parents[row]
                    gear = next((n for n in row.iter("node") if self.gear(n)), None)
                    if gear is not None:
                        self.tap(gear)
                        break
            time.sleep(.5)
        raise AssertionError(f"{self.label} VPN Settings gear absent within 60s; UI retained")

    def widget(self, tree, label):
        node = self.text_node(tree, label); assert node is not None, (label, "switch label absent")
        parents = {child: parent for parent in tree.iter() for child in parent}
        row = node
        while not any(n.get("checkable") == "true" for n in row.iter("node")):
            assert row in parents, (label, "switch widget absent")
            row = parents[row]
        return node, next(n for n in row.iter("node") if n.get("checkable") == "true")

    def switch(self, label, enabled):
        tree = self.ui("switch-before"); node, widget = self.widget(tree, label)
        if (widget.get("checked") == "true") != enabled:
            self.tap(node); tree = self.ui("switch-toggled")
            if self.text_node(tree, label) is None:
                positive = self.text_node(tree, "TURN ON")
                assert positive is not None, "unrecognized VPN switch confirmation; UI retained"
                self.tap(positive); tree = self.ui("switch-confirmed")
            _, widget = self.widget(tree, label)
            assert (widget.get("checked") == "true") == enabled, (label, enabled)

    def forget(self):
        tree = self.ui("before-forget"); forget = self.text_node(tree, "Forget VPN")
        assert forget is not None, "Forget VPN control absent; UI retained"
        self.tap(forget); tree = self.ui("forget-confirmation")
        confirm = self.text_node(tree, "FORGET")
        assert confirm is not None and confirm.get("class", "").endswith("Button"), "Forget confirmation absent; UI retained"
        self.tap(confirm); return self.ui("after-forget")
