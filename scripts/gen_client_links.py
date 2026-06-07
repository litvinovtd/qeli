#!/usr/bin/env python3
"""Convert the prod client JSON configs to the new qeli:// link format (the one
the APK imports via paste / QR / file). Writes <name>.qeli (link) and <name>.png
(QR) into /etc/qeli/client/ on prod, keeps local copies, prints the links."""
import os
import paramiko, json, io, os
import qrcode

PROD = ("222.167.246.143", "root", os.environ.get("QELI_PROD_PASS", ""))
REMOTE_DIR = "/etc/qeli/client"
LOCAL_DIR = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\release\prod-client-configs"
os.makedirs(LOCAL_DIR, exist_ok=True)

UNRESERVED = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~")
def pct(s: str) -> str:
    out = []
    for b in s.encode("utf-8"):
        ch = chr(b)
        out.append(ch if ch in UNRESERVED else f"%{b:02X}")
    return "".join(out)

def build_link(d: dict, label: str) -> str:
    a, srv, obf = d["auth"], d["server"], d.get("obfuscation", {})
    user, pwd = pct(a["username"]), pct(a.get("password", ""))
    host, port = srv["address"], srv["port"]
    uri = f"qeli://{user}:{pwd}@{host}:{port}"
    q = [("proto", srv.get("protocol", "tcp")), ("mode", obf.get("mode", "fake-tls"))]
    key = a.get("server_public_key", "")
    if key: q.append(("key", key))
    sni = obf.get("sni")
    if sni: q.append(("sni", sni))
    obfs_key = obf.get("obfs_key")
    if obfs_key: q.append(("obfs", obfs_key))
    uri += "?" + "&".join(f"{k}={pct(v)}" for k, v in q)
    uri += "#" + pct(label)
    return uri

c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(PROD[0], username=PROD[1], password=PROD[2], timeout=25, look_for_keys=False, allow_agent=False)
def sh(cmd, t=40):
    i, o, e = c.exec_command(cmd, timeout=t)
    return (o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")).rstrip()
sf = c.open_sftp()

names = sh(f"ls {REMOTE_DIR}/*.json").split()
print(f"found {len(names)} client json configs\n")
for path in names:
    base = os.path.splitext(os.path.basename(path))[0]
    d = json.loads(sh(f"cat {path}"))
    label = d.get("name", base)
    link = build_link(d, label)
    # write .qeli (link text) to prod folder + local
    sf.putfo(io.BytesIO((link + "\n").encode()), f"{REMOTE_DIR}/{base}.qeli")
    open(os.path.join(LOCAL_DIR, base + ".qeli"), "w", encoding="utf-8").write(link + "\n")
    # QR png -> prod folder + local
    img = qrcode.make(link)
    buf = io.BytesIO(); img.save(buf, format="PNG"); png = buf.getvalue()
    sf.putfo(io.BytesIO(png), f"{REMOTE_DIR}/{base}.png")
    open(os.path.join(LOCAL_DIR, base + ".png"), "wb").write(png)
    print(f"== {base} ({label}) ==\n{link}\n")

sf.close()
print("prod folder now:\n" + sh(f"ls -la {REMOTE_DIR}"))
print(f"\nlocal copies in: {LOCAL_DIR}")
c.close()
