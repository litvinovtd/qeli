"""Runs ON server .10. Generates 5 client users (Argon2id hashes), writes their
import-ready JSON configs to /etc/qeli/client/, and appends the users to the
max-obf server config. Prints the credentials.
"""
import json, os, secrets, string
from argon2 import PasswordHasher

KEY = "7ff1c27410a4f36f5306554a9ff3bd486c2692f4e40ed57c78c18c90638b2057"
SERVER_ADDR = "10.66.116.10"   # lab server; change in the JSON for other deployments
CONF = "/etc/qeli/server-maxobf.conf"
CLIENT_DIR = "/etc/qeli/client"
N = 5

ph = PasswordHasher()  # argon2id, standard PHC output (server verifies via PasswordHash::new)
os.makedirs(CLIENT_DIR, exist_ok=True)

def rand_pw(n=14):
    alph = string.ascii_letters + string.digits
    return "".join(secrets.choice(alph) for _ in range(n))

users_toml = []
creds = []
for i in range(1, N + 1):
    user = f"client{i}"
    pw = rand_pw()
    h = ph.hash(pw)
    creds.append((user, pw))
    users_toml.append(
        f'  [[auth.users]]\n  username = "{user}"\n  password_hash = "{h}"\n  enabled = true\n'
    )
    cfg = {
        "name": f"Client {i}",
        "server": {"address": SERVER_ADDR, "port": 443, "protocol": "tcp",
                   "connection_timeout_secs": 30,
                   "reconnect": {"enabled": True, "max_retries": -1, "base_delay_secs": 1, "max_delay_secs": 60}},
        "auth": {"username": user, "password": pw, "server_public_key": KEY},
        "tun": {"mtu": 1400},
        "routing": {"mode": "full-tunnel", "add_default_gateway": True, "include": [], "exclude": []},
        "dns": {"servers": ["1.1.1.1", "8.8.8.8"]},
        "obfuscation": {"mode": "fake-tls", "sni": "www.microsoft.com",
                        "padding": {"enabled": True, "min_bytes": 40, "max_bytes": 400},
                        "heartbeat": {"enabled": True, "interval_ms": 15000, "data_size_bytes": 64, "jitter_ms": 5000},
                        "quic": {"enabled": False}}}
    with open(f"{CLIENT_DIR}/client{i}.json", "w") as f:
        json.dump(cfg, f, indent=2)

# Insert the new users into the [auth] section (before [logging]).
with open(CONF) as f:
    text = f.read()
# Drop any client* users from a previous run (idempotent re-run).
import re
text = re.sub(r'  \[\[auth\.users\]\]\n  username = "client\d+"\n  password_hash = "[^"]*"\n  enabled = true\n', "", text)
block = "".join(users_toml)
if "[logging]" in text:
    text = text.replace("[logging]", block + "[logging]", 1)
else:
    text = text + "\n" + block
with open(CONF, "w") as f:
    f.write(text)

print("CREDS")
for u, p in creds:
    print(f"{u}\t{p}")
print("WROTE", N, "json files to", CLIENT_DIR)
