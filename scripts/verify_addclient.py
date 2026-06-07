#!/usr/bin/env python3
"""Live test of `qeli add-client` against a scratch config + users file."""
import os
import paramiko

SRV = ("10.66.116.10", "root", os.environ.get("QELI_LAB_PASS", ""))
BIN = "/opt/qeli-src/target/debug/qeli"


def sh(c, cmd, t=120):
    i, o, e = c.exec_command(cmd, timeout=t)
    out = o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")
    return out.strip(), o.channel.recv_exit_status()


c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(SRV[0], username=SRV[1], password=SRV[2], timeout=20, look_for_keys=False, allow_agent=False)

# scratch dir with a minimal server.conf (reuse the real identity dir so the
# share link can load/create a profile key) and an empty users file.
setup = r'''
set -e
D=/tmp/qeli_addclient_test
rm -rf $D && mkdir -p $D/identity
cat > $D/users.conf <<'EOF'
EOF
cat > $D/server.conf <<EOF
[server]
users_file = $D/users.conf

[profile:tcp]
identity_key = $D/identity/tcp.key
bind = tcp://0.0.0.0:443
mode = fake-tls
sni  = www.cloudflare.com
EOF
echo "scratch ready at $D"
'''
out, rc = sh(c, setup)
print("== setup ==\n", out, "rc", rc)

# 1. add a client with explicit password + a share link
out, rc = sh(c, f"{BIN} add-client phone1 --password 's3cret-pw' "
                f"--profiles tcp --max-sessions 2 "
                f"--link --host vpn.example.com --config /tmp/qeli_addclient_test/server.conf")
print("\n== add-client (explicit pw + link) ==\n", out, "\nrc", rc)

# 2. add a client with a generated password
out, rc = sh(c, f"{BIN} add-client phone2 --config /tmp/qeli_addclient_test/server.conf")
print("\n== add-client (generated pw) ==\n", out, "\nrc", rc)

# 3. duplicate should fail
out, rc = sh(c, f"{BIN} add-client phone1 --password x --config /tmp/qeli_addclient_test/server.conf")
print("\n== add-client duplicate (expect error, rc!=0) ==\n", out, "\nrc", rc)

# 4. show the resulting users file (flat INI)
out, _ = sh(c, "cat /tmp/qeli_addclient_test/users.conf")
print("\n== resulting users.conf ==\n", out)

# 5. confirm the new INI parses back and both users load (reuse list via a tiny check)
out, _ = sh(c, "grep -c '^\\[user:' /tmp/qeli_addclient_test/users.conf")
print("\n== user entries count ==", out)

c.close()
