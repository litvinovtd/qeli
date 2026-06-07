"""Quick sanity: re-run plain TCP (everything off) — should give ~235 Mbps."""
import sys, json
from pathlib import Path
sys.path.insert(0, str(Path(r"C:\Users\Administrator\Documents\project\vpn\scripts")))
from bench_v5 import Host, USERS_JSON, bring_up, measure_tcp, measure_ping, server_cfg, client_cfg

srv, cli = Host("10.66.116.10"), Host("10.66.116.11")
mode = {"transport":"tcp", "port":443, "max_obf": False}
s = server_cfg(transport="tcp", port=443, max_obf=False)
c = client_cfg(transport="tcp", port=443, max_obf=False)
srv.put("/etc/qeli/server.json", json.dumps(s, indent=2))
srv.put("/etc/qeli/users.json", json.dumps(USERS_JSON, indent=2))
cli.put("/etc/qeli/client.json", json.dumps(c, indent=2))
cli.put("/etc/qeli/password.txt", "qelibench")
if not bring_up(srv, cli):
    print("tunnel did not come up"); sys.exit(1)
print("tunnel up")
cli.sh("ping -c 3 -W 1 10.8.0.1 >/dev/null 2>&1")
print("→ TCP")
print(measure_tcp(srv, cli, "10.8.0.1", 10))
print("→ ping")
print(measure_ping(cli, "10.8.0.1"))
