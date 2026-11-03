# qeli in Docker

One **multi-arch** image (`linux/amd64`, `linux/arm64`, `linux/arm/v7`) that
carries **both roles** — `qeli server` and `qeli client` — with every runtime
dependency bundled (`iproute2`, `iptables`, CA certs, plus `ping` for diagnostics).
It runs on any Linux host and on router container runtimes (MikroTik RouterOS v7,
OpenWrt, etc.).

```
release/docker/
├── Dockerfile               # multi-stage, multi-arch, both roles
├── Dockerfile.dockerignore  # keeps the build context small
├── entrypoint.sh            # role select + first-run config seed + ip_forward/tun checks
├── docker-compose.yml       # Linux server (+ optional gateway client) example
└── README.md                # this file
```

The binary built is `qeli` (server **and** client). The MIPS-only `qeli-client`
binary is not part of this image.

> **Verified (2026-06-22)** on a fresh Debian 13 / Docker 29 host: builds, both
> roles run, and a client container tunnels to a remote server. Stable over 15+ min
> (0 reconnects/panics, flat memory) and reaches **~780–986 Mbit/s** through the
> encrypted tunnel on a local path — parity with bare metal. Full numbers in §8.
> (Client containers need `dns = off`; see §5.)

> **Re-verified (2026-07-08)** on Docker 29 / Debian 13 with `qeli 0.7.9`: a
> **two-container** server↔client test on a user bridge — auth, tunnel-gateway ping,
> and internet egress via the server's NAT all pass (0% loss). Copy-paste walkthrough
> with full server + client configs in **§2d**. This is historical 0.7.9 evidence.

---

## 1. Get the image

### Easiest — pull the published image (no build)

CI (`.github/workflows/docker-publish.yml`) builds a versioned multi-arch image
after release-tag admission. `:latest` is promoted only for the highest stable Git
version with a published, non-prerelease GitHub Release; it does not follow beta releases.

An explicit maintainer recovery can separately promote a verified beta image to
`:latest`, as requested for 0.8.2 in [issue #200](https://github.com/litvinovtd/qeli/issues/200).
This does not change the GitHub Release's beta status or the automatic workflow's
stable-only policy. For 0.8.3 Beta, pin `:0.8.3` only after its multi-arch Docker
workflow succeeds. A draft or published GitHub Release alone does not confirm that
the image is available; it does not automatically move `:latest` to a Beta.

```sh
docker pull ghcr.io/litvinovtd/qeli:latest     # automatic stable channel; explicit recovery promotions may include a beta
docker pull ghcr.io/litvinovtd/qeli:0.8.3      # beta, only after its Docker workflow succeeds
```

Use that image name anywhere `qeli:latest` appears below. Build locally only to
modify the source or if the registry is unreachable.

> **First publish:** images appear only after the workflow has run for a release —
> i.e. once a `v*` tag is pushed (or the workflow is triggered manually from the
> Actions tab) **and** the GHCR package is made public. Until then, build locally
> (below).

### Build it yourself

> Run all build commands from the **repository root** (the build context is the
> repo; the Cargo project is `qeli/`). You need Docker with **buildx**.
>
> The Dockerfile is **version-agnostic** — it builds whatever source is checked
> out, so the image's `qeli --version` equals the `qeli/Cargo.toml` of your
> checkout. **A stale checkout builds an old version.** Development is on `dev`.
> Fetch the repository and select the exact reviewed commit or published release tag
> before building (for example `git fetch origin --tags`, then `git checkout v0.8.3`
> once that tag is published). The nearest tag is not necessarily the newest release.

Multi-arch (one tag, three arches):

```sh
docker buildx create --use --name qeli-builder   # once
# A multi-arch build cannot `--load` into the local daemon — it must `--push` to a
# registry, so the tag has to be registry-qualified.
docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 \
  -f release/docker/Dockerfile -t ghcr.io/YOUR_ACCOUNT/qeli:local-build --push .
```

Single arch you can `--load` into the local daemon (e.g. amd64 for a Linux box,
or arm64 for a Pi/MikroTik):

```sh
docker buildx build --platform linux/amd64 \
  -f release/docker/Dockerfile -t qeli:latest --load .
```

**Note on speed:** non-native arches build under QEMU emulation (a Rust compile
under QEMU is slow — tens of minutes). For fast cross-compiles, build with
[`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild) on the host and
`COPY` the artifact in instead — the repo already cross-builds the router client
that way (see `scripts/build_keenetic.py`). The plain Dockerfile here favors
simplicity/correctness over build speed.

---

## 2. Run on Linux

### a) docker compose (recommended)

```sh
docker buildx build -f release/docker/Dockerfile -t qeli:latest --load .
docker compose -f release/docker/docker-compose.yml up -d qeli-server
```

First start seeds `./data/server/etc/server.conf` from the example **and an empty
`users.conf`**. Users live in that separate file — edit `server.conf` (bind, and
optionally enable NAT), then add users with `add-client` (below), which writes them
to `/etc/qeli/users.conf`. Don't add inline `[user:*]` to `server.conf` (it would
shadow the file). Then bring the panel up or add a client:

```sh
# add a user (writes the users file inside the mounted /etc/qeli volume)
docker exec -it qeli-server qeli add-client --config /etc/qeli/server.conf myphone

# print the server identity key to pin on clients
docker exec -it qeli-server qeli show-identity --config /etc/qeli/server.conf

docker compose -f release/docker/docker-compose.yml restart qeli-server
```

### b) plain `docker run` — server

```sh
docker run -d --name qeli-server \
  --cap-add NET_ADMIN --cap-add NET_RAW --cap-add NET_BIND_SERVICE \
  --device /dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 \
  -v "$PWD/data/server/etc:/etc/qeli" \
  -v "$PWD/data/server/lib:/var/lib/qeli" \
  -p 443:443/tcp -p 8080:8080/tcp \
  qeli:latest server
```

### c) plain `docker run` — client (VPN gateway)

```sh
# put your client.conf (or a qeli:// derived INI) in data/client/etc/ first
docker run -d --name qeli-client \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -v "$PWD/data/client/etc:/etc/qeli" \
  -v "$PWD/data/client/lib:/var/lib/qeli" \
  qeli:latest client
```

Route another container's traffic through the client:
`docker run --network=container:qeli-client ...`.

### d) Worked example — two containers talking end-to-end (copy-paste)

A self-contained connectivity test: a **server** and a **client** container on one
Docker host, on a user-defined bridge, verified with pings through the tunnel. This
is the minimal "does it actually work in Docker" reproduction — no remote server, no
published ports (the two containers reach each other **by name** on the bridge's
embedded DNS). The manual steps are below. For isolated audit runs,
[`scripts/audit_docker_runtime_case.py`](../../scripts/audit_docker_runtime_case.py)
requires a separately prepared, resource-limited audit daemon and SHA-verified
image record; it never installs Docker or uses the host default socket. Its pinned
TCP test covers local tunnel traffic, volumes, recreation and deliberate bad-image
recovery; it does not repeat the historical Internet/NAT or throughput benchmark.

**1. Config dirs + the server config.** One fake-TLS TCP profile on `:443` with NAT
egress on. `dns.enabled = false` (the server pushes no resolver); comments must be on
their own line:

```sh
mkdir -p qtest/server/etc/identity qtest/client/etc
cat > qtest/server/etc/server.conf <<'EOF'
[auth]
users_file = /etc/qeli/users.conf

[logging]
level = info

[profile:tcp]
identity_key = /etc/qeli/identity/tcp.key
bind.address = 0.0.0.0
bind.port = 443
bind.transport = tcp
tun.name = vpn0
tun.address = 10.8.0.1
tun.mtu = 1400
pool.cidr = 10.8.0.0/24
pool.exclude = 10.8.0.1
routing.nat.enabled = true
dns.enabled = false
obf.mode = fake-tls
obf.recordizer.policy = prefer
obf.recordizer.batch.delay_min_ms = 2
obf.recordizer.batch.delay_max_ms = 8
obf.recordizer.batch.max_packets = 16
obf.recordizer.batch.max_queue_bytes = 262144
obf.recordizer.record.max_payload_bytes = 0
obf.recordizer.record.small_min_ratio = 0.25
obf.recordizer.record.small_max_ratio = 0.875
obf.recordizer.record.full_probability = 0.72
obf.recordizer.fragment.enabled = true
obf.recordizer.fragment.reassembly_timeout_ms = 3000
obf.recordizer.fragment.max_inflight_packets = 64
obf.recordizer.fragment.max_reassembly_bytes = 4194304
obf.recordizer.fragment.max_fragments_per_packet = 64
obf.tls.server_name = www.microsoft.com
EOF
```

`routing.nat.enabled = true` gives clients internet egress — it needs `NET_RAW` +
`--sysctl net.ipv4.ip_forward=1` on the server container (below). Drop it for a
split-tunnel (tunnel-subnet-only) server.

**2. A user.** For a quick test drop a known user in `users.conf` (user `test`,
password `testpass123`). In production generate one instead:
`docker exec qeli-server qeli add-client myphone --config /etc/qeli/server.conf`
(it appends a user with a fresh random password to this same file).

```sh
cat > qtest/server/etc/users.conf <<'EOF'
[user:test]
password_hash = $argon2id$v=19$m=16384,t=2,p=1$cWVsaVNhbHRWYWw$CCYuTv8pvqQrvhrBQW3KjPpEN0MZaFfTKv3HOcGqB8w
enabled = true
EOF
```

**3. Network + server container.**

```sh
docker network create qnet

docker run -d --name qeli-server --network qnet \
  --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 \
  -v "$PWD/qtest/server/etc:/etc/qeli" \
  qeli:latest server
```

**4. Pin the server key, write the client config.** Read the server's identity key
from its log and put it in `client.conf`. Two keys are **Docker-specific**:
`dns = off` (mandatory — see §5) and `gateway = true` (full tunnel, so the client's
internet traffic egresses through the server's NAT; drop it for split-tunnel):

```sh
PUBKEY=$(docker logs qeli-server 2>&1 | grep -oE '[0-9a-f]{64}' | head -1)
cat > qtest/client/etc/client.conf <<EOF
[qeli]
server = qeli-server:443
proto = tcp
user = test
pass = testpass123
key = ${PUBKEY}
mode = fake-tls
sni = www.microsoft.com
dns = off
gateway = true

[logging]
level = info
EOF
```

`server = qeli-server:443` resolves the **container name** over the bridge's embedded
DNS. Pinning `key` is required: H-1 (`bind_static_to_session`) is on by default since
0.7.1, so an unpinned client is rejected.

**5. Client container.**

```sh
docker run -d --name qeli-client --network qnet \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -v "$PWD/qtest/client/etc:/etc/qeli" \
  qeli:latest client
```

**6. Verify.** The client authenticates, gets `10.8.0.2`, and reaches both the
server's tunnel gateway and the internet through the server's NAT:

```sh
docker logs qeli-client 2>&1 | grep 'Auth OK'   # Auth OK, assigned IP: 10.8.0.2
docker exec qeli-client ping -c3 10.8.0.1        # tunnel gateway  -> 0% loss
docker exec qeli-client ping -c3 1.1.1.1         # internet via NAT -> 0% loss
```

Expected (verified 2026-07-08, image `qeli 0.7.9`, Docker 29 / Debian 13):

```
[server] AUTH OK TCP 172.18.0.3:...: user=test on profile 'tcp'
[client] Auth OK, assigned IP: 10.8.0.2
client -> 10.8.0.1 : 4 received, 0% packet loss, ~1.1 ms   (tunnel data plane)
client -> 1.1.1.1  : 4 received, 0% packet loss, ~37 ms    (egress via server NAT)
```

Tear down: `docker rm -f qeli-server qeli-client && docker network rm qnet`.

> **Same configs, other topologies.** `server.conf` / `client.conf` above are
> unchanged whether the peers are two containers on one host (here), two hosts, or a
> MikroTik pair (§3). Only the **L3 link** and the client's `server =` target differ:
> a bridge resolves the server by name; across hosts / on RouterOS use the server's
> reachable **IP:port**.

---

## 3. Run on MikroTik RouterOS v7

RouterOS v7 has a built-in OCI **container** runtime. The image just needs to
match the router's CPU arch.

1. **Enable containers** (one-time, requires a reboot):
   ```
   /system/device-mode/update container=yes
   ```
   (Confirm via the documented power/button step RouterOS asks for.)

2. **Build the image for the router's arch** and export it as a tarball. Most
   modern MikroTik boards are `arm64`; older ones `arm/v7`; x86/CHR is `amd64`.
   **The `--provenance=false --sbom=false` flags are required:** without them
   `buildx` attaches provenance/SBOM *attestations*, which turn the export into a
   multi-manifest image that RouterOS's loader can't parse — `/container/add` then
   fails with **`could not load next layer`**.
   ```sh
   docker buildx build --platform linux/arm64 \
     --provenance=false --sbom=false \
     -f release/docker/Dockerfile -t qeli:latest-arm64 \
     -o type=docker,dest=qeli-arm64.tar .
   ```
   > Swap `linux/arm64` → `linux/amd64` (x86/CHR) or `linux/arm/v7` to match the
   > board, renaming the output tar to suit.
   >
   > **Alternative — Podman.** buildah adds no attestations, so there's nothing to
   > disable; this is the simplest route on RouterOS:
   > ```sh
   > podman build --platform linux/arm64 -f release/docker/Dockerfile -t qeli:latest-arm64 .
   > podman save --format docker-archive -o qeli-arm64.tar qeli:latest-arm64
   > ```
   > (`--format docker-archive` matters — the default `oci-archive` can also trip
   > RouterOS.)

3. **Upload `qeli-arm64.tar`** to the router (Files / FTP), then add the
   container with a veth interface and the two persistent mounts:
   ```
   /interface/veth/add name=veth-qeli address=172.18.0.2/24 gateway=172.18.0.1
   /container/mounts/add name=qeli-etc src=disk1/qeli/etc dst=/etc/qeli
   /container/mounts/add name=qeli-lib src=disk1/qeli/lib dst=/var/lib/qeli
   /container/add file=qeli-arm64.tar interface=veth-qeli \
       root-dir=disk1/qeli/root mounts=qeli-etc,qeli-lib \
       cmd="server" start-on-boot=yes
   ```
   Route/NAT the wire port to the veth IP on the router as usual.

**Client role on the router** (MikroTik as a VPN client / gateway for the LAN) — same
image, `cmd="client"`, and the **same `client.conf` from §2d** with two changes: point
`server =` at the **remote server's public `IP:port`** (RouterOS has no embedded DNS to
resolve a peer container's name) and keep `dns = off`. To masquerade the router's LAN out
through the tunnel, add `gateway_nat = true` under `[qeli]`. Drop the file in the mounted
`/etc/qeli`, then:

```
/interface/veth/add name=veth-qeli-cli address=172.19.0.2/24 gateway=172.19.0.1
/container/mounts/add name=qeli-cli-etc src=disk1/qeli-cli/etc dst=/etc/qeli
/container/add file=qeli-arm64.tar interface=veth-qeli-cli \
    root-dir=disk1/qeli-cli/root mounts=qeli-cli-etc \
    cmd="client" start-on-boot=yes
```

> **Caveat — `/dev/net/tun` on RouterOS:** the container runtime is minimal and
> TUN access is **version/board dependent and may be restricted**. qeli opens
> `/dev/net/tun` to bring up each profile's interface, so if the node is missing a
> profile fails at startup with `Profile '<name>' error: No such file or directory
> (os error 2)`. RouterOS's `/container` has no `--device` flag, so whether the node
> exists inside the container is up to the RouterOS build — there's no in-container
> workaround if it doesn't. (This is separate from the image-load step above: it
> only shows up *after* the container starts.) If TUN isn't available, run qeli on a
> small Linux host **behind** the MikroTik (port-forward the wire port to it)
> instead — the same image, `network_mode: host` on Linux. Treat MikroTik as
> best-effort; Linux is the fully-supported target.

---

## 4. Host prerequisites

| Need | Why | How |
|------|-----|-----|
| `/dev/net/tun` | the data-plane interface (both roles) | usually present; `modprobe tun` if not |
| caps `NET_ADMIN`,`NET_RAW`,`NET_BIND_SERVICE` | create TUN, set routes/iptables, bind :443 | `--cap-add` (no `--privileged` needed) |
| `net.ipv4.ip_forward=1` | **server NAT** (`routing.nat.enabled`) — internet egress | `--sysctl net.ipv4.ip_forward=1` |
| `nf_nat` / `iptable_nat` kernel modules | **server NAT** MASQUERADE | host kernel (`modprobe iptable_nat`) — containers share the host kernel |
| `net.core.rmem_max` ≥ requested UDP receive buffer | **UDP profiles** — permits Qeli's explicit buffer requests and bounded growth | Check the host limit and actual socket readback (see below) |

A **client-only** container needs just `/dev/net/tun` + `NET_ADMIN` (no iptables,
no ip_forward). NAT is opt-in (`routing.nat.enabled` in the server config); a
server without NAT (e.g. behind a host that NATs) doesn't need iptables at all.

**Running a `udp-*` profile in Docker.** In automatic mode Qeli requests a 4 MiB
receive buffer and may grow it to 16 MiB within its own RAM budget. UDP has no
kernel receive autotuning; Qeli supplies its own bounded controller. Check host
`net.core.rmem_max`: raising `rmem_default` alone does not permit larger explicit
requests. The one-shot Linux installer requests a 16 MiB maximum; for a manually
configured host, preserve the previous value/file and add this limit to your
existing tuning file if needed:

```ini
net.core.rmem_max=16777216
```

Apply that file with `sudo sysctl -p /etc/sysctl.d/99-qeli-perf.conf` (use your actual
file path), then recreate affected sockets, for example with `docker restart qeli-server`.
Check Qeli logs and `docker exec qeli-server ss -ulnm`; Linux normally reports twice
the requested `SO_RCVBUF` in `rb`: about `rb8388608` for a 4 MiB request, up to
`rb33554432` for 16 MiB, subject to kernel limits. Monitor overflow counters as well;
larger buffers do not eliminate sustained overload or TUN drops.

**TCP autotuning.** In each server TCP `[profile:...]`, use:

```ini
perf.tcp.send_buffer_size = 0
perf.tcp.recv_buffer_size = 0
```

These keys leave socket buffers to the OS; explicit nonzero values are preserved
and lock the corresponding buffer. Check the TCP sysctls **in the container's
network namespace**: `docker exec qeli-server sysctl net.ipv4.tcp_moderate_rcvbuf net.ipv4.tcp_rmem net.ipv4.tcp_wmem`.
If necessary, set `--sysctl net.ipv4.tcp_moderate_rcvbuf=1` when creating a bridge-network
container (or the equivalent Compose `sysctls`). With host networking, configure
these on the host instead. Preserve existing RAM limits; do not copy large
per-socket budgets blindly to routers. Restart/reconnect for new TCP sockets.
The image does not modify host sysctl. See the [Linux server tuning guide](../../docs/eng/manuals/CONFIG.md).

---

## 5. Configuration & persistence

- **Persist `/etc/qeli`** (a named volume or bind mount). The per-profile
  **identity key** is generated there on first start — losing it makes every
  pinned client fail to connect (`BAD_DECRYPT`). The users file lives there too.
- `/var/lib/qeli` holds the client TOFU pin store — persist it for clients.
- The example configs (`server.conf`, `server-multiprofile.conf`, `server-ipv6.conf`,
  `server-maxobf.conf`, `users.conf`, `client.conf`, `client-reality.conf`,
  `client-maxobf.conf`)
  ship inside the image under `/usr/share/qeli/*.example`; the entrypoint copies
  the relevant one to `/etc/qeli` on first run. See `docs/{ru,eng}/CONFIG.md`.
- **Client `dns = off` (Docker requirement).** Docker bind-mounts `/etc/resolv.conf`,
  which qeli's default client DNS management (`dns = tunnel`) cannot atomically
  replace — it errors out and reconnect-loops. Set `dns = off` under `[qeli]` in a
  container client config (the same escape hatch routers use). The entrypoint warns
  if it is missing.
- **Server logging → stdout.** The bundled `server.conf` logs to
  `/var/log/qeli/server.log`. For `docker logs` to show server output, omit the
  `file = …` line under `[logging]` so it goes to stdout.
- **Web panel:** set `[web] bind = 0.0.0.0` + a `password_hash` (generate with
  `qeli set-web-password`) and publish `-p 8080:8080`. A public bind without a
  password refuses to start (fail-closed).
- **Applying config changes / restart (no systemd here).** There is no systemd in the
  container, so the panel's **Apply & Restart** cannot `systemctl restart` — and it does
  **not** try. It detects the container and never asks for a polkit rule, so the
  `qeli install-polkit` hint (a systemd-host thing) is **never shown in Docker**. Instead:
  - **Profile / user / DNS / NAT / obfuscation changes** are applied automatically by the
    in-process **worker restart** — the supervisor respawns the data-plane inside the same
    container. No host action; the panel does not drop.
  - **Panel-socket changes** (`web.bind` / `web.port` / `web.tls*` / `web.enabled`) bind at
    container start, so recreate the container from the host:
    `docker compose -f release/docker/docker-compose.yml restart qeli-server`
    (or `docker restart <name>`). The `/etc/qeli` volume keeps the saved config, which the
    entrypoint re-reads on start.
- **Multiprofile server** (all wire modes at once): select the bundled example with
  the `QELI_CONFIG` env var —
  `docker run ... -e QELI_CONFIG=/usr/share/qeli/server-multiprofile.conf.example qeli:latest server`
  — or, to be able to edit it, copy it into the volume first:
  `docker run --rm -v qeli-etc:/etc/qeli qeli:latest sh -c 'cp /usr/share/qeli/server-multiprofile.conf.example /etc/qeli/server.conf'`.

- **Dual-stack server:** select `/usr/share/qeli/server-ipv6.conf.example`. When Docker
  does not allow the daemon to write namespaced IPv6 sysctls, start the container with
  `--sysctl net.ipv6.conf.all.forwarding=1`; the profile preflight remains fail-closed if
  IPv6 forwarding, the IPv6 uplink, or `ip6tables` is unavailable.

  Two things to know. The examples live in **`/usr/share/qeli`**, not `/etc/qeli` — a
  volume mounted at `/etc/qeli` would hide them. And appending your own `--config` does
  **not** work the way it looks: the entrypoint always passes its own `--config "$CONF"`
  first and your argument lands after it. clap takes the last one, so it does select your
  file — but the startup log still prints the entrypoint's path, and the seeding logic
  has already populated that other file. Use `QELI_CONFIG`, which the entrypoint reads
  directly, so the log and the actual config agree.

  Also note `QELI_CONFIG` only chooses the *path*; when that path is empty the entrypoint
  seeds it from `/usr/share/qeli/<role>.conf.example` — the **single-profile** example.
  Pointing `QELI_CONFIG` at a fresh `…/server-multiprofile.conf` therefore gives you a
  single-profile config under a multiprofile name. Either point at the `.example` file
  directly (read-only, as above) or copy it in yourself first.

---

## 6. Troubleshooting

- **`/dev/net/tun is missing`** → add `--device /dev/net/tun --cap-add NET_ADMIN`.
- **NAT enabled but no internet egress** → the host kernel lacks `nf_nat`
  (`modprobe iptable_nat`), or `ip_forward` is off (`--sysctl net.ipv4.ip_forward=1`).
- **`iptables` rule "applied" but traffic isn't NATed** → the host uses the
  `nft` backend while the container's `iptables` hits a legacy chain (or vice
  versa). qeli is iptables-CLI-only and detects the mismatch; align the backends
  (the image ships Debian's default `iptables-nft`).
- **Clients drop after a container recreate** → `/etc/qeli` wasn't persisted, so
  a fresh identity key was generated. Mount it as a volume.

---

## 7. Image size

Base `debian:bookworm-slim` + `iproute2`/`iptables`/`iputils-ping`/`ca-certificates`
+ the stripped `qeli` binary ≈ 70–80 MB per arch. For a smaller footprint (tight
router flash) build a musl-static binary and swap the runtime base to `alpine:3`
(still `apk add iproute2 iptables iputils`) — the binary shells out to
`ip`/`iptables`, so a truly empty `scratch`/distroless image will not work.

---

## 8. Test results (2026-06-22)

Built and tested on a fresh **Debian 13 / Docker 29 / 4-core** host. Two
scenarios: end-to-end stability over a WAN path, and a high-throughput data-plane
stress on a local path (to load the crypto plane without a network bottleneck).
The run used the `0.7.2` binary; the Docker layer is version-agnostic, so the
results carry to later releases (`0.7.3`+) unchanged.

### Build & smoke
- Image builds from the repo (`docker build`), `qeli 0.7.2`, **152 MB**.
- Both roles + all subcommands present; `ip`/`iptables` bundled; binary 7.7 MB.
- **Server** container boots, generates its identity, binds `:443` (port-mapped).
- **Client** container connected to a remote qeli server (fake-tls), authenticated
  (`Auth OK`), brought its TUN up, and carried a tunnel.

### Scenario 1 — stability (client container → remote server, RTT ~63 ms, 15+ min)

| Metric | Result |
|--------|--------|
| Reconnects | **0** over 15 min |
| Crashes / panics | **0** (logs clean) |
| CPU (idle / load) | ~1.25 % / ~1.3 % |
| Memory (qeli RSS) | 7.2 MB, **flat** — 60 s soak **Δ = 0 KB (no leak)** |
| Tunnel liveness | up at every sample; **0 retransmits** single-stream |
| Throughput (WAN-bound) | up 16 / down 45 / `-P4` 43 Mbit/s |

> **These numbers are the link, not Docker.** The docker host's internet uplink is
> capped at **~100 Mbit/s** — and even a plain speedtest on it lands around **80**,
> not a full 100 (normal for the link). On top of that, the ~63 ms RTT throttles a
> single TCP flow via the bandwidth-delay product. So the Scenario 1 figures reflect
> the **WAN channel**, not container overhead — Scenario 2 below removes the network
> bottleneck and the same container reaches ~780–986 Mbit/s.

### Scenario 2 — high-throughput (container ↔ container, loopback, no WAN limit)

| Test (through the encrypted tunnel) | Throughput |
|-------------------------------------|------------|
| TCP upload | **779 Mbit/s** |
| TCP download (`-R`) | **986 Mbit/s** (≈ line-rate Gbit) |
| TCP `-P8` (aggregate) | **831 Mbit/s** |

Under a sustained `-P8` / 30 s load: data-plane **server 112 % CPU, client 122 %**
(the multi-queue data plane spreads crypto across cores). Memory: **server RSS
Δ = 0**, client **+644 KB** (allocator slack under bursty allocation, not a runaway
leak). Both containers stayed **Up, 0 reconnects, 0 panics**.

### Verdict
The Dockerized data plane is at **parity with bare metal** (~590–986 Mbit/s,
~1.1–1.2 cores under load) with **no leaks, reconnects, or panics** across 15+ min
idle + load + ~90 s of combined soak. The netns/veth overhead is negligible.

> **Stability depends on `dns = off`** for client containers — Docker bind-mounts
> `/etc/resolv.conf`, which the default `dns = tunnel` cannot atomically replace
> (EBUSY → reconnect loop). The entrypoint warns if it's missing; see §5.

## First-run configuration and filesystem behavior

With no arguments the entrypoint selects `server`. `QELI_CONFIG` chooses the default
path; an explicit `--config PATH`, `--config=PATH`, `-c PATH` or `-cPATH` takes
precedence and is passed to qeli once. Missing/empty/duplicate config options refuse
before writing. Help/version options do not create config or users files.

New config and empty users files are0600. Existing regular files retain their contents
and permissions; symlinks and other file types refuse startup. Creation publishes a
complete temporary file with GNU `ln -T`, preserving a concurrent regular creator and
refusing a concurrent link/directory. First-run volumes need hard-link support; failed
copy/link or readonly storage refuses instead of leaving a partial final file. This
is not fsync/power-loss durability, and SIGKILL can leave a temporary file. Administrator
changes to parent paths are outside the cooperative publication boundary.

[Q33 audit](../../docs/eng/reports/audit-0.8.2/AUDIT-Q33-DOCKER-ENTRYPOINT.md) records34 shell/chroot
scenarios. These checks use an argv-recording executable and do not qualify Docker
image builds, daemon networking, health or recreation.

### Publication and recovery policy

`docker-publish` validates release tags before login/build. Manual branch runs
publish a full `sha-<commit>` tag; stable SemVer release tags also publish `latest`,
while prereleases never replace it. Cargo builds use `--locked`.

Keep `/etc/qeli` and `/var/lib/qeli` volumes across recreation. Record and retain
the current image ID and back up configuration/state before upgrading. Check logs,
client authentication and actual tunnel traffic after recreation; Running is only
process state. Restore the saved image with the same volumes on failure. Neither
this image nor the example compose implements automatic rollback or HEALTHCHECK.

On 2026-10-08 the actual amd64 runtime stage was built with a SHA-verified existing
0.8.2 release ELF supplied via the named `build` context, then passed26 local
runtime/volume/recreation/fault-recovery checks on Debian13/Docker29.8.2. This did
not rerun the Rust compiler stage, multiarch publication, Internet NAT or old
throughput benchmarks. See the [scoped audit report](../../docs/eng/reports/audit-0.8.2/AUDIT-Q33-DOCKER-ENTRYPOINT.md).

## Release source and legal resources

The runtime image retains the project AGPL, LICENSING and common reviewed Cargo/
toolchain notices in `/usr/share/doc/qeli/`; the complete native legal bundle is
under `licenses/rust/`. Validate `python3 scripts/native_licenses.py` from the repo
root before a local build. Publication CI runs that check before registry login.
Rust1.97.0 builder and Debian Bookworm runtime bases use recorded multiarch digests;
base pinning does not pin live APT packages or qualify a whole image rebuild.
The official tag metadata lists amd64,arm64/v8 and arm/v7; current layer pull/full
Docker build/runtime on these new pins remains a separate qualification.

GitHub provides release-tag source archives. Record the exact source commit and
build provenance alongside distributed artifacts; a tag name alone can be moved.
The Linux release workflow now requires an actual tag on HEAD, matching committed
Cargo version and successful CI for that exact commit before installing build tools.
This does not replace the full multi-platform/SDK release preflight. See
[licensing and publication maintenance](../../LICENSING.md).


### Release tag admission and compiler qualification

The publication workflow checks the full Git ref and, for a release tag, runs
`python3 scripts/release_tag.py --tag "$GITHUB_REF_NAME" --require-ci` before
build tools or registry login. The tag must identify the checked-out clean commit,
match committed `qeli/Cargo.toml` version, and have successful CI for that exact
commit. SemVer syntax alone is insufficient. Manual branch builds retain SHA-only
tags. Missing, failed or stale CI refuses release publication; this gate needs
`actions: read`. Local tag/version inspection without publication:

```sh
python3 scripts/release_tag.py --tag v0.8.2
```

[Q34 compiler/image qualification](../../docs/eng/reports/audit-0.8.2/AUDIT-Q34-DOCKER-BUILD.md)
records an actual amd64 build with the pinned Rust/Debian bases, default release
fat LTO/jemalloc and no prebuilt binary override; exact image notices and compact
VPN/recreation/rollback checks passed. This is scoped amd64 evidence. ARM images,
registry publication, hosted signatures and reproducible A/B remain separate.
The runtime fixture used explicit AppArmor unconfined with default seccomp;
Docker's automatically loaded default profile was restored after strict ownership
checks. It does not qualify the default AppArmor confinement on this new image.


### Updating immutable build inputs

The Dockerfile frontend is pinned by digest. Runtime APT uses only the reviewed
Debian and Debian-security snapshot `20261008T000000Z`, defined in
`release/docker/debian.sources`; inherited live sources are removed first.
APT verifies Debian archive signatures and package hashes using the base image's
archive keyring. `Check-Valid-Until: no` is scoped to the historical snapshot.
HTTP permits bootstrap before the slim image has CA certificates; it does not
turn off repository authentication.

To receive newer security packages, review and update the snapshot date explicitly,
together with the Rust/Debian base and frontend pins as needed. Keep the Debian
and Debian-security dates identical, check signed metadata and package installation,
then qualify the affected image. Do not add live mirrors as a fallback.
These pins fix the selected inputs; they do not establish byte-for-byte image
reproducibility. [Q34 input qualification](../../docs/eng/reports/audit-0.8.2/AUDIT-Q34-DOCKER-INPUTS.md)
records the exact scope of the frontend and amd64 APT checks.
