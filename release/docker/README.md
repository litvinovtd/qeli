# qeli in Docker

One **multi-arch** image (`linux/amd64`, `linux/arm64`, `linux/arm/v7`) that
carries **both roles** — `qeli server` and `qeli client` — with every runtime
dependency bundled (`iproute2`, `iptables`, CA certs). It runs on any Linux host
and on router container runtimes (MikroTik RouterOS v7, OpenWrt, etc.).

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

---

## 1. Build

> Run all build commands from the **repository root** (the build context is the
> repo; the Cargo project is `qeli/`). You need Docker with **buildx**.

Multi-arch (one tag, three arches):

```sh
docker buildx create --use --name qeli-builder   # once
docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 \
  -f release/docker/Dockerfile -t qeli:0.7.2 \
  --push .          # push to a registry, OR build per-arch with --load below
```

Single arch you can `--load` into the local daemon (e.g. amd64 for a Linux box,
or arm64 for a Pi/MikroTik):

```sh
docker buildx build --platform linux/amd64 \
  -f release/docker/Dockerfile -t qeli:0.7.2 --load .
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
docker buildx build -f release/docker/Dockerfile -t qeli:0.7.2 --load .
docker compose -f release/docker/docker-compose.yml up -d qeli-server
```

First start seeds `./data/server/etc/server.conf` from the example. Edit it, add
a user and (optionally) enable NAT, then bring the panel up or add a client:

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
  qeli:0.7.2 server
```

### c) plain `docker run` — client (VPN gateway)

```sh
# put your client.conf (or a qeli:// derived INI) in data/client/etc/ first
docker run -d --name qeli-client \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -v "$PWD/data/client/etc:/etc/qeli" \
  -v "$PWD/data/client/lib:/var/lib/qeli" \
  qeli:0.7.2 client
```

Route another container's traffic through the client:
`docker run --network=container:qeli-client ...`.

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
   modern MikroTik boards are `arm64`; older ones `arm/v7`; x86/CHR is `amd64`:
   ```sh
   docker buildx build --platform linux/arm64 \
     -f release/docker/Dockerfile -t qeli:0.7.2-arm64 \
     -o type=docker,dest=qeli-arm64.tar .
   ```

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

> **Caveat — `/dev/net/tun` on RouterOS:** the container runtime is minimal and
> TUN access is **version/board dependent and may be restricted**. Verify on your
> device. If TUN isn't available inside the container, run qeli on a small Linux
> host **behind** the MikroTik (port-forward the wire port to it) instead — the
> same image, `network_mode: host` on Linux. Treat MikroTik as best-effort; Linux
> is the fully-supported target.

---

## 4. Host prerequisites

| Need | Why | How |
|------|-----|-----|
| `/dev/net/tun` | the data-plane interface (both roles) | usually present; `modprobe tun` if not |
| caps `NET_ADMIN`,`NET_RAW`,`NET_BIND_SERVICE` | create TUN, set routes/iptables, bind :443 | `--cap-add` (no `--privileged` needed) |
| `net.ipv4.ip_forward=1` | **server NAT** (`routing.nat.enabled`) — internet egress | `--sysctl net.ipv4.ip_forward=1` |
| `nf_nat` / `iptable_nat` kernel modules | **server NAT** MASQUERADE | host kernel (`modprobe iptable_nat`) — containers share the host kernel |

A **client-only** container needs just `/dev/net/tun` + `NET_ADMIN` (no iptables,
no ip_forward). NAT is opt-in (`routing.nat.enabled` in the server config); a
server without NAT (e.g. behind a host that NATs) doesn't need iptables at all.

---

## 5. Configuration & persistence

- **Persist `/etc/qeli`** (a named volume or bind mount). The per-profile
  **identity key** is generated there on first start — losing it makes every
  pinned client fail to connect (`BAD_DECRYPT`). The users file lives there too.
- `/var/lib/qeli` holds the client TOFU pin store — persist it for clients.
- The example configs (`server.conf`, `server-multiprofile.conf`, `client.conf`)
  ship inside the image as `*.example`; the entrypoint copies the relevant one on
  first run. See `docs/{ru,eng}/CONFIG.md` for every key.
- **Web panel:** set `[web] bind = 0.0.0.0` + a `password_hash` (generate with
  `qeli set-web-password`) and publish `-p 8080:8080`. A public bind without a
  password refuses to start (fail-closed).
- **Multiprofile server** (all wire modes at once): point the entrypoint at the
  bundled example —
  `docker run ... qeli:0.7.2 server --config /etc/qeli/server-multiprofile.conf.example`
  (or copy it into the volume and edit).

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

Base `debian:bookworm-slim` + `iproute2`/`iptables`/`ca-certificates` + the
stripped `qeli` binary ≈ 70–80 MB per arch. For a smaller footprint (tight router
flash) build a musl-static binary and swap the runtime base to `alpine:3` (still
`apk add iproute2 iptables`) — the binary shells out to `ip`/`iptables`, so a
truly empty `scratch`/distroless image will not work.
