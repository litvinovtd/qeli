# syntax=docker/dockerfile:1

# ============================================================================
# qeli — ONE multi-arch image, BOTH roles (`qeli server` / `qeli client`), with
# every runtime dependency bundled. Runs on any Linux host (amd64/arm64/armv7)
# and on router container runtimes (MikroTik RouterOS v7, OpenWrt, etc.).
#
# Build (run from the REPOSITORY ROOT, not from release/docker). A multi-arch
# build must --push to a registry (it can't --load a manifest list locally):
#   docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 \
#     -f release/docker/Dockerfile -t ghcr.io/litvinovtd/qeli:latest --push .
#
# One arch only (e.g. arm64 for a MikroTik / Raspberry-Pi router):
#   docker buildx build --platform linux/arm64 \
#     -f release/docker/Dockerfile -t qeli:latest-arm64 --load .
#
# See release/docker/README.md for running on Linux and on MikroTik.
# ============================================================================

# ---- build stage (buildx runs this natively per target arch; cross arches
#      build under QEMU emulation — slow but correct) --------------------------
FROM rust:1-bookworm AS build
WORKDIR /src/qeli
# Only the real build inputs are copied (no target/, no client apps) so the
# context is small and the layers cache well. The `ring` crypto provider needs a
# C compiler + perl, both already in the rust image (no cmake — aws-lc-rs is
# deliberately avoided).
COPY qeli/Cargo.toml qeli/Cargo.lock ./
COPY qeli/src ./src
# The `qeli` binary carries BOTH roles (default features = server + client). The
# `qeli-client` MIPS/router-only binary is intentionally not built here.
# Cache the cargo registry/git + the target dir across builds so a source change
# doesn't recompile every dependency from scratch (esp. slow under QEMU). The
# binary MUST be copied OUT of the target cache-mount — a cache mount is not part
# of the image layer, so the runtime stage COPYs it from /qeli, not from target/.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/qeli/target \
    cargo build --release --bin qeli \
 && cp target/release/qeli /qeli \
 && strip /qeli

# ---- runtime stage ----------------------------------------------------------
FROM debian:bookworm-slim
# qeli shells out to `ip` (iproute2 — always, for the TUN + routes) and to
# `iptables` (server NAT mode only); ca-certificates is for any outbound TLS
# (REALITY cert borrowing). `iputils-ping` is not a qeli dependency — it's bundled
# so you can `docker exec <c> ping <tunnel-gw>` to sanity-check the data plane.
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 iptables iputils-ping ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /qeli /usr/local/bin/qeli
# Baked-in example configs — the entrypoint seeds a writable copy on first run.
# These live in /usr/share/qeli (NOT /etc/qeli): a volume mounted at /etc/qeli
# would otherwise hide them and the first-run seed would fail.
COPY qeli/config/server.conf              /usr/share/qeli/server.conf.example
COPY qeli/config/server-multiprofile.conf /usr/share/qeli/server-multiprofile.conf.example
COPY qeli/config/client.conf              /usr/share/qeli/client.conf.example
COPY release/docker/entrypoint.sh         /usr/local/bin/entrypoint.sh
# Strip any CR so the `#!/bin/sh` shebang works even when the build context was
# checked out on Windows with CRLF line endings (otherwise the kernel looks for
# an interpreter `/bin/sh\r` and the container dies with
# "exec …/entrypoint.sh: no such file or directory"). Belt-and-suspenders on top
# of .gitattributes `eol=lf`.
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh \
 && chmod +x /usr/local/bin/entrypoint.sh \
 && mkdir -p /etc/qeli /var/lib/qeli /var/log/qeli

# Persist these: /etc/qeli holds the per-profile identity key (generated on first
# start — losing it makes every pinned client fail) + the users file; /var/lib/qeli
# holds the client TOFU pin store.
VOLUME ["/etc/qeli", "/var/lib/qeli"]

# Default wire :443, the extra TCP profiles, the UDP profiles, and the web panel.
# (Only the ports your config actually binds need publishing at run time.)
EXPOSE 443/tcp 8443-8447/tcp 8448-8450/udp 8080/tcp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["server"]
