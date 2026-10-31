# Qeli repository instructions

## Branch policy

- The only permanent branches, locally and on GitHub, are `main`, `dev`, and `blog`.
- All agent-authored development, fixes, tests, documentation and release preparation happen on `dev` in the primary checkout.
- Do not create or push any other development branch, including `codex/*`, feature, hotfix, maintenance or release branches. Do not create a worktree that creates such a branch.
- Keep `main` and `blog` unchanged unless the user explicitly requests work on them or a release merge.
- User-approved exception: Dependabot may create temporary head branches for open pull requests targeting `dev`. Remove those temporary branches after the PR is merged and its commits are verified to be included in `dev`. Do not disable Dependabot or its security notifications merely to enforce the permanent-branch list.
- Existing detached worktrees may be retained as historical build/audit snapshots; do not use them for new development.
- This policy does not itself authorize commits, code pushes, merges or release publication.

## Linux release policy

- Starting with 0.8.4, every release, including Beta/prereleases, must include both
  Linux server architectures: `qeli-linux-amd64`, `qeli-linux-arm64`,
  `qeli_<version>_amd64.deb` and `qeli_<version>_arm64.deb`. Build and qualify both
  from the same release source commit; an amd64-only candidate is incomplete.
- Distributable Linux amd64/arm64 `qeli` binaries and `.deb` packages must target glibc 2.28
  and enable jemalloc. Use `make -C qeli/debian binary-portable` or `deb-portable`
  (`deb` is also portable); never distribute a native `cargo build --release` output.
  Architecture defaults to the host; use `ARCH=amd64` or `ARCH=arm64` for an explicit
  native/cross target. Never relabel an ELF/package of the other architecture.
- Before copying a candidate into `release/dist`, run
  `python scripts/linux_release.py --binary PATH` and `--deb PACKAGE` as applicable.
  Before generating checksums/uploading, run `--assets DIRECTORY`. A failed or missing
  check blocks the copy/publication; do not replace the gate with a provenance claim.
- These host-glibc rules concern portable server executables, not Windows/Apple/Android
  FFI, musl router clients, or container-internal binaries linked to their bundled runtime.
