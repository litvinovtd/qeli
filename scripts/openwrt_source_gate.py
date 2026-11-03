"""Local OpenWrt release source admission; never downloads or extracts archives."""
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import tomllib


class SourceGateError(RuntimeError):
    pass


VARIABLES = ("PKG_VERSION", "PKG_SOURCE_VERSION", "PKG_MIRROR_HASH")
INPUTS = ("qeli", "qeli-openwrt/Makefile", "qeli-openwrt/verify-source.sh", "scripts/release_preflight.py",
          "scripts/openwrt_source_gate.py")
OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")


def _git(root, *args):
    try:
        result = subprocess.run(["git", *args], cwd=root, capture_output=True,
                                text=True, encoding="utf-8", errors="replace", timeout=30)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SourceGateError(f"Git query failed: {error}") from error
    if result.returncode:
        raise SourceGateError(f"Git query failed: {result.stderr.strip() or result.returncode}")
    return result.stdout


def _metadata(text):
    values = {}
    active = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
    for name in VARIABLES:
        rows = re.findall(r"^\s*(?:(?:override|export|private)\s+)*"+name+r"\s*([:+?]?=)([^\n]*)$",
                          text, re.M)
        definitions = re.findall(r"^\s*(?:(?:override|export|private)\s+)*(?:define|undefine)\s+"+name+r"(?:\s|$)", text, re.M)
        assignments = re.findall(r"(?<![A-Za-z0-9_])"+name+r"\s*[:+?]?=", active)
        if definitions or len(assignments) != 1 or len(rows) != 1 or rows[0][0] != ":=":
            raise SourceGateError(f"{name} requires one literal := assignment")
        value = rows[0][1].split("#", 1)[0].strip()
        if not value or any(c.isspace() for c in value) or "$" in value or "\\" in value:
            raise SourceGateError(f"{name} must be a nonempty literal")
        values[name] = value
    return values


def _oid(root, expression, kind):
    oid = _git(root, "rev-parse", "--verify", expression).strip()
    if not OID.fullmatch(oid) or _git(root, "cat-file", "-t", oid).strip() != kind:
        raise SourceGateError(f"{expression} does not identify a {kind}")
    return oid


def _archive_digest(path):
    path = Path(path)
    if path.is_symlink():
        raise SourceGateError("SDK source archive must be a regular file, not a link")
    # Open first, then inspect this descriptor: no FIFO/device read or pathname
    # hash substitution. A privileged concurrent writer is outside this gate.
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags), "rb", buffering=0) as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not before.st_size:
            raise SourceGateError("SDK source archive must be a nonempty regular file")
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise SourceGateError("SDK source archive changed while hashing")
    return digest


def check_openwrt_source(root, archive_path=None, emit=print):
    """Require committed recipe/source, immutable matching pin and actual mirror bytes.

    archive_path is the SDK-generated Source archive, not a git-archive substitute.
    Its integrity is checked without decompression; SDK generation/compilation is a
    separate qualification. No arbitrary Make conditional/environment evaluation.
    """
    root = Path(root)
    try:
        if _git(root, "status", "--porcelain", "--", *INPUTS).strip():
            raise SourceGateError("committed OpenWrt recipe/source inputs required")
        flags = _git(root, "ls-files", "-v", "--", *INPUTS).splitlines()
        if any(line and (line[0].islower() or line[0] == "S") for line in flags):
            raise SourceGateError("OpenWrt source has assume-unchanged/skip-worktree Git flags")
        head = _oid(root, "HEAD^{commit}", "commit")
        recipe = _git(root, "show", head+":qeli-openwrt/Makefile")
        values = _metadata(recipe)
        pin = values["PKG_SOURCE_VERSION"]
        if not OID.fullmatch(pin):
            raise SourceGateError("PKG_SOURCE_VERSION must be a full immutable commit SHA")
        if _oid(root, pin+"^{commit}", "commit") != pin:
            raise SourceGateError("PKG_SOURCE_VERSION must identify a commit, not a tag object")
        if _oid(root, pin+":qeli", "tree") != _oid(root, head+":qeli", "tree"):
            raise SourceGateError("PKG_SOURCE_VERSION qeli/ tree differs from release source")
        cargo = tomllib.loads(_git(root, "show", head+":qeli/Cargo.toml"))
        package = cargo.get("package")
        version = package.get("version") if isinstance(package, dict) else None
        if not isinstance(version, str) or not version:
            raise SourceGateError("literal Cargo [package].version required")
        if version != values["PKG_VERSION"]:
            raise SourceGateError(f"PKG_VERSION={values['PKG_VERSION']} differs from Cargo {version}")
        expected = values["PKG_MIRROR_HASH"]
        if not re.fullmatch(r"[0-9a-f]{64}", expected) or expected == "0"*64:
            raise SourceGateError("PKG_MIRROR_HASH must be a real lowercase SHA256; skip/placeholder refused")
        if not archive_path:
            raise SourceGateError("QELI_OPENWRT_SOURCE_ARCHIVE must name the SDK-generated Source archive")
        if _archive_digest(archive_path) != expected:
            raise SourceGateError("SDK source archive SHA256 differs from PKG_MIRROR_HASH")
        emit(f"  OpenWrt source PASS: version={version}, pin={pin}, mirror={expected}")
        return []
    except (SourceGateError, OSError, ValueError, TypeError, tomllib.TOMLDecodeError) as error:
        return [f"OpenWrt source gate: {error}"]
