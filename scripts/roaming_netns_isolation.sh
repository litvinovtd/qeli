#!/usr/bin/env bash
# Internal launcher shared by TCP/UDP roaming tests. No host namespace cleanup.
# Source this file, then call roaming_netns_isolate before creating any resources.
roaming_netns_verify_private() {
  local kind own parent
  for kind in mnt net pid; do
    own=$(readlink "/proc/self/ns/$kind") || return 2
    case "$kind" in
      mnt) parent=$ROAMING_PRIVATE_PARENT_MNT ;;
      net) parent=$ROAMING_PRIVATE_PARENT_NET ;;
      pid) parent=$ROAMING_PRIVATE_PARENT_PID ;;
    esac
    if [[ -z "$parent" || "$own" == "$parent" ]]; then
      echo "roaming runner requires a new $kind namespace" >&2
      return 2
    fi
  done
}

roaming_netns_isolate() {
  local helper=${BASH_SOURCE[0]} runner=$1 kind
  shift
  # This call stack is established by the launcher, never by an environment flag.
  if [[ ${FUNCNAME[2]:-} == roaming_netns_private_run && ${BASH_SOURCE[2]:-} == "$helper" ]]; then
    roaming_netns_verify_private || return 2
    return 0
  fi
  local parent_mnt parent_net parent_pid
  parent_mnt=$(readlink /proc/self/ns/mnt) || return 2
  parent_net=$(readlink /proc/self/ns/net) || return 2
  parent_pid=$(readlink /proc/self/ns/pid) || return 2
  command -v unshare >/dev/null || { echo "roaming runner requires util-linux unshare" >&2; return 2; }
  local supervisor
  supervisor=$(dirname -- "$helper")/roaming_netns_supervisor.py
  if [[ ! -r "$supervisor" ]] || ! command -v python3 >/dev/null; then
    echo "roaming runner requires Python 3 and its namespace supervisor" >&2
    return 2
  fi
  # The supervisor handles TERM/INT and its own death; kill-child connects the
  # unshare job's death to the private namespace's init.
  # All descendants die when the private PID namespace's init exits.
  exec python3 "$supervisor" unshare --mount --net --pid --fork --mount-proc --kill-child=KILL \
    bash "$helper" --private "$parent_mnt" "$parent_net" "$parent_pid" "$runner" "$@"
}

roaming_netns_private_run() {
  local ROAMING_PRIVATE_PARENT_MNT=$1 ROAMING_PRIVATE_PARENT_NET=$2 ROAMING_PRIVATE_PARENT_PID=$3 runner=$4
  shift 4
  roaming_netns_verify_private || return 2
  # Break propagation before changing mounts. /run owns the named-netns registry
  # and transient journals. Overlay /etc preserves normal config/certificates but
  # places ip-netns per-namespace hosts files in private, memory-backed storage.
  mount --make-rprivate / || return 2
  mount -t tmpfs -o mode=755 tmpfs /run || return 2
  # Unix socket addresses have a kernel length limit. Keep control paths short
  # even when the retained WORK/TMPDIR is deeply nested. /run is private per job.
  mkdir -m 700 /run/qeli-roaming-control || return 2
  local ROAMING_CONTROL_SOCKET=/run/qeli-roaming-control/control.sock
  local ROAMING_SECONDARY_CONTROL_SOCKET=/run/qeli-roaming-control/control-secondary.sock
  mkdir -p /run/qeli-roaming-etc/upper /run/qeli-roaming-etc/work || return 2
  mount -t overlay -o lowerdir=/etc,upperdir=/run/qeli-roaming-etc/upper,workdir=/run/qeli-roaming-etc/work overlay /etc || return 2
  mount -t sysfs -o ro sysfs /sys || return 2
  source "$runner" "$@"
}

if [[ ${BASH_SOURCE[0]} == "$0" && ${#BASH_SOURCE[@]} == 1 ]]; then
  if [[ $# -lt 5 || $1 != --private ]]; then
    echo "internal roaming isolation launcher: invalid invocation" >&2
    exit 2
  fi
  shift
  roaming_netns_private_run "$@"
  exit $?
fi
