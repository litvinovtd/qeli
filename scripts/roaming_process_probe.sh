# shellcheck shell=bash
# Exact process identity helpers shared by the TCP and UDP roaming resource gates.

roaming_find_server_worker_pid() {
  if [ "$#" -lt 4 ]; then
    echo "usage: roaming_find_server_worker_pid BINARY CONFIG PROC_ROOT PID..." >&2
    return 2
  fi

  local binary=$1
  local config=$2
  local proc_root=$3
  shift 3

  local expected_exe
  expected_exe=$(readlink -f -- "$binary") || {
    echo "could not resolve qeli binary: $binary" >&2
    return 1
  }

  local candidate="" matches=0 pid exe config_match i
  local -a argv=()
  for pid in "$@"; do
    case "$pid" in
      ''|*[!0-9]*) continue ;;
    esac
    [ -r "$proc_root/$pid/cmdline" ] || continue
    exe=$(readlink -f -- "$proc_root/$pid/exe" 2>/dev/null || true)
    [ "$exe" = "$expected_exe" ] || continue

    argv=()
    mapfile -d '' -t argv <"$proc_root/$pid/cmdline"
    [ "${argv[1]-}" = "_worker" ] || continue

    config_match=0
    i=2
    while [ "$i" -lt "${#argv[@]}" ]; do
      if { [ "${argv[$i]}" = "-c" ] || [ "${argv[$i]}" = "--config" ]; } \
          && [ "${argv[$((i + 1))]-}" = "$config" ]; then
        config_match=1
        break
      fi
      i=$((i + 1))
    done
    [ "$config_match" -eq 1 ] || continue

    candidate=$pid
    matches=$((matches + 1))
  done

  case "$matches" in
    1)
      printf '%s\n' "$candidate"
      ;;
    0)
      echo "no exact qeli _worker for config $config among namespace PIDs" >&2
      return 1
      ;;
    *)
      echo "multiple exact qeli _worker processes for config $config" >&2
      return 1
      ;;
  esac
}
