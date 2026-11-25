# shellcheck shell=bash
# Exact process identity helpers shared by the TCP and UDP roaming resource gates.

# Return one peer per authenticated JOIN, in log order; do not deduplicate.
# Both formats are needed when the harness is run against older binaries.
roaming_tcp_join_peers() {
  [ "$#" -eq 2 ] || return 2
  case "$2" in 0|1|2|'[12]') ;; *) return 2 ;; esac
  LC_ALL=C awk -v slots="$2" '
    {
      slot = peer = ""
      if (match($0, /TCP stream JOINed session stream_index=[0-9]+ pid=[0-9]+ conn=[0-9]+ transport=tcp peer=[^[:space:]]+/)) {
        split(substr($0, RSTART, RLENGTH), fields, " ")
        slot = substr(fields[5], length("stream_index=") + 1)
        peer = substr(fields[9], length("peer=") + 1)
      } else if (match($0, /Stream #[0-9]+ JOINed session for user /)) {
        split(substr($0, RSTART, RLENGTH), fields, " ")
        slot = substr(fields[2], 2)
        if (match($0, / from [^[:space:]]+[[:space:]]*$/)) {
          peer = substr($0, RSTART + length(" from "), RLENGTH - length(" from "))
          sub(/[[:space:]]+$/, "", peer)
        }
      }
      if (slot ~ ("^(" slots ")$") &&
          peer ~ /^(\[[0-9A-Za-z:._%+-]+\]|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):[0-9]+$/) {
        print peer
      }
    }' <"$1"
}

roaming_tcp_join_count() {
  [ "$#" -eq 2 ] || [ "$#" -eq 3 ] || return 2
  local peers
  peers=$(roaming_tcp_join_peers "$1" "$2") || return
  printf '%s\n' "$peers" | awk -v prefix="${3-}" '
    NF && (prefix == "" || index($0, prefix ":") == 1) { count++ }
    END { print count + 0 }'
}

roaming_tcp_last_join_port() {
  [ "$#" -eq 3 ] || return 2
  local peers
  peers=$(roaming_tcp_join_peers "$1" "$2") || return
  printf '%s\n' "$peers" | awk -v prefix="$3:" '
    index($0, prefix) == 1 { port = substr($0, length(prefix) + 1) }
    END { if (port != "") print port; else exit 1 }'
}

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
