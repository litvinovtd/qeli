# shellcheck shell=bash
# Canonical decimal counts shared by soak cases and their admission wrappers.
# Leading zeros are refused: Bash arithmetic interprets them as octal.
roaming_soak_count() {
  local name=$1 value=$2 minimum=$3
  case "$value" in
    ''|0*|*[!0-9]*)
      echo "$name must be a canonical positive decimal integer" >&2
      return 2
      ;;
  esac
  # Keep all arithmetic within the common signed 32-bit positive range.
  if [ "${#value}" -gt 10 ] || [ "$value" -gt 2147483647 ] || [ "$value" -lt "$minimum" ]; then
    echo "$name must be between $minimum and 2147483647" >&2
    return 2
  fi
}

roaming_soak_counts() {
  local iterations=$1 sample_every=$2 minimum=${3:-1}
  roaming_soak_count QELI_ROAMING_SOAK_ITERATIONS "$iterations" "$minimum" || return 2
  roaming_soak_count QELI_ROAMING_SOAK_SAMPLE_EVERY "$sample_every" 1 || return 2
  if [ "$sample_every" -gt "$iterations" ]; then
    echo "QELI_ROAMING_SOAK_SAMPLE_EVERY must not exceed iterations" >&2
    return 2
  fi
}
