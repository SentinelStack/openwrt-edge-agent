#!/usr/bin/env sh
set -eu

if [ -f "./config/router.env" ]; then
  . "./config/router.env"
fi

ROUTER="${ROUTER:-root@192.168.1.1}"

if [ "${#}" -gt 1 ]; then
  echo "Usage: $0 [--tcp|--udp]" >&2
  exit 1
fi

ARGS=""
if [ "${#}" -eq 1 ]; then
  ARGS="$1"
  if [ "${ARGS}" != "--tcp" ] && [ "${ARGS}" != "--udp" ]; then
    echo "Invalid argument: ${ARGS}" >&2
    echo "Usage: $0 [--tcp|--udp]" >&2
    exit 1
  fi
fi

REMOTE_ENV=""
for var in BACKEND_HOST BACKEND_PORT BACKEND_SCHEME AGENT_API_KEY DEVICE_ID DEVICE_ID_FILE DEVICE_NAME DEVICE_IP DEVICE_FIRMWARE DEVICE_MODEL; do
  eval "val=\${${var}:-}"
  if [ -n "${val}" ]; then
    REMOTE_ENV="${REMOTE_ENV}${var}='${val}' "
  fi
done

REMOTE_CMD="${REMOTE_ENV}/root/openwrt-agent ${ARGS}"

if [ "${ROUTER_AUTH_MODE:-key}" = "password" ]; then
  if ! command -v sshpass >/dev/null 2>&1; then
    echo "sshpass is required for ROUTER_AUTH_MODE=password." >&2
    echo "Install it or use SSH key authentication." >&2
    exit 1
  fi
  if [ -z "${ROUTER_PASSWORD:-}" ]; then
    echo "ROUTER_PASSWORD is not set." >&2
    exit 1
  fi
  sshpass -p "${ROUTER_PASSWORD}" ssh "${ROUTER}" "${REMOTE_CMD}"
else
  ssh "${ROUTER}" "${REMOTE_CMD}"
fi
