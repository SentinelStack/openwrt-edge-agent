#!/usr/bin/env sh
set -eu

if [ -f "./config/router.env" ]; then
  . "./config/router.env"
fi

ROUTER="${ROUTER:-root@192.168.1.1}"
BINARY="openwrt-agent"
REMOTE_PATH="/root/${BINARY}"

if [ ! -f "${BINARY}" ]; then
  echo "Binary '${BINARY}' not found. Run 'make build' first." >&2
  exit 1
fi

echo "Deploying ${BINARY} to ${ROUTER}:${REMOTE_PATH}"
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
  sshpass -p "${ROUTER_PASSWORD}" scp -O "${BINARY}" "${ROUTER}:${REMOTE_PATH}"
  sshpass -p "${ROUTER_PASSWORD}" ssh "${ROUTER}" "chmod +x ${REMOTE_PATH}"
else
  scp -O "${BINARY}" "${ROUTER}:${REMOTE_PATH}"
  ssh "${ROUTER}" "chmod +x ${REMOTE_PATH}"
fi
echo "Deployment complete."
