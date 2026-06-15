#!/usr/bin/env sh
set -eu

if [ -f "./config/router.env" ]; then
  . "./config/router.env"
fi

ROUTER="${ROUTER:-root@192.168.1.1}"
BINARY="openwrt-agent"
REMOTE_PATH="/root/${BINARY}"
REMOTE_TMP="${REMOTE_PATH}.new"
SERVICE="sentinel-agent"

if [ ! -f "${BINARY}" ]; then
  echo "Binary '${BINARY}' not found. Run 'make build' first." >&2
  exit 1
fi

# Stop the running agent, swap the binary by rename (works even while the old
# one is in use — avoids "Text file busy" from overwriting a running executable),
# then restart the service if it's installed.
REMOTE_CMD="
  chmod +x '${REMOTE_TMP}'
  if [ -x /etc/init.d/${SERVICE} ]; then /etc/init.d/${SERVICE} stop >/dev/null 2>&1 || true; fi
  killall '${BINARY}' >/dev/null 2>&1 || true
  sleep 1
  mv -f '${REMOTE_TMP}' '${REMOTE_PATH}'
  if [ -x /etc/init.d/${SERVICE} ]; then /etc/init.d/${SERVICE} start >/dev/null 2>&1 || true; fi
  true
"

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
  sshpass -p "${ROUTER_PASSWORD}" scp -O "${BINARY}" "${ROUTER}:${REMOTE_TMP}"
  sshpass -p "${ROUTER_PASSWORD}" ssh "${ROUTER}" "${REMOTE_CMD}"
else
  scp -O "${BINARY}" "${ROUTER}:${REMOTE_TMP}"
  ssh "${ROUTER}" "${REMOTE_CMD}"
fi
echo "Deployment complete."
