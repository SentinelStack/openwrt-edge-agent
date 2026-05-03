#!/usr/bin/env sh
set -eu

if [ -f "./config/router.env" ]; then
  # shellcheck disable=SC1091
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
  sshpass -p "${ROUTER_PASSWORD}" ssh "${ROUTER}" "/root/openwrt-agent ${ARGS}"
else
  ssh "${ROUTER}" "/root/openwrt-agent ${ARGS}"
fi
