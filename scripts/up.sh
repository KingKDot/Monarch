#!/usr/bin/env sh
set -eu

if [ "${1:-}" = "--no-cloudflared" ]; then
  echo "Starting Monarch without cloudflared profile"
  docker compose up -d --build
elif [ "${1:-}" = "--with-cloudflared" ]; then
  echo "Starting Monarch with cloudflared profile"
  COMPOSE_PROFILES=debian docker compose up -d --build
elif [ -f /etc/debian_version ]; then
  echo "Debian detected: starting Monarch with cloudflared profile"
  COMPOSE_PROFILES=debian docker compose up -d --build
else
  echo "Starting Monarch without cloudflared profile"
  docker compose up -d --build
fi
