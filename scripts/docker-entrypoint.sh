#!/bin/sh
set -eu

storage_dir="${MONARCH_STORAGE_DIR:-/var/lib/monarch/storage}"

mkdir -p "${storage_dir}"
chown -R monarch:monarch "${storage_dir}" 2>/dev/null || true

if su-exec monarch sh -c "test -w \"${storage_dir}\""; then
  exec su-exec monarch /app/monarch
fi

echo "warning: ${storage_dir} is not writable by user monarch; running as root"
exec /app/monarch
