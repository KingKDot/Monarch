@echo off
setlocal

echo Starting Monarch on Windows (cloudflared disabled)
docker compose up -d --build

endlocal
