# Monarch (test setup)

This is the fastest way to test Monarch with a single Windows VM running Defender.

## 1) Create the Windows VM (Defender target)

On the Windows VM:

1. Create folders:

   - `C:\Monarch\scripts`
   - `C:\Monarch\work`

2. Copy the repo script to the VM as:

   - `C:\Monarch\scripts\scan.ps1` (from [scripts/scan.ps1](scripts/scan.ps1))

3. Enable WinRM (simple HTTP test mode):

   Run PowerShell as Administrator:

   - `winrm quickconfig -q`
   - `Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true`
   - `Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true`
   - `Enable-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)"`

   Notes:
   - This is OK for an isolated lab network, but for real deployments you should switch to WinRM over HTTPS (5986) and disable unencrypted/basic.

4. Make sure Defender real-time protection is enabled (default on most Windows installs).

## 2) Configure Monarch AV targets

On the machine/VM running Monarch, create `avs.json` next to `docker-compose.yml`:

```json
[
  {
      "Antivirus": "Defender-VM1",
      "IP": "<WINDOWS_VM1_IP>",
      "WinRMUser": "<VM1_USER>",
      "WinRMPass": "<VM1_PASS>",
      "ScriptLocation": "C:\\Monarch\\scripts\\scan.ps1",
      "RemoteWorkDir": "C:\\Monarch\\work"
   },
   {
      "Antivirus": "Defender-VM2",
      "IP": "<WINDOWS_VM2_IP>",
      "WinRMUser": "<VM2_USER>",
      "WinRMPass": "<VM2_PASS>",
    "ScriptLocation": "C:\\Monarch\\scripts\\scan.ps1",
    "RemoteWorkDir": "C:\\Monarch\\work"
  }
]
```

## 3) Run Monarch + Postgres via Docker

1. Copy [.env.example](.env.example) to `.env` and fill in:

   - `MONARCH_COOKIE_SECRET`

   WinRM credentials are now configured per target inside `avs.json` (`WinRMUser` / `WinRMPass`).

2. Start:

   - Windows (no Cloudflare tunnel): `scripts\\up.bat`
   - Debian (auto-enables Cloudflare tunnel): `sh scripts/up.sh`
   - Debian (force disable tunnel): `sh scripts/up.sh --no-cloudflared`
   - Other Linux/macOS (without tunnel by default): `sh scripts/up.sh`
   - Any Linux/macOS with tunnel (optional): `sh scripts/up.sh --with-cloudflared`

   Notes:
   - The `cloudflared` service is behind the Compose profile `debian`.
   - You can also run manually with: `COMPOSE_PROFILES=debian docker compose up -d --build`
   - Services use `restart: unless-stopped`, so they start again after reboot unless you stop them.

3. Open:

   - `http://localhost:8080`

Admin panel (optional):
- `/admin/` is protected by HTTP Basic Auth using `MONARCH_ADMIN_USER` / `MONARCH_ADMIN_PASS`.
- The `/login` form is for normal users and requires the per-user **Account ID** created via `/signup`.

## 4) Do a safe test (EICAR)

Use the standard EICAR test string (commonly detected by AV) to validate deletion behavior.

- Upload an EICAR file via the UI.
- After the scan finishes, check the scan page and the public hash lookup.

Public lookup:
- `/hash/<sha256>`
- `/api/hash/<sha256>`
