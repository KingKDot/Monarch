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
    "Antivirus": "Defender",
    "IP": "<WINDOWS_VM_IP>",
    "ScriptLocation": "C:\\Monarch\\scripts\\scan.ps1",
    "RemoteWorkDir": "C:\\Monarch\\work"
  }
]
```

## 3) Run Monarch + Postgres via Docker

1. Copy [.env.example](.env.example) to `.env` and fill in:

   - `MONARCH_WINRM_USER`
   - `MONARCH_WINRM_PASS`
   - `MONARCH_COOKIE_SECRET`

2. Start:

   - `docker compose up --build`

3. Open:

   - `http://localhost:8080`

## 4) Do a safe test (EICAR)

Use the standard EICAR test string (commonly detected by AV) to validate deletion behavior.

- Upload an EICAR file via the UI.
- After the scan finishes, check the scan page and the public hash lookup.

Public lookup:
- `/hash/<sha256>`
- `/api/hash/<sha256>`
