import argparse
import json
import socket
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple


def read_targets(config_path: Path) -> List[Dict[str, Any]]:
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    with config_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, list):
        raise ValueError("avs.json must be a JSON array")
    return data


def tcp_check(host: str, port: int, timeout: float) -> Tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "ok"
    except Exception as exc:
        return False, str(exc)


def run_remote_checks(
    host: str,
    user: str,
    password: str,
    script_location: str,
    remote_workdir: str,
    port: int,
    use_https: bool,
    insecure: bool,
    timeout: int,
) -> Tuple[bool, Dict[str, Any], str]:
    try:
        import winrm
    except Exception:
        return (
            False,
            {},
            "pywinrm is not installed. Install with: pip install pywinrm",
        )

    endpoint = f"{'https' if use_https else 'http'}://{host}:{port}/wsman"
    transport = "ntlm"

    try:
        session = winrm.Session(
            target=endpoint,
            auth=(user, password),
            transport=transport,
            server_cert_validation="ignore" if insecure else "validate",
            read_timeout_sec=max(30, timeout),
            operation_timeout_sec=max(20, timeout),
        )
    except Exception as exc:
        return False, {}, f"session error: {exc}"

    ps_script = f"""
$ErrorActionPreference = 'Stop'
$result = [ordered]@{{
  computer_name = $env:COMPUTERNAME
  user_name = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
  script_location = '{script_location.replace("'", "''")}'
  script_exists = Test-Path -LiteralPath '{script_location.replace("'", "''")}'
  remote_workdir = '{remote_workdir.replace("'", "''")}'
  remote_workdir_exists = Test-Path -LiteralPath '{remote_workdir.replace("'", "''")}'
  powershell_version = $PSVersionTable.PSVersion.ToString()
}}
$result | ConvertTo-Json -Compress
"""

    try:
        response = session.run_ps(ps_script)
    except Exception as exc:
        return False, {}, f"run_ps error: {exc}"

    stdout = response.std_out.decode("utf-8", errors="replace").strip()
    stderr = response.std_err.decode("utf-8", errors="replace").strip()

    if response.status_code != 0:
        err = (
            stderr
            or stdout
            or f"remote command failed with status {response.status_code}"
        )
        return False, {}, err

    try:
        parsed = json.loads(stdout) if stdout else {}
    except Exception as exc:
        return False, {}, f"invalid JSON response: {exc}; raw={stdout!r}"

    return True, parsed, "ok"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Test WinRM/WSMAN connectivity and paths from avs.json targets."
    )
    parser.add_argument(
        "--config",
        default="avs.json",
        help="Path to avs config file (default: avs.json)",
    )
    parser.add_argument("--port", type=int, default=5985, help="WinRM port")
    parser.add_argument(
        "--https",
        action="store_true",
        help="Use HTTPS endpoint (https://host:port/wsman)",
    )
    parser.add_argument(
        "--strict-cert",
        action="store_true",
        help="Validate TLS certs when using --https",
    )
    parser.add_argument(
        "--timeout", type=int, default=12, help="Network timeout seconds"
    )
    args = parser.parse_args()

    config_path = Path(args.config)
    try:
        targets = read_targets(config_path)
    except Exception as exc:
        print(f"[fatal] {exc}")
        return 1

    if not targets:
        print("[fatal] No targets found in config.")
        return 1

    print(f"Loaded {len(targets)} target(s) from {config_path}")
    print("=" * 88)

    failures = 0

    for idx, target in enumerate(targets, start=1):
        name = str(target.get("Antivirus", f"Target-{idx}"))
        ip = str(target.get("IP", "")).strip()
        user = str(target.get("WinRMUser", "")).strip()
        password = str(target.get("WinRMPass", ""))
        script_location = str(target.get("ScriptLocation", "")).strip()
        remote_workdir = str(target.get("RemoteWorkDir", "C:\\Monarch\\work")).strip()

        print(f"[{idx}] {name}")
        print(f"    IP: {ip}")
        print(f"    User: {user}")
        print(f"    ScriptLocation: {script_location}")
        print(f"    RemoteWorkDir: {remote_workdir}")

        if not ip or not user or not password:
            print("    [FAIL] Missing IP/WinRMUser/WinRMPass in target config")
            failures += 1
            print("-" * 88)
            continue

        tcp_ok, tcp_msg = tcp_check(ip, args.port, args.timeout)
        print(f"    TCP {ip}:{args.port}: {'OK' if tcp_ok else 'FAIL'} ({tcp_msg})")
        if not tcp_ok:
            failures += 1
            print("-" * 88)
            continue

        auth_ok, info, msg = run_remote_checks(
            host=ip,
            user=user,
            password=password,
            script_location=script_location,
            remote_workdir=remote_workdir,
            port=args.port,
            use_https=args.https,
            insecure=not args.strict_cert,
            timeout=args.timeout,
        )

        if not auth_ok:
            print(f"    [FAIL] WinRM auth/command: {msg}")
            failures += 1
            print("-" * 88)
            continue

        print("    [OK] WinRM auth/command")
        print(f"    Remote host: {info.get('computer_name', 'unknown')}")
        print(f"    Running as: {info.get('user_name', 'unknown')}")
        print(f"    PowerShell: {info.get('powershell_version', 'unknown')}")
        print(
            f"    Script exists: {info.get('script_exists')} ({info.get('script_location')})"
        )
        print(
            f"    Work dir exists: {info.get('remote_workdir_exists')} ({info.get('remote_workdir')})"
        )

        if not info.get("script_exists") or not info.get("remote_workdir_exists"):
            failures += 1
            print("    [WARN] Path checks failed on this target")

        print("-" * 88)

    if failures:
        print(f"Completed with {failures} issue(s).")
        return 1

    print("All targets passed connectivity and path checks.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
