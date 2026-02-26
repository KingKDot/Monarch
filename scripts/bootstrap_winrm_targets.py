import argparse
import base64
import hashlib
import json
import socket
import sys
import threading
import time
from dataclasses import dataclass
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import quote


@dataclass
class Target:
    name: str
    ip: str
    user: str
    password: str
    script_location: str
    remote_workdir: str


def load_targets(config_path: Path) -> List[Target]:
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    data = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Config JSON must be an array of targets")

    targets: List[Target] = []
    for index, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Target at index {index} is not an object")

        name = (
            str(item.get("Antivirus", f"Target-{index}")).strip() or f"Target-{index}"
        )
        ip = str(item.get("IP", "")).strip()
        user = str(item.get("WinRMUser", "")).strip()
        password = str(item.get("WinRMPass", ""))
        script_location = str(item.get("ScriptLocation", "")).strip()
        remote_workdir = (
            str(item.get("RemoteWorkDir", "C:\\Monarch\\work")).strip()
            or "C:\\Monarch\\work"
        )

        if not ip or not user or not password or not script_location:
            raise ValueError(
                f"Target '{name}' is missing one of: IP, WinRMUser, WinRMPass, ScriptLocation"
            )

        targets.append(
            Target(
                name=name,
                ip=ip,
                user=user,
                password=password,
                script_location=script_location,
                remote_workdir=remote_workdir,
            )
        )

    return targets


def find_local_script(script_location: str, search_dirs: List[Path]) -> Path:
    remote_name = Path(script_location).name
    if not remote_name:
        raise FileNotFoundError(
            f"Cannot extract script filename from ScriptLocation '{script_location}'"
        )

    matches: List[Path] = []
    remote_name_lower = remote_name.lower()

    for base in search_dirs:
        if not base.exists():
            continue
        for candidate in base.rglob("*"):
            if candidate.is_file() and candidate.name.lower() == remote_name_lower:
                matches.append(candidate)

    if not matches:
        raise FileNotFoundError(
            f"No local script named '{remote_name}' was found in: {', '.join(str(p) for p in search_dirs)}"
        )

    if len(matches) > 1:
        prefer = [p for p in matches if p.parent.name.lower() == "scripts"]
        if len(prefer) == 1:
            return prefer[0]
        ordered = sorted(matches, key=lambda p: (len(p.parts), str(p).lower()))
        return ordered[0]

    return matches[0]


def tcp_check(host: str, port: int, timeout_seconds: float) -> Tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout_seconds):
            return True, "ok"
    except Exception as exc:
        return False, str(exc)


def detect_local_ip_for_target(target_ip: str) -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((target_ip, 1))
        local_ip = probe.getsockname()[0]
        if local_ip and not local_ip.startswith("127."):
            return local_ip
    except Exception:
        pass
    finally:
        probe.close()

    try:
        fallback = socket.gethostbyname(socket.gethostname())
        if fallback:
            return fallback
    except Exception:
        pass

    return "127.0.0.1"


def build_session(
    host: str, user: str, password: str, port: int, https: bool, strict_cert: bool
):
    import winrm

    endpoint = f"{'https' if https else 'http'}://{host}:{port}/wsman"
    return winrm.Session(
        target=endpoint,
        auth=(user, password),
        transport="ntlm",
        server_cert_validation="validate" if strict_cert else "ignore",
        read_timeout_sec=60,
        operation_timeout_sec=40,
    )


def run_ps(session, script: str) -> Tuple[int, str, str]:
    try:
        response = session.run_ps(script)
    except Exception as exc:
        return -1, "", str(exc)
    stdout = response.std_out.decode("utf-8", errors="replace").strip()
    stderr = response.std_err.decode("utf-8", errors="replace").strip()
    return response.status_code, stdout, stderr


def is_retryable_winrm_error(message: str) -> bool:
    text = (message or "").lower()
    markers = [
        "connection aborted",
        "connectionreseterror",
        "forcibly closed by the remote host",
        "winerror 10054",
        "read timed out",
        "timed out",
    ]
    return any(marker in text for marker in markers)


def with_session_retry(
    target: Target,
    args: argparse.Namespace,
    phase_name: str,
    operation,
) -> Tuple[bool, str, Optional[str]]:
    attempts = max(1, args.winrm_retries + 1)
    last_message = ""
    for attempt in range(1, attempts + 1):
        try:
            session = build_session(
                host=target.ip,
                user=target.user,
                password=target.password,
                port=args.port,
                https=args.https,
                strict_cert=args.strict_cert,
            )
        except Exception as exc:
            last_message = f"WinRM session creation failed: {exc}"
            if attempt == attempts:
                return False, last_message, None
            time.sleep(1)
            continue

        ok, message, value = operation(session)
        if ok:
            return True, message, value

        last_message = message
        if attempt == attempts or not is_retryable_winrm_error(message):
            return False, last_message, None

        print(
            f"    [WARN] {phase_name} transient WinRM error on attempt {attempt}/{attempts}: {message}"
        )
        time.sleep(1)

    return False, last_message or f"{phase_name} failed", None


def ensure_remote_ready(
    session,
    script_location: str,
    remote_workdir: str,
    allow_unencrypted: bool,
    allow_basic_auth: bool,
    bootstrap_mode: str,
) -> Tuple[bool, str]:
    escaped_script_location = script_location.replace("'", "''")
    escaped_remote_workdir = remote_workdir.replace("'", "''")

    bootstrap_lines = ["$ErrorActionPreference = 'Stop'"]
    if bootstrap_mode == "full":
        bootstrap_lines.extend(
            [
                "Enable-PSRemoting -Force",
                "Set-Service -Name WinRM -StartupType Automatic",
                "Start-Service -Name WinRM",
                "$rules = Get-NetFirewallRule -DisplayGroup 'Windows Remote Management' -ErrorAction SilentlyContinue",
                "if ($rules) {",
                "  $rules | Enable-NetFirewallRule | Out-Null",
                "}",
            ]
        )

    bootstrap_lines.extend(
        [
            f"if ({'$true' if allow_unencrypted else '$false'}) {{",
            "  Set-Item -Path WSMan:\\\\localhost\\\\Service\\\\AllowUnencrypted -Value $true -Force",
            "}",
            f"if ({'$true' if allow_basic_auth else '$false'}) {{",
            "  Set-Item -Path WSMan:\\\\localhost\\\\Service\\\\Auth\\\\Basic -Value $true -Force",
            "}",
            f"$scriptPath = '{escaped_script_location}'",
            f"$workDir = '{escaped_remote_workdir}'",
            "$scriptDir = Split-Path -Parent $scriptPath",
            "if ($scriptDir -and !(Test-Path -LiteralPath $scriptDir)) {",
            "  New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null",
            "}",
            "if (!(Test-Path -LiteralPath $workDir)) {",
            "  New-Item -ItemType Directory -Path $workDir -Force | Out-Null",
            "}",
            "'OK'",
        ]
    )
    ps_script = "\n".join(bootstrap_lines)

    code, stdout, stderr = run_ps(session, ps_script)
    if code != 0:
        detail = stderr or stdout or f"exit code {code}"
        return False, detail
    return True, stdout or "OK"


def upload_script_chunked(
    session,
    local_script: Path,
    remote_script_path: str,
    chunk_chars: int,
) -> Tuple[bool, str, Optional[str]]:
    content = local_script.read_bytes()
    local_sha = hashlib.sha256(content).hexdigest().lower()
    b64 = base64.b64encode(content).decode("ascii")
    b64_path = f"{remote_script_path}.b64"

    init_ps = f"""
$ErrorActionPreference = 'Stop'
$target = '{remote_script_path.replace("'", "''")}'
$tmp = '{b64_path.replace("'", "''")}'
$targetDir = Split-Path -Parent $target
if ($targetDir -and !(Test-Path -LiteralPath $targetDir)) {{
  New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
}}
Set-Content -LiteralPath $tmp -Value '' -NoNewline -Encoding Ascii
'OK'
"""

    code, stdout, stderr = run_ps(session, init_ps)
    if code != 0:
        return False, stderr or stdout or f"chunk init failed (exit={code})", None

    for i in range(0, len(b64), chunk_chars):
        chunk = b64[i : i + chunk_chars].replace("'", "''")
        append_ps = f"""
$ErrorActionPreference = 'Stop'
$tmp = '{b64_path.replace("'", "''")}'
Add-Content -LiteralPath $tmp -Value '{chunk}' -NoNewline -Encoding Ascii
'OK'
"""
        code, stdout, stderr = run_ps(session, append_ps)
        if code != 0:
            return False, stderr or stdout or f"chunk append failed (exit={code})", None

    finalize_ps = f"""
$ErrorActionPreference = 'Stop'
$target = '{remote_script_path.replace("'", "''")}'
$tmp = '{b64_path.replace("'", "''")}'
$b64 = Get-Content -LiteralPath $tmp -Raw -Encoding Ascii
$bytes = [Convert]::FromBase64String($b64)
[IO.File]::WriteAllBytes($target, $bytes)
Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
$hash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
$hash
"""

    code, stdout, stderr = run_ps(session, finalize_ps)
    if code != 0:
        return False, stderr or stdout or f"chunk finalize failed (exit={code})", None

    remote_sha = stdout.splitlines()[-1].strip().lower() if stdout else ""
    if remote_sha != local_sha:
        return (
            False,
            f"hash mismatch (local={local_sha}, remote={remote_sha or 'empty'})",
            remote_sha or None,
        )

    return True, "uploaded", remote_sha


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:
        return


class TemporaryHTTPServer:
    def __init__(self, directory: Path, bind_host: str, port: int) -> None:
        self.directory = directory
        self.bind_host = bind_host
        self.port = port
        self.server: Optional[ThreadingHTTPServer] = None
        self.thread: Optional[threading.Thread] = None

    def __enter__(self) -> "TemporaryHTTPServer":
        handler = partial(QuietHandler, directory=str(self.directory))
        self.server = ThreadingHTTPServer((self.bind_host, self.port), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        if self.thread is not None:
            self.thread.join(timeout=2)

    @property
    def actual_port(self) -> int:
        if self.server is None:
            return self.port
        return int(self.server.server_port)


def upload_script_http(
    session,
    local_script: Path,
    remote_script_path: str,
    download_host: str,
    download_port: int,
) -> Tuple[bool, str, Optional[str]]:
    local_sha = hashlib.sha256(local_script.read_bytes()).hexdigest().lower()
    file_name = quote(local_script.name)
    source_url = f"http://{download_host}:{download_port}/{file_name}"

    ps_script = f"""
$ErrorActionPreference = 'Stop'
$target = '{remote_script_path.replace("'", "''")}'
$targetDir = Split-Path -Parent $target
if ($targetDir -and !(Test-Path -LiteralPath $targetDir)) {{
  New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
}}
Invoke-WebRequest -UseBasicParsing -Uri '{source_url}' -OutFile $target
$hash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
$hash
"""

    code, stdout, stderr = run_ps(session, ps_script)
    if code != 0:
        return False, stderr or stdout or f"http download failed (exit={code})", None

    remote_sha = stdout.splitlines()[-1].strip().lower() if stdout else ""
    if remote_sha != local_sha:
        return (
            False,
            f"hash mismatch (local={local_sha}, remote={remote_sha or 'empty'})",
            remote_sha or None,
        )

    return True, "downloaded", remote_sha


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bootstrap WinRM settings and deploy target PowerShell scripts from avs.json."
    )
    parser.add_argument(
        "--config", default="avs.json", help="Path to target config JSON"
    )
    parser.add_argument("--port", type=int, default=5985, help="WinRM port")
    parser.add_argument("--https", action="store_true", help="Use HTTPS WinRM endpoint")
    parser.add_argument(
        "--strict-cert",
        action="store_true",
        help="Validate TLS certificate when using --https",
    )
    parser.add_argument(
        "--search-dir",
        action="append",
        default=[],
        help="Additional local directories to search for script filenames",
    )
    parser.add_argument(
        "--allow-unencrypted",
        action="store_true",
        help="Set WSMan Service AllowUnencrypted=true on targets",
    )
    parser.add_argument(
        "--allow-basic-auth",
        action="store_true",
        help="Set WSMan Service Auth.Basic=true on targets",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=4.0,
        help="TCP pre-check timeout in seconds",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Resolve targets and local script mapping without changing remote hosts",
    )
    parser.add_argument(
        "--transfer",
        choices=["auto", "http", "chunked"],
        default="chunked",
        help="Script transfer mode (default: chunked)",
    )
    parser.add_argument(
        "--serve-bind",
        default="0.0.0.0",
        help="Local bind address for temporary HTTP server (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--serve-port",
        type=int,
        default=8765,
        help="Local port for temporary HTTP server (default: 8765)",
    )
    parser.add_argument(
        "--download-host",
        default="",
        help="Host/IP targets should use to download scripts (default: auto-detect per target)",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=1500,
        help="Base64 chunk size used by chunked transfer mode",
    )
    parser.add_argument(
        "--bootstrap-mode",
        choices=["minimal", "full"],
        default="minimal",
        help="WinRM bootstrap mode (default: minimal)",
    )
    parser.add_argument(
        "--winrm-retries",
        type=int,
        default=2,
        help="Retry count for transient WinRM failures (default: 2)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        import winrm  # noqa: F401
    except Exception:
        print("[fatal] pywinrm is not installed. Install with: pip install pywinrm")
        return 1

    config_path = Path(args.config)
    workspace = Path.cwd()

    try:
        targets = load_targets(config_path)
    except Exception as exc:
        print(f"[fatal] {exc}")
        return 1

    search_dirs: List[Path] = [workspace / "scripts", workspace]
    for item in args.search_dir:
        search_dirs.append(Path(item))

    print(f"Loaded {len(targets)} target(s) from {config_path}")
    print(f"Local search dirs: {', '.join(str(p) for p in search_dirs)}")
    print("=" * 96)

    failures = 0

    for idx, target in enumerate(targets, start=1):
        print(f"[{idx}] {target.name} ({target.ip})")
        print(f"    ScriptLocation: {target.script_location}")
        print(f"    RemoteWorkDir: {target.remote_workdir}")

        try:
            local_script = find_local_script(target.script_location, search_dirs)
            print(f"    Local script: {local_script}")
        except Exception as exc:
            print(f"    [FAIL] {exc}")
            failures += 1
            print("-" * 96)
            continue

        ok, msg = tcp_check(target.ip, args.port, args.timeout)
        print(f"    TCP {target.ip}:{args.port}: {'OK' if ok else 'FAIL'} ({msg})")
        if not ok:
            failures += 1
            print("-" * 96)
            continue

        if args.dry_run:
            print("    [DRY-RUN] Skipping remote changes")
            print("-" * 96)
            continue

        ready_ok, ready_msg, _ = with_session_retry(
            target=target,
            args=args,
            phase_name="WinRM bootstrap",
            operation=lambda session: (lambda ok, msg: (ok, msg, None))(
                *ensure_remote_ready(
                    session=session,
                    script_location=target.script_location,
                    remote_workdir=target.remote_workdir,
                    allow_unencrypted=args.allow_unencrypted,
                    allow_basic_auth=args.allow_basic_auth,
                    bootstrap_mode=args.bootstrap_mode,
                )
            ),
        )
        if not ready_ok:
            print(f"    [FAIL] WinRM bootstrap failed: {ready_msg}")
            failures += 1
            print("-" * 96)
            continue

        print("    [OK] WinRM bootstrap complete")

        transferred = False

        if args.transfer in ("auto", "http"):
            download_host = args.download_host.strip() or detect_local_ip_for_target(
                target.ip
            )
            try:
                with TemporaryHTTPServer(
                    local_script.parent, args.serve_bind, args.serve_port
                ) as httpd:
                    print(
                        f"    HTTP source: http://{download_host}:{httpd.actual_port}/{local_script.name}"
                    )
                    up_ok, up_msg, remote_sha = with_session_retry(
                        target=target,
                        args=args,
                        phase_name="HTTP transfer",
                        operation=lambda session: upload_script_http(
                            session=session,
                            local_script=local_script,
                            remote_script_path=target.script_location,
                            download_host=download_host,
                            download_port=httpd.actual_port,
                        ),
                    )
                if up_ok:
                    print(f"    [OK] Script downloaded over HTTP (sha256={remote_sha})")
                    transferred = True
                else:
                    print(f"    [WARN] HTTP transfer failed: {up_msg}")
                    if args.transfer == "http":
                        failures += 1
            except Exception as exc:
                print(f"    [WARN] HTTP transfer exception: {exc}")
                if args.transfer == "http":
                    failures += 1

        if not transferred and args.transfer in ("auto", "chunked"):
            up_ok, up_msg, remote_sha = with_session_retry(
                target=target,
                args=args,
                phase_name="chunked transfer",
                operation=lambda session: upload_script_chunked(
                    session=session,
                    local_script=local_script,
                    remote_script_path=target.script_location,
                    chunk_chars=max(200, args.chunk_size),
                ),
            )
            if up_ok:
                print(f"    [OK] Script uploaded in chunks (sha256={remote_sha})")
                transferred = True
            else:
                print(f"    [FAIL] Chunked transfer failed: {up_msg}")
                failures += 1

        if transferred:
            print("-" * 96)
            continue

        if args.transfer == "auto":
            failures += 1

        print("-" * 96)

    if failures:
        print(f"Completed with {failures} failure(s).")
        return 1

    print("All targets bootstrapped successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
