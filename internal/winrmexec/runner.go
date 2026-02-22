package winrmexec

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/masterzen/winrm"
)

type Config struct {
	User     string
	Pass     string
	Port     int
	UseHTTPS bool
	Insecure bool
}

type Runner struct {
	cfg Config
}

type ScanRequest struct {
	TargetIP      string
	AVName        string
	ScriptPath    string
	RemoteWorkDir string
	ScanID        string
	SHA256        string
	Bytes         []byte
	Wait          time.Duration
}

type ScanResult struct {
	AV         string    `json:"av"`
	TargetIP   string    `json:"target_ip"`
	RemoteDir  string    `json:"remote_dir"`
	RemotePath string    `json:"remote_path"`
	ScriptOut  string    `json:"script_out"`
	ResultOut  string    `json:"result_out"`
	Deleted    bool      `json:"deleted"`
	FileExists    bool      `json:"file_exists"`
	EventDetected bool      `json:"event_detected"`
	CheckedAt  time.Time `json:"checked_at"`
	Stdout     string    `json:"stdout"`
	Stderr     string    `json:"stderr"`
	ExitCode   int       `json:"exit_code"`
	ScriptPath string    `json:"script_path"`
}

func NewRunner(cfg Config) *Runner {
	return &Runner{cfg: cfg}
}

func (r *Runner) RunScan(ctx context.Context, req ScanRequest) (ScanResult, error) {
	endpoint := winrm.NewEndpoint(req.TargetIP, r.cfg.Port, r.cfg.UseHTTPS, r.cfg.Insecure, nil, nil, nil, 30*time.Second)
	client, err := winrm.NewClient(endpoint, r.cfg.User, r.cfg.Pass)
	if err != nil {
		return ScanResult{}, err
	}

	remoteDir := req.RemoteWorkDir
	if remoteDir == "" {
		remoteDir = "C:\\Monarch\\work"
	}
	if req.ScanID == "" {
		req.ScanID = "scan"
	}
	if req.SHA256 == "" {
		return ScanResult{}, fmt.Errorf("missing SHA256")
	}
	remoteDir = remoteDir + "\\" + req.ScanID
	remotePath := remoteDir + "\\" + req.SHA256
	scriptOut := remoteDir + "\\script.json"
	resultOut := remoteDir + "\\monarch.json"

	// IMPORTANT: Do not embed file bytes (or base64 of them) in the PowerShell script.
	// Defender/AMSI can block the entire script when scanning known test strings like EICAR.
	// We send raw bytes via STDIN and the script writes them to disk.
	ps := strings.Join([]string{
		"$ErrorActionPreference='Stop'",
		fmt.Sprintf("New-Item -ItemType Directory -Force -Path '%s' | Out-Null", escapePS(remoteDir)),
		// Record time before writing file so event log queries don't catch stale events.
		"$scanStart = (Get-Date)",
		// Read raw bytes from STDIN.
		"$stdinStream = [Console]::OpenStandardInput()",
		"$ms = New-Object System.IO.MemoryStream",
		"$buf = New-Object byte[] 65536",
		"while (($n = $stdinStream.Read($buf, 0, $buf.Length)) -gt 0) { $ms.Write($buf, 0, $n) }",
		fmt.Sprintf("[IO.File]::WriteAllBytes('%s', $ms.ToArray())", escapePS(remotePath)),
		"$stderr='' ; $exit=0",
		"try {",
		fmt.Sprintf("  if (Test-Path -LiteralPath '%s') {", escapePS(req.ScriptPath)),
		fmt.Sprintf("    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '%s' -InputFile '%s' -OutputFile '%s' | Out-Null", escapePS(req.ScriptPath), escapePS(remotePath), escapePS(scriptOut)),
		"  }",
		"} catch { $stderr = $_.ToString(); $exit = 1 }",
		// Poll: exit as soon as file is gone OR Defender event log records a detection (1116=detected, 1117=action taken).
		// Checking the event log means we react before Defender finishes deleting/quarantining the file.
		fmt.Sprintf("$deadline = (Get-Date).AddSeconds(%d)", int(req.Wait.Seconds())),
		fmt.Sprintf(
			"while ((Get-Date) -lt $deadline) { if (-not (Test-Path -LiteralPath '%s')) { break }; $ev=$null; try { $ev = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=@(1116,1117); StartTime=$scanStart} -ErrorAction Stop | Where-Object { $_.Message -match '%s' } | Select-Object -First 1 } catch {}; if ($ev) { break }; Start-Sleep -Milliseconds 200 }",
			escapePS(remotePath), req.SHA256,
		),
		fmt.Sprintf("$exists = Test-Path -LiteralPath '%s'", escapePS(remotePath)),
		// Final event check for the result JSON (covers the case where the loop exited via event, not file deletion).
		fmt.Sprintf("$evDet=$false; try { $evDet=[bool]((Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=@(1116,1117); StartTime=$scanStart} -ErrorAction Stop | Where-Object { $_.Message -match '%s' } | Select-Object -First 1) -ne $null) } catch {}", req.SHA256),
		"$res = [ordered]@{ file_exists=$exists; deleted=(-not $exists -or $evDet); event_detected=$evDet; script_out_path='' }",
		fmt.Sprintf("if (Test-Path -LiteralPath '%s') { $res.script_out_path='%s' }", escapePS(scriptOut), escapePS(scriptOut)),
		fmt.Sprintf("$res | ConvertTo-Json -Compress | Set-Content -LiteralPath '%s' -Encoding UTF8", escapePS(resultOut)),
		fmt.Sprintf("Get-Content -LiteralPath '%s' -Raw", escapePS(resultOut)),
		"exit $exit",
	}, "; ")

	encoded := encodePS(ps)
	stdout, stderr, exitCode, err := runPS(ctx, client, "powershell -NoProfile -NonInteractive -EncodedCommand "+encoded, bytes.NewReader(req.Bytes))
	result := ScanResult{
		AV:         req.AVName,
		TargetIP:   req.TargetIP,
		RemoteDir:  remoteDir,
		RemotePath: remotePath,
		ScriptOut:  scriptOut,
		ResultOut:  resultOut,
		CheckedAt:  time.Now().UTC(),
		Stdout:     stdout,
		Stderr:     stderr,
		ExitCode:   exitCode,
		ScriptPath: req.ScriptPath,
	}
	if err != nil {
		return result, err
	}
	if exitCode != 0 {
		return result, fmt.Errorf("remote powershell failed (exit=%d)", exitCode)
	}

	// stdout should be JSON from remoteOut.
	var remote struct {
		Deleted       bool `json:"deleted"`
		FileExists    bool `json:"file_exists"`
		EventDetected bool `json:"event_detected"`
	}
	if uerr := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &remote); uerr == nil {
		result.Deleted = remote.Deleted
		result.FileExists = remote.FileExists
		result.EventDetected = remote.EventDetected
	}
	return result, nil
}

func runPS(ctx context.Context, c *winrm.Client, command string, stdin io.Reader) (stdout string, stderr string, exitCode int, err error) {
	// masterzen/winrm doesn't take context; enforce a coarse timeout by closing over ctx.
	ch := make(chan struct{})
	var so, se strings.Builder
	go func() {
		exitCode, err = c.RunWithInput(command, &so, &se, stdin)
		stdout = so.String()
		stderr = se.String()
		close(ch)
	}()

	select {
	case <-ctx.Done():
		return "", "timeout", -1, ctx.Err()
	case <-ch:
		return stdout, stderr, exitCode, err
	}
}

func escapePS(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

func encodePS(script string) string {
	// PowerShell -EncodedCommand expects base64-encoded UTF-16LE.
	utf16le := utf16leBytes(script)
	return base64.StdEncoding.EncodeToString(utf16le)
}

func utf16leBytes(s string) []byte {
	// Manual UTF-16LE encoding (no BOM).
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		if r > 0xFFFF {
			// Replace out-of-BMP chars with '?'
			r = '?'
		}
		out = append(out, byte(r&0xFF), byte((r>>8)&0xFF))
	}
	return out
}
