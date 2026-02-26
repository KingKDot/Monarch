package winrmexec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/masterzen/winrm"
)

type Config struct {
	Port     int
	UseHTTPS bool
	Insecure bool
}

type Runner struct {
	cfg Config
}

type ScanRequest struct {
	TargetIP      string
	User          string
	Pass          string
	Port          int
	UseHTTPS      bool
	Insecure      bool
	AVName        string
	ScriptPath    string
	RemoteWorkDir string
	ScanID        string
	SHA256        string
	OriginalName  string
	Bytes         []byte
	Wait          time.Duration
}

type ScanResult struct {
	AV            string          `json:"av"`
	TargetIP      string          `json:"target_ip"`
	RemoteDir     string          `json:"remote_dir"`
	RemotePath    string          `json:"remote_path"`
	ScriptOut     string          `json:"script_out"`
	ResultOut     string          `json:"result_out"`
	Deleted       bool            `json:"deleted"`
	FileExists    bool            `json:"file_exists"`
	EventDetected bool            `json:"event_detected"`
	EventMessage  string          `json:"event_message"`
	ThreatName    string          `json:"threat_name"`
	ScriptJSON    json.RawMessage `json:"script_json,omitempty"`
	CheckedAt     time.Time       `json:"checked_at"`
	Stdout        string          `json:"stdout"`
	Stderr        string          `json:"stderr"`
	ExitCode      int             `json:"exit_code"`
	ScriptPath    string          `json:"script_path"`
}

func NewRunner(cfg Config) *Runner {
	return &Runner{cfg: cfg}
}

func (r *Runner) RunScan(ctx context.Context, req ScanRequest) (ScanResult, error) {
	result := ScanResult{
		AV:         req.AVName,
		TargetIP:   req.TargetIP,
		CheckedAt:  time.Now().UTC(),
		ScriptPath: req.ScriptPath,
	}
	if req.User == "" || req.Pass == "" {
		err := fmt.Errorf("missing WinRM credentials for target %s", req.TargetIP)
		result.Stderr = err.Error()
		result.ExitCode = -1
		return result, err
	}
	port := req.Port
	if port == 0 {
		port = r.cfg.Port
	}
	if port == 0 {
		port = 5985
	}
	useHTTPS := req.UseHTTPS
	insecure := req.Insecure
	endpoint := winrm.NewEndpoint(req.TargetIP, port, useHTTPS, insecure, nil, nil, nil, 30*time.Second)
	client, err := winrm.NewClient(endpoint, req.User, req.Pass)
	if err != nil {
		result.Stderr = err.Error()
		result.ExitCode = -1
		return result, err
	}

	remoteDir := req.RemoteWorkDir
	if remoteDir == "" {
		remoteDir = "C:\\Monarch\\work"
	}
	if req.ScanID == "" {
		req.ScanID = "scan"
	}
	if req.SHA256 == "" {
		err := fmt.Errorf("missing SHA256")
		result.Stderr = err.Error()
		result.ExitCode = -1
		return result, err
	}
	remoteDir = remoteDir + "\\" + req.ScanID
	remoteName := req.SHA256 + safeFileExtension(req.OriginalName)
	remotePath := remoteDir + "\\" + remoteName
	scriptOut := remoteDir + "\\script.json"
	result.RemoteDir = remoteDir
	result.RemotePath = remotePath
	result.ScriptOut = scriptOut
	result.ResultOut = scriptOut
	defer cleanupRemoteDir(ctx, client, remoteDir)
	command := fmt.Sprintf("powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File %s -InputFile %s -OutputFile %s -SHA256 %s -WaitSeconds %d -FromStdin",
		quoteCmdArg(req.ScriptPath), quoteCmdArg(remotePath), quoteCmdArg(scriptOut), quoteCmdArg(req.SHA256), int(req.Wait.Seconds()))
	stdin := bytes.NewReader(req.Bytes)
	stdout, stderr, exitCode, err := runPS(ctx, client, command, stdin)
	result.Stdout = stdout
	result.Stderr = stderr
	result.ExitCode = exitCode
	if err != nil {
		return result, err
	}
	if exitCode != 0 {
		return result, fmt.Errorf("remote powershell failed (exit=%d)", exitCode)
	}

	// stdout should be JSON from remoteOut.
	var remote struct {
		Deleted       bool            `json:"deleted"`
		FileExists    bool            `json:"file_exists"`
		EventDetected bool            `json:"event_detected"`
		EventMessage  string          `json:"event_message"`
		ThreatName    string          `json:"threat_name"`
		ScriptJSON    json.RawMessage `json:"script_json"`
	}
	if uerr := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &remote); uerr == nil {
		result.Deleted = remote.Deleted
		result.FileExists = remote.FileExists
		result.EventDetected = remote.EventDetected
		result.EventMessage = remote.EventMessage
		result.ThreatName = remote.ThreatName
		result.ScriptJSON = remote.ScriptJSON
	}
	return result, nil
}

func cleanupRemoteDir(ctx context.Context, client *winrm.Client, remoteDir string) {
	if remoteDir == "" {
		return
	}
	command := fmt.Sprintf("powershell -NoProfile -NonInteractive -Command \"Remove-Item -Recurse -Force -ErrorAction SilentlyContinue -LiteralPath '%s'\"",
		escapePSSingleQuoted(remoteDir))
	if _, stderr, exitCode, err := runPS(ctx, client, command, nil); err != nil || exitCode != 0 {
		log.Printf("winrm cleanup failed for %s (exit=%d, err=%v, stderr=%s)", remoteDir, exitCode, err, stderr)
	}
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

func quoteCmdArg(s string) string {
	// Double-quote args so cmd passes clean paths to PowerShell -File.
	return "\"" + strings.ReplaceAll(s, "\"", "\\\"") + "\""
}

func escapePSSingleQuoted(s string) string {
	// Escape for single-quoted PowerShell string literals.
	return strings.ReplaceAll(s, "'", "''")
}

func safeFileExtension(name string) string {
	ext := strings.TrimSpace(filepath.Ext(strings.TrimSpace(name)))
	if ext == "" || ext == "." {
		return ""
	}
	if len(ext) > 16 {
		return ""
	}
	for _, ch := range ext[1:] {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' {
			continue
		}
		return ""
	}
	return ext
}
