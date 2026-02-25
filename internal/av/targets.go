package av

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type Target struct {
	Antivirus      string `json:"Antivirus"`
	IP             string `json:"IP"`
	ScriptLocation string `json:"ScriptLocation"`
	RemoteWorkDir  string `json:"RemoteWorkDir"`
	WinRMUser      string `json:"WinRMUser"`
	WinRMPass      string `json:"WinRMPass"`
}

func LoadTargets(path string) ([]Target, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read AV config: %w", err)
	}
	var targets []Target
	if err := json.Unmarshal(b, &targets); err != nil {
		return nil, fmt.Errorf("parse AV config: %w", err)
	}
	for i := range targets {
		if targets[i].RemoteWorkDir == "" {
			targets[i].RemoteWorkDir = "C:\\Monarch\\work"
		}
		if strings.TrimSpace(targets[i].WinRMUser) == "" || strings.TrimSpace(targets[i].WinRMPass) == "" {
			return nil, fmt.Errorf("target %q (%s) is missing WinRMUser/WinRMPass", targets[i].Antivirus, targets[i].IP)
		}
	}
	return targets, nil
}
