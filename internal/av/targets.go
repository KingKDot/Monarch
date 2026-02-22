package av

import (
	"encoding/json"
	"fmt"
	"os"
)

type Target struct {
	Antivirus      string `json:"Antivirus"`
	IP             string `json:"IP"`
	ScriptLocation string `json:"ScriptLocation"`
	RemoteWorkDir  string `json:"RemoteWorkDir"`
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
	}
	return targets, nil
}
