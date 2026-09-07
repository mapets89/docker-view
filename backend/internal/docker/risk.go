package docker

import "strings"

type Mount struct {
	Type        string `json:"type"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Mode        string `json:"mode"`
}
type RiskInput struct {
	Privileged                    bool
	PidMode, NetworkMode, IpcMode string
	Mounts                        []Mount
	Devices                       []string
	System                        bool
}
type RiskAssessment struct {
	Level    string   `json:"level"`
	Findings []string `json:"findings"`
	Score    int      `json:"score"`
}

func AssessRisk(in RiskInput) RiskAssessment {
	r := RiskAssessment{Level: "Low"}
	add := func(score int, msg string) { r.Score += score; r.Findings = append(r.Findings, msg) }
	if in.Privileged {
		add(100, "Privileged container")
	}
	if in.System {
		add(80, "DockerView system container")
	}
	if in.PidMode == "host" {
		add(60, "Host PID namespace")
	}
	if in.NetworkMode == "host" {
		add(35, "Host network namespace")
	}
	if in.IpcMode == "host" {
		add(35, "Host IPC namespace")
	}
	for _, m := range in.Mounts {
		s := strings.ToLower(m.Source)
		d := strings.ToLower(m.Destination)
		if strings.Contains(s, "docker.sock") || strings.Contains(d, "docker.sock") {
			add(100, "Docker socket mounted")
		} else if m.Type == "bind" && (s == "/" || strings.HasPrefix(s, "/etc") || strings.HasPrefix(s, "/proc") || strings.HasPrefix(s, "/sys") || strings.HasPrefix(s, "/var/run")) {
			add(70, "Sensitive host filesystem mounted: "+m.Source)
		}
	}
	if len(in.Devices) > 0 {
		add(60, "Host devices exposed")
	}
	switch {
	case r.Score >= 100:
		r.Level = "Critical"
	case r.Score >= 60:
		r.Level = "High"
	case r.Score >= 25:
		r.Level = "Medium"
	}
	if len(r.Findings) == 0 {
		r.Findings = []string{"No elevated runtime configuration detected"}
	}
	return r
}
