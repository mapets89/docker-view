package docker

import "testing"

func TestRisk(t *testing.T) {
	if got := AssessRisk(RiskInput{Mounts: []Mount{{Type: "bind", Source: "/var/run/docker.sock", Destination: "/var/run/docker.sock"}}}); got.Level != "Critical" {
		t.Fatalf("got %s", got.Level)
	}
	if AssessRisk(RiskInput{}).Level != "Low" {
		t.Fatal("safe configuration not low")
	}
}
