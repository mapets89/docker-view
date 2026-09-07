package policies

import (
	"github.com/dockerview/dockerview/backend/internal/database"
	"testing"
)

func TestPrecedence(t *testing.T) {
	u := database.User{Roles: []string{"Developer"}, Permissions: []string{"container.exec"}}
	ps := []database.Policy{{Name: "scope", Enabled: true, Rules: []database.PolicyRule{{Effect: "allow", Action: "container.exec", MatchType: "name", MatchValue: "api-*"}, {Effect: "deny", Action: "container.exec", MatchType: "name", MatchValue: "api-prod"}}}}
	if Evaluate(u, "container.exec", Resource{Name: "api-prod"}, ps).Allowed {
		t.Fatal("deny must override allow")
	}
	if !Evaluate(u, "container.exec", Resource{Name: "api-dev"}, ps).Allowed {
		t.Fatal("allow denied")
	}
	if Evaluate(u, "container.exec", Resource{Name: "dockerview", System: true}, ps).Allowed {
		t.Fatal("system policy bypassed")
	}
}
func TestNoPermissionCannotBeElevatedByPolicy(t *testing.T) {
	u := database.User{Roles: []string{"Viewer"}}
	ps := []database.Policy{{Name: "bad", Enabled: true, Rules: []database.PolicyRule{{Effect: "allow", Action: "container.exec", MatchType: "name", MatchValue: "*"}}}}
	if Evaluate(u, "container.exec", Resource{Name: "api"}, ps).Allowed {
		t.Fatal("policy elevated missing role permission")
	}
}
