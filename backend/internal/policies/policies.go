package policies

import (
	"path"
	"strings"

	"github.com/dockerview/dockerview/backend/internal/database"
	"github.com/dockerview/dockerview/backend/internal/rbac"
)

type Resource struct {
	Name   string
	Labels map[string]string
	System bool
}
type Decision struct {
	Allowed bool
	Reason  string
}

// Evaluate applies immutable system policy, then explicit deny, explicit allow,
// role permission, and finally default deny. Patterns use path.Match semantics
// with '/' treated as a normal character by matching each resource name only.
func Evaluate(user database.User, action string, resource Resource, all []database.Policy) Decision {
	if resource.System && (action == "container.exec" || action == "container.restart") {
		return Decision{false, "system containers are immutable"}
	}
	hasPermission := rbac.Allowed(user, action)
	explicitAllow := false
	roles := map[string]bool{}
	for _, r := range user.Roles {
		roles[r] = true
	}
	for _, r := range user.RoleIDs {
		roles[r] = true
	}
	for _, p := range all {
		if !p.Enabled {
			continue
		}
		for _, rule := range p.Rules {
			if rule.Action != action || rule.SubjectRoleID != "" && !roles[rule.SubjectRoleID] {
				continue
			}
			if !matches(rule, resource) {
				continue
			}
			if rule.Effect == "deny" {
				return Decision{false, "explicit policy deny: " + p.Name}
			}
			if rule.Effect == "allow" {
				explicitAllow = true
			}
		}
	}
	if !hasPermission {
		return Decision{false, "missing permission"}
	}
	if explicitAllow {
		return Decision{true, "explicit policy allow"}
	}
	return Decision{true, "role permission"}
}
func matches(rule database.PolicyRule, r Resource) bool {
	switch rule.MatchType {
	case "label":
		return r.Labels[rule.MatchKey] == rule.MatchValue
	case "name":
		if strings.Contains(rule.MatchValue, "/") {
			return false
		}
		ok, err := path.Match(rule.MatchValue, r.Name)
		return err == nil && ok
	}
	return false
}
