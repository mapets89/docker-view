package rbac

import (
	"github.com/dockerview/dockerview/backend/internal/database"
	"testing"
)

func TestPermissionBasedNotRoleName(t *testing.T) {
	u := database.User{Roles: []string{"Admin"}, Permissions: []string{"container.read"}}
	if Allowed(u, "container.exec") {
		t.Fatal("role name bypassed permission catalog")
	}
	if !Allowed(u, "container.read") {
		t.Fatal("granted permission denied")
	}
}
