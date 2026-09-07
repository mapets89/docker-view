package rbac

import "github.com/dockerview/dockerview/backend/internal/database"

func Allowed(user database.User, permission string) bool {
	for _, p := range user.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}
