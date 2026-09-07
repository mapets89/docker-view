package auth

import (
	"context"
	"github.com/dockerview/dockerview/backend/internal/database"
)

type Provider interface {
	Authenticate(context.Context, string, string) (database.User, bool, error)
	Name() string
}
type LocalProvider struct{ Store *database.Store }

func (l LocalProvider) Authenticate(ctx context.Context, u, p string) (database.User, bool, error) {
	return l.Store.Authenticate(ctx, u, p)
}
func (l LocalProvider) Name() string { return "local" }
