package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dockerview/dockerview/backend/internal/security"
	_ "modernc.org/sqlite"
)

type Store struct{ DB *sql.DB }

var dummyPasswordHash = func() string { h, _ := security.HashPassword("DockerView timing equalization value"); return h }()

type User struct {
	ID, Username                string
	Enabled                     bool
	CreatedAt                   string
	LastLoginAt, LastActivityAt *string
	Roles                       []string
	RoleIDs                     []string
	Permissions                 []string
}
type Role struct {
	ID, Name, Description string
	Builtin               bool
	Permissions           []string
}
type Permission struct {
	Name, Category, Description string
	Roles                       []string
}
type Policy struct {
	ID, Name, Description string
	Enabled               bool
	Rules                 []PolicyRule
}
type PolicyRule struct {
	ID, PolicyID, Effect, Action, SubjectRoleID, MatchType, MatchKey, MatchValue string
	Priority                                                                     int
}
type Session struct {
	User                           User
	TokenHash, CSRFHash, ExpiresAt string
}
type AuditEvent struct {
	ID, Timestamp, UserID, Username, SourceIP, Action, ResourceType, ResourceID, Result, Reason, SessionID string
	Metadata                                                                                               json.RawMessage
}
type TerminalSession struct{ ID, UserID, ContainerID, Shell, CreatedAt, LastActivityAt, ExpiresAt, Status string }

var PermissionCatalog = []Permission{
	{"container.read", "Containers", "List and view containers", nil}, {"container.inspect", "Containers", "View container configuration", nil},
	{"container.stats", "Containers", "View live resource statistics", nil}, {"container.logs", "Containers", "View and follow logs", nil},
	{"container.exec", "Terminal", "Open an interactive shell (privileged)", nil}, {"container.restart", "Containers", "Restart a container", nil},
	{"secret.view", "Secrets", "Reveal masked container secrets", nil}, {"user.read", "Users", "View users", nil}, {"user.manage", "Users", "Manage users", nil},
	{"role.read", "Roles", "View roles", nil}, {"role.manage", "Roles", "Manage roles", nil}, {"permission.read", "Roles", "View permission catalog", nil},
	{"policy.read", "Policies", "View policies", nil}, {"policy.manage", "Policies", "Manage policies", nil}, {"audit.read", "Audit", "Read audit events", nil},
	{"settings.read", "Settings", "View settings", nil}, {"settings.manage", "Settings", "Manage settings", nil},
}

const schema = `
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,username TEXT NOT NULL UNIQUE COLLATE NOCASE,password_hash TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,last_login_at TEXT,last_activity_at TEXT);
CREATE TABLE IF NOT EXISTS roles(id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE COLLATE NOCASE,description TEXT NOT NULL DEFAULT '',builtin INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS permissions(name TEXT PRIMARY KEY,category TEXT NOT NULL,description TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS role_permissions(role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,permission TEXT NOT NULL REFERENCES permissions(name) ON DELETE CASCADE,PRIMARY KEY(role_id,permission));
CREATE TABLE IF NOT EXISTS user_roles(user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,scope_type TEXT NOT NULL DEFAULT 'host',scope_id TEXT NOT NULL DEFAULT 'local',PRIMARY KEY(user_id,role_id,scope_type,scope_id));
CREATE TABLE IF NOT EXISTS sessions(id_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,csrf_hash TEXT NOT NULL,created_at TEXT NOT NULL,expires_at TEXT NOT NULL,last_activity_at TEXT NOT NULL,revoked_at TEXT,source_ip TEXT NOT NULL DEFAULT '',user_agent TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS policies(id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE,description TEXT NOT NULL DEFAULT '',enabled INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS policy_rules(id TEXT PRIMARY KEY,policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,effect TEXT NOT NULL CHECK(effect IN ('allow','deny')),action TEXT NOT NULL REFERENCES permissions(name),subject_role_id TEXT REFERENCES roles(id) ON DELETE CASCADE,match_type TEXT NOT NULL CHECK(match_type IN ('name','label')),match_key TEXT NOT NULL DEFAULT '',match_value TEXT NOT NULL,priority INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS audit_events(id TEXT PRIMARY KEY,timestamp TEXT NOT NULL,user_id TEXT,username TEXT NOT NULL DEFAULT '',source_ip TEXT NOT NULL DEFAULT '',action TEXT NOT NULL,resource_type TEXT NOT NULL DEFAULT '',resource_id TEXT NOT NULL DEFAULT '',result TEXT NOT NULL,reason TEXT NOT NULL DEFAULT '',session_id TEXT NOT NULL DEFAULT '',metadata TEXT NOT NULL DEFAULT '{}');
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp DESC);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS terminal_sessions(id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,container_id TEXT NOT NULL,shell TEXT NOT NULL,created_at TEXT NOT NULL,last_activity_at TEXT NOT NULL,expires_at TEXT NOT NULL,status TEXT NOT NULL,ended_at TEXT);
INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(1,CURRENT_TIMESTAMP);`

func Open(path string) (*Store, error) {
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate database: %w", err)
	}
	if path != ":memory:" {
		_ = os.Chmod(path, 0600)
	}
	s := &Store{DB: db}
	if err = s.seed(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) Close() error { return s.DB.Close() }
func now() string             { return time.Now().UTC().Format(time.RFC3339Nano) }

func (s *Store) seed() error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, p := range PermissionCatalog {
		if _, err = tx.Exec(`INSERT INTO permissions(name,category,description) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET category=excluded.category,description=excluded.description`, p.Name, p.Category, p.Description); err != nil {
			return err
		}
	}
	roles := []struct {
		id, name, desc string
		perms          []string
	}{
		{"role-viewer", "Viewer", "Read-only container troubleshooting", []string{"container.read", "container.inspect", "container.stats", "container.logs"}},
		{"role-developer", "Developer", "Viewer plus privileged terminal access", []string{"container.read", "container.inspect", "container.stats", "container.logs", "container.exec"}},
		{"role-admin", "Admin", "Full administrative access", nil},
	}
	for _, r := range roles {
		if _, err = tx.Exec(`INSERT OR IGNORE INTO roles(id,name,description,builtin,created_at) VALUES(?,?,?,?,?)`, r.id, r.name, r.desc, 1, now()); err != nil {
			return err
		}
		perms := r.perms
		if r.name == "Admin" {
			for _, p := range PermissionCatalog {
				perms = append(perms, p.Name)
			}
		}
		for _, p := range perms {
			if _, err = tx.Exec(`INSERT OR IGNORE INTO role_permissions(role_id,permission) VALUES(?,?)`, r.id, p); err != nil {
				return err
			}
		}
	}
	defaults := map[string]string{"auth_provider": "local"}
	for k, v := range defaults {
		if _, err = tx.Exec(`INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES(?,?,?)`, k, v, now()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) UserCount(ctx context.Context) (int, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}
func (s *Store) CreateUser(ctx context.Context, username, password string, roles []string) (User, error) {
	if !security.ValidateUsername(username) {
		return User{}, errors.New("invalid username")
	}
	hash, err := security.HashPassword(password)
	if err != nil {
		return User{}, err
	}
	id, _ := security.ID()
	t := now()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx, `INSERT INTO users(id,username,password_hash,created_at,updated_at) VALUES(?,?,?,?,?)`, id, username, hash, t, t); err != nil {
		return User{}, errors.New("username already exists")
	}
	for _, role := range roles {
		res, er := tx.ExecContext(ctx, `INSERT INTO user_roles(user_id,role_id) SELECT ?,id FROM roles WHERE id=? OR name=?`, id, role, role)
		if er != nil {
			return User{}, er
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return User{}, fmt.Errorf("unknown role %q", role)
		}
	}
	if err = tx.Commit(); err != nil {
		return User{}, err
	}
	return s.GetUser(ctx, id)
}
func (s *Store) BootstrapAdmin(ctx context.Context, username, password string) (User, error) {
	if !security.ValidateUsername(username) {
		return User{}, errors.New("invalid username")
	}
	hash, err := security.HashPassword(password)
	if err != nil {
		return User{}, err
	}
	id, _ := security.ID()
	t := now()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `INSERT INTO users(id,username,password_hash,created_at,updated_at) SELECT ?,?,?,?,? WHERE NOT EXISTS(SELECT 1 FROM users)`, id, username, hash, t, t)
	if err != nil {
		return User{}, errors.New("bootstrap unavailable")
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return User{}, errors.New("bootstrap already completed")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO user_roles(user_id,role_id) VALUES(?,'role-admin')`, id); err != nil {
		return User{}, err
	}
	if err = tx.Commit(); err != nil {
		return User{}, err
	}
	return s.GetUser(ctx, id)
}
func (s *Store) Authenticate(ctx context.Context, username, password string) (User, bool, error) {
	var id, hash string
	var enabled bool
	err := s.DB.QueryRowContext(ctx, `SELECT id,password_hash,enabled FROM users WHERE username=?`, username).Scan(&id, &hash, &enabled)
	if err == sql.ErrNoRows {
		_ = security.VerifyPassword(dummyPasswordHash, password)
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, err
	}
	if !enabled || !security.VerifyPassword(hash, password) {
		return User{}, false, nil
	}
	_, _ = s.DB.ExecContext(ctx, `UPDATE users SET last_login_at=?,last_activity_at=? WHERE id=?`, now(), now(), id)
	u, err := s.GetUser(ctx, id)
	return u, true, err
}
func (s *Store) GetUser(ctx context.Context, id string) (User, error) {
	var u User
	err := s.DB.QueryRowContext(ctx, `SELECT id,username,enabled,created_at,last_login_at,last_activity_at FROM users WHERE id=?`, id).Scan(&u.ID, &u.Username, &u.Enabled, &u.CreatedAt, &u.LastLoginAt, &u.LastActivityAt)
	if err != nil {
		return u, err
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT r.id,r.name,p.permission FROM user_roles ur JOIN roles r ON r.id=ur.role_id LEFT JOIN role_permissions p ON p.role_id=r.id WHERE ur.user_id=? AND ur.scope_type='host' AND ur.scope_id='local'`, id)
	if err != nil {
		return u, err
	}
	defer func() { _ = rows.Close() }()
	seen := map[string]bool{}
	seenPermission := map[string]bool{}
	for rows.Next() {
		var roleID, role string
		var perm sql.NullString
		if err = rows.Scan(&roleID, &role, &perm); err != nil {
			return u, err
		}
		if !seen[role] {
			u.Roles = append(u.Roles, role)
			u.RoleIDs = append(u.RoleIDs, roleID)
			seen[role] = true
		}
		if perm.Valid && !seenPermission[perm.String] {
			u.Permissions = append(u.Permissions, perm.String)
			seenPermission[perm.String] = true
		}
	}
	return u, rows.Err()
}
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	var out []User
	for _, id := range ids {
		u, e := s.GetUser(ctx, id)
		if e != nil {
			return nil, e
		}
		out = append(out, u)
	}
	return out, nil
}
func (s *Store) UpdateUser(ctx context.Context, id string, enabled *bool, roles []string, password string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if enabled != nil {
		if _, err = tx.ExecContext(ctx, `UPDATE users SET enabled=?,updated_at=? WHERE id=?`, *enabled, now(), id); err != nil {
			return err
		}
	}
	if password != "" {
		h, e := security.HashPassword(password)
		if e != nil {
			return e
		}
		if _, err = tx.ExecContext(ctx, `UPDATE users SET password_hash=?,updated_at=? WHERE id=?`, h, now(), id); err != nil {
			return err
		}
	}
	if roles != nil {
		if _, err = tx.ExecContext(ctx, `DELETE FROM user_roles WHERE user_id=?`, id); err != nil {
			return err
		}
		for _, role := range roles {
			res, e := tx.ExecContext(ctx, `INSERT INTO user_roles(user_id,role_id) SELECT ?,id FROM roles WHERE id=? OR name=?`, id, role, role)
			if e != nil {
				return e
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return fmt.Errorf("unknown role")
			}
		}
	}
	return tx.Commit()
}
func (s *Store) ActiveAdminCount(ctx context.Context) (int, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(DISTINCT u.id) FROM users u JOIN user_roles ur ON ur.user_id=u.id JOIN roles r ON r.id=ur.role_id WHERE u.enabled=1 AND r.name='Admin'`).Scan(&n)
	return n, err
}

func (s *Store) CreateSession(ctx context.Context, userID, sourceIP, userAgent string, ttl time.Duration) (token, csrf string, err error) {
	token, err = security.RandomToken(32)
	if err != nil {
		return
	}
	csrf, err = security.RandomToken(32)
	if err != nil {
		return
	}
	t := time.Now().UTC()
	_, err = s.DB.ExecContext(ctx, `INSERT INTO sessions(id_hash,user_id,csrf_hash,created_at,expires_at,last_activity_at,source_ip,user_agent) VALUES(?,?,?,?,?,?,?,?)`, security.TokenHash(token), userID, security.TokenHash(csrf), t.Format(time.RFC3339Nano), t.Add(ttl).Format(time.RFC3339Nano), t.Format(time.RFC3339Nano), sourceIP, truncate(userAgent, 256))
	return
}
func (s *Store) ResolveSession(ctx context.Context, token string) (Session, error) {
	var x Session
	var userID string
	err := s.DB.QueryRowContext(ctx, `SELECT user_id,csrf_hash,expires_at FROM sessions WHERE id_hash=? AND revoked_at IS NULL AND expires_at>?`, security.TokenHash(token), now()).Scan(&userID, &x.CSRFHash, &x.ExpiresAt)
	if err != nil {
		return x, err
	}
	x.TokenHash = security.TokenHash(token)
	x.User, err = s.GetUser(ctx, userID)
	if err != nil || !x.User.Enabled {
		return Session{}, sql.ErrNoRows
	}
	_, _ = s.DB.ExecContext(ctx, `UPDATE sessions SET last_activity_at=? WHERE id_hash=?`, now(), x.TokenHash)
	return x, nil
}
func (s *Store) RevokeSession(ctx context.Context, token string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE sessions SET revoked_at=? WHERE id_hash=?`, now(), security.TokenHash(token))
	return err
}
func (s *Store) RevokeUserSessions(ctx context.Context, userID string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`, now(), userID)
	return err
}

func (s *Store) ListRoles(ctx context.Context) ([]Role, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id,name,description,builtin FROM roles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var out []Role
	for rows.Next() {
		var r Role
		if err = rows.Scan(&r.ID, &r.Name, &r.Description, &r.Builtin); err != nil {
			_ = rows.Close()
			return nil, err
		}
		out = append(out, r)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	for i := range out {
		pr, e := s.DB.QueryContext(ctx, `SELECT permission FROM role_permissions WHERE role_id=? ORDER BY permission`, out[i].ID)
		if e != nil {
			return nil, e
		}
		for pr.Next() {
			var p string
			if e = pr.Scan(&p); e != nil {
				_ = pr.Close()
				return nil, e
			}
			out[i].Permissions = append(out[i].Permissions, p)
		}
		if e = pr.Err(); e != nil {
			_ = pr.Close()
			return nil, e
		}
		if e = pr.Close(); e != nil {
			return nil, e
		}
	}
	return out, nil
}
func (s *Store) SaveRole(ctx context.Context, r Role) (Role, error) {
	if strings.TrimSpace(r.Name) == "" || len(r.Name) > 64 {
		return r, errors.New("invalid role name")
	}
	if r.ID == "" {
		r.ID, _ = security.ID()
		_, err := s.DB.ExecContext(ctx, `INSERT INTO roles(id,name,description,builtin,created_at) VALUES(?,?,?,0,?)`, r.ID, r.Name, truncate(r.Description, 500), now())
		if err != nil {
			return r, errors.New("role name already exists")
		}
	} else {
		var current string
		var builtin bool
		if err := s.DB.QueryRowContext(ctx, `SELECT name,builtin FROM roles WHERE id=?`, r.ID).Scan(&current, &builtin); err != nil {
			return r, err
		}
		if builtin && current != r.Name {
			return r, errors.New("built-in role cannot be renamed")
		}
		if _, err := s.DB.ExecContext(ctx, `UPDATE roles SET name=?,description=? WHERE id=?`, r.Name, truncate(r.Description, 500), r.ID); err != nil {
			return r, err
		}
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return r, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx, `DELETE FROM role_permissions WHERE role_id=?`, r.ID); err != nil {
		return r, err
	}
	for _, p := range r.Permissions {
		if _, err = tx.ExecContext(ctx, `INSERT INTO role_permissions(role_id,permission) VALUES(?,?)`, r.ID, p); err != nil {
			return r, fmt.Errorf("unknown permission %q", p)
		}
	}
	return r, tx.Commit()
}
func (s *Store) DeleteRole(ctx context.Context, id string) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM roles WHERE id=? AND builtin=0`, id)
	if err == nil {
		if n, _ := res.RowsAffected(); n == 0 {
			return errors.New("built-in or unknown role")
		}
	}
	return err
}
func (s *Store) ListPermissions(ctx context.Context) ([]Permission, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT p.name,p.category,p.description,COALESCE(group_concat(r.name), '') FROM permissions p LEFT JOIN role_permissions rp ON rp.permission=p.name LEFT JOIN roles r ON r.id=rp.role_id GROUP BY p.name ORDER BY p.category,p.name`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Permission
	for rows.Next() {
		var p Permission
		var roles string
		if err = rows.Scan(&p.Name, &p.Category, &p.Description, &roles); err != nil {
			return nil, err
		}
		if roles != "" {
			p.Roles = strings.Split(roles, ",")
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) ListPolicies(ctx context.Context) ([]Policy, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id,name,description,enabled FROM policies ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var out []Policy
	for rows.Next() {
		var p Policy
		if err = rows.Scan(&p.ID, &p.Name, &p.Description, &p.Enabled); err != nil {
			_ = rows.Close()
			return nil, err
		}
		out = append(out, p)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	for i := range out {
		rr, e := s.DB.QueryContext(ctx, `SELECT id,effect,action,COALESCE(subject_role_id,''),match_type,match_key,match_value,priority FROM policy_rules WHERE policy_id=? ORDER BY priority DESC`, out[i].ID)
		if e != nil {
			return nil, e
		}
		for rr.Next() {
			var r PolicyRule
			r.PolicyID = out[i].ID
			if e = rr.Scan(&r.ID, &r.Effect, &r.Action, &r.SubjectRoleID, &r.MatchType, &r.MatchKey, &r.MatchValue, &r.Priority); e != nil {
				_ = rr.Close()
				return nil, e
			}
			out[i].Rules = append(out[i].Rules, r)
		}
		if e = rr.Err(); e != nil {
			_ = rr.Close()
			return nil, e
		}
		if e = rr.Close(); e != nil {
			return nil, e
		}
	}
	return out, nil
}
func (s *Store) SavePolicy(ctx context.Context, p Policy) (Policy, error) {
	if len(strings.TrimSpace(p.Name)) < 1 || len(p.Name) > 100 {
		return p, errors.New("invalid policy name")
	}
	if p.ID == "" {
		p.ID, _ = security.ID()
	}
	t := now()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return p, err
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx, `INSERT INTO policies(id,name,description,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,description=excluded.description,enabled=excluded.enabled,updated_at=excluded.updated_at`, p.ID, p.Name, truncate(p.Description, 500), p.Enabled, t, t)
	if err != nil {
		return p, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM policy_rules WHERE policy_id=?`, p.ID); err != nil {
		return p, err
	}
	for i, r := range p.Rules {
		if r.Effect != "allow" && r.Effect != "deny" {
			return p, errors.New("invalid effect")
		}
		if r.MatchType != "name" && r.MatchType != "label" {
			return p, errors.New("invalid match type")
		}
		if len(r.MatchValue) > 128 || strings.Contains(r.MatchValue, "[") {
			return p, errors.New("invalid policy pattern")
		}
		if r.ID == "" {
			r.ID, _ = security.ID()
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO policy_rules(id,policy_id,effect,action,subject_role_id,match_type,match_key,match_value,priority) VALUES(?,?,?,?,NULLIF(?,''),?,?,?,?)`, r.ID, p.ID, r.Effect, r.Action, r.SubjectRoleID, r.MatchType, truncate(r.MatchKey, 128), r.MatchValue, i)
		if err != nil {
			return p, err
		}
	}
	return p, tx.Commit()
}
func (s *Store) DeletePolicy(ctx context.Context, id string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM policies WHERE id=?`, id)
	return err
}

func (s *Store) Settings(ctx context.Context) (map[string]string, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT key,value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	m := map[string]string{}
	for rows.Next() {
		var k, v string
		_ = rows.Scan(&k, &v)
		m[k] = v
	}
	return m, rows.Err()
}

var allowedSettings = map[string]bool{"instance_name": true, "environment": true, "terminal_idle_timeout": true, "default_log_tail": true, "secret_masking": true}

// EnsureSettings writes operator-provided defaults only when a setting has not
// already been persisted through the administration UI.
func (s *Store) EnsureSettings(ctx context.Context, m map[string]string) error {
	for k, v := range m {
		if !allowedSettings[k] || len(v) > 200 {
			return errors.New("invalid setting")
		}
		if _, err := s.DB.ExecContext(ctx, `INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES(?,?,?)`, k, v, now()); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) UpdateSettings(ctx context.Context, m map[string]string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for k, v := range m {
		if !allowedSettings[k] || len(v) > 200 {
			return errors.New("invalid setting")
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at`, k, v, now()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Audit(ctx context.Context, e AuditEvent) error {
	e.ID, _ = security.ID()
	if e.Timestamp == "" {
		e.Timestamp = now()
	}
	if len(e.Metadata) == 0 {
		e.Metadata = json.RawMessage(`{}`)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO audit_events(id,timestamp,user_id,username,source_ip,action,resource_type,resource_id,result,reason,session_id,metadata) VALUES(?,?,NULLIF(?,''),?,?,?,?,?,?,?,?,?)`, e.ID, e.Timestamp, e.UserID, truncate(e.Username, 64), truncate(e.SourceIP, 64), truncate(e.Action, 64), truncate(e.ResourceType, 64), truncate(e.ResourceID, 128), truncate(e.Result, 16), truncate(e.Reason, 300), truncate(e.SessionID, 64), string(e.Metadata)); err != nil {
		return err
	}
	_, err := s.DB.ExecContext(ctx, `DELETE FROM audit_events WHERE id IN (SELECT id FROM audit_events ORDER BY timestamp DESC LIMIT -1 OFFSET 100000)`)
	return err
}
func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditEvent, error) {
	if limit < 1 || limit > 1000 {
		limit = 200
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id,timestamp,COALESCE(user_id,''),username,source_ip,action,resource_type,resource_id,result,reason,session_id,metadata FROM audit_events ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		var metadata string
		if err = rows.Scan(&e.ID, &e.Timestamp, &e.UserID, &e.Username, &e.SourceIP, &e.Action, &e.ResourceType, &e.ResourceID, &e.Result, &e.Reason, &e.SessionID, &metadata); err != nil {
			return nil, err
		}
		e.Metadata = json.RawMessage(metadata)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) CreateTerminal(ctx context.Context, userID, containerID, shell string, ttl time.Duration) (TerminalSession, error) {
	id, _ := security.ID()
	t := time.Now().UTC()
	x := TerminalSession{id, userID, containerID, shell, t.Format(time.RFC3339Nano), t.Format(time.RFC3339Nano), t.Add(ttl).Format(time.RFC3339Nano), "created"}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO terminal_sessions(id,user_id,container_id,shell,created_at,last_activity_at,expires_at,status) VALUES(?,?,?,?,?,?,?,?)`, x.ID, x.UserID, x.ContainerID, x.Shell, x.CreatedAt, x.LastActivityAt, x.ExpiresAt, x.Status)
	return x, err
}
func (s *Store) GetTerminal(ctx context.Context, id, userID string) (TerminalSession, error) {
	var x TerminalSession
	err := s.DB.QueryRowContext(ctx, `SELECT id,user_id,container_id,shell,created_at,last_activity_at,expires_at,status FROM terminal_sessions WHERE id=? AND user_id=? AND status IN ('created','attached') AND expires_at>?`, id, userID, now()).Scan(&x.ID, &x.UserID, &x.ContainerID, &x.Shell, &x.CreatedAt, &x.LastActivityAt, &x.ExpiresAt, &x.Status)
	return x, err
}
func (s *Store) TouchTerminal(ctx context.Context, id, status string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE terminal_sessions SET last_activity_at=?,status=?,ended_at=CASE WHEN ?='ended' THEN ? ELSE ended_at END WHERE id=?`, now(), status, status, now(), id)
	return err
}

func truncate(v string, n int) string {
	if len(v) > n {
		return v[:n]
	}
	return v
}
