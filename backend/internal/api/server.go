package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dockerview/dockerview/backend/internal/auth"
	"github.com/dockerview/dockerview/backend/internal/config"
	"github.com/dockerview/dockerview/backend/internal/database"
	dockermodel "github.com/dockerview/dockerview/backend/internal/docker"
	"github.com/dockerview/dockerview/backend/internal/policies"
	"github.com/dockerview/dockerview/backend/internal/rbac"
	"github.com/dockerview/dockerview/backend/internal/security"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
)

const sessionCookie = "dv_session"
const csrfCookie = "dv_csrf"

type contextKey string

const sessionKey contextKey = "session"

type Server struct {
	Cfg                                                      config.Config
	Store                                                    *database.Store
	Gateway                                                  *GatewayClient
	Auth                                                     auth.Provider
	loginLimit, bootstrapLimit, terminalLimit, passwordLimit *limiter
	upgrader                                                 websocket.Upgrader
}

func New(cfg config.Config, store *database.Store) *Server {
	s := &Server{Cfg: cfg, Store: store, Gateway: NewGatewayClient(cfg.GatewayURL, cfg.GatewaySecret), Auth: auth.LocalProvider{Store: store}, loginLimit: newLimiter(10, 5*time.Minute), bootstrapLimit: newLimiter(5, 10*time.Minute), terminalLimit: newLimiter(10, time.Minute), passwordLimit: newLimiter(5, 10*time.Minute)}
	s.upgrader = websocket.Upgrader{ReadBufferSize: 8192, WriteBufferSize: 8192, CheckOrigin: s.originAllowed}
	return s
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(s.recoverer, s.securityHeaders, s.bodyLimit)
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) { respond(w, 200, map[string]string{"status": "ok"}) })
	r.Get("/ready", s.ready)
	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/status", s.status)
		r.Post("/bootstrap", s.bootstrap)
		r.Post("/auth/login", s.login)
		r.Group(func(r chi.Router) {
			r.Use(s.requireSession)
			r.Get("/auth/me", s.me)
			r.With(s.requireCSRF).Post("/auth/logout", s.logout)
			r.Get("/overview", s.overview)
			r.Route("/containers", func(r chi.Router) {
				r.With(s.requirePermission("container.read")).Get("/", s.containers)
				r.Route("/{id}", func(r chi.Router) {
					r.With(s.requirePermission("container.inspect")).Get("/", s.container)
					r.With(s.requirePermission("container.stats")).Get("/stats", s.stats)
					r.With(s.requirePermission("container.logs")).Get("/logs", s.logs)
					r.With(s.requirePermission("container.logs")).Get("/logs/stream", s.logsStream)
					r.With(s.requirePermission("container.restart"), s.requireCSRF).Post("/restart", s.restart)
					r.With(s.requirePermission("container.exec"), s.requireCSRF).Post("/terminal", s.createTerminal)
				})
			})
			r.Get("/terminal/{session}/ws", s.terminalWS)
			r.With(s.requirePermission("user.read")).Get("/users", s.users)
			r.With(s.requirePermission("user.manage"), s.requireCSRF).Post("/users", s.createUser)
			r.With(s.requirePermission("user.manage"), s.requireCSRF).Put("/users/{id}", s.updateUser)
			r.With(s.requirePermission("user.manage"), s.requireCSRF).Post("/users/{id}/invalidate-sessions", s.invalidateSessions)
			r.With(s.requirePermission("role.read")).Get("/roles", s.roles)
			r.With(s.requirePermission("role.manage"), s.requireCSRF).Post("/roles", s.saveRole)
			r.With(s.requirePermission("role.manage"), s.requireCSRF).Put("/roles/{id}", s.saveRole)
			r.With(s.requirePermission("role.manage"), s.requireCSRF).Delete("/roles/{id}", s.deleteRole)
			r.With(s.requirePermission("permission.read")).Get("/permissions", s.permissions)
			r.With(s.requirePermission("policy.read")).Get("/policies", s.policyList)
			r.With(s.requirePermission("policy.manage"), s.requireCSRF).Post("/policies", s.savePolicy)
			r.With(s.requirePermission("policy.manage"), s.requireCSRF).Put("/policies/{id}", s.savePolicy)
			r.With(s.requirePermission("policy.manage"), s.requireCSRF).Delete("/policies/{id}", s.deletePolicy)
			r.With(s.requirePermission("audit.read")).Get("/audit", s.auditList)
			r.With(s.requirePermission("settings.read")).Get("/settings", s.settings)
			r.With(s.requirePermission("settings.manage"), s.requireCSRF).Put("/settings", s.updateSettings)
		})
	})
	r.NotFound(s.static)
	return r
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}
func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recover() != nil {
				slog.Error("request panic", "component", "server")
				problemResponse(w, 500, "INTERNAL", "Internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
func (s *Server) bodyLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, s.Cfg.MaxBodyBytes)
		next.ServeHTTP(w, r)
	})
}
func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		problemResponse(w, 404, "NOT_FOUND", "Endpoint not found")
		return
	}
	clean := filepath.Clean("/" + r.URL.Path)
	name := filepath.Join(s.Cfg.StaticDir, clean)
	if info, err := os.Stat(name); err == nil && info.IsDir() {
		name = filepath.Join(name, "index.html")
	}
	if _, err := os.Stat(name); err != nil {
		name = filepath.Join(s.Cfg.StaticDir, "index.html")
	}
	http.ServeFile(w, r, name)
}
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if err := s.Store.DB.PingContext(r.Context()); err != nil {
		problemResponse(w, 503, "DATABASE_UNAVAILABLE", "Database unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.Gateway.Ready(ctx); err != nil {
		problemResponse(w, 503, "GATEWAY_UNAVAILABLE", "Docker Gateway unavailable")
		return
	}
	respond(w, 200, map[string]string{"status": "ready"})
}
func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	n, err := s.Store.UserCount(r.Context())
	if err != nil {
		problemResponse(w, 500, "DATABASE_ERROR", "Unable to read setup status")
		return
	}
	settings, _ := s.Store.Settings(r.Context())
	instance := settings["instance_name"]
	environment := settings["environment"]
	if instance == "" {
		instance = s.Cfg.InstanceName
	}
	if environment == "" {
		environment = s.Cfg.Environment
	}
	respond(w, 200, map[string]interface{}{"product": "DockerView", "needs_setup": n == 0, "instance": instance, "environment": environment})
}

func (s *Server) bootstrap(w http.ResponseWriter, r *http.Request) {
	if !s.bootstrapLimit.allow(clientIP(r)) {
		problemResponse(w, 429, "RATE_LIMITED", "Try again later")
		return
	}
	var in struct{ Username, Password string }
	if decodeJSON(r, &in) != nil {
		problemResponse(w, 400, "INVALID_REQUEST", "Invalid request")
		return
	}
	u, err := s.Store.BootstrapAdmin(r.Context(), in.Username, in.Password)
	if err != nil {
		problemResponse(w, 409, "BOOTSTRAP_UNAVAILABLE", err.Error())
		return
	}
	s.audit(r, u, "BOOTSTRAP_ADMIN", "user", u.ID, "success", "", nil)
	s.issueSession(w, r, u)
	respond(w, 201, map[string]interface{}{"user": u})
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.loginLimit.allow(clientIP(r)) {
		s.audit(r, database.User{}, "LOGIN_FAILED", "auth", "", "denied", "rate limited", nil)
		problemResponse(w, 429, "RATE_LIMITED", "Try again later")
		return
	}
	var in struct{ Username, Password string }
	if decodeJSON(r, &in) != nil || len(in.Username) > 64 || len(in.Password) > 1024 {
		problemResponse(w, 400, "INVALID_REQUEST", "Invalid credentials")
		return
	}
	u, ok, err := s.Auth.Authenticate(r.Context(), in.Username, in.Password)
	if err != nil || !ok {
		s.audit(r, database.User{Username: truncate(in.Username, 64)}, "LOGIN_FAILED", "auth", "", "denied", "invalid credentials", nil)
		problemResponse(w, 401, "INVALID_CREDENTIALS", "Invalid username or password")
		return
	}
	s.issueSession(w, r, u)
	s.audit(r, u, "LOGIN_SUCCESS", "auth", "", "success", "", nil)
	respond(w, 200, map[string]interface{}{"user": u})
}
func (s *Server) issueSession(w http.ResponseWriter, r *http.Request, u database.User) {
	token, csrf, err := s.Store.CreateSession(r.Context(), u.ID, clientIP(r), r.UserAgent(), s.Cfg.SessionTTL)
	if err != nil {
		panic(err)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: s.Cfg.CookieSecure, SameSite: http.SameSiteStrictMode, MaxAge: int(s.Cfg.SessionTTL.Seconds())})
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: csrf, Path: "/", HttpOnly: false, Secure: s.Cfg.CookieSecure, SameSite: http.SameSiteStrictMode, MaxAge: int(s.Cfg.SessionTTL.Seconds())})
}
func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			problemResponse(w, 401, "AUTH_REQUIRED", "Authentication required")
			return
		}
		sess, err := s.Store.ResolveSession(r.Context(), c.Value)
		if err != nil {
			problemResponse(w, 401, "SESSION_INVALID", "Session expired or revoked")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey, sess)))
	})
}
func sessionFrom(r *http.Request) database.Session {
	return r.Context().Value(sessionKey).(database.Session)
}
func (s *Server) requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := sessionFrom(r)
		provided := r.Header.Get("X-CSRF-Token")
		if provided == "" {
			provided = r.URL.Query().Get("csrf")
		}
		actual := security.TokenHash(provided)
		if len(actual) != len(sess.CSRFHash) || subtle.ConstantTimeCompare([]byte(actual), []byte(sess.CSRFHash)) != 1 {
			problemResponse(w, 403, "CSRF_INVALID", "CSRF validation failed")
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && !s.originAllowed(r) {
			problemResponse(w, 403, "ORIGIN_INVALID", "Origin is not allowed")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (s *Server) requirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !rbac.Allowed(sessionFrom(r).User, permission) {
				problemResponse(w, 403, "FORBIDDEN", "Permission denied")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
func (s *Server) originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	for _, allowed := range s.Cfg.AllowedOrigins {
		if origin == allowed {
			return true
		}
	}
	return false
}
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	respond(w, 200, map[string]interface{}{"user": sessionFrom(r).User})
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	u := sessionFrom(r).User
	if c, e := r.Cookie(sessionCookie); e == nil {
		_ = s.Store.RevokeSession(r.Context(), c.Value)
	}
	clearCookies(w, s.Cfg.CookieSecure)
	s.audit(r, u, "LOGOUT", "auth", "", "success", "", nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	if !rbac.Allowed(sessionFrom(r).User, "container.read") {
		problemResponse(w, 403, "FORBIDDEN", "Permission denied")
		return
	}
	var containers []map[string]interface{}
	if err := s.Gateway.JSON(r.Context(), http.MethodGet, "/v1/containers", nil, &containers); err != nil {
		problemResponse(w, 502, "GATEWAY_UNAVAILABLE", "Unable to query Docker Gateway")
		return
	}
	var hostInfo map[string]interface{}
	if err := s.Gateway.JSON(r.Context(), http.MethodGet, "/v1/info", nil, &hostInfo); err != nil {
		hostInfo = map[string]interface{}{}
	}
	running, stopped, unhealthy := 0, 0, 0
	for _, c := range containers {
		if c["State"] == "running" {
			running++
		} else {
			stopped++
		}
		if h, ok := c["Health"].(map[string]interface{}); ok && h["Status"] == "unhealthy" {
			unhealthy++
		}
	}
	settings, _ := s.Store.Settings(r.Context())
	instance := settings["instance_name"]
	environment := settings["environment"]
	if instance == "" {
		instance = s.Cfg.InstanceName
	}
	if environment == "" {
		environment = s.Cfg.Environment
	}
	respond(w, 200, map[string]interface{}{"instance": instance, "environment": environment, "docker": "connected", "running": running, "stopped": stopped, "unhealthy": unhealthy, "containers": containers, "host": hostInfo})
}
func (s *Server) containers(w http.ResponseWriter, r *http.Request) {
	var out interface{}
	if err := s.Gateway.JSON(r.Context(), http.MethodGet, "/v1/containers", nil, &out); err != nil {
		problemResponse(w, 502, "GATEWAY_UNAVAILABLE", "Unable to list containers")
		return
	}
	respond(w, 200, out)
}
func (s *Server) inspectResource(ctx context.Context, id string) (map[string]interface{}, policies.Resource, error) {
	if !security.ValidateContainerID(id) {
		return nil, policies.Resource{}, errors.New("invalid container")
	}
	raw, err := s.Gateway.Raw(ctx, gatewayContainerPath(id, "/"))
	if err != nil {
		return nil, policies.Resource{}, err
	}
	var v map[string]interface{}
	if json.Unmarshal(raw, &v) != nil {
		return nil, policies.Resource{}, errors.New("invalid gateway response")
	}
	name, _ := v["Name"].(string)
	name = strings.TrimPrefix(name, "/")
	labels := map[string]string{}
	if cfg, ok := v["Config"].(map[string]interface{}); ok {
		if lm, ok := cfg["Labels"].(map[string]interface{}); ok {
			for k, x := range lm {
				if z, ok := x.(string); ok {
					labels[k] = z
				}
			}
		}
	}
	return v, policies.Resource{Name: name, Labels: labels, System: strings.EqualFold(labels["dockerview.system"], "true")}, nil
}
func (s *Server) authorizeResource(w http.ResponseWriter, r *http.Request, action, id string) (map[string]interface{}, policies.Resource, bool) {
	v, res, err := s.inspectResource(r.Context(), id)
	if err != nil {
		problemResponse(w, 404, "CONTAINER_NOT_FOUND", "Container not found")
		return nil, res, false
	}
	ps, _ := s.Store.ListPolicies(r.Context())
	decision := policies.Evaluate(sessionFrom(r).User, action, res, ps)
	if !decision.Allowed {
		auditAction := strings.ToUpper(strings.ReplaceAll(action, ".", "_")) + "_DENIED"
		if action == "container.exec" {
			auditAction = "EXEC_DENIED"
		}
		s.audit(r, sessionFrom(r).User, auditAction, "container", id, "denied", decision.Reason, nil)
		problemResponse(w, 403, "POLICY_DENIED", decision.Reason)
		return v, res, false
	}
	return v, res, true
}

func (s *Server) container(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	v, res, ok := s.authorizeResource(w, r, "container.inspect", id)
	if !ok {
		return
	}
	reveal := r.URL.Query().Get("reveal") == "true"
	canViewSecrets := rbac.Allowed(sessionFrom(r).User, "secret.view")
	if reveal && !canViewSecrets {
		problemResponse(w, 403, "SECRET_PERMISSION_REQUIRED", "Permission secret.view is required")
		return
	}
	settings, _ := s.Store.Settings(r.Context())
	masking := settings["secret_masking"] != "false" && s.Cfg.SecretMasking
	if reveal {
		s.audit(r, sessionFrom(r).User, "SECRET_REVEAL", "container", id, "success", "", nil)
	} else if masking || !canViewSecrets {
		maskInspect(v)
	}
	risk := riskFromInspect(v, res.System)
	s.audit(r, sessionFrom(r).User, "CONTAINER_VIEW", "container", id, "success", "", nil)
	respond(w, 200, map[string]interface{}{"inspect": v, "risk": risk, "system": res.System})
}
func riskFromInspect(v map[string]interface{}, system bool) dockermodel.RiskAssessment {
	in := dockermodel.RiskInput{System: system}
	if h, ok := v["HostConfig"].(map[string]interface{}); ok {
		in.Privileged = boolValue(h["Privileged"])
		in.PidMode = stringValue(h["PidMode"])
		in.NetworkMode = stringValue(h["NetworkMode"])
		in.IpcMode = stringValue(h["IpcMode"])
		if ds, ok := h["Devices"].([]interface{}); ok {
			for _, d := range ds {
				in.Devices = append(in.Devices, fmt.Sprint(d))
			}
		}
	}
	if ms, ok := v["Mounts"].([]interface{}); ok {
		for _, raw := range ms {
			if m, ok := raw.(map[string]interface{}); ok {
				in.Mounts = append(in.Mounts, dockermodel.Mount{Type: stringValue(m["Type"]), Source: stringValue(m["Source"]), Destination: stringValue(m["Destination"]), Mode: stringValue(m["Mode"])})
			}
		}
	}
	return dockermodel.AssessRisk(in)
}
func maskInspect(v interface{}) {
	switch x := v.(type) {
	case map[string]interface{}:
		for k, val := range x {
			if security.SensitiveKey(k) {
				x[k] = "********"
				continue
			}
			if k == "Env" {
				if arr, ok := val.([]interface{}); ok {
					for i, item := range arr {
						if text, ok := item.(string); ok {
							masked := security.MaskEnv([]string{text}, false)
							arr[i] = masked[0]
						}
					}
				}
			} else {
				maskInspect(val)
			}
		}
	case []interface{}:
		for _, v := range x {
			maskInspect(v)
		}
	}
}
func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, _, ok := s.authorizeResource(w, r, "container.stats", id); !ok {
		return
	}
	raw, err := s.Gateway.Raw(r.Context(), gatewayContainerPath(id, "/stats"))
	if err != nil {
		problemResponse(w, 502, "STATS_UNAVAILABLE", "Container stats unavailable")
		return
	}
	var v interface{}
	if json.Unmarshal(raw, &v) != nil {
		problemResponse(w, 502, "INVALID_GATEWAY_RESPONSE", "Invalid stats response")
		return
	}
	respond(w, 200, v)
}
func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, _, ok := s.authorizeResource(w, r, "container.logs", id); !ok {
		return
	}
	tail := security.ParseBoundedInt(r.URL.Query().Get("tail"), s.defaultLogTail(r.Context()), 1, 5000)
	body, err := s.Gateway.Stream(r.Context(), logsPath(id, tail, false))
	if err != nil {
		problemResponse(w, 502, "LOGS_UNAVAILABLE", "Container logs unavailable")
		return
	}
	defer func() { _ = body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(body, 8<<20))
	s.audit(r, sessionFrom(r).User, "CONTAINER_LOGS", "container", id, "success", "", map[string]interface{}{"tail": tail})
	respond(w, 200, map[string]string{"logs": string(data)})
}
func (s *Server) logsStream(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, _, ok := s.authorizeResource(w, r, "container.logs", id); !ok {
		return
	}
	tail := security.ParseBoundedInt(r.URL.Query().Get("tail"), s.defaultLogTail(r.Context()), 1, 5000)
	body, err := s.Gateway.Stream(r.Context(), logsPath(id, tail, true))
	if err != nil {
		problemResponse(w, 502, "LOGS_UNAVAILABLE", "Container logs unavailable")
		return
	}
	defer func() { _ = body.Close() }()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	s.audit(r, sessionFrom(r).User, "CONTAINER_LOGS", "container", id, "success", "live stream", nil)
	buf := make([]byte, 16<<10)
	for {
		n, e := body.Read(buf)
		if n > 0 {
			payload, _ := json.Marshal(string(buf[:n]))
			if _, x := fmt.Fprintf(w, "data: %s\n\n", payload); x != nil {
				return
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		if e != nil {
			return
		}
	}
}
func (s *Server) restart(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, _, ok := s.authorizeResource(w, r, "container.restart", id); !ok {
		return
	}
	var out interface{}
	if err := s.Gateway.JSON(r.Context(), http.MethodPost, gatewayContainerPath(id, "/restart"), map[string]interface{}{}, &out); err != nil {
		s.audit(r, sessionFrom(r).User, "CONTAINER_RESTART", "container", id, "failed", "gateway rejected", nil)
		problemResponse(w, 502, "RESTART_FAILED", "Container restart failed")
		return
	}
	s.audit(r, sessionFrom(r).User, "CONTAINER_RESTART", "container", id, "success", "", nil)
	respond(w, 202, out)
}
func (s *Server) createTerminal(w http.ResponseWriter, r *http.Request) {
	u := sessionFrom(r).User
	if !s.terminalLimit.allow(u.ID) {
		problemResponse(w, 429, "RATE_LIMITED", "Too many terminal sessions")
		return
	}
	id := chi.URLParam(r, "id")
	if _, res, ok := s.authorizeResource(w, r, "container.exec", id); !ok {
		return
	} else if res.System {
		problemResponse(w, 403, "SYSTEM_CONTAINER", "System containers cannot be accessed")
		return
	}
	var in struct {
		Shell string `json:"shell"`
	}
	if decodeJSON(r, &in) != nil {
		problemResponse(w, 400, "INVALID_REQUEST", "Invalid request")
		return
	}
	shell, ok := validateShell(in.Shell)
	if !ok {
		problemResponse(w, 400, "INVALID_SHELL", "Invalid shell selection")
		return
	}
	idle := s.terminalIdle(r.Context())
	x, err := s.Store.CreateTerminal(r.Context(), u.ID, id, shell, idle)
	if err != nil {
		problemResponse(w, 500, "TERMINAL_FAILED", "Unable to create terminal session")
		return
	}
	s.audit(r, u, "EXEC_START", "container", id, "success", "", map[string]interface{}{"terminal_session": x.ID, "shell": shell})
	respond(w, 201, map[string]interface{}{"session_id": x.ID, "shell": shell, "expires_at": x.ExpiresAt})
}
func (s *Server) terminalWS(w http.ResponseWriter, r *http.Request) {
	if !s.originAllowed(r) {
		problemResponse(w, 403, "ORIGIN_INVALID", "Origin is not allowed")
		return
	}
	sess := sessionFrom(r)
	actual := security.TokenHash(r.URL.Query().Get("csrf"))
	if subtle.ConstantTimeCompare([]byte(actual), []byte(sess.CSRFHash)) != 1 {
		problemResponse(w, 403, "CSRF_INVALID", "CSRF validation failed")
		return
	}
	x, err := s.Store.GetTerminal(r.Context(), chi.URLParam(r, "session"), sess.User.ID)
	if err != nil {
		problemResponse(w, 404, "TERMINAL_NOT_FOUND", "Terminal session invalid or expired")
		return
	}
	if _, _, ok := s.authorizeResource(w, r, "container.exec", x.ContainerID); !ok {
		return
	}
	ticket, shell, err := s.Gateway.CreateExec(r.Context(), x.ContainerID, x.Shell)
	if err != nil {
		_ = s.Store.TouchTerminal(r.Context(), x.ID, "ended")
		problemResponse(w, 502, "EXEC_FAILED", "Unable to create Docker exec")
		return
	}
	browser, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer func() { _ = browser.Close() }()
	gateway, err := s.Gateway.DialExec(r.Context(), ticket)
	if err != nil {
		_ = browser.WriteJSON(map[string]string{"type": "error", "message": "Unable to attach terminal"})
		_ = s.Store.TouchTerminal(r.Context(), x.ID, "ended")
		return
	}
	defer func() { _ = gateway.Close() }()
	_ = s.Store.TouchTerminal(r.Context(), x.ID, "attached")
	start := time.Now()
	browser.SetReadLimit(16 << 10)
	gateway.SetReadLimit(16 << 10)
	done := make(chan struct{}, 3)
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	watchdogStop := make(chan struct{})
	defer close(watchdogStop)
	copyWS := func(dst, src *websocket.Conn) {
		defer func() { done <- struct{}{} }()
		for {
			typ, msg, e := src.ReadMessage()
			if e != nil {
				return
			}
			lastActivity.Store(time.Now().UnixNano())
			if len(msg) > 16<<10 {
				return
			}
			_ = dst.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if e = dst.WriteMessage(typ, msg); e != nil {
				return
			}
		}
	}
	go copyWS(gateway, browser)
	go copyWS(browser, gateway)
	go func() {
		idle := s.terminalIdle(context.Background())
		interval := idle / 4
		if interval > time.Minute {
			interval = time.Minute
		}
		if interval < time.Second {
			interval = time.Second
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-watchdogStop:
				return
			case <-ticker.C:
				if time.Since(time.Unix(0, lastActivity.Load())) >= idle {
					done <- struct{}{}
					return
				}
			}
		}
	}()
	<-done
	_ = gateway.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "disconnect"), time.Now().Add(time.Second))
	_ = browser.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "disconnect"), time.Now().Add(time.Second))
	_ = s.Store.TouchTerminal(context.Background(), x.ID, "ended")
	s.audit(r, sess.User, "EXEC_END", "container", x.ContainerID, "success", "", map[string]interface{}{"terminal_session": x.ID, "shell": shell, "duration_seconds": int(time.Since(start).Seconds())})
}

func (s *Server) users(w http.ResponseWriter, r *http.Request) {
	v, err := s.Store.ListUsers(r.Context())
	if err != nil {
		problemResponse(w, 500, "DATABASE_ERROR", "Unable to list users")
		return
	}
	respond(w, 200, v)
}
func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username, Password string
		Roles              []string
	}
	if decodeJSON(r, &in) != nil {
		problemResponse(w, 400, "INVALID_REQUEST", "Invalid request")
		return
	}
	u, err := s.Store.CreateUser(r.Context(), in.Username, in.Password, in.Roles)
	if err != nil {
		problemResponse(w, 400, "USER_CREATE_FAILED", err.Error())
		return
	}
	s.audit(r, sessionFrom(r).User, "USER_CREATE", "user", u.ID, "success", "", map[string]interface{}{"username": u.Username, "roles": u.Roles})
	respond(w, 201, u)
}
func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	target, err := s.Store.GetUser(r.Context(), id)
	if err != nil {
		problemResponse(w, 404, "USER_NOT_FOUND", "User not found")
		return
	}
	var in struct {
		Enabled  *bool     `json:"enabled"`
		Password string    `json:"password"`
		Roles    *[]string `json:"roles"`
	}
	if decodeJSON(r, &in) != nil {
		problemResponse(w, 400, "INVALID_REQUEST", "Invalid request")
		return
	}
	roles := []string(nil)
	if in.Roles != nil {
		roles = *in.Roles
	}
	if in.Password != "" && !s.passwordLimit.allow(sessionFrom(r).User.ID) {
		problemResponse(w, 429, "RATE_LIMITED", "Too many password resets")
		return
	}
	removesAdmin := in.Enabled != nil && !*in.Enabled || in.Roles != nil && !contains(*in.Roles, "Admin")
	if contains(target.Roles, "Admin") && removesAdmin {
		n, _ := s.Store.ActiveAdminCount(r.Context())
		if n <= 1 {
			problemResponse(w, 409, "LAST_ADMIN", "The last enabled administrator cannot be disabled or demoted")
			return
		}
	}
	if err = s.Store.UpdateUser(r.Context(), id, in.Enabled, roles, in.Password); err != nil {
		problemResponse(w, 400, "USER_UPDATE_FAILED", err.Error())
		return
	}
	action := "USER_UPDATE"
	if in.Password != "" {
		action = "USER_PASSWORD_RESET"
	} else if in.Enabled != nil && *in.Enabled {
		action = "USER_ENABLE"
	} else if in.Enabled != nil {
		action = "USER_DISABLE"
	}
	s.audit(r, sessionFrom(r).User, action, "user", id, "success", "", nil)
	u, _ := s.Store.GetUser(r.Context(), id)
	respond(w, 200, u)
}
func (s *Server) invalidateSessions(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.Store.RevokeUserSessions(r.Context(), id); err != nil {
		problemResponse(w, 500, "SESSION_INVALIDATE_FAILED", "Unable to invalidate sessions")
		return
	}
	s.audit(r, sessionFrom(r).User, "USER_SESSIONS_INVALIDATE", "user", id, "success", "", nil)
	w.WriteHeader(204)
}
func (s *Server) roles(w http.ResponseWriter, r *http.Request) {
	v, err := s.Store.ListRoles(r.Context())
	if err != nil {
		problemResponse(w, 500, "DATABASE_ERROR", "Unable to list roles")
		return
	}
	respond(w, 200, v)
}
func (s *Server) saveRole(w http.ResponseWriter, r *http.Request) {
	var role database.Role
	if decodeJSON(r, &role) != nil {
		problemResponse(w, 400, "INVALID_REQUEST", "Invalid role")
		return
	}
	if id := chi.URLParam(r, "id"); id != "" {
		role.ID = id
	}
	saved, err := s.Store.SaveRole(r.Context(), role)
	if err != nil {
		problemResponse(w, 400, "ROLE_SAVE_FAILED", err.Error())
		return
	}
	action := "ROLE_CREATE"
	if chi.URLParam(r, "id") != "" {
		action = "ROLE_UPDATE"
	}
	s.audit(r, sessionFrom(r).User, action, "role", saved.ID, "success", "", nil)
	respond(w, 200, saved)
}
func (s *Server) deleteRole(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.Store.DeleteRole(r.Context(), id); err != nil {
		problemResponse(w, 409, "ROLE_DELETE_FAILED", err.Error())
		return
	}
	s.audit(r, sessionFrom(r).User, "ROLE_DELETE", "role", id, "success", "", nil)
	w.WriteHeader(204)
}
func (s *Server) permissions(w http.ResponseWriter, r *http.Request) {
	v, err := s.Store.ListPermissions(r.Context())
	if err != nil {
		problemResponse(w, 500, "DATABASE_ERROR", "Unable to list permissions")
		return
	}
	respond(w, 200, v)
}
func (s *Server) policyList(w http.ResponseWriter, r *http.Request) {
	v, err := s.Store.ListPolicies(r.Context())
	if err != nil {
		problemResponse(w, 500, "DATABASE_ERROR", "Unable to list policies")
		return
	}
	respond(w, 200, v)
}
func (s *Server) savePolicy(w http.ResponseWriter, r *http.Request) {
	var p database.Policy
	if decodeJSON(r, &p) != nil {
		problemResponse(w, 400, "INVALID_REQUEST", "Invalid policy")
		return
	}
	if id := chi.URLParam(r, "id"); id != "" {
		p.ID = id
	}
	saved, err := s.Store.SavePolicy(r.Context(), p)
	if err != nil {
		problemResponse(w, 400, "POLICY_SAVE_FAILED", err.Error())
		return
	}
	action := "POLICY_CREATE"
	if chi.URLParam(r, "id") != "" {
		action = "POLICY_UPDATE"
	}
	s.audit(r, sessionFrom(r).User, action, "policy", saved.ID, "success", "", nil)
	respond(w, 200, saved)
}
func (s *Server) deletePolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.Store.DeletePolicy(r.Context(), id); err != nil {
		problemResponse(w, 500, "POLICY_DELETE_FAILED", "Unable to delete policy")
		return
	}
	s.audit(r, sessionFrom(r).User, "POLICY_DELETE", "policy", id, "success", "", nil)
	w.WriteHeader(204)
}
func (s *Server) auditList(w http.ResponseWriter, r *http.Request) {
	limit := security.ParseBoundedInt(r.URL.Query().Get("limit"), 200, 1, 1000)
	v, err := s.Store.ListAudit(r.Context(), limit)
	if err != nil {
		problemResponse(w, 500, "DATABASE_ERROR", "Unable to list audit events")
		return
	}
	respond(w, 200, v)
}
func (s *Server) settings(w http.ResponseWriter, r *http.Request) {
	v, err := s.Store.Settings(r.Context())
	if err != nil {
		problemResponse(w, 500, "DATABASE_ERROR", "Unable to read settings")
		return
	}
	respond(w, 200, v)
}
func (s *Server) updateSettings(w http.ResponseWriter, r *http.Request) {
	var v map[string]string
	if decodeJSON(r, &v) != nil {
		problemResponse(w, 400, "INVALID_REQUEST", "Invalid settings")
		return
	}
	if raw, ok := v["terminal_idle_timeout"]; ok {
		d, e := time.ParseDuration(raw)
		if e != nil || d < time.Minute || d > 8*time.Hour {
			problemResponse(w, 400, "INVALID_TIMEOUT", "Terminal timeout must be between 1m and 8h")
			return
		}
	}
	if err := s.Store.UpdateSettings(r.Context(), v); err != nil {
		problemResponse(w, 400, "SETTINGS_UPDATE_FAILED", err.Error())
		return
	}
	s.audit(r, sessionFrom(r).User, "SETTINGS_UPDATE", "settings", "global", "success", "", map[string]interface{}{"keys": mapKeys(v)})
	respond(w, 200, v)
}

func (s *Server) audit(r *http.Request, u database.User, action, resourceType, resourceID, result, reason string, metadata interface{}) {
	var raw json.RawMessage
	if metadata != nil {
		raw, _ = json.Marshal(metadata)
	}
	sid := ""
	if sess, ok := r.Context().Value(sessionKey).(database.Session); ok {
		sid = sess.TokenHash[:min(12, len(sess.TokenHash))]
	}
	if err := s.Store.Audit(context.Background(), database.AuditEvent{UserID: u.ID, Username: u.Username, SourceIP: clientIP(r), Action: action, ResourceType: resourceType, ResourceID: resourceID, Result: result, Reason: reason, SessionID: sid, Metadata: raw}); err != nil {
		slog.Error("audit write failed", "action", action)
	}
}
func respond(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func problemResponse(w http.ResponseWriter, status int, code, message string) {
	respond(w, status, map[string]interface{}{"error": map[string]string{"code": code, "message": message}})
}
func decodeJSON(r *http.Request, v interface{}) error {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var extra interface{}
	if d.Decode(&extra) != io.EOF {
		return errors.New("multiple JSON values")
	}
	return nil
}
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return truncate(r.RemoteAddr, 64)
}
func truncate(v string, n int) string {
	if len(v) > n {
		return v[:n]
	}
	return v
}
func clearCookies(w http.ResponseWriter, secure bool) {
	for _, name := range []string{sessionCookie, csrfCookie} {
		http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", HttpOnly: name == sessionCookie, Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	}
}
func boolValue(v interface{}) bool     { x, _ := v.(bool); return x }
func stringValue(v interface{}) string { x, _ := v.(string); return x }
func validateShell(s string) (string, bool) {
	switch s {
	case "", "auto":
		return "auto", true
	case "/bin/bash", "/bin/sh", "/bin/ash":
		return s, true
	}
	return "", false
}
func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
func mapKeys(m map[string]string) []string {
	r := make([]string, 0, len(m))
	for k := range m {
		r = append(r, k)
	}
	return r
}
func (s *Server) defaultLogTail(ctx context.Context) int {
	settings, err := s.Store.Settings(ctx)
	if err == nil {
		return security.ParseBoundedInt(settings["default_log_tail"], s.Cfg.LogTailDefault, 1, 5000)
	}
	return s.Cfg.LogTailDefault
}
func (s *Server) terminalIdle(ctx context.Context) time.Duration {
	settings, err := s.Store.Settings(ctx)
	if err == nil {
		if d, e := time.ParseDuration(settings["terminal_idle_timeout"]); e == nil && d >= time.Minute && d <= 8*time.Hour {
			return d
		}
	}
	return s.Cfg.TerminalIdle
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
