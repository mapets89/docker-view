package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dockerview/dockerview/backend/internal/security"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
)

type ticket struct {
	ExecID, ContainerID string
	Expires             time.Time
	Used                bool
}
type Handler struct {
	Docker   DockerService
	Secret   string
	tickets  map[string]*ticket
	mu       sync.Mutex
	upgrader websocket.Upgrader
}

func NewHandler(d DockerService, secret string) *Handler {
	return &Handler{Docker: d, Secret: secret, tickets: map[string]*ticket{}, upgrader: websocket.Upgrader{ReadBufferSize: 4096, WriteBufferSize: 4096, CheckOrigin: func(r *http.Request) bool { return r.Header.Get("Origin") == "" }}}
}

func (h *Handler) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(h.recoverer, h.limitBody)
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) { write(w, 200, map[string]string{"status": "ok"}) })
	r.Get("/ready", h.ready)
	r.Group(func(r chi.Router) {
		r.Use(h.auth)
		r.Get("/v1/info", h.info)
		r.Get("/v1/containers", h.list)
		r.Route("/v1/containers/{id}", func(r chi.Router) {
			r.Get("/", h.inspect)
			r.Get("/stats", h.stats)
			r.Get("/logs", h.logs)
			r.Post("/restart", h.restart)
			r.Post("/exec", h.createExec)
		})
		r.Get("/v1/exec/{ticket}", h.attach)
	})
	r.NotFound(func(w http.ResponseWriter, _ *http.Request) {
		problem(w, 404, "OPERATION_NOT_ALLOWED", "Gateway operation is not allowed")
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) {
		problem(w, 405, "OPERATION_NOT_ALLOWED", "Gateway operation is not allowed")
	})
	return r
}
func (h *Handler) info(w http.ResponseWriter, r *http.Request) {
	raw, err := h.Docker.Info(r.Context())
	if err != nil {
		dockerProblem(w, err)
		return
	}
	jsonRaw(w, raw)
}
func (h *Handler) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !security.ConstantTimeSecret(h.Secret, r.Header.Get("X-DockerView-Gateway-Secret")) {
			problem(w, 401, "UNAUTHORIZED", "Invalid gateway credentials")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (h *Handler) limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		next.ServeHTTP(w, r)
	})
}
func (h *Handler) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				slog.Error("gateway panic", "component", "gateway")
				problem(w, 500, "INTERNAL", "Internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
func (h *Handler) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := h.Docker.Ping(ctx); err != nil {
		problem(w, 503, "DOCKER_UNAVAILABLE", "Docker Engine unavailable")
		return
	}
	write(w, 200, map[string]string{"status": "ready"})
}
func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	raw, err := h.Docker.List(r.Context())
	if err != nil {
		dockerProblem(w, err)
		return
	}
	jsonRaw(w, raw)
}
func (h *Handler) inspectRaw(r *http.Request) (json.RawMessage, string, error) {
	id := chi.URLParam(r, "id")
	if !security.ValidateContainerID(id) {
		return nil, "", errors.New("invalid container")
	}
	raw, err := h.Docker.Inspect(r.Context(), id)
	return raw, id, err
}
func (h *Handler) inspect(w http.ResponseWriter, r *http.Request) {
	raw, _, err := h.inspectRaw(r)
	if err != nil {
		dockerProblem(w, err)
		return
	}
	jsonRaw(w, raw)
}
func (h *Handler) stats(w http.ResponseWriter, r *http.Request) {
	_, id, err := h.inspectRaw(r)
	if err != nil {
		dockerProblem(w, err)
		return
	}
	body, err := h.Docker.Stats(r.Context(), id)
	if err != nil {
		dockerProblem(w, err)
		return
	}
	defer func() { _ = body.Close() }()
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.Copy(w, io.LimitReader(body, 4<<20))
}
func (h *Handler) logs(w http.ResponseWriter, r *http.Request) {
	_, id, err := h.inspectRaw(r)
	if err != nil {
		dockerProblem(w, err)
		return
	}
	tail := security.ParseBoundedInt(r.URL.Query().Get("tail"), 500, 1, 5000)
	follow := r.URL.Query().Get("follow") == "true"
	body, err := h.Docker.Logs(r.Context(), id, tail, follow)
	if err != nil {
		dockerProblem(w, err)
		return
	}
	defer func() { _ = body.Close() }()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	buf := make([]byte, 32<<10)
	for {
		n, e := body.Read(buf)
		if n > 0 {
			if _, x := w.Write(buf[:n]); x != nil {
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
func (h *Handler) restart(w http.ResponseWriter, r *http.Request) {
	raw, id, err := h.inspectRaw(r)
	if err != nil {
		dockerProblem(w, err)
		return
	}
	if IsSystem(raw) {
		problem(w, 403, "SYSTEM_CONTAINER", "System containers cannot be restarted")
		return
	}
	if err = h.Docker.Restart(r.Context(), id); err != nil {
		dockerProblem(w, err)
		return
	}
	write(w, 202, map[string]string{"status": "restarting"})
}
func (h *Handler) createExec(w http.ResponseWriter, r *http.Request) {
	raw, id, err := h.inspectRaw(r)
	if err != nil {
		dockerProblem(w, err)
		return
	}
	if IsSystem(raw) {
		problem(w, 403, "SYSTEM_CONTAINER", "System containers cannot be accessed with exec")
		return
	}
	var in struct {
		Shell string `json:"shell"`
	}
	if err = decode(r, &in); err != nil {
		problem(w, 400, "INVALID_REQUEST", "Invalid request")
		return
	}
	shell, ok := ValidateShell(in.Shell)
	if !ok {
		problem(w, 400, "INVALID_SHELL", "Only approved interactive shells are allowed")
		return
	}
	execID, resolvedShell, err := h.Docker.CreateExec(r.Context(), id, shell)
	if err != nil {
		dockerProblem(w, err)
		return
	}
	token, _ := security.RandomToken(24)
	h.mu.Lock()
	h.cleanupTickets()
	h.tickets[token] = &ticket{ExecID: execID, ContainerID: id, Expires: time.Now().Add(30 * time.Second)}
	h.mu.Unlock()
	write(w, 201, map[string]string{"ticket": token, "shell": resolvedShell})
}
func (h *Handler) attach(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "ticket")
	h.mu.Lock()
	t, ok := h.tickets[token]
	if ok && (t.Used || time.Now().After(t.Expires)) {
		ok = false
	}
	if ok {
		t.Used = true
	}
	h.mu.Unlock()
	if !ok {
		problem(w, 404, "INVALID_TICKET", "Terminal ticket is invalid or expired")
		return
	}
	ws, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer func() { _ = ws.Close() }()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	attached, err := h.Docker.AttachExec(ctx, t.ExecID)
	if err != nil {
		_ = ws.WriteJSON(map[string]string{"type": "error", "message": "Unable to attach terminal"})
		return
	}
	defer attached.Close()
	ws.SetReadLimit(16 << 10)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 8192)
		for {
			n, e := attached.Reader.Read(buf)
			if n > 0 {
				_ = ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if x := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); x != nil {
					return
				}
			}
			if e != nil {
				return
			}
		}
	}()
	for {
		typ, msg, e := ws.ReadMessage()
		if e != nil {
			break
		}
		if typ != websocket.BinaryMessage && typ != websocket.TextMessage {
			continue
		}
		var ctl struct {
			Type string `json:"type"`
			Cols uint   `json:"cols"`
			Rows uint   `json:"rows"`
		}
		if typ == websocket.TextMessage && json.Unmarshal(msg, &ctl) == nil && ctl.Type == "resize" {
			if ValidateResize(ctl.Cols, ctl.Rows) {
				_ = h.Docker.ResizeExec(ctx, t.ExecID, ctl.Cols, ctl.Rows)
			}
			continue
		}
		if len(msg) > 16<<10 {
			break
		}
		if _, e = attached.Conn.Write(msg); e != nil {
			break
		}
	}
	attached.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
	}
}
func (h *Handler) cleanupTickets() {
	for k, v := range h.tickets {
		if v.Used || time.Now().After(v.Expires) {
			delete(h.tickets, k)
		}
	}
}

func decode(r *http.Request, v interface{}) error {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var extra interface{}
	if d.Decode(&extra) != io.EOF {
		return errors.New("multiple values")
	}
	return nil
}
func write(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func jsonRaw(w http.ResponseWriter, v json.RawMessage) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(v)
}
func problem(w http.ResponseWriter, status int, code, message string) {
	write(w, status, map[string]interface{}{"error": map[string]string{"code": code, "message": message}})
}
func dockerProblem(w http.ResponseWriter, err error) {
	status := 502
	code := "DOCKER_ERROR"
	msg := "Docker operation failed"
	low := strings.ToLower(err.Error())
	if strings.Contains(low, "not found") || strings.Contains(low, "no such container") {
		status = 404
		code = "CONTAINER_NOT_FOUND"
		msg = "Container not found"
	}
	problem(w, status, code, msg)
}
