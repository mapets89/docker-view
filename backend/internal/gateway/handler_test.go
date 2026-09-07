package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeDocker struct {
	system  bool
	created int
}

func (f *fakeDocker) Ping(context.Context) error { return nil }
func (f *fakeDocker) Info(context.Context) (json.RawMessage, error) {
	return json.RawMessage(`{"NCPU":8,"MemTotal":17179869184}`), nil
}
func (f *fakeDocker) List(context.Context) (json.RawMessage, error) {
	return json.RawMessage(`[]`), nil
}
func (f *fakeDocker) Inspect(_ context.Context, id string) (json.RawMessage, error) {
	label := "false"
	if f.system {
		label = "true"
	}
	return json.RawMessage(`{"Id":"` + id + `","Config":{"Labels":{"dockerview.system":"` + label + `"}}}`), nil
}
func (f *fakeDocker) Stats(context.Context, string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewBufferString(`{}`)), nil
}
func (f *fakeDocker) Logs(context.Context, string, int, bool) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewBuffer(nil)), nil
}
func (f *fakeDocker) Restart(context.Context, string) error { return nil }
func (f *fakeDocker) CreateExec(_ context.Context, _ string, shell string) (string, string, error) {
	f.created++
	return "exec", shell, nil
}
func (f *fakeDocker) AttachExec(context.Context, string) (*Attach, error) {
	a, b := net.Pipe()
	go func() { _ = b.Close() }()
	return &Attach{Conn: a, Reader: bufio.NewReader(a)}, nil
}
func (f *fakeDocker) ResizeExec(context.Context, string, uint, uint) error { return nil }

func TestGatewayAuthentication(t *testing.T) {
	h := NewHandler(&fakeDocker{}, "01234567890123456789012345678901").Router()
	for _, secret := range []string{"", "wrong"} {
		r := httptest.NewRequest(http.MethodGet, "/v1/containers", nil)
		r.Header.Set("X-DockerView-Gateway-Secret", secret)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatalf("secret %q got %d", secret, w.Code)
		}
	}
}
func TestGatewaySystemExecAndUnknownFieldsRejected(t *testing.T) {
	f := &fakeDocker{system: true}
	h := NewHandler(f, "01234567890123456789012345678901").Router()
	r := httptest.NewRequest(http.MethodPost, "/v1/containers/system/exec", bytes.NewBufferString(`{"shell":"/bin/sh"}`))
	r.Header.Set("X-DockerView-Gateway-Secret", "01234567890123456789012345678901")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 || f.created != 0 {
		t.Fatalf("system exec reached Docker: status=%d created=%d", w.Code, f.created)
	}
	f.system = false
	r = httptest.NewRequest(http.MethodPost, "/v1/containers/api/exec", bytes.NewBufferString(`{"shell":"/bin/sh","privileged":true}`))
	r.Header.Set("X-DockerView-Gateway-Secret", "01234567890123456789012345678901")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 400 || f.created != 0 {
		t.Fatalf("arbitrary option accepted: status=%d", w.Code)
	}
}
func TestResizeBoundsAndShellAllowlist(t *testing.T) {
	if ValidateResize(9999, 24) || ValidateResize(80, 0) {
		t.Fatal("oversized resize accepted")
	}
	if _, ok := ValidateShell("/bin/zsh"); ok {
		t.Fatal("arbitrary shell accepted")
	}
}
