//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestLiveTerminal(t *testing.T) {
	base := os.Getenv("DOCKERVIEW_SMOKE_URL")
	if base == "" {
		base = "http://localhost:8080"
	}
	username, password := os.Getenv("DOCKERVIEW_SMOKE_USER"), os.Getenv("DOCKERVIEW_SMOKE_PASSWORD")
	if username == "" || password == "" {
		t.Skip("set smoke credentials")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	res, err := client.Post(base+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		data, _ := io.ReadAll(res.Body)
		t.Fatalf("login %d: %s", res.StatusCode, data)
	}
	var session, csrf *http.Cookie
	for _, c := range res.Cookies() {
		switch c.Name {
		case "dv_session":
			session = c
		case "dv_csrf":
			csrf = c
		}
	}
	if session == nil || csrf == nil {
		t.Fatal("auth cookies missing")
	}
	req, _ := http.NewRequest(http.MethodGet, base+"/api/v1/containers/", nil)
	req.AddCookie(session)
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var list []struct {
		ID    string `json:"Id"`
		Names []string
	}
	if err = json.NewDecoder(res.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	id := ""
	for _, c := range list {
		if len(c.Names) > 0 && strings.TrimPrefix(c.Names[0], "/") == "dockerview-smoke-target" {
			id = c.ID
		}
	}
	if id == "" {
		t.Skip("dockerview-smoke-target not running")
	}
	body, _ = json.Marshal(map[string]string{"shell": "/bin/sh"})
	req, _ = http.NewRequest(http.MethodPost, base+"/api/v1/containers/"+url.PathEscape(id)+"/terminal", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf.Value)
	req.Header.Set("Origin", base)
	req.AddCookie(session)
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var created struct {
		SessionID string `json:"session_id"`
	}
	if err = json.NewDecoder(res.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 201 {
		t.Fatalf("terminal create status %d", res.StatusCode)
	}
	wsURL := "ws" + strings.TrimPrefix(base, "http") + "/api/v1/terminal/" + url.PathEscape(created.SessionID) + "/ws?csrf=" + url.QueryEscape(csrf.Value)
	headers := http.Header{"Origin": []string{base}, "Cookie": []string{session.Name + "=" + session.Value}}
	ws, resp, err := websocket.DefaultDialer.Dial(wsURL, headers)
	if err != nil {
		if resp != nil {
			t.Fatalf("websocket status %d: %v", resp.StatusCode, err)
		}
		t.Fatal(err)
	}
	defer ws.Close()
	if err = ws.WriteMessage(websocket.BinaryMessage, []byte("echo dockerview-terminal-ok\n")); err != nil {
		t.Fatal(err)
	}
	_ = ws.SetReadDeadline(time.Now().Add(10 * time.Second))
	var output strings.Builder
	for !strings.Contains(output.String(), "dockerview-terminal-ok") {
		_, msg, e := ws.ReadMessage()
		if e != nil {
			t.Fatalf("terminal read: %v; output=%q", e, output.String())
		}
		output.Write(msg)
	}
	_ = ws.WriteMessage(websocket.BinaryMessage, []byte("exit\n"))
}
