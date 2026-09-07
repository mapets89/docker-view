package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type GatewayClient struct {
	BaseURL, Secret string
	HTTP            *http.Client
}

func NewGatewayClient(base, secret string) *GatewayClient {
	transport := &http.Transport{Proxy: nil}
	return &GatewayClient{strings.TrimRight(base, "/"), secret, &http.Client{Transport: transport, Timeout: 15 * time.Second}}
}
func (g *GatewayClient) request(ctx context.Context, method, path string, body interface{}, stream bool) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil {
			return nil, e
		}
		reader = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(ctx, method, g.BaseURL+path, reader)
	if e != nil {
		return nil, e
	}
	req.Header.Set("X-DockerView-Gateway-Secret", g.Secret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := g.HTTP
	if stream {
		client = &http.Client{Transport: g.HTTP.Transport, Timeout: 0}
	}
	res, e := client.Do(req)
	if e != nil {
		return nil, e
	}
	if res.StatusCode >= 400 {
		defer func() { _ = res.Body.Close() }()
		return nil, errors.New("gateway rejected operation")
	}
	return res, nil
}
func (g *GatewayClient) JSON(ctx context.Context, method, path string, body, out interface{}) error {
	res, e := g.request(ctx, method, path, body, false)
	if e != nil {
		return e
	}
	defer func() { _ = res.Body.Close() }()
	return json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(out)
}
func (g *GatewayClient) Raw(ctx context.Context, path string) (json.RawMessage, error) {
	res, e := g.request(ctx, http.MethodGet, path, nil, false)
	if e != nil {
		return nil, e
	}
	defer func() { _ = res.Body.Close() }()
	return io.ReadAll(io.LimitReader(res.Body, 8<<20))
}
func (g *GatewayClient) Stream(ctx context.Context, path string) (io.ReadCloser, error) {
	res, e := g.request(ctx, http.MethodGet, path, nil, true)
	if e != nil {
		return nil, e
	}
	return res.Body, nil
}
func (g *GatewayClient) Ready(ctx context.Context) error {
	res, e := g.request(ctx, http.MethodGet, "/ready", nil, false)
	if e != nil {
		return e
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != 200 {
		return fmt.Errorf("not ready")
	}
	return nil
}
func (g *GatewayClient) CreateExec(ctx context.Context, id, shell string) (string, string, error) {
	var out struct{ Ticket, Shell string }
	e := g.JSON(ctx, http.MethodPost, "/v1/containers/"+url.PathEscape(id)+"/exec", map[string]string{"shell": shell}, &out)
	return out.Ticket, out.Shell, e
}
func (g *GatewayClient) DialExec(ctx context.Context, ticket string) (*websocket.Conn, error) {
	u, e := url.Parse(g.BaseURL)
	if e != nil {
		return nil, e
	}
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	u.Path = "/v1/exec/" + url.PathEscape(ticket)
	headers := http.Header{"X-DockerView-Gateway-Secret": []string{g.Secret}}
	dialer := *websocket.DefaultDialer
	dialer.Proxy = nil
	c, _, e := dialer.DialContext(ctx, u.String(), headers)
	return c, e
}
func gatewayContainerPath(id, suffix string) string {
	return "/v1/containers/" + url.PathEscape(id) + suffix
}
func logsPath(id string, tail int, follow bool) string {
	return gatewayContainerPath(id, "/logs") + "?tail=" + strconv.Itoa(tail) + "&follow=" + strconv.FormatBool(follow)
}
