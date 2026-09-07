package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"
)

type Attach struct {
	Conn   net.Conn
	Reader *bufio.Reader
	close  func()
}

func (a *Attach) Close() {
	if a.close != nil {
		a.close()
	} else if a.Conn != nil {
		_ = a.Conn.Close()
	}
}

type DockerService interface {
	Ping(context.Context) error
	Info(context.Context) (json.RawMessage, error)
	List(context.Context) (json.RawMessage, error)
	Inspect(context.Context, string) (json.RawMessage, error)
	Stats(context.Context, string) (io.ReadCloser, error)
	Logs(context.Context, string, int, bool) (io.ReadCloser, error)
	Restart(context.Context, string) error
	CreateExec(context.Context, string, string) (string, string, error)
	AttachExec(context.Context, string) (*Attach, error)
	ResizeExec(context.Context, string, uint, uint) error
}

type MobyService struct{ cli *client.Client }

func NewMobyService() (*MobyService, error) {
	c, err := client.New(client.FromEnv)
	if err != nil {
		return nil, err
	}
	return &MobyService{c}, nil
}
func (m *MobyService) Close() error { return m.cli.Close() }
func (m *MobyService) Ping(ctx context.Context) error {
	_, err := m.cli.Ping(ctx, client.PingOptions{})
	return err
}
func (m *MobyService) Info(ctx context.Context) (json.RawMessage, error) {
	r, err := m.cli.Info(ctx, client.InfoOptions{})
	if err != nil {
		return nil, err
	}
	return json.Marshal(r.Info)
}
func (m *MobyService) List(ctx context.Context) (json.RawMessage, error) {
	r, err := m.cli.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return nil, err
	}
	return json.Marshal(r.Items)
}
func (m *MobyService) Inspect(ctx context.Context, id string) (json.RawMessage, error) {
	r, err := m.cli.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if err != nil {
		return nil, err
	}
	return r.Raw, nil
}
func (m *MobyService) Stats(ctx context.Context, id string) (io.ReadCloser, error) {
	r, err := m.cli.ContainerStats(ctx, id, client.ContainerStatsOptions{Stream: false})
	return r.Body, err
}
func (m *MobyService) Logs(ctx context.Context, id string, tail int, follow bool) (io.ReadCloser, error) {
	r, err := m.cli.ContainerLogs(ctx, id, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true, Timestamps: true, Follow: follow, Tail: strconv.Itoa(tail)})
	if err != nil {
		return nil, err
	}
	inspect, e := m.cli.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if e == nil && inspect.Container.Config != nil && inspect.Container.Config.Tty {
		return r, nil
	}
	pr, pw := io.Pipe()
	go func() { defer func() { _ = r.Close() }(); _, e := stdcopy.StdCopy(pw, pw, r); _ = pw.CloseWithError(e) }()
	return pr, nil
}

func (m *MobyService) Restart(ctx context.Context, id string) error {
	seconds := 10
	_, err := m.cli.ContainerRestart(ctx, id, client.ContainerRestartOptions{Timeout: &seconds})
	return err
}
func (m *MobyService) CreateExec(ctx context.Context, id, shell string) (string, string, error) {
	if shell == "auto" {
		var detected string
		for _, candidate := range []string{"/bin/bash", "/bin/sh", "/bin/ash"} {
			probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			result, err := m.cli.ExecCreate(probeCtx, id, client.ExecCreateOptions{AttachStdout: true, AttachStderr: true, Cmd: []string{candidate, "-c", "exit 0"}})
			if err == nil {
				attached, attachErr := m.cli.ExecAttach(probeCtx, result.ID, client.ExecAttachOptions{})
				if attachErr == nil {
					_, _ = io.Copy(io.Discard, attached.Reader)
					attached.Close()
					inspected, inspectErr := m.cli.ExecInspect(probeCtx, result.ID, client.ExecInspectOptions{})
					if inspectErr == nil && inspected.ExitCode == 0 {
						detected = candidate
					}
				}
			}
			cancel()
			if detected != "" {
				shell = detected
				break
			}
		}
		if shell == "auto" {
			return "", "", errors.New("no supported shell found")
		}
	}
	r, err := m.cli.ExecCreate(ctx, id, client.ExecCreateOptions{TTY: true, AttachStdin: true, AttachStdout: true, AttachStderr: true, Cmd: []string{shell}})
	return r.ID, shell, err
}
func (m *MobyService) AttachExec(ctx context.Context, id string) (*Attach, error) {
	r, err := m.cli.ExecAttach(ctx, id, client.ExecAttachOptions{TTY: true})
	if err != nil {
		return nil, err
	}
	return &Attach{Conn: r.Conn, Reader: r.Reader, close: r.Close}, nil
}
func (m *MobyService) ResizeExec(ctx context.Context, id string, cols, rows uint) error {
	_, err := m.cli.ExecResize(ctx, id, client.ExecResizeOptions{Height: rows, Width: cols})
	return err
}

func IsSystem(raw json.RawMessage) bool {
	var v struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	return json.Unmarshal(raw, &v) == nil && strings.EqualFold(v.Config.Labels["dockerview.system"], "true")
}
func ValidateShell(s string) (string, bool) {
	switch s {
	case "", "auto":
		return "auto", true
	case "/bin/sh":
		return s, true
	case "/bin/bash":
		return s, true
	case "/bin/ash":
		return s, true
	default:
		return "", false
	}
}
func ValidateResize(cols, rows uint) bool {
	return cols >= 10 && cols <= 500 && rows >= 5 && rows <= 300
}
