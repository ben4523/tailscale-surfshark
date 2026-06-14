package wireguard

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, string(out))
	}
	return out, nil
}

type Controller struct{ r Runner }

func New() *Controller                   { return &Controller{r: execRunner{}} }
func NewWithRunner(r Runner) *Controller { return &Controller{r: r} }

func (c *Controller) Up(ctx context.Context, confPath string) error {
	_, err := c.r.Run(ctx, "wg-quick", "up", confPath)
	return err
}

func (c *Controller) Down(ctx context.Context, ifaceOrPath string) error {
	_, err := c.r.Run(ctx, "wg-quick", "down", ifaceOrPath)
	return err
}

func (c *Controller) LastHandshake(ctx context.Context, iface string) (time.Time, error) {
	out, err := c.r.Run(ctx, "wg", "show", iface, "latest-handshakes")
	if err != nil {
		return time.Time{}, err
	}
	line := strings.TrimSpace(string(out))
	if line == "" {
		return time.Time{}, nil
	}
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return time.Time{}, fmt.Errorf("unexpected output: %q", line)
	}
	ts, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	if ts == 0 {
		return time.Time{}, nil
	}
	return time.Unix(ts, 0), nil
}
