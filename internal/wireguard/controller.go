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

type Logger interface {
	Info(msg string, kv ...any)
	Warn(msg string, kv ...any)
}

type Controller struct {
	r Runner
	l Logger
}

func New() *Controller                   { return &Controller{r: execRunner{}} }
func NewWithRunner(r Runner) *Controller { return &Controller{r: r} }

// SetLogger enables per-command diagnostic logging. Without it the controller
// is silent (useful for unit tests).
func (c *Controller) SetLogger(l Logger) { c.l = l }

func (c *Controller) logInfo(msg string, kv ...any) {
	if c.l != nil {
		c.l.Info(msg, kv...)
	}
}

func (c *Controller) logWarn(msg string, kv ...any) {
	if c.l != nil {
		c.l.Warn(msg, kv...)
	}
}

func (c *Controller) Up(ctx context.Context, confPath string) error {
	if _, err := c.r.Run(ctx, "wg-quick", "up", confPath); err != nil {
		return err
	}
	// wireguard-go (userspace) sometimes returns from its parent process a
	// hair before the kernel TUN device is queryable. Spin briefly (up to ~2s)
	// until `ip link show wg0` succeeds — then any follow-up `ip route add ...
	// dev wg0` will not race.
	for i := 0; i < 20; i++ {
		if _, err := c.r.Run(ctx, "ip", "link", "show", "wg0"); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("wg-quick up returned ok but wg0 never appeared (within 2s)")
}

func (c *Controller) Down(ctx context.Context, ifaceOrPath string) error {
	_, err := c.r.Run(ctx, "wg-quick", "down", ifaceOrPath)
	return err
}

// InstallDefaultRoutes wires the kernel routing so all traffic exits via wg0
// except the connection to the Surfshark peer itself.
func (c *Controller) InstallDefaultRoutes(ctx context.Context, endpointIP, lanIface string) error {
	// Hard timeout per command so a stalled netlink call can't hang the whole
	// request indefinitely.
	step := func(label string, args ...string) error {
		c.logInfo("routes: "+label, "cmd", strings.Join(args, " "))
		stepCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		out, err := c.r.Run(stepCtx, args[0], args[1:]...)
		if err != nil {
			c.logWarn("routes: step failed", "label", label, "err", err.Error(), "out", string(out))
		}
		return err
	}

	// Defensive: make sure wg0 is actually up before we attach routes to it.
	// wg-quick should have done this, but the userspace impl sometimes races.
	if err := step("link-up", "ip", "link", "set", "dev", "wg0", "up"); err != nil {
		return err
	}
	if err := step("peer-exception", "ip", "route", "add", endpointIP+"/32", "dev", lanIface); err != nil {
		c.RemoveDefaultRoutes(context.Background(), endpointIP, lanIface)
		return err
	}
	if err := step("half-default-low", "ip", "route", "add", "0.0.0.0/1", "dev", "wg0"); err != nil {
		c.RemoveDefaultRoutes(context.Background(), endpointIP, lanIface)
		return err
	}
	if err := step("half-default-high", "ip", "route", "add", "128.0.0.0/1", "dev", "wg0"); err != nil {
		c.RemoveDefaultRoutes(context.Background(), endpointIP, lanIface)
		return err
	}
	c.logInfo("routes: installed", "peer", endpointIP, "via_iface", "wg0")
	return nil
}

// RemoveDefaultRoutes is best-effort; missing-route errors are ignored.
func (c *Controller) RemoveDefaultRoutes(ctx context.Context, endpointIP, lanIface string) {
	_, _ = c.r.Run(ctx, "ip", "route", "del", "0.0.0.0/1", "dev", "wg0")
	_, _ = c.r.Run(ctx, "ip", "route", "del", "128.0.0.0/1", "dev", "wg0")
	if endpointIP != "" {
		_, _ = c.r.Run(ctx, "ip", "route", "del", endpointIP+"/32", "dev", lanIface)
	}
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
