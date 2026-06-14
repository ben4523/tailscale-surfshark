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
// except the connection to the Surfshark peer itself. Avoids wg-quick's
// policy-routing path (which requires writing the src_valid_mark sysctl —
// blocked on Synology DSM).
//
// Layout:
//
//	<endpointIP>/32 dev <lanIface>  : keep WG <-> peer traffic on the LAN
//	0.0.0.0/1 dev wg0               : half-default 1
//	128.0.0.0/1 dev wg0             : half-default 2
//
// The two /1 routes are more specific than the host's pre-existing default
// (0.0.0.0/0) so they win without us having to touch the original default.
func (c *Controller) InstallDefaultRoutes(ctx context.Context, endpointIP, lanIface string) error {
	cmds := [][]string{
		{"ip", "route", "add", endpointIP + "/32", "dev", lanIface},
		{"ip", "route", "add", "0.0.0.0/1", "dev", "wg0"},
		{"ip", "route", "add", "128.0.0.0/1", "dev", "wg0"},
	}
	for _, cmd := range cmds {
		if _, err := c.r.Run(ctx, cmd[0], cmd[1:]...); err != nil {
			c.RemoveDefaultRoutes(context.Background(), endpointIP, lanIface)
			return err
		}
	}
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
