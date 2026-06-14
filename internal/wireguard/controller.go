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
	// wireguard-go (userspace) is observed to sometimes block its parent
	// after the TUN is created, so wg-quick can hang waiting for it. Decouple:
	// run wg-quick in a goroutine; in parallel, poll `ip link show wg0`. As
	// soon as wg0 is visible we proceed, regardless of whether wg-quick
	// has finished yet. Errors from wg-quick are still propagated.
	upCtx, upCancel := context.WithTimeout(ctx, 10*time.Second)
	defer upCancel()

	done := make(chan error, 1)
	go func() {
		_, err := c.r.Run(upCtx, "wg-quick", "up", confPath)
		done <- err
	}()

	deadline := time.After(10 * time.Second)
	for {
		// Authoritative: if wg-quick reported back, honor the result first.
		select {
		case err := <-done:
			if err != nil {
				return fmt.Errorf("wg-quick up: %w", err)
			}
			// wg-quick succeeded — wg0 should be present (allow a tiny grace).
			if _, qerr := c.r.Run(ctx, "ip", "link", "show", "wg0"); qerr == nil {
				return nil
			}
			time.Sleep(200 * time.Millisecond)
			if _, qerr := c.r.Run(ctx, "ip", "link", "show", "wg0"); qerr == nil {
				return nil
			}
			return fmt.Errorf("wg-quick up exited ok but wg0 never appeared")
		default:
		}

		// wg-quick still running — bypass the wait if wg0 is already up.
		if _, err := c.r.Run(ctx, "ip", "link", "show", "wg0"); err == nil {
			c.logInfo("wg-quick: wg0 visible, proceeding (background wg-quick may still be running)")
			return nil
		}

		select {
		case <-deadline:
			return fmt.Errorf("wg-quick up: wg0 never appeared within 10s")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (c *Controller) Down(ctx context.Context, ifaceOrPath string) error {
	_, err := c.r.Run(ctx, "wg-quick", "down", ifaceOrPath)
	return err
}

// DetectLANInterface returns the interface name carrying the host's default
// route. Synology systems running Open vSwitch have an `eth0` slave that
// can't be used directly; the real LAN interface is `ovs_eth0`. Reading the
// default route avoids hard-coding either.
func (c *Controller) DetectLANInterface(ctx context.Context) (string, error) {
	out, err := c.r.Run(ctx, "ip", "route", "show", "default")
	if err != nil {
		return "", err
	}
	// "default via 192.168.0.1 dev ovs_eth0 ..."  -> we want "ovs_eth0"
	fields := strings.Fields(string(out))
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "dev" {
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("no `dev` token in `ip route show default`: %q", string(out))
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
	if err := step("peer-exception", "ip", "route", "replace", endpointIP+"/32", "dev", lanIface); err != nil {
		c.RemoveDefaultRoutes(context.Background(), endpointIP, lanIface)
		return err
	}
	if err := step("half-default-low", "ip", "route", "replace", "0.0.0.0/1", "dev", "wg0"); err != nil {
		c.RemoveDefaultRoutes(context.Background(), endpointIP, lanIface)
		return err
	}
	if err := step("half-default-high", "ip", "route", "replace", "128.0.0.0/1", "dev", "wg0"); err != nil {
		c.RemoveDefaultRoutes(context.Background(), endpointIP, lanIface)
		return err
	}
	c.logInfo("routes: installed", "peer", endpointIP, "via_iface", "wg0")
	return nil
}

// AddPeerException adds a single host route to keep traffic toward `ip`
// off wg0 (so the WG control packets themselves can reach the peer).
// Best-effort: silently ignored if the route already exists.
func (c *Controller) AddPeerException(ctx context.Context, ip, lanIface string) error {
	_, err := c.r.Run(ctx, "ip", "route", "replace", ip+"/32", "dev", lanIface)
	return err
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
