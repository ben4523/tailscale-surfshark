package watchdog

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/ben4523/tailscale-surfshark/internal/eventbus"
	"github.com/ben4523/tailscale-surfshark/internal/state"
)

// StatusPoller refreshes public-facing stats periodically.
// It mutates the State and publishes a "status_update" event on the bus.
type StatusPoller struct {
	bus      *eventbus.Bus
	st       *state.State
	stPath   string
	hsFunc   func(ctx context.Context) (time.Time, error)
	pubIPURL string
	hsEvery  time.Duration
	ipEvery  time.Duration
}

func NewStatusPoller(bus *eventbus.Bus, st *state.State, stPath string,
	handshake func(ctx context.Context) (time.Time, error),
	publicIPURL string, hsEvery, ipEvery time.Duration) *StatusPoller {
	return &StatusPoller{
		bus: bus, st: st, stPath: stPath,
		hsFunc: handshake, pubIPURL: publicIPURL,
		hsEvery: hsEvery, ipEvery: ipEvery,
	}
}

func (p *StatusPoller) Run(ctx context.Context) {
	hsT := time.NewTicker(p.hsEvery)
	ipT := time.NewTicker(p.ipEvery)
	defer hsT.Stop()
	defer ipT.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-hsT.C:
			if hs, err := p.hsFunc(ctx); err == nil {
				p.st.Stats.WG0LastHandshake = hs
				_ = p.st.Save(p.stPath)
				p.bus.Publish(eventbus.Event{Type: "status_update"})
			}
		case <-ipT.C:
			ip, err := p.measurePublicIP(ctx)
			if err == nil {
				p.st.Stats.PublicIP = ip
				p.st.Stats.LastMeasured = time.Now().UTC()
				_ = p.st.Save(p.stPath)
				p.bus.Publish(eventbus.Event{Type: "status_update"})
			}
		}
	}
}

func (p *StatusPoller) measurePublicIP(ctx context.Context) (string, error) {
	c := &http.Client{Timeout: 5 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "GET", p.pubIPURL, nil)
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	ip := string(b)
	if len(ip) > 0 && ip[len(ip)-1] == '\n' {
		ip = ip[:len(ip)-1]
	}
	if net.ParseIP(ip) == nil {
		return "", errors.New("not an IP: " + ip)
	}
	return ip, nil
}
