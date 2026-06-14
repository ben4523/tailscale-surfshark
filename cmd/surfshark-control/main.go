package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ben4523/tailscale-surfshark/internal/config"
	"github.com/ben4523/tailscale-surfshark/internal/eventbus"
	"github.com/ben4523/tailscale-surfshark/internal/gluetun"
	"github.com/ben4523/tailscale-surfshark/internal/httpapi"
	"github.com/ben4523/tailscale-surfshark/internal/logging"
	"github.com/ben4523/tailscale-surfshark/internal/state"
	tsc "github.com/ben4523/tailscale-surfshark/internal/tailscale"
	"github.com/ben4523/tailscale-surfshark/internal/watchdog"
	"github.com/ben4523/tailscale-surfshark/web"
)

const (
	dataDir   = "/data"
	statePath = "/data/state.json"
	pubIPURL  = "https://ifconfig.io"
	httpPort  = 8080
)

// Ops bridges the HTTP API to gluetun's control server.
// gluetun owns the Surfshark connection; we only orchestrate.
type Ops struct {
	logger *logging.Logger
	st     *state.State
	tsCli  *tsc.Client
	g      *gluetun.Client
	bus    *eventbus.Bus
	cfg    *config.Config
}

// AvailableLocations returns a "Country / City" picker list. Switch behavior:
// if the user picks "Country / City", we set city in gluetun; if "Country" only,
// we set country. The Switch handler parses the slash.
func (o *Ops) AvailableLocations() []string {
	return []string{
		// Format: "Country / City" (slash with spaces). City entries are the
		// Surfshark city names gluetun uses internally.
		"Australia / Sydney", "Australia / Melbourne",
		"Austria / Vienna",
		"Belgium / Brussels",
		"Brazil / Sao Paulo",
		"Bulgaria / Sofia",
		"Canada / Montreal", "Canada / Toronto", "Canada / Vancouver",
		"Chile / Santiago",
		"Czech Republic / Prague",
		"Denmark / Copenhagen",
		"Finland / Helsinki",
		"France / Paris", "France / Marseille",
		"Germany / Berlin", "Germany / Frankfurt", "Germany / Munich",
		"Greece / Athens",
		"Hong Kong / Hong Kong",
		"Hungary / Budapest",
		"Iceland / Reykjavik",
		"India / Chennai", "India / Indore", "India / Mumbai",
		"Indonesia / Jakarta",
		"Ireland / Dublin",
		"Israel / Tel Aviv",
		"Italy / Milan", "Italy / Rome",
		"Japan / Tokyo",
		"Latvia / Riga",
		"Lithuania / Vilnius",
		"Luxembourg / Steinsel",
		"Malaysia / Kuala Lumpur",
		"Mexico / Mexico City",
		"Netherlands / Amsterdam",
		"New Zealand / Auckland",
		"Norway / Oslo",
		"Philippines / Manila",
		"Poland / Warsaw",
		"Portugal / Lisbon",
		"Romania / Bucharest",
		"Serbia / Belgrade",
		"Singapore / Singapore",
		"Slovakia / Bratislava",
		"Slovenia / Ljubljana",
		"South Africa / Johannesburg",
		"South Korea / Seoul",
		"Spain / Madrid", "Spain / Barcelona",
		"Sweden / Stockholm",
		"Switzerland / Zurich",
		"Taiwan / Taipei",
		"Thailand / Bangkok",
		"Turkey / Istanbul",
		"Ukraine / Kyiv",
		"United Arab Emirates / Dubai",
		"United Kingdom / London", "United Kingdom / Manchester", "United Kingdom / Glasgow",
		"United States / New York", "United States / Los Angeles",
		"United States / Chicago", "United States / Miami", "United States / Seattle",
		"United States / Dallas", "United States / San Francisco",
		"Vietnam / Hanoi",
	}
}

func (o *Ops) Toggle(ctx context.Context, on bool) error {
	if err := o.g.SetRunning(ctx, on); err != nil {
		return err
	}
	o.st.Surfshark.Toggle = on
	o.bus.Publish(eventbus.Event{Type: "status_update"})
	return o.st.Save(statePath)
}

func (o *Ops) SwitchLocation(ctx context.Context, loc string) error {
	o.logger.Info("switch location", "location", loc)

	// "Country / City"  → switch by city (more specific). "Country" alone → country.
	var err error
	if idx := strings.Index(loc, " / "); idx > 0 {
		city := strings.TrimSpace(loc[idx+3:])
		err = o.g.SwitchCity(ctx, city)
	} else {
		err = o.g.SwitchCountry(ctx, strings.TrimSpace(loc))
	}
	if err != nil {
		return err
	}

	// gluetun's PUT /v1/vpn/settings stores the new settings but does NOT
	// force a reconnect on its own. Cycle the VPN to pick them up.
	if err := o.g.SetRunning(ctx, false); err != nil {
		o.logger.Warn("stop before reconnect failed", "err", err.Error())
	}
	time.Sleep(1 * time.Second)
	if err := o.g.SetRunning(ctx, true); err != nil {
		return fmt.Errorf("restart vpn after switch: %w", err)
	}

	o.st.Surfshark.CurrentLocation = loc
	_ = o.st.Save(statePath)
	o.bus.Publish(eventbus.Event{Type: "status_update"})

	// Wait for the new public IP to materialize (gluetun re-queries it after
	// reconnect, ~5-15s).
	prevIP := o.st.Stats.PublicIP
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if ip, err := o.g.PublicIP(ctx); err == nil && ip != "" && ip != prevIP {
			o.st.Stats.PublicIP = ip
			o.st.Stats.LastMeasured = time.Now().UTC()
			_ = o.st.Save(statePath)
			o.bus.Publish(eventbus.Event{Type: "status_update"})
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("public IP did not change within 30s (still %s)", prevIP)
}

func (o *Ops) Refresh(ctx context.Context) error {
	// No-op now: gluetun maintains its own server list. We just refresh UI state.
	o.bus.Publish(eventbus.Event{Type: "refresh_complete"})
	return nil
}

func (o *Ops) SetPreferred(ctx context.Context, locs []string) error {
	o.st.Surfshark.PreferredLocations = locs
	o.bus.Publish(eventbus.Event{Type: "status_update"})
	return o.st.Save(statePath)
}

func main() {
	logger := logging.New(os.Stdout, os.Getenv("LOG_LEVEL"))
	cfg, err := config.Load()
	if err != nil {
		logger.Error("config", "error", err.Error())
		os.Exit(1)
	}

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		logger.Error("mkdir data", "error", err.Error())
		os.Exit(1)
	}
	st, err := state.Load(statePath)
	if err != nil {
		logger.Error("state load", "error", err.Error())
		os.Exit(1)
	}
	st.KillSwitch.EnabledByEnv = cfg.KillSwitch

	bus := eventbus.New(64)
	tsCli := tsc.New()

	gluetunBase := os.Getenv("GLUETUN_URL")
	if gluetunBase == "" {
		gluetunBase = "http://127.0.0.1:8000"
	}
	g := gluetun.New(gluetunBase)

	ops := &Ops{logger: logger, st: st, tsCli: tsCli, g: g, bus: bus, cfg: cfg}

	srv := httpapi.NewServer(httpapi.Deps{
		Whois:   tsCli,
		Allowed: cfg.TSAllowedUsers,
		State:   st,
		Bus:     bus,
		Ops:     ops,
		Logger:  logger,
	})
	srv.MountStatic(web.FS)

	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

	// Watchdog: poll gluetun status; publish updates and persist last public IP.
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-rootCtx.Done():
				return
			case <-t.C:
				if ip, err := g.PublicIP(rootCtx); err == nil {
					st.Stats.PublicIP = ip
					st.Stats.LastMeasured = time.Now().UTC()
					_ = st.Save(statePath)
					bus.Publish(eventbus.Event{Type: "status_update"})
				}
			}
		}
	}()

	tsWatch := watchdog.NewTailscaledWatchdog(
		func(ctx context.Context) error { _, e := tsCli.Status(ctx); return e },
		func(ctx context.Context) error { return nil },
		30*time.Second,
	)
	go tsWatch.Run(rootCtx)

	httpServer := &http.Server{
		Addr:              "127.0.0.1:" + fmt.Sprintf("%d", httpPort),
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		logger.Info("http listening", "addr", httpServer.Addr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("http server", "error", err.Error())
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	logger.Info("shutting down")
	shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
	_ = httpServer.Shutdown(shutdownCtx)
	c()
}
