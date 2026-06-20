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

	// Parse "Country / City" → country, optional city.
	country, city := loc, ""
	if idx := strings.Index(loc, " / "); idx > 0 {
		country = strings.TrimSpace(loc[:idx])
		city = strings.TrimSpace(loc[idx+3:])
	}

	// Write both country AND city explicitly. PUT /v1/vpn/settings merges, so
	// sending only city leaves a stale Countries=[boot env var] in place, and
	// gluetun's filter intersects them — usually zero matches → random server
	// in the old country. SwitchTarget overrides both fields together.
	// Also persist the new country to .env so a future restart picks it up.
	if err := o.g.SwitchTarget(ctx, country, city); err != nil {
		return err
	}
	_ = o.updateEnvSurfsharkLocation(country, city) // best-effort

	o.st.Surfshark.CurrentLocation = loc
	_ = o.st.Save(statePath)
	o.bus.Publish(eventbus.Event{Type: "status_update"})

	// Cycle the VPN asynchronously so the HTTP response returns immediately.
	// The brief tunnel-down window (~5–10s) does temporarily cut egress from
	// gluetun's netns — tailscaled's DERP connection may pause but the netns
	// itself persists, so as soon as the new tunnel is up the UI recovers.
	go func() {
		bg, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := o.g.SetRunning(bg, false); err != nil {
			o.logger.Error("gluetun stop", "error", err.Error())
			return
		}
		time.Sleep(500 * time.Millisecond)
		if err := o.g.SetRunning(bg, true); err != nil {
			o.logger.Error("gluetun start", "error", err.Error())
		}
	}()
	return nil
}

// updateEnvSurfsharkLocation rewrites SURFSHARK_COUNTRY (and optionally a new
// SURFSHARK_CITIES) in /workspace/.env, preserving every other line as-is.
func (o *Ops) updateEnvSurfsharkLocation(country, city string) error {
	const envPath = "/workspace/.env"
	data, err := os.ReadFile(envPath)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	wroteCountry := false
	wroteCities := false
	for i, l := range lines {
		switch {
		case strings.HasPrefix(l, "SURFSHARK_COUNTRY="):
			lines[i] = "SURFSHARK_COUNTRY=" + country
			wroteCountry = true
		case strings.HasPrefix(l, "SURFSHARK_CITIES="):
			if city != "" {
				lines[i] = "SURFSHARK_CITIES=" + city
			} else {
				lines[i] = "SURFSHARK_CITIES="
			}
			wroteCities = true
		}
	}
	if !wroteCountry {
		lines = append(lines, "SURFSHARK_COUNTRY="+country)
	}
	if !wroteCities && city != "" {
		lines = append(lines, "SURFSHARK_CITIES="+city)
	}
	return os.WriteFile(envPath, []byte(strings.Join(lines, "\n")), 0o600)
}

func (o *Ops) Refresh(ctx context.Context) error {
	// No-op now: gluetun maintains its own server list. We just refresh UI state.
	o.bus.Publish(eventbus.Event{Type: "refresh_complete"})
	return nil
}

func (o *Ops) SetKillSwitch(ctx context.Context, on bool) error {
	o.st.KillSwitch.UserOn = on
	o.bus.Publish(eventbus.Event{Type: "status_update"})
	return o.st.Save(statePath)
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
	// Persist a sane default for first-boot. If state.json already had a
	// value (loaded from disk above), keep it — user toggles via UI win.
	if !st.KillSwitch.UserOn && cfg.KillSwitch {
		st.KillSwitch.UserOn = true
	}

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
		t := time.NewTicker(8 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-rootCtx.Done():
				return
			case <-t.C:
				// Skip writes when gluetun returns empty (still measuring after
				// a reconnect) so the UI keeps showing the previous value.
				if ip, err := g.PublicIP(rootCtx); err == nil && ip != "" {
					if ip != st.Stats.PublicIP {
						st.Stats.PublicIP = ip
						st.Stats.LastMeasured = time.Now().UTC()
						_ = st.Save(statePath)
						bus.Publish(eventbus.Event{Type: "status_update"})
					}
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

	// Bind on all interfaces so the dashboard is reachable both via the
	// loopback proxy from `tailscale serve` (when tailscaled lives in this
	// netns) AND from the host-side tailscale-front through gluetun's bridge
	// IP (172.30.0.2). Auth middleware gates access — no leak risk.
	httpServer := &http.Server{
		Addr:              "0.0.0.0:" + fmt.Sprintf("%d", httpPort),
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
