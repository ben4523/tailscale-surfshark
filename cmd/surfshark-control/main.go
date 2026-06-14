package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
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

// AvailableLocations returns the country list gluetun supports for Surfshark.
// Hard-coded for now; gluetun has them all built-in.
func (o *Ops) AvailableLocations() []string {
	return []string{
		"Albania", "Argentina", "Australia", "Austria", "Belgium", "Brazil",
		"Bulgaria", "Canada", "Chile", "Colombia", "Costa Rica", "Croatia",
		"Cyprus", "Czech Republic", "Denmark", "Estonia", "Finland", "France",
		"Germany", "Greece", "Hong Kong", "Hungary", "Iceland", "India",
		"Indonesia", "Ireland", "Israel", "Italy", "Japan", "Kazakhstan",
		"Latvia", "Lithuania", "Luxembourg", "Malaysia", "Mexico",
		"Netherlands", "New Zealand", "Nigeria", "North Macedonia", "Norway",
		"Paraguay", "Philippines", "Poland", "Portugal", "Romania", "Serbia",
		"Singapore", "Slovakia", "Slovenia", "South Africa", "South Korea",
		"Spain", "Sweden", "Switzerland", "Taiwan", "Thailand", "Turkey",
		"Ukraine", "United Arab Emirates", "United Kingdom", "United States",
		"Vietnam",
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

func (o *Ops) SwitchLocation(ctx context.Context, country string) error {
	o.logger.Info("switch country", "country", country)
	if err := o.g.SwitchCountry(ctx, country); err != nil {
		return err
	}
	o.st.Surfshark.CurrentLocation = country
	_ = o.st.Save(statePath)
	o.bus.Publish(eventbus.Event{Type: "status_update"})

	// Wait up to 15s for gluetun to report "running" again after reconnect.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if s, err := o.g.Status(ctx); err == nil && s == "running" {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("gluetun did not report running within 15s after switch")
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
