package main

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bbitton/tailscale-surfshark/internal/config"
	"github.com/bbitton/tailscale-surfshark/internal/eventbus"
	"github.com/bbitton/tailscale-surfshark/internal/httpapi"
	"github.com/bbitton/tailscale-surfshark/internal/iptables"
	"github.com/bbitton/tailscale-surfshark/internal/logging"
	"github.com/bbitton/tailscale-surfshark/internal/state"
	"github.com/bbitton/tailscale-surfshark/internal/surfshark"
	tsc "github.com/bbitton/tailscale-surfshark/internal/tailscale"
	"github.com/bbitton/tailscale-surfshark/internal/watchdog"
	"github.com/bbitton/tailscale-surfshark/internal/wireguard"
)

//go:embed all:web
var webFS embed.FS

const (
	dataDir    = "/data"
	statePath  = "/data/state.json"
	confDir    = "/data/surfshark"
	wg0OutPath = "/etc/wireguard/wg0.conf"
	pubIPURL   = "https://ifconfig.io"
	httpPort   = 8080
)

type Ops struct {
	logger *logging.Logger
	st     *state.State
	tsCli  *tsc.Client
	api    *surfshark.Client
	store  *surfshark.ConfigStore
	wg     *wireguard.Controller
	ipt    *iptables.Manager
	bus    *eventbus.Bus
	cfg    *config.Config
}

func (o *Ops) AvailableLocations() []string {
	locs, _ := o.store.List()
	return locs
}

func (o *Ops) Toggle(ctx context.Context, on bool) error {
	if on {
		if err := o.bringUpWG(ctx); err != nil {
			return err
		}
		o.st.Surfshark.Toggle = true
		if o.cfg.KillSwitch {
			_ = o.ipt.ArmKillSwitch(ctx, "tailscale0", "eth0")
			o.st.KillSwitch.CurrentlyArmed = true
		}
	} else {
		_ = o.wg.Down(ctx, "wg0")
		o.st.Surfshark.Toggle = false
		if o.cfg.KillSwitch {
			_ = o.ipt.ArmKillSwitch(ctx, "tailscale0", "eth0")
			o.st.KillSwitch.CurrentlyArmed = true
		} else {
			_ = o.ipt.DisarmKillSwitch(ctx, "tailscale0", "eth0")
			o.st.KillSwitch.CurrentlyArmed = false
		}
	}
	o.bus.Publish(eventbus.Event{Type: "status_update"})
	return o.st.Save(statePath)
}

func (o *Ops) SwitchLocation(ctx context.Context, loc string) error {
	if err := o.store.RenderWG0Conf(loc, wg0OutPath); err != nil {
		return err
	}
	_ = o.wg.Down(ctx, "wg0")
	if err := o.wg.Up(ctx, wg0OutPath); err != nil {
		return err
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", "1.1.1.1:53", 1*time.Second)
		if err == nil {
			c.Close()
			o.st.Surfshark.CurrentLocation = loc
			_ = o.st.Save(statePath)
			o.bus.Publish(eventbus.Event{Type: "status_update"})
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("location %s: no connectivity after 10s", loc)
}

func (o *Ops) Refresh(ctx context.Context) error {
	if o.cfg.SurfsharkEmail == "" || o.cfg.SurfsharkPassword == "" {
		return fmt.Errorf("SURFSHARK_EMAIL/PASSWORD not set")
	}
	tok, err := o.api.Login(ctx, o.cfg.SurfsharkEmail, o.cfg.SurfsharkPassword)
	if err != nil {
		return err
	}
	_, pub, err := o.store.EnsureKeypair()
	if err != nil {
		return err
	}
	if err := o.api.RegisterPubKey(ctx, tok, pub); err != nil {
		return err
	}
	servers, err := o.api.ListServers(ctx, tok)
	if err != nil {
		return err
	}
	if err := o.store.WriteAll(servers); err != nil {
		return err
	}
	now := time.Now().UTC()
	o.st.Surfshark.LastRefresh = &now
	_ = o.st.Save(statePath)
	o.bus.Publish(eventbus.Event{Type: "refresh_complete"})
	return nil
}

func (o *Ops) SetPreferred(ctx context.Context, locs []string) error {
	o.st.Surfshark.PreferredLocations = locs
	o.bus.Publish(eventbus.Event{Type: "status_update"})
	return o.st.Save(statePath)
}

func (o *Ops) bringUpWG(ctx context.Context) error {
	loc := o.st.Surfshark.CurrentLocation
	if loc == "" {
		avail := o.AvailableLocations()
		if len(avail) == 0 {
			return fmt.Errorf("no Surfshark configs available")
		}
		loc = avail[0]
	}
	return o.SwitchLocation(ctx, loc)
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
	store := surfshark.NewConfigStore(confDir)
	wgCtrl := wireguard.New()
	ipt := iptables.New()
	apiBase := os.Getenv("SURFSHARK_API_BASE")
	if apiBase == "" {
		apiBase = "https://api.surfshark.com"
	}
	api := surfshark.NewClient(apiBase)

	ops := &Ops{
		logger: logger, st: st, tsCli: tsCli,
		api: api, store: store, wg: wgCtrl, ipt: ipt,
		bus: bus, cfg: cfg,
	}

	// First-boot cache fill if env present and no cache:
	available, _ := store.List()
	if len(available) == 0 && cfg.SurfsharkEmail != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		if err := ops.Refresh(ctx); err != nil {
			logger.Warn("first-boot refresh failed", "error", err.Error())
		}
		cancel()
	}

	bootCtx, bootCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := ipt.ApplyBase(bootCtx, "tailscale0", "wg0", "eth0"); err != nil {
		logger.Warn("iptables base", "error", err.Error())
	}
	bootCancel()

	if st.Surfshark.Toggle {
		_ = ops.Toggle(context.Background(), true)
	} else if cfg.KillSwitch {
		_ = ipt.ArmKillSwitch(context.Background(), "tailscale0", "eth0")
		st.KillSwitch.CurrentlyArmed = true
	}

	// Bind on the container's tailscale IP if available, else 0.0.0.0
	ip, err := tsCli.IPv4(context.Background())
	if err != nil || ip == "" {
		logger.Warn("tailscale ip unavailable, binding 0.0.0.0", "error", fmt.Sprintf("%v", err))
		ip = "0.0.0.0"
	}
	addr := fmt.Sprintf("%s:%d", ip, httpPort)

	srv := httpapi.NewServer(httpapi.Deps{
		Whois:   tsCli,
		Allowed: cfg.TSAllowedUsers,
		State:   st,
		Bus:     bus,
		Ops:     ops,
	})
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		logger.Error("embed web/", "error", err.Error())
		os.Exit(1)
	}
	srv.MountStatic(sub)

	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

	tsWatch := watchdog.NewTailscaledWatchdog(
		func(ctx context.Context) error { _, e := tsCli.Status(ctx); return e },
		func(ctx context.Context) error { return nil },
		30*time.Second,
	)
	go tsWatch.Run(rootCtx)

	statusPoll := watchdog.NewStatusPoller(
		bus, st, statePath,
		func(ctx context.Context) (time.Time, error) { return wgCtrl.LastHandshake(ctx, "wg0") },
		pubIPURL, 10*time.Second, 60*time.Second,
	)
	go statusPoll.Run(rootCtx)

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		logger.Info("http listening", "addr", addr)
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
