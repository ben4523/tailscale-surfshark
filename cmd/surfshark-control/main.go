package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ben4523/tailscale-surfshark/internal/config"
	"github.com/ben4523/tailscale-surfshark/internal/eventbus"
	"github.com/ben4523/tailscale-surfshark/internal/httpapi"
	"github.com/ben4523/tailscale-surfshark/internal/iptables"
	"github.com/ben4523/tailscale-surfshark/internal/logging"
	"github.com/ben4523/tailscale-surfshark/internal/state"
	"github.com/ben4523/tailscale-surfshark/internal/surfshark"
	tsc "github.com/ben4523/tailscale-surfshark/internal/tailscale"
	"github.com/ben4523/tailscale-surfshark/internal/watchdog"
	"github.com/ben4523/tailscale-surfshark/internal/wireguard"
	"github.com/ben4523/tailscale-surfshark/web"
)

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
		o.wg.RemoveDefaultRoutes(ctx, o.st.Surfshark.CurrentEndpointIP, "eth0")
		_ = o.wg.Down(ctx, "wg0")
		o.st.Surfshark.Toggle = false
		o.st.Surfshark.CurrentEndpointIP = ""
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
	o.logger.Info("switch start", "location", loc)
	// Tear down any prior routes/interface from the previous location.
	prevLan, _ := o.wg.DetectLANInterface(ctx)
	if prevLan == "" {
		prevLan = "eth0"
	}
	o.wg.RemoveDefaultRoutes(ctx, o.st.Surfshark.CurrentEndpointIP, prevLan)
	o.logger.Info("switch routes removed")

	downCtx, downCancel := context.WithTimeout(ctx, 5*time.Second)
	if err := o.wg.Down(downCtx, "wg0"); err != nil {
		o.logger.Info("switch wg.Down skipped/failed (expected if wg0 absent)", "err", err.Error())
	} else {
		o.logger.Info("switch wg.Down ok")
	}
	downCancel()

	renderCtx, renderCancel := context.WithTimeout(ctx, 5*time.Second)
	endpointIPs, err := o.store.RenderWG0ConfAll(loc, wg0OutPath, renderCtx)
	renderCancel()
	if err != nil {
		return fmt.Errorf("render wg0.conf: %w", err)
	}
	endpointIP := endpointIPs[0] // primary IP (state tracking only — all IPs get /32 exceptions below)
	o.logger.Info("switch resolved endpoints", "location", loc, "endpoint_ips", endpointIPs)
	upCtx, upCancel := context.WithTimeout(ctx, 30*time.Second)
	if err := o.wg.Up(upCtx, wg0OutPath); err != nil {
		upCancel()
		return fmt.Errorf("wg-quick up: %w", err)
	}
	upCancel()
	o.logger.Info("switch wg0 up", "location", loc)
	lanIface, lerr := o.wg.DetectLANInterface(ctx)
	if lerr != nil {
		o.logger.Warn("could not detect LAN interface, falling back to eth0", "err", lerr.Error())
		lanIface = "eth0"
	}
	o.logger.Info("switch lan iface", "iface", lanIface)
	if err := o.wg.InstallDefaultRoutes(ctx, endpointIP, lanIface); err != nil {
		_ = o.wg.Down(context.Background(), "wg0")
		return fmt.Errorf("install routes: %w", err)
	}
	// Add /32 exceptions for the other resolved IPs too (hostname is
	// load-balanced — Surfshark may pick any of these backends).
	for _, ip := range endpointIPs[1:] {
		_ = o.wg.AddPeerException(ctx, ip, lanIface)
	}
	o.logger.Info("switch routes installed", "location", loc, "endpoint_ip", endpointIP)

	o.st.Surfshark.CurrentLocation = loc
	o.st.Surfshark.CurrentEndpointIP = endpointIP
	_ = o.st.Save(statePath)
	o.bus.Publish(eventbus.Event{Type: "status_update"})

	// Connectivity probe.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c, derr := net.DialTimeout("tcp", "1.1.1.1:53", 1*time.Second)
		if derr == nil {
			c.Close()
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("location %s: no connectivity after 10s", loc)
}

func (o *Ops) Refresh(ctx context.Context) error {
	servers, err := o.api.ListServers(ctx)
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
	o.logger.Info("surfshark refresh", "servers", len(servers))
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
	if cfg.SurfsharkPrivateKey != "" {
		store.SetEnvPrivateKey(cfg.SurfsharkPrivateKey)
	} else {
		logger.Warn("SURFSHARK_PRIVATE_KEY not set — wg0 will not handshake until you set it from my.surfshark.com manual setup")
	}
	wgCtrl := wireguard.New()
	wgCtrl.SetLogger(logger)
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

	// Always refresh on boot if cache is empty (now requires no credentials).
	available, _ := store.List()
	if len(available) == 0 {
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

	// Bind on loopback only. Public exposure to the tailnet is handled by
	// `tailscale serve --http=8080 http://127.0.0.1:8080` set up in the
	// entrypoint — which works in userspace-networking mode (where the
	// Tailscale IP is NOT on any kernel interface and cannot be bound to).
	addr := fmt.Sprintf("127.0.0.1:%d", httpPort)

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
