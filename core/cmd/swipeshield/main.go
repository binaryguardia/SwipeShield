// Command swipeshield runs the SwipeShield reverse-proxy gateway.
//
// Usage: swipeshield -config config.json
//
// It loads the config, builds per-site engines, and serves HTTP (optionally
// with TLS termination and ClientHello fingerprint capture) on the listeners
// derived from the config.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/binaryguardia/swipeshield/internal/agent"
	"github.com/binaryguardia/swipeshield/internal/config"
	"github.com/binaryguardia/swipeshield/internal/envoy"
	"github.com/binaryguardia/swipeshield/internal/mgmtapi"
	"github.com/binaryguardia/swipeshield/internal/proxy"
	"github.com/binaryguardia/swipeshield/internal/store"
	"github.com/binaryguardia/swipeshield/internal/webui"
)

// Version is the release version of the gateway. Override at build time with
// -ldflags "-X main.Version=...".
var Version = "v0.1.0"

func main() {
	// Top-level panic guard: a defect in a listener goroutine must not leave
	// the process wedged. Panics here are fatal (the gateway is down), so we
	// log the stack and exit non-zero for the supervisor to restart us.
	defer func() {
		if rec := recover(); rec != nil {
			log.Error().Interface("panic", rec).
				Stack().Msg("swipeshield crashed; restarting")
			os.Exit(1)
		}
	}()

	var (
		configPath  = flag.String("config", "config.json", "path to WAF config (JSON or YAML)")
		mgmtEnabled = flag.Bool("mgmt", true, "enable the management API")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Fprintln(os.Stdout, Version)
		os.Exit(0)
	}

	zerolog.TimeFieldFormat = time.RFC3339Nano
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	log.Info().Str("version", Version).Msg("SwipeShield starting")

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal().Err(err).Str("config", *configPath).Msg("invalid configuration")
	}

	g, err := proxy.New(cfg, proxy.Options{})
	if err != nil {
		log.Fatal().Err(err).Msg("failed to start gateway")
	}
	defer g.Close()

	// Persistent manager store (agents + streamed events). Only opened when a
	// DB path is configured (manager/admin mode).
	var db *store.Store
	if cfg.DB.Path != "" {
		db, err = store.Open(cfg.DB.Path)
		if err != nil {
			log.Fatal().Err(err).Str("path", cfg.DB.Path).Msg("failed to open manager store")
		}
		defer db.Close()
		log.Info().Str("path", cfg.DB.Path).Msg("manager store open")
	}

	// Optional Envoy ext_proc sidecar: when an address is configured, expose
	// the gateway's decision engine to service-mesh data planes.
	if cfg.Envoy.Listen != "" {
		sidecar := envoy.NewServer(g)
		go func() {
			if err := sidecar.ListenAndServe(cfg.Envoy.Listen); err != nil {
				log.Error().Err(err).Str("addr", cfg.Envoy.Listen).Msg("ext_proc sidecar stopped")
			}
		}()
	}

	// Agent channel: monitored servers dial out here to enroll and stream.
	if cfg.Agent.Enabled && db != nil {
		if cfg.Agent.TLSCert == "" || cfg.Agent.TLSKey == "" {
			// Self-signed cert keeps the channel encrypted by default.
			certDir := filepath.Join(filepath.Dir(cfg.DB.Path), "tls")
			cfg.Agent.TLSCert = filepath.Join(certDir, "agent-cert.pem")
			cfg.Agent.TLSKey = filepath.Join(certDir, "agent-key.pem")
			if err := agent.SelfSigned(cfg.Agent.TLSCert, cfg.Agent.TLSKey); err != nil {
				log.Fatal().Err(err).Msg("failed to generate agent TLS cert")
			}
		}
		as := agent.NewServer(db)
		go func() {
			log.Info().Str("addr", cfg.Agent.Listen).Msg("agent service listening")
			if err := agent.ListenAndServe(cfg.Agent.Listen, cfg.Agent.TLSCert, cfg.Agent.TLSKey, as); err != nil {
				log.Error().Err(err).Str("addr", cfg.Agent.Listen).Msg("agent service stopped")
			}
		}()
	}

	var handler http.Handler = g
	adminServers := make([]*http.Server, 0)
	if *mgmtEnabled {
		mgmt := mgmtapi.New(mgmtapi.Options{
			Backend:           g,
			RulesDir:          managedRulesDir(*configPath),
			JWTSecret:         cfg.Auth.JWTSecret,
			AdminUser:         cfg.Auth.AdminUser,
			AdminPasswordHash: cfg.Auth.AdminPasswordHash,
			Store:             db,
			AgentPort:         listenPort(cfg.Agent.Listen),
		})
		if cfg.Admin.Enabled {
			// Dedicated admin listener: embedded dashboard + management API,
			// separate from the proxy front door. CORS is enabled so a
			// desktop viewer pointed at a remote manager works.
			adminHandler, err := buildAdminHandler(mgmt)
			if err != nil {
				log.Fatal().Err(err).Msg("failed to build admin handler")
			}
			adminSrv := &http.Server{
				Addr:              cfg.Admin.Address,
				Handler:           adminHandler,
				ReadHeaderTimeout: 10 * time.Second,
				IdleTimeout:       60 * time.Second,
			}
			adminServers = append(adminServers, adminSrv)
			go func() {
				log.Info().Str("addr", cfg.Admin.Address).Msg("admin UI + API listening")
				if err := adminSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					log.Error().Err(err).Str("addr", cfg.Admin.Address).Msg("admin server error")
				}
			}()
		} else {
			// Legacy mode: management API rides on the proxy listener.
			mux := http.NewServeMux()
			mux.Handle("/api/v1/", mgmt.Handler())
			mux.Handle("/", g)
			handler = mux
			log.Info().Msg("management API mounted at /api/v1")
		}
	}

	servers := make([]*http.Server, 0, len(cfg.ListenerList()))
	h3servers := make([]*proxy.HTTP3, 0)
	for _, l := range cfg.ListenerList() {
		srv := &http.Server{
			Addr:              l.Address,
			Handler:           handler,
			ConnContext:       proxy.ConnContext,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		ln, err := net.Listen("tcp", l.Address)
		if err != nil {
			log.Fatal().Err(err).Str("addr", l.Address).Msg("listen failed")
		}
		if l.TLS {
			cert, err := tls.LoadX509KeyPair(l.CertPath, l.KeyPath)
			if err != nil {
				log.Fatal().Err(err).Str("addr", l.Address).Msg("load TLS cert failed")
			}
			tlsConf := &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS13,
				NextProtos:   []string{"h2", "http/1.1"},
			}
			srv.TLSConfig = tlsConf
			// Capture JA3/JA4 from the ClientHello before crypto/tls consumes it.
			ln = proxy.WrapListener(ln, true)

			// HTTP/3 (QUIC) shares the port over UDP. It is served with the
			// same certificate; the gateway handles requests identically.
			if l.HTTP3 {
				addr := udpAddrFor(l.Address)
				h3, err := proxy.StartHTTP3(addr, tlsConf, g, l.Allow0RTT)
				if err != nil {
					log.Fatal().Err(err).Str("addr", addr).Msg("http/3 listen failed")
				}
				h3servers = append(h3servers, h3)
				go func(h *proxy.HTTP3) {
					log.Info().Str("addr", h.Addr()).Msg("http/3 listening")
					if err := h.Err(); err != nil {
						log.Error().Err(err).Str("addr", h.Addr()).Msg("http/3 server error")
					}
				}(h3)
			}
		}
		servers = append(servers, srv)
		go func(srv *http.Server, ln net.Listener, tlsOn bool) {
			log.Info().Str("addr", ln.Addr().String()).Msg("listening")
			var err error
			if tlsOn {
				// ServeTLS with empty cert/key files serves from srv.TLSConfig.
				err = srv.ServeTLS(ln, "", "")
			} else {
				err = srv.Serve(ln)
			}
			if err != nil && err != http.ErrServerClosed {
				log.Error().Err(err).Str("addr", ln.Addr().String()).Msg("server error")
			}
		}(srv, ln, l.TLS)
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Info().Msg("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(ctx)
	}
	for _, srv := range adminServers {
		_ = srv.Shutdown(ctx)
	}
	for _, h3 := range h3servers {
		_ = h3.Close(ctx)
	}
}

// buildAdminHandler wires the management API and the embedded dashboard behind
// a single CORS-enabled mux for the dedicated admin listener.
func buildAdminHandler(mgmt *mgmtapi.Server) (http.Handler, error) {
	ui, err := webui.Handler()
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/api/v1/", mgmt.Handler())
	mux.Handle("/", ui)
	return cors(mux), nil
}

// cors adds permissive CORS so the dashboard can be reached cross-origin (a
// desktop viewer pointed at a remote manager). Auth is via the JWT bearer
// token; credentials are not shared via cookies.
func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With")
		h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// managedRulesDir returns the directory for Management-API-created rule files,
// anchored next to the config file so reloads resolve them consistently.
func managedRulesDir(configPath string) string {
	dir := "rules/custom"
	if abs, err := filepath.Abs(configPath); err == nil {
		dir = filepath.Join(filepath.Dir(abs), "rules", "custom")
	}
	return dir
}

// listenPort extracts the port from a listen address (":9443" -> "9443").
func listenPort(addr string) string {
	if i := strings.LastIndexByte(addr, ':'); i >= 0 {
		return addr[i+1:]
	}
	return addr
}

// udpAddrFor maps a TCP listener address to the UDP address used for HTTP/3
// on the same port (":8443" stays ":8443"; "host:port" keeps the host).
func udpAddrFor(tcpAddr string) string {
	host, port, err := net.SplitHostPort(tcpAddr)
	if err != nil {
		return tcpAddr
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		return ":" + port
	}
	return net.JoinHostPort(host, port)
}
