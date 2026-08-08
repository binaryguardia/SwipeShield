// Command swipeshield-agent is the small always-on agent installed on each
// monitored server. It dials OUT to the SwipeShield manager, enrolls with a
// one-time token, and then streams heartbeats and (optionally) the local
// WAF's security events back home. No inbound ports are required on the host.
//
// Usage:
//
//	swipeshield-agent enroll -m manager.example.com:9443 -t <token>
//	swipeshield-agent run                  # run in foreground (systemd)
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/binaryguardia/swipeshield/internal/agent/agentclient"
	"github.com/binaryguardia/swipeshield/internal/agent/agentpb"
)

// Version is the agent release version.
var Version = "v0.1.0"

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "swipeshield-agent %s\n\n", Version)
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  swipeshield-agent enroll -m HOST:PORT -t TOKEN [-config PATH] [-insecure]")
		fmt.Fprintln(os.Stderr, "  swipeshield-agent run [-config PATH] [-insecure]")
		fmt.Fprintln(os.Stderr, "  swipeshield-agent -version")
		flag.PrintDefaults()
	}
	if len(os.Args) > 1 && os.Args[1] == "-version" {
		fmt.Println(Version)
		return
	}
	sub := "run"
	args := os.Args[1:]
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		sub = args[0]
		args = args[1:]
	}
	switch sub {
	case "enroll":
		runEnroll(args)
	case "run":
		runAgent(args)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", sub)
		flag.Usage()
		os.Exit(2)
	}
}

func runEnroll(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	manager := fs.String("m", "", "manager agent service host:port")
	token := fs.String("t", "", "one-time enrollment token")
	configPath := fs.String("config", agentclient.DefaultConfigPath(), "agent config path")
	insecure := fs.Bool("insecure", false, "allow plaintext / skip TLS verification (self-signed manager)")
	_ = fs.Parse(args)
	if *manager == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "enroll requires -m and -t")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cfg, err := agentclient.Enroll(ctx, *manager, *token, *insecure)
	if err != nil {
		log.Fatalf("enroll failed: %v", err)
	}
	if err := agentclient.SaveConfig(*configPath, cfg); err != nil {
		log.Fatalf("save config: %v", err)
	}
	log.Printf("enrolled as %s with manager %s (config: %s)", cfg.AgentID, cfg.Manager, *configPath)
	log.Printf("start the agent with: swipeshield-agent run")
}

func runAgent(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", agentclient.DefaultConfigPath(), "agent config path")
	insecure := fs.Bool("insecure", false, "skip TLS verification (self-signed manager)")
	wafLog := fs.String("waf-log", "", "local WAF events.log to stream home")
	_ = fs.Parse(args)

	cfg, err := agentclient.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if *insecure {
		cfg.Insecure = true
	}
	if *wafLog != "" {
		cfg.WAFEventLog = *wafLog
	}
	log.Printf("agent %s starting (manager %s)", cfg.AgentID, cfg.Manager)
	if cfg.WAFEventLog != "" {
		log.Printf("streaming local WAF events from %s", cfg.WAFEventLog)
	}

	backoff := time.Second
	for {
		err := runOnce(cfg)
		if err == nil {
			return
		}
		log.Printf("stream ended: %v; reconnecting in %s", err, backoff)
		select {
		case <-time.After(backoff):
		}
		if backoff < time.Minute {
			backoff *= 2
		}
	}
}

func runOnce(cfg *agentclient.Config) error {
	ctx := context.Background()
	s, err := agentclient.NewStreamer(ctx, cfg)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer s.Close()

	hostname, _ := os.Hostname()
	tailer := agentclient.NewTailer(cfg.WAFEventLog)
	send := func(msg *agentpb.AgentToManager) error {
		if _, err := s.Send(msg); err != nil {
			return err
		}
		return nil
	}
	if err := send(heartbeat(hostname)); err != nil {
		return err
	}
	// Heartbeats mark liveness; the tailer is polled far more often so WAF
	// events stream home with low latency.
	hb := time.NewTicker(agentclient.DefaultInterval)
	defer hb.Stop()
	poll := time.NewTicker(time.Second)
	defer poll.Stop()
	for {
		select {
		case <-hb.C:
			if err := send(heartbeat(hostname)); err != nil {
				return err
			}
		case <-poll.C:
			for _, line := range tailer.Lines() {
				if err := send(&agentpb.AgentToManager{Msg: &agentpb.AgentToManager_Event{
					Event: &agentpb.SecurityEvent{Type: "waf_event", Payload: line},
				}}); err != nil {
					return err
				}
			}
		}
	}
}

func heartbeat(hostname string) *agentpb.AgentToManager {
	return &agentpb.AgentToManager{Msg: &agentpb.AgentToManager_Heartbeat{
		Heartbeat: &agentpb.Heartbeat{Ts: time.Now().Unix(), Hostname: hostname, OsInfo: "linux"},
	}}
}
