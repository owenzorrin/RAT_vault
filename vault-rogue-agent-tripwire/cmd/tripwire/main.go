package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/OWNER/vault-rogue-agent-tripwire/internal/action"
	"github.com/OWNER/vault-rogue-agent-tripwire/internal/config"
	"github.com/OWNER/vault-rogue-agent-tripwire/internal/detect"
	"github.com/OWNER/vault-rogue-agent-tripwire/internal/event"
	"github.com/OWNER/vault-rogue-agent-tripwire/internal/ingest"
	"github.com/OWNER/vault-rogue-agent-tripwire/internal/notify"
)

func main() {
	cfgPath := "config/tripwire.yaml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)

	slog.Info("tripwire starting",
		"listen_addr", cfg.ListenAddr,
		"vault_addr", cfg.VaultAddr,
		"dry_run", cfg.DryRun,
	)

	// Vault token from environment.
	vaultToken := os.Getenv("VAULT_TOKEN")
	if vaultToken == "" && !cfg.DryRun {
		fmt.Fprintf(os.Stderr, "VAULT_TOKEN not set (required when dry_run=false)\n")
		os.Exit(1)
	}

	vaultClient := action.NewHTTPVaultClient(cfg.VaultAddr, vaultToken)
	killer, err := action.NewKiller(vaultClient, cfg.LeasePrefixTemplate, cfg.DryRun)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create killer: %v\n", err)
		os.Exit(1)
	}

	notifier := notify.New(cfg.Notify.WebhookURL)

	decoyDetector := detect.NewDecoyDetector(
		cfg.Decoys,
		cfg.KVMounts,
		cfg.EvalRoleRe(),
	)
	detectors := []detect.Detector{decoyDetector}

	listener := ingest.New(cfg.Ingest.BufferSize)
	if err := listener.ListenAndServe(cfg.ListenAddr); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start listener: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go processLines(ctx, listener, detectors, killer, notifier)

	<-ctx.Done()
	slog.Info("tripwire shutting down", "drops_total", listener.Drops())
}

// processLines drains the ingest channel, runs detectors, and dispatches
// SevKill findings to the killer in a dedicated goroutine (so detection
// is never blocked by a slow kill).
func processLines(ctx context.Context, l *ingest.Listener, detectors []detect.Detector, killer *action.Killer, notifier *notify.Notifier) {
	for {
		select {
		case <-ctx.Done():
			return
		case raw := <-l.Lines:
			ev, err := event.Parse(raw)
			if err != nil {
				slog.Warn("event: parse error", "err", err, "raw", string(raw[:min(128, len(raw))]))
				continue
			}
			slog.Info("audit event",
				"type", ev.Type,
				"time", ev.Time,
				"request_id", ev.RequestID,
				"path", ev.Path,
				"operation", ev.Operation,
				"remote_addr", ev.RemoteAddr,
				"entity_id", ev.EntityID,
				"accessor", ev.Accessor,
				"metadata", ev.Metadata,
				"error", ev.Error,
			)
			for _, d := range detectors {
				for _, f := range d.Inspect(ev) {
					notifier.Finding(f)
					if f.Severity == detect.SevKill {
						entityID := f.Event.EntityID
						role := f.Event.Metadata["role"]
						// Kill in its own goroutine — detection must not block.
						go func(finding detect.Finding) {
							result := killer.Kill(ctx, entityID, role)
							notifier.KillResult(result)
						}(f)
					}
				}
			}
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
