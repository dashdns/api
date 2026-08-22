// Command policy-controller serves the DNS policy control plane consumed by
// dnsd (github.com/dashdns/dnsd) via its -ip-blocklist-url flag.
//
// It runs in two modes from one binary:
//
//	single-tenant  (default)  self-hosted inside a customer VNET
//	multi-tenant   (-multi-tenant)  our central SaaS deployment
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/dashdns/api/internal/config"
	"github.com/dashdns/api/internal/server"
	"github.com/dashdns/api/internal/store/sqlstore"
)

// version is overridden at build time:
//
//	go build -ldflags "-X main.version=$(git describe --tags --always)"
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("policy-controller failed", "error", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("policy-controller", flag.ContinueOnError)
	logLevel := fs.String("log-level", "info", "Log level: debug, info, warn or error")
	logFormat := fs.String("log-format", "text", "Log format: text or json")
	showVersion := fs.Bool("version", false, "Print the version and exit")

	cfg, err := config.Parse(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *showVersion {
		fmt.Println(buildVersion())
		return nil
	}

	setupLogging(*logLevel, *logFormat)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := sqlstore.Open(ctx, cfg.DBDriver, cfg.DBDSN)
	if err != nil {
		return err
	}
	defer func() {
		if err := st.Close(); err != nil {
			slog.Error("closing store failed", "error", err)
		}
	}()

	srv := server.New(cfg, st, buildVersion())
	if err := srv.Bootstrap(ctx); err != nil {
		return err
	}

	slog.Info("policy-controller starting",
		"version", buildVersion(),
		"mode", srv.Mode(),
		"db_driver", cfg.DBDriver,
		"listen", cfg.Listen,
		"metrics", cfg.MetricsListen,
	)
	return srv.Run(ctx)
}

func setupLogging(level, format string) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}

	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	slog.SetDefault(slog.New(handler))
}

// buildVersion prefers the ldflags value, falling back to the VCS revision the
// Go toolchain stamps into the binary.
func buildVersion() string {
	if version != "dev" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return version
	}
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" && len(setting.Value) >= 7 {
			return "dev+" + setting.Value[:7]
		}
	}
	return version
}
