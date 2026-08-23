// Command nsupdated serves RFC 2136 dynamic updates and AXFR over a Unix
// domain socket, backed by any DNSControl v5 DNS provider.
//
// It performs no authentication; terminate mTLS in front of the socket, e.g.
// with ghostunnel.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"codeberg.org/miekg/dns"
	"golang.org/x/sync/errgroup"

	"github.com/tomfitzhenry/nsupdated/internal/provider"
	"github.com/tomfitzhenry/nsupdated/internal/rfc2136"
)

func main() {
	var (
		listen    string
		credsFile string
		logLevel  slog.Level
	)
	flag.StringVar(&listen, "listen", "", "Unix domain socket to listen on")
	flag.StringVar(&credsFile, "creds-file", "", "path to a JSON provider config")
	flag.TextVar(&logLevel, "log-level", slog.LevelInfo, "log level (debug, info, warn, error)")
	flag.Parse()

	if listen == "" || credsFile == "" {
		flag.Usage()
		os.Exit(2)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))

	config, err := loadConfig(credsFile)
	if err != nil {
		slog.Error("loading config", "file", credsFile, "err", err)
		os.Exit(1)
	}

	// Providers that use the process-wide HTTP client inherit this timeout.
	http.DefaultClient.Timeout = 15 * time.Second

	// Remove a stale socket left by a previous run.
	os.Remove(listen)
	ln, err := net.Listen("unix", listen)
	if err != nil {
		slog.Error("listening", "socket", listen, "err", err)
		os.Exit(1)
	}

	recs, err := provider.NewFromCreds(config)
	if err != nil {
		slog.Error("creating provider", "err", err)
		os.Exit(1)
	}
	handler := &rfc2136.Handler{
		Records: recs,
		Logger:  slog.Default(),
	}

	srv := &dns.Server{
		Listener:    ln,
		Handler:     dns.HandlerFunc(handler.ServeDNS),
		ReadTimeout: 5 * time.Second,
		IdleTimeout: 60 * time.Second,
	}

	// Shut down the server when the process receives a signal, and propagate
	// an unexpected ListenAndServe error.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		<-ctx.Done()
		slog.Info("shutting down")
		srv.Shutdown(context.Background())
		return nil
	})
	g.Go(func() error {
		slog.Info("listening", "socket", listen)
		return srv.ListenAndServe()
	})
	if err := g.Wait(); err != nil {
		slog.Error("server", "err", err)
		os.Exit(1)
	}
	os.Remove(listen)
	slog.Info("done")
}

// loadConfig reads a provider config JSON object. Values of the form $ENV_VAR
// are replaced with the environment variable's value, so secrets need not live
// in the file.
func loadConfig(path string) (map[string]string, error) {
	dat, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config map[string]string
	if err := json.Unmarshal(dat, &config); err != nil {
		return nil, err
	}
	for k, v := range config {
		if strings.HasPrefix(v, "$") {
			config[k] = os.Getenv(v[1:])
		}
	}
	return config, nil
}
