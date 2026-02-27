// Package main is the entrypoint for the a2a-sentinel security gateway.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/vivars7/a2a-sentinel/internal/config"
	"github.com/vivars7/a2a-sentinel/internal/migrate"
	"github.com/vivars7/a2a-sentinel/internal/server"
)

// Version is set at build time via -ldflags.
var Version = "dev"

// startable is an interface for anything that can be started and then
// shut down with a context — satisfied by *server.Server.
type startable interface {
	Start(ctx context.Context) error
}

// serverFactory creates a startable server from config. Tests can inject a
// failing factory to cover the server.New() error path.
type serverFactory func(*config.Config, string) (startable, error)

// defaultServerFactory is the production factory that delegates to server.New.
func defaultServerFactory(cfg *config.Config, version string) (startable, error) {
	return server.New(cfg, version)
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	// Global flags
	fs := flag.NewFlagSet("sentinel", flag.ContinueOnError)
	configPath := fs.String("config", "sentinel.yaml", "path to configuration file")
	showVersion := fs.Bool("version", false, "print version and exit")

	// Parse only known flags before the subcommand
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			printUsage()
			return 0
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	if *showVersion {
		fmt.Printf("a2a-sentinel %s\n", Version)
		return 0
	}

	// Setup structured logging (JSON format)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Determine subcommand
	subcmd := "serve"
	remaining := fs.Args()
	if len(remaining) > 0 {
		subcmd = remaining[0]
		remaining = remaining[1:]
	}

	switch subcmd {
	case "serve":
		return cmdServe(*configPath, defaultServerFactory)
	case "validate":
		return cmdValidate(*configPath)
	case "init":
		return cmdInit(remaining)
	case "migrate":
		return cmdMigrate(*configPath, remaining)
	case "help":
		printUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", subcmd)
		printUsage()
		return 1
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `a2a-sentinel %s — A2A Protocol Security Gateway

Usage:
  sentinel [flags] <command>

Commands:
  serve      Start the gateway server (default)
  validate   Validate configuration file
  init       Generate a new sentinel.yaml
  migrate    Migrate config to agentgateway format
  help       Show this help message

Flags:
  --config string   Path to configuration file (default "sentinel.yaml")
  --version         Print version and exit

Examples:
  sentinel serve --config sentinel.yaml
  sentinel validate --config sentinel.yaml
  sentinel init --profile dev
  sentinel migrate --config sentinel.yaml --to agentgateway
`, Version)
}

// cmdServe starts the gateway HTTP server with graceful shutdown.
func cmdServe(configPath string, newServer serverFactory) int {
	logger := slog.Default()
	logger.Info("starting a2a-sentinel",
		"version", Version,
		"config", configPath,
	)

	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Error("configuration error", "error", err)
		return 1
	}

	srv, err := newServer(cfg, Version)
	if err != nil {
		logger.Error("server initialization error", "error", err)
		return 1
	}

	// Graceful shutdown on SIGINT/SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := srv.Start(ctx); err != nil {
		logger.Error("server error", "error", err)
		return 1
	}

	return 0
}

// cmdValidate loads and validates the configuration file.
func cmdValidate(configPath string) int {
	logger := slog.Default()
	logger.Info("validating configuration", "config", configPath)

	if _, err := config.Load(configPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	fmt.Println("config valid")
	return 0
}

// cmdInit generates a new sentinel.yaml with the specified profile.
func cmdInit(args []string) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	profile := fs.String("profile", "dev", "configuration profile (dev or prod)")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	switch *profile {
	case "dev", "prod":
		// valid
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown profile %q (use dev or prod)\n", *profile)
		return 1
	}

	profileYAML := generateProfileYAML(*profile)

	outPath := "sentinel.yaml"
	if err := os.WriteFile(outPath, []byte(profileYAML), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", outPath, err)
		return 1
	}

	fmt.Printf("Generated %s with profile %q\n", outPath, *profile)
	return 0
}

// generateProfileYAML returns a YAML configuration string for the given profile.
func generateProfileYAML(profile string) string {
	switch profile {
	case "prod":
		return config.ProdProfile()
	default:
		return config.DevProfile()
	}
}

// cmdMigrate converts sentinel configuration to a target gateway format.
func cmdMigrate(configPath string, args []string) int {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	output := fs.String("output", "", "output file path (default: stdout)")
	to := fs.String("to", "agentgateway", "target format (only \"agentgateway\" supported)")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	if *to != "agentgateway" {
		fmt.Fprintf(os.Stderr, "Error: unsupported target format %q (only \"agentgateway\" is supported)\n", *to)
		return 1
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		return 1
	}

	gw, warnings, err := migrate.Convert(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error converting config: %v\n", err)
		return 1
	}

	data, err := migrate.Marshal(gw, warnings)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshalling config: %v\n", err)
		return 1
	}

	if *output != "" {
		if err := os.WriteFile(*output, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", *output, err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "Migrated config written to %s\n", *output)
	} else {
		fmt.Print(string(data))
	}

	// Print warnings to stderr.
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "WARNING: %s — %s\n", w.Field, w.Message)
	}

	return 0
}
