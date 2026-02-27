package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/vivars7/a2a-sentinel/internal/config"
)

func TestRunHelp(t *testing.T) {
	code := run([]string{"--help"})
	if code != 0 {
		t.Errorf("expected exit code 0 for --help, got %d", code)
	}
}

func TestRunVersion(t *testing.T) {
	code := run([]string{"--version"})
	if code != 0 {
		t.Errorf("expected exit code 0 for --version, got %d", code)
	}
}

func TestRunUnknownCommand(t *testing.T) {
	code := run([]string{"nonexistent"})
	if code != 1 {
		t.Errorf("expected exit code 1 for unknown command, got %d", code)
	}
}

func TestRunValidateNoConfig(t *testing.T) {
	code := run([]string{"--config", "nonexistent.yaml", "validate"})
	if code != 1 {
		t.Errorf("expected exit code 1 for missing config, got %d", code)
	}
}

func TestRunValidateWithConfig(t *testing.T) {
	// Create a temporary config file with minimal valid config
	tmpFile, err := os.CreateTemp("", "sentinel-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	minimalConfig := []byte(`agents:
  - name: test-agent
    url: http://localhost:9000
`)
	if _, err := tmpFile.Write(minimalConfig); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	code := run([]string{"--config", tmpFile.Name(), "validate"})
	if code != 0 {
		t.Errorf("expected exit code 0 for valid config, got %d", code)
	}
}

func TestRunInitDev(t *testing.T) {
	// Use a temp directory to avoid polluting the project
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmpDir, err := os.MkdirTemp("", "sentinel-init-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	defer os.Chdir(origDir)
	os.Chdir(tmpDir)

	code := run([]string{"init", "--profile", "dev"})
	if code != 0 {
		t.Errorf("expected exit code 0 for init --profile dev, got %d", code)
	}

	// Verify the file was created
	if _, err := os.Stat("sentinel.yaml"); os.IsNotExist(err) {
		t.Error("sentinel.yaml was not created")
	}
}

func TestRunInitProd(t *testing.T) {
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmpDir, err := os.MkdirTemp("", "sentinel-init-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	defer os.Chdir(origDir)
	os.Chdir(tmpDir)

	code := run([]string{"init", "--profile", "prod"})
	if code != 0 {
		t.Errorf("expected exit code 0 for init --profile prod, got %d", code)
	}
}

func TestRunInitInvalidProfile(t *testing.T) {
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmpDir, err := os.MkdirTemp("", "sentinel-init-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	defer os.Chdir(origDir)
	os.Chdir(tmpDir)

	code := run([]string{"init", "--profile", "invalid"})
	if code != 1 {
		t.Errorf("expected exit code 1 for invalid profile, got %d", code)
	}
}

func TestBuildSucceeds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping build test in short mode")
	}

	cmd := exec.Command("go", "build", "-o", os.DevNull, "./.")
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("build failed: %v\n%s", err, output)
	}
}

// TestRunFlagParseError covers the non-help flag parse error branch in run().
func TestRunFlagParseError(t *testing.T) {
	// --unknown-flag causes ContinueOnError to return an error (not ErrHelp).
	code := run([]string{"--unknown-flag-xyz"})
	if code != 1 {
		t.Errorf("expected exit code 1 for unknown flag, got %d", code)
	}
}

// TestRunHelpSubcommand covers the "help" subcommand branch in run().
func TestRunHelpSubcommand(t *testing.T) {
	code := run([]string{"help"})
	if code != 0 {
		t.Errorf("expected exit code 0 for help subcommand, got %d", code)
	}
}

// TestCmdServeConfigLoadError covers the config load error branch in cmdServe().
func TestCmdServeConfigLoadError(t *testing.T) {
	code := cmdServe("/nonexistent/path/sentinel.yaml", defaultServerFactory)
	if code != 1 {
		t.Errorf("expected exit code 1 for missing config, got %d", code)
	}
}

// TestCmdServePortInUse covers the srv.Start() error branch in cmdServe() by
// pre-binding the configured port so that the server's Listen call fails.
func TestCmdServePortInUse(t *testing.T) {
	// Pre-bind a port so that sentinel cannot listen on it.
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind blocker port: %v", err)
	}
	defer blocker.Close()
	blockedPort := blocker.Addr().(*net.TCPAddr).Port

	configYAML := fmt.Sprintf(`
listen:
  host: 127.0.0.1
  port: %d
agents:
  - name: test-agent
    url: http://127.0.0.1:19999
    default: true
    allow_insecure: true
    health_check:
      enabled: false
security:
  auth:
    mode: passthrough-strict
    allow_unauthenticated: true
  card_signature:
    require: false
`, blockedPort)

	tmpFile, err := os.CreateTemp("", "sentinel-busy-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp config: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.WriteString(configYAML); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	tmpFile.Close()

	code := cmdServe(tmpFile.Name(), defaultServerFactory)
	if code != 1 {
		t.Errorf("expected exit code 1 for port-in-use, got %d", code)
	}
}

// TestCmdServeStartsAndShutdown starts a real server with a mock backend,
// verifies the health endpoint responds, then sends SIGINT to trigger graceful shutdown.
func TestCmdServeStartsAndShutdown(t *testing.T) {
	// Mock backend serving a minimal agent card.
	agentCard := map[string]interface{}{
		"name":        "test-agent",
		"description": "Test agent",
		"url":         "http://localhost:0",
		"version":     "1.0.0",
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(agentCard)
	}))
	defer backend.Close()

	// Pick a free port for sentinel to listen on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	// Write a config pointing at the mock backend and our chosen port.
	configYAML := fmt.Sprintf(`
listen:
  host: 127.0.0.1
  port: %d
agents:
  - name: test-agent
    url: %s
    default: true
    allow_insecure: true
    health_check:
      enabled: false
security:
  auth:
    mode: passthrough-strict
    allow_unauthenticated: true
  card_signature:
    require: false
`, port, backend.URL)

	tmpFile, err := os.CreateTemp("", "sentinel-serve-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp config: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.WriteString(configYAML); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	tmpFile.Close()

	// Run cmdServe in a goroutine.
	doneCh := make(chan int, 1)
	go func() {
		doneCh <- run([]string{"--config", tmpFile.Name(), "serve"})
	}()

	// Poll the health endpoint until the server is ready (up to 3 seconds).
	healthURL := fmt.Sprintf("http://127.0.0.1:%d/healthz", port)
	deadline := time.Now().Add(3 * time.Second)
	started := false
	for time.Now().Before(deadline) {
		resp, err := http.Get(healthURL)
		if err == nil {
			resp.Body.Close()
			started = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !started {
		t.Error("server did not become ready within timeout")
	}

	// Send SIGINT to our own process to trigger graceful shutdown via signal.NotifyContext.
	syscall.Kill(syscall.Getpid(), syscall.SIGINT)

	// Wait for cmdServe to return (with a generous timeout).
	select {
	case code := <-doneCh:
		if code != 0 {
			t.Errorf("expected exit code 0 after graceful shutdown, got %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Error("server did not shut down within timeout")
	}
}

// TestCmdServeServerNewFails covers the server.New() failure path via a failing factory.
func TestCmdServeServerNewFails(t *testing.T) {
	// Write a valid config so config.Load succeeds, but the factory fails.
	tmpFile, err := os.CreateTemp("", "sentinel-factory-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	configYAML := `agents:
  - name: test-agent
    url: http://localhost:9000
    default: true
    allow_insecure: true
`
	if _, err := tmpFile.WriteString(configYAML); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	failingFactory := func(_ *config.Config, _ string) (startable, error) {
		return nil, errors.New("server creation failed")
	}

	code := cmdServe(tmpFile.Name(), failingFactory)
	if code != 1 {
		t.Errorf("expected exit code 1 for server.New failure, got %d", code)
	}
}

// TestCmdServeStartError covers the srv.Start() error path via a factory that
// returns a server whose Start always fails.
func TestCmdServeStartError(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "sentinel-starterr-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	configYAML := `agents:
  - name: test-agent
    url: http://localhost:9000
    default: true
    allow_insecure: true
`
	if _, err := tmpFile.WriteString(configYAML); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	failStartFactory := func(_ *config.Config, _ string) (startable, error) {
		return &failingServer{}, nil
	}

	code := cmdServe(tmpFile.Name(), failStartFactory)
	if code != 1 {
		t.Errorf("expected exit code 1 for Start() error, got %d", code)
	}
}

type failingServer struct{}

func (f *failingServer) Start(_ context.Context) error {
	return errors.New("start failed")
}

// TestCmdInitHelp covers the --help flag branch in cmdInit().
func TestCmdInitHelp(t *testing.T) {
	code := run([]string{"init", "--help"})
	if code != 0 {
		t.Errorf("expected exit code 0 for init --help, got %d", code)
	}
}

// TestCmdInitFlagParseError covers the non-help flag parse error branch in cmdInit().
func TestCmdInitFlagParseError(t *testing.T) {
	// --unknown is not a recognised flag for the init FlagSet.
	code := run([]string{"init", "--unknown-flag-xyz"})
	if code != 1 {
		t.Errorf("expected exit code 1 for unknown init flag, got %d", code)
	}
}

// TestCmdInitWriteError covers the os.WriteFile error branch in cmdInit()
// by making the working directory read-only so writing sentinel.yaml fails.
func TestCmdInitWriteError(t *testing.T) {
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	tmpDir, err := os.MkdirTemp("", "sentinel-init-ro-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	defer os.Chdir(origDir)

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}

	// Make the directory read-only so WriteFile fails.
	if err := os.Chmod(tmpDir, 0555); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(tmpDir, 0755) // restore so RemoveAll can clean up

	code := run([]string{"init", "--profile", "dev"})
	if code != 1 {
		t.Errorf("expected exit code 1 for read-only dir, got %d", code)
	}
}

// --- migrate subcommand tests ---

// writeTempConfig writes a minimal valid sentinel config to a temp file and returns its path.
// The caller is responsible for cleaning up via the returned cleanup function.
func writeTempConfig(t *testing.T) (string, func()) {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "sentinel-migrate-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	configYAML := `agents:
  - name: test-agent
    url: http://localhost:9000
    default: true
    allow_insecure: true
`
	if _, err := tmpFile.WriteString(configYAML); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()
	return tmpFile.Name(), func() { os.Remove(tmpFile.Name()) }
}

// TestRunMigrateSuccess tests the migrate subcommand with a valid config to stdout.
func TestRunMigrateSuccess(t *testing.T) {
	cfgPath, cleanup := writeTempConfig(t)
	defer cleanup()

	code := run([]string{"--config", cfgPath, "migrate"})
	if code != 0 {
		t.Errorf("expected exit code 0 for migrate, got %d", code)
	}
}

// TestRunMigrateToFile tests writing migrate output to a file.
func TestRunMigrateToFile(t *testing.T) {
	cfgPath, cleanup := writeTempConfig(t)
	defer cleanup()

	outFile, err := os.CreateTemp("", "sentinel-migrate-out-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	outPath := outFile.Name()
	outFile.Close()
	defer os.Remove(outPath)

	code := run([]string{"--config", cfgPath, "migrate", "--output", outPath})
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty output file")
	}
}

// TestRunMigrateMissingConfig tests migrate with a nonexistent config file.
func TestRunMigrateMissingConfig(t *testing.T) {
	code := run([]string{"--config", "/nonexistent/path.yaml", "migrate"})
	if code != 1 {
		t.Errorf("expected exit code 1 for missing config, got %d", code)
	}
}

// TestRunMigrateUnsupportedFormat tests migrate with an unsupported --to flag.
func TestRunMigrateUnsupportedFormat(t *testing.T) {
	cfgPath, cleanup := writeTempConfig(t)
	defer cleanup()

	code := run([]string{"--config", cfgPath, "migrate", "--to", "unknown"})
	if code != 1 {
		t.Errorf("expected exit code 1 for unsupported format, got %d", code)
	}
}

// TestRunMigrateHelp tests the --help flag for the migrate subcommand.
func TestRunMigrateHelp(t *testing.T) {
	code := run([]string{"migrate", "--help"})
	if code != 0 {
		t.Errorf("expected exit code 0 for migrate --help, got %d", code)
	}
}

// TestRunMigrateFlagParseError tests an unknown flag for the migrate subcommand.
func TestRunMigrateFlagParseError(t *testing.T) {
	code := run([]string{"migrate", "--unknown-flag-xyz"})
	if code != 1 {
		t.Errorf("expected exit code 1 for unknown migrate flag, got %d", code)
	}
}

// TestRunMigrateWriteError tests migrate when the output path is not writable.
func TestRunMigrateWriteError(t *testing.T) {
	cfgPath, cleanup := writeTempConfig(t)
	defer cleanup()

	code := run([]string{"--config", cfgPath, "migrate", "--output", "/nonexistent-dir/out.yaml"})
	if code != 1 {
		t.Errorf("expected exit code 1 for unwritable output, got %d", code)
	}
}
