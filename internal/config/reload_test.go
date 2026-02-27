package config

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// testSubscriber implements Reloadable for testing.
type testSubscriber struct {
	mu       sync.Mutex
	calls    int
	lastCfg  *Config
	returnErr error
}

func (s *testSubscriber) OnConfigReload(newCfg *Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.lastCfg = newCfg
	return s.returnErr
}

func (s *testSubscriber) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *testSubscriber) lastConfig() *Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastCfg
}

// newTestLogger creates a slog.Logger that writes to a buffer for assertions.
func newTestLogger() (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	h := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(h), buf
}

// writeConfig writes a valid YAML config to a file.
func writeConfig(t *testing.T, path string, agentName, agentURL string) {
	t.Helper()
	content := fmt.Sprintf(`agents:
  - name: %s
    url: %s
`, agentName, agentURL)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}
}

// writeConfigWithLevel writes a valid YAML config with a specific log level.
func writeConfigWithLevel(t *testing.T, path string, level string) {
	t.Helper()
	content := fmt.Sprintf(`agents:
  - name: test-agent
    url: http://localhost:9000
logging:
  level: %s
`, level)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}
}

func TestConfigReloader_ManualReload(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sentinel.yaml")
	writeConfig(t, cfgPath, "agent-a", "http://localhost:9000")

	initialCfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("loading initial config: %v", err)
	}

	logger, _ := newTestLogger()
	reloader := NewConfigReloader(cfgPath, initialCfg, logger)

	sub := &testSubscriber{}
	reloader.Register(sub)

	// Change the config file
	writeConfig(t, cfgPath, "agent-a", "http://localhost:9999")

	// Manual reload
	if err := reloader.Reload(); err != nil {
		t.Fatalf("reload failed: %v", err)
	}

	if sub.callCount() != 1 {
		t.Errorf("subscriber called %d times, want 1", sub.callCount())
	}

	got := reloader.Current()
	if got.Agents[0].URL != "http://localhost:9999" {
		t.Errorf("agent URL = %q, want http://localhost:9999", got.Agents[0].URL)
	}
}

func TestConfigReloader_InvalidConfigRetainsOld(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sentinel.yaml")
	writeConfig(t, cfgPath, "agent-a", "http://localhost:9000")

	initialCfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("loading initial config: %v", err)
	}

	logger, _ := newTestLogger()
	reloader := NewConfigReloader(cfgPath, initialCfg, logger)

	sub := &testSubscriber{}
	reloader.Register(sub)

	// Write invalid config (no agents)
	if err := os.WriteFile(cfgPath, []byte("agents: []\n"), 0644); err != nil {
		t.Fatalf("writing invalid config: %v", err)
	}

	err = reloader.Reload()
	if err == nil {
		t.Fatal("expected error for invalid config")
	}

	// Subscriber should NOT have been called
	if sub.callCount() != 0 {
		t.Errorf("subscriber called %d times on invalid reload, want 0", sub.callCount())
	}

	// Current config should still be original
	got := reloader.Current()
	if got.Agents[0].URL != "http://localhost:9000" {
		t.Errorf("config should be retained, got URL %q", got.Agents[0].URL)
	}
}

func TestConfigReloader_NoChanges_NoNotification(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sentinel.yaml")
	writeConfig(t, cfgPath, "agent-a", "http://localhost:9000")

	initialCfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("loading initial config: %v", err)
	}

	logger, logBuf := newTestLogger()
	reloader := NewConfigReloader(cfgPath, initialCfg, logger)

	sub := &testSubscriber{}
	reloader.Register(sub)

	// Reload without changing the file
	if err := reloader.Reload(); err != nil {
		t.Fatalf("reload failed: %v", err)
	}

	// No subscriber notification when nothing changed
	if sub.callCount() != 0 {
		t.Errorf("subscriber called %d times with no changes, want 0", sub.callCount())
	}

	if !strings.Contains(logBuf.String(), "no changes detected") {
		t.Error("expected 'no changes detected' log message")
	}
}

func TestConfigReloader_NonReloadableChangeWarned(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sentinel.yaml")

	// Initial config with port 8080
	content := `listen:
  port: 8080
agents:
  - name: agent-a
    url: http://localhost:9000
`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	initialCfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("loading initial config: %v", err)
	}

	logger, logBuf := newTestLogger()
	reloader := NewConfigReloader(cfgPath, initialCfg, logger)

	// Change port (non-reloadable)
	content = `listen:
  port: 9090
agents:
  - name: agent-a
    url: http://localhost:9000
`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	if err := reloader.Reload(); err != nil {
		t.Fatalf("reload failed: %v", err)
	}

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "requires restart") {
		t.Error("expected warning about non-reloadable change requiring restart")
	}
}

func TestConfigReloader_SubscriberError_ContinuesOthers(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sentinel.yaml")
	writeConfig(t, cfgPath, "agent-a", "http://localhost:9000")

	initialCfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("loading initial config: %v", err)
	}

	logger, logBuf := newTestLogger()
	reloader := NewConfigReloader(cfgPath, initialCfg, logger)

	errSub := &testSubscriber{returnErr: fmt.Errorf("subscriber broke")}
	okSub := &testSubscriber{}
	reloader.Register(errSub)
	reloader.Register(okSub)

	// Change config
	writeConfig(t, cfgPath, "agent-a", "http://localhost:9999")

	if err := reloader.Reload(); err != nil {
		t.Fatalf("reload failed: %v", err)
	}

	// Both subscribers should have been called
	if errSub.callCount() != 1 {
		t.Errorf("error subscriber called %d times, want 1", errSub.callCount())
	}
	if okSub.callCount() != 1 {
		t.Errorf("ok subscriber called %d times, want 1", okSub.callCount())
	}

	// Error should be logged
	if !strings.Contains(logBuf.String(), "subscriber reload failed") {
		t.Error("expected log entry for failed subscriber")
	}
}

func TestConfigReloader_ReloadableFieldApplied(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sentinel.yaml")
	writeConfigWithLevel(t, cfgPath, "info")

	initialCfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("loading initial config: %v", err)
	}

	logger, _ := newTestLogger()
	reloader := NewConfigReloader(cfgPath, initialCfg, logger)

	sub := &testSubscriber{}
	reloader.Register(sub)

	// Change log level (reloadable)
	writeConfigWithLevel(t, cfgPath, "debug")

	if err := reloader.Reload(); err != nil {
		t.Fatalf("reload failed: %v", err)
	}

	if sub.callCount() != 1 {
		t.Fatalf("subscriber called %d times, want 1", sub.callCount())
	}

	if sub.lastConfig().Logging.Level != "debug" {
		t.Errorf("subscriber got logging.level=%q, want debug", sub.lastConfig().Logging.Level)
	}

	if reloader.Current().Logging.Level != "debug" {
		t.Errorf("current config logging.level=%q, want debug", reloader.Current().Logging.Level)
	}
}

func TestConfigReloader_SIGHUP(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sentinel.yaml")
	writeConfig(t, cfgPath, "agent-a", "http://localhost:9000")

	initialCfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("loading initial config: %v", err)
	}
	// Disable file watching for this test to isolate SIGHUP
	initialCfg.Reload.WatchFile = false

	logger, _ := newTestLogger()
	reloader := NewConfigReloader(cfgPath, initialCfg, logger)

	sub := &testSubscriber{}
	reloader.Register(sub)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := reloader.Start(ctx); err != nil {
		t.Fatalf("start failed: %v", err)
	}

	// Change config before sending signal
	writeConfig(t, cfgPath, "agent-a", "http://localhost:9999")

	// Send SIGHUP to self
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("finding process: %v", err)
	}
	if err := proc.Signal(syscall.SIGHUP); err != nil {
		t.Fatalf("sending SIGHUP: %v", err)
	}

	// Wait for reload to be processed
	deadline := time.After(5 * time.Second)
	for {
		if sub.callCount() >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timeout waiting for SIGHUP reload")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	got := reloader.Current()
	if got.Agents[0].URL != "http://localhost:9999" {
		t.Errorf("after SIGHUP, agent URL = %q, want http://localhost:9999", got.Agents[0].URL)
	}

	reloader.Stop()
}

func TestConfigReloader_FileWatch(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sentinel.yaml")
	writeConfig(t, cfgPath, "agent-a", "http://localhost:9000")

	initialCfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("loading initial config: %v", err)
	}
	// Use a short debounce for testing
	initialCfg.Reload.Debounce.Duration = 100 * time.Millisecond
	initialCfg.Reload.WatchFile = true

	logger, _ := newTestLogger()
	reloader := NewConfigReloader(cfgPath, initialCfg, logger)

	sub := &testSubscriber{}
	reloader.Register(sub)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := reloader.Start(ctx); err != nil {
		t.Fatalf("start failed: %v", err)
	}

	// Small pause to let watcher settle
	time.Sleep(50 * time.Millisecond)

	// Modify the config file
	writeConfig(t, cfgPath, "agent-a", "http://localhost:8888")

	// Wait for debounce + processing
	deadline := time.After(5 * time.Second)
	for {
		if sub.callCount() >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timeout waiting for file watch reload")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	got := reloader.Current()
	if got.Agents[0].URL != "http://localhost:8888" {
		t.Errorf("after file change, agent URL = %q, want http://localhost:8888", got.Agents[0].URL)
	}

	reloader.Stop()
}

func TestConfigReloader_DebounceMultipleWrites(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sentinel.yaml")
	writeConfig(t, cfgPath, "agent-a", "http://localhost:9000")

	initialCfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("loading initial config: %v", err)
	}
	// Use a debounce long enough to coalesce rapid writes
	initialCfg.Reload.Debounce.Duration = 300 * time.Millisecond
	initialCfg.Reload.WatchFile = true

	logger, _ := newTestLogger()
	reloader := NewConfigReloader(cfgPath, initialCfg, logger)

	var reloadCount atomic.Int32
	sub := &testSubscriber{}
	reloader.Register(sub)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := reloader.Start(ctx); err != nil {
		t.Fatalf("start failed: %v", err)
	}

	// Small pause to let watcher settle
	time.Sleep(50 * time.Millisecond)

	// Write multiple times rapidly (within debounce window)
	for i := 0; i < 5; i++ {
		writeConfig(t, cfgPath, "agent-a", fmt.Sprintf("http://localhost:%d", 9001+i))
		time.Sleep(20 * time.Millisecond)
	}

	// Wait for debounce + processing
	time.Sleep(600 * time.Millisecond)

	_ = reloadCount // suppress unused warning

	// Should have been debounced to 1-2 reloads (not 5)
	count := sub.callCount()
	if count > 2 {
		t.Errorf("expected at most 2 reloads due to debounce, got %d", count)
	}
	if count < 1 {
		t.Error("expected at least 1 reload")
	}

	reloader.Stop()
}

func TestConfigReloader_StopCleanup(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sentinel.yaml")
	writeConfig(t, cfgPath, "agent-a", "http://localhost:9000")

	initialCfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("loading initial config: %v", err)
	}
	initialCfg.Reload.WatchFile = false

	logger, _ := newTestLogger()
	reloader := NewConfigReloader(cfgPath, initialCfg, logger)

	ctx := context.Background()
	if err := reloader.Start(ctx); err != nil {
		t.Fatalf("start failed: %v", err)
	}

	// Stop should return without blocking
	done := make(chan struct{})
	go func() {
		reloader.Stop()
		close(done)
	}()

	select {
	case <-done:
		// good
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() blocked for too long")
	}
}

func TestConfigReloader_Current_Concurrent(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sentinel.yaml")
	writeConfig(t, cfgPath, "agent-a", "http://localhost:9000")

	initialCfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("loading initial config: %v", err)
	}

	logger, _ := newTestLogger()
	reloader := NewConfigReloader(cfgPath, initialCfg, logger)

	// Concurrent reads/reloads should not race
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				cfg := reloader.Current()
				_ = cfg.Listen.Port
			}
		}()
	}

	// Concurrent reload
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 10; j++ {
			_ = reloader.Reload()
		}
	}()

	wg.Wait()
}

func TestConfigReloader_RegisterMultiple(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sentinel.yaml")
	writeConfig(t, cfgPath, "agent-a", "http://localhost:9000")

	initialCfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("loading initial config: %v", err)
	}

	logger, _ := newTestLogger()
	reloader := NewConfigReloader(cfgPath, initialCfg, logger)

	sub1 := &testSubscriber{}
	sub2 := &testSubscriber{}
	sub3 := &testSubscriber{}
	reloader.Register(sub1)
	reloader.Register(sub2)
	reloader.Register(sub3)

	// Change config
	writeConfig(t, cfgPath, "agent-a", "http://localhost:9999")

	if err := reloader.Reload(); err != nil {
		t.Fatalf("reload failed: %v", err)
	}

	// All three should have been notified
	if sub1.callCount() != 1 {
		t.Errorf("sub1 called %d times, want 1", sub1.callCount())
	}
	if sub2.callCount() != 1 {
		t.Errorf("sub2 called %d times, want 1", sub2.callCount())
	}
	if sub3.callCount() != 1 {
		t.Errorf("sub3 called %d times, want 1", sub3.callCount())
	}
}

func TestConfigReloader_ReloadDefaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sentinel.yaml")
	writeConfig(t, cfgPath, "agent-a", "http://localhost:9000")

	initialCfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("loading initial config: %v", err)
	}

	// Verify reload defaults were applied
	if !initialCfg.Reload.Enabled {
		t.Error("reload.enabled should default to true")
	}
	if !initialCfg.Reload.WatchFile {
		t.Error("reload.watch_file should default to true")
	}
	if initialCfg.Reload.Debounce.Duration != 2*time.Second {
		t.Errorf("reload.debounce = %v, want 2s", initialCfg.Reload.Debounce.Duration)
	}
}
