package config

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Reloadable is implemented by components that can update their config at runtime.
type Reloadable interface {
	// OnConfigReload is called when the configuration has changed.
	// Implementations should apply relevant changes and return an error
	// if the component cannot update itself. The reloader logs errors
	// but continues notifying other subscribers.
	OnConfigReload(newCfg *Config) error
}

// ConfigReloader watches for config changes and coordinates reloads.
// It supports SIGHUP signals and optional file-system watching with debounce.
type ConfigReloader struct {
	configPath  string
	currentCfg  atomic.Pointer[Config]
	subscribers []Reloadable
	logger      *slog.Logger
	debounce    time.Duration
	watchFile   bool

	mu       sync.RWMutex
	cancel   context.CancelFunc
	watcher  *fsnotify.Watcher
	stopped  chan struct{}
	sigChan  chan os.Signal
}

// NewConfigReloader creates a ConfigReloader for the given config file path.
// The initialCfg is set as the current config atomically.
func NewConfigReloader(configPath string, initialCfg *Config, logger *slog.Logger) *ConfigReloader {
	r := &ConfigReloader{
		configPath: configPath,
		logger:     logger,
		debounce:   initialCfg.Reload.Debounce.Duration,
		watchFile:  initialCfg.Reload.WatchFile,
		stopped:    make(chan struct{}),
	}
	r.currentCfg.Store(initialCfg)
	return r
}

// Register adds a component to receive reload notifications.
// Must be called before Start.
func (r *ConfigReloader) Register(sub Reloadable) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.subscribers = append(r.subscribers, sub)
}

// Current returns the current active configuration. Safe for concurrent use.
func (r *ConfigReloader) Current() *Config {
	return r.currentCfg.Load()
}

// Start begins watching for config changes via SIGHUP and optional file watching.
// It blocks until the provided context is cancelled or Stop is called.
func (r *ConfigReloader) Start(ctx context.Context) error {
	ctx, r.cancel = context.WithCancel(ctx)

	// Set up SIGHUP handler
	r.sigChan = make(chan os.Signal, 1)
	signal.Notify(r.sigChan, syscall.SIGHUP)

	// Set up file watcher if enabled
	if r.watchFile {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			return fmt.Errorf("creating file watcher: %w", err)
		}
		r.watcher = watcher

		if err := watcher.Add(r.configPath); err != nil {
			watcher.Close()
			return fmt.Errorf("watching config file %q: %w", r.configPath, err)
		}
		r.logger.Info("config file watcher started", "path", r.configPath, "debounce", r.debounce)
	}

	go r.run(ctx)
	return nil
}

// Stop shuts down the reloader, stopping signal and file watchers.
func (r *ConfigReloader) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
	<-r.stopped
}

// Reload manually triggers a config reload. It reads the config file, validates it,
// computes a diff, logs warnings for non-reloadable changes, and notifies subscribers.
// Returns an error if the new config is invalid (old config is retained).
func (r *ConfigReloader) Reload() error {
	r.logger.Info("config reload triggered", "path", r.configPath)

	newCfg, err := Load(r.configPath)
	if err != nil {
		r.logger.Error("config reload failed: invalid config, keeping current",
			"error", err,
			"path", r.configPath,
		)
		return fmt.Errorf("config reload: %w", err)
	}

	oldCfg := r.currentCfg.Load()
	changes := Diff(oldCfg, newCfg)

	if len(changes) == 0 {
		r.logger.Info("config reload: no changes detected")
		return nil
	}

	// Log each change, warn on non-reloadable
	hasNonReloadable := false
	for _, c := range changes {
		if c.Reloadable {
			r.logger.Info("config change detected",
				"field", c.Field,
				"old", fmt.Sprintf("%v", c.OldValue),
				"new", fmt.Sprintf("%v", c.NewValue),
				"reloadable", true,
			)
		} else {
			hasNonReloadable = true
			r.logger.Warn("config change requires restart (ignored)",
				"field", c.Field,
				"old", fmt.Sprintf("%v", c.OldValue),
				"new", fmt.Sprintf("%v", c.NewValue),
				"reloadable", false,
			)
		}
	}

	if hasNonReloadable {
		r.logger.Warn("some config changes require a restart to take effect")
	}

	// Store the new config atomically
	r.currentCfg.Store(newCfg)

	// Notify subscribers
	r.mu.RLock()
	subs := make([]Reloadable, len(r.subscribers))
	copy(subs, r.subscribers)
	r.mu.RUnlock()

	for _, sub := range subs {
		if err := sub.OnConfigReload(newCfg); err != nil {
			r.logger.Error("subscriber reload failed",
				"error", err,
				"subscriber", fmt.Sprintf("%T", sub),
			)
		}
	}

	r.logger.Info("config_reloaded",
		"changes", len(changes),
		"path", r.configPath,
	)

	return nil
}

// run is the main loop that listens for SIGHUP and file change events.
func (r *ConfigReloader) run(ctx context.Context) {
	defer close(r.stopped)
	defer signal.Stop(r.sigChan)
	if r.watcher != nil {
		defer r.watcher.Close()
	}

	var debounceTimer *time.Timer
	var debounceCh <-chan time.Time

	for {
		select {
		case <-ctx.Done():
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return

		case sig := <-r.sigChan:
			r.logger.Info("received signal, reloading config", "signal", sig)
			if err := r.Reload(); err != nil {
				r.logger.Error("SIGHUP reload failed", "error", err)
			}

		case event, ok := <-r.watcherEvents():
			if !ok {
				return
			}
			// Only react to writes, creates, and renames (file replacement pattern)
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Rename) {
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				debounceTimer = time.NewTimer(r.debounce)
				debounceCh = debounceTimer.C
			}

		case err, ok := <-r.watcherErrors():
			if !ok {
				return
			}
			r.logger.Error("file watcher error", "error", err)

		case <-debounceCh:
			debounceCh = nil
			debounceTimer = nil
			r.logger.Info("config file changed, reloading", "path", r.configPath)
			// Re-add the watch in case the file was replaced (rename/create pattern)
			if r.watcher != nil {
				// Ignore errors: the file may have been temporarily removed
				_ = r.watcher.Add(r.configPath)
			}
			if err := r.Reload(); err != nil {
				r.logger.Error("file watch reload failed", "error", err)
			}
		}
	}
}

// watcherEvents returns the watcher's event channel, or a nil channel if no watcher.
func (r *ConfigReloader) watcherEvents() <-chan fsnotify.Event {
	if r.watcher == nil {
		return nil
	}
	return r.watcher.Events
}

// watcherErrors returns the watcher's error channel, or a nil channel if no watcher.
func (r *ConfigReloader) watcherErrors() <-chan error {
	if r.watcher == nil {
		return nil
	}
	return r.watcher.Errors
}
