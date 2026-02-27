// Package server integrates all components into a complete HTTP server
// for the a2a-sentinel security gateway.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/vivars7/a2a-sentinel/internal/agentcard"
	"github.com/vivars7/a2a-sentinel/internal/audit"
	"github.com/vivars7/a2a-sentinel/internal/config"
	"github.com/vivars7/a2a-sentinel/internal/ctxkeys"
	sentinelerrors "github.com/vivars7/a2a-sentinel/internal/errors"
	sentinelgrpc "github.com/vivars7/a2a-sentinel/internal/grpc"
	"github.com/vivars7/a2a-sentinel/internal/health"
	"github.com/vivars7/a2a-sentinel/internal/protocol"
	"github.com/vivars7/a2a-sentinel/internal/proxy"
	"github.com/vivars7/a2a-sentinel/internal/router"
	"github.com/vivars7/a2a-sentinel/internal/security"
)

// cardStarter abstracts the card manager methods used by Server and adapters.
// *agentcard.Manager satisfies this interface.
type cardStarter interface {
	Start(ctx context.Context) error
	Stop()
	GetAggregatedCard() *protocol.AgentCard
	IsHealthy(name string) bool
	HealthyAgents() []string
}

// Server is the main a2a-sentinel HTTP server assembling all components.
type Server struct {
	cfg           *config.Config
	mu            sync.Mutex
	httpServer    *http.Server
	grpcServer    *sentinelgrpc.GRPCServer
	cardManager   cardStarter
	listener      net.Listener // if non-nil, Start uses this instead of creating one
	streamMgr     *proxy.StreamManager
	httpProxy     *proxy.HTTPProxy
	sseProxy      *proxy.SSEProxy
	router        *router.Router
	healthHandler *health.Handler
	auditLogger   *audit.Logger
	metrics       *audit.Metrics
	logger        *slog.Logger
	version       string
}

// agentLookupAdapter adapts cardStarter to router.AgentLookup interface.
type agentLookupAdapter struct {
	manager cardStarter
	agents  []config.AgentConfig
}

// IsHealthy returns whether the named agent is currently healthy.
func (a *agentLookupAdapter) IsHealthy(name string) bool {
	return a.manager.IsHealthy(name)
}

// HealthyAgents returns the names of all healthy agents.
func (a *agentLookupAdapter) HealthyAgents() []string {
	return a.manager.HealthyAgents()
}

// GetAgentURL returns the backend URL for the named agent.
func (a *agentLookupAdapter) GetAgentURL(name string) (string, bool) {
	for _, agent := range a.agents {
		if agent.Name == name {
			return agent.URL, true
		}
	}
	return "", false
}

// GetDefaultAgent returns the name, URL, and whether a default agent exists.
func (a *agentLookupAdapter) GetDefaultAgent() (string, string, bool) {
	for _, agent := range a.agents {
		if agent.Default {
			return agent.Name, agent.URL, true
		}
	}
	return "", "", false
}

// healthCheckerAdapter adapts cardStarter to health.AgentHealthChecker.
type healthCheckerAdapter struct {
	manager cardStarter
	agents  []config.AgentConfig
}

// HealthyAgents returns the list of healthy agent names.
func (h *healthCheckerAdapter) HealthyAgents() []string {
	return h.manager.HealthyAgents()
}

// AllAgentNames returns all configured agent names regardless of health.
func (h *healthCheckerAdapter) AllAgentNames() []string {
	names := make([]string, len(h.agents))
	for i, a := range h.agents {
		names[i] = a.Name
	}
	return names
}

// New creates a new Server from configuration.
func New(cfg *config.Config, version string) (*Server, error) {
	// 1. Create logger based on config
	logger := buildLogger(cfg)

	// 2. Create agentcard.Manager
	cardManager := agentcard.NewManager(cfg.Agents, cfg.Security.CardSignature, logger)

	// 3. Create StreamManager
	streamMgr := proxy.NewStreamManager()

	// 4. Create HTTPProxy
	httpTransport := proxy.NewHTTPTransport()
	httpProxy := proxy.NewHTTPProxy(httpTransport, logger)

	// 5. Create SSEProxy
	streamTransport := proxy.NewStreamTransport()
	sseProxy := proxy.NewSSEProxy(streamTransport, streamMgr, logger)

	// 6. Create Router with AgentLookup adapter
	lookup := &agentLookupAdapter{
		manager: cardManager,
		agents:  cfg.Agents,
	}
	rtr := router.NewRouter(cfg.Routing.Mode, lookup)

	// 7. Create AuditLogger
	auditSampling := audit.SamplingConfig{
		Rate:      cfg.Logging.Audit.SamplingRate,
		ErrorRate: cfg.Logging.Audit.ErrorSamplingRate,
		MaxBody:   cfg.Logging.Audit.MaxBodyLogSize,
	}
	auditLogger := audit.NewLogger(logger, auditSampling)

	// 7b. Create Metrics collector
	metrics := audit.NewMetrics()

	// 8. Find default agent name for health handler
	defaultAgent := ""
	for _, a := range cfg.Agents {
		if a.Default {
			defaultAgent = a.Name
			break
		}
	}

	// 9. Create Health handler
	healthChecker := &healthCheckerAdapter{
		manager: cardManager,
		agents:  cfg.Agents,
	}
	healthHandler := health.NewHandler(healthChecker, version, cfg.Health.ReadinessMode, defaultAgent)

	srv := &Server{
		cfg:           cfg,
		cardManager:   cardManager,
		streamMgr:     streamMgr,
		httpProxy:     httpProxy,
		sseProxy:      sseProxy,
		router:        rtr,
		healthHandler: healthHandler,
		auditLogger:   auditLogger,
		metrics:       metrics,
		logger:        logger,
		version:       version,
	}

	// 10. Create gRPC server if grpc_port is configured
	if cfg.Listen.GRPCPort > 0 {
		pipelineCfg := srv.buildSecurityPipelineConfig()
		middlewares := security.BuildPipeline(pipelineCfg)
		srv.grpcServer = sentinelgrpc.NewGRPCServer(cfg, rtr, httpProxy, sseProxy, middlewares, logger)
		logger.Info("gRPC server configured", "port", cfg.Listen.GRPCPort)
	}

	return srv, nil
}

// Start begins listening and serving. It blocks until the context is canceled
// or an unrecoverable error occurs.
func (s *Server) Start(ctx context.Context) error {
	// Start card manager polling
	if err := s.cardManager.Start(ctx); err != nil {
		return fmt.Errorf("starting card manager: %w", err)
	}

	// Build handler
	handler := s.handler()

	listenAddr := fmt.Sprintf("%s:%d", s.cfg.Listen.Host, s.cfg.Listen.Port)

	// Use injected listener or create one
	ln := s.listener
	if ln == nil {
		var err error
		ln, err = net.Listen("tcp", listenAddr)
		if err != nil {
			return fmt.Errorf("listening on %s: %w", listenAddr, err)
		}

		// Wrap with LimitedListener if configured
		if s.cfg.Listen.MaxConnections > 0 {
			ln = newLimitedListener(ln, s.cfg.Listen.MaxConnections)
		}
	}

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	s.mu.Lock()
	s.httpServer = srv
	s.mu.Unlock()

	errCh := make(chan error, 2)
	go func() {
		s.logger.Info("listening", "addr", listenAddr)
		errCh <- srv.Serve(ln)
	}()

	// Start gRPC server if configured
	if s.grpcServer != nil {
		grpcAddr := fmt.Sprintf("%s:%d", s.cfg.Listen.Host, s.cfg.Listen.GRPCPort)
		grpcLn, err := net.Listen("tcp", grpcAddr)
		if err != nil {
			return fmt.Errorf("listening gRPC on %s: %w", grpcAddr, err)
		}
		go func() {
			errCh <- s.grpcServer.Serve(grpcLn)
		}()
	}

	// Wait for context cancellation or server error
	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("server error: %w", err)
		}
	case <-ctx.Done():
		s.logger.Info("shutdown signal received")
	}

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.Shutdown.Timeout.Duration)
	defer cancel()

	if err := s.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown error: %w", err)
	}

	s.logger.Info("server stopped gracefully")
	return nil
}

// Shutdown performs graceful shutdown.
func (s *Server) Shutdown(ctx context.Context) error {
	// 1. Drain SSE streams
	drainCtx, drainCancel := context.WithTimeout(ctx, s.cfg.Shutdown.DrainTimeout.Duration)
	defer drainCancel()
	if err := s.streamMgr.DrainAll(drainCtx); err != nil {
		s.logger.Warn("drain timeout, some streams may be interrupted", "error", err)
	}

	// 2. Shutdown HTTP server
	s.mu.Lock()
	hs := s.httpServer
	s.mu.Unlock()

	if hs != nil {
		if err := hs.Shutdown(ctx); err != nil {
			return fmt.Errorf("http server shutdown: %w", err)
		}
	}

	// 2b. Graceful stop gRPC server
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}

	// 3. Stop card manager
	s.cardManager.Stop()

	return nil
}

// handler builds the complete HTTP handler with security pipeline and routing.
func (s *Server) handler() http.Handler {
	// Main request handler (behind security pipeline)
	mainHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Agent Card request (bypass routing)
		if r.Method == http.MethodGet && r.URL.Path == "/.well-known/agent.json" {
			s.handleAgentCard(w, r)
			return
		}

		// Protocol detection
		result, err := protocol.Detect(r)
		if err != nil {
			sentinelerrors.WriteHTTPError(w, sentinelerrors.ErrInvalidRequest)
			return
		}

		// Store request meta in context
		ctx := ctxkeys.WithRequestMeta(r.Context(), ctxkeys.RequestMeta{
			Protocol: string(result.Protocol),
			Method:   result.Method,
			Binding:  result.Binding,
		})

		// Initialize audit entry
		auditEntry := &ctxkeys.AuditEntry{
			Method:    result.Method,
			Protocol:  string(result.Protocol),
			StartTime: time.Now(),
		}
		ctx = ctxkeys.WithAuditEntry(ctx, auditEntry)
		r = r.WithContext(ctx)

		// Route request
		target, routeErr := s.router.Route(r)
		if routeErr != nil {
			s.writeError(w, r, routeErr)
			s.finalizeAudit(r, "blocked")
			return
		}

		auditEntry.TargetAgent = target.AgentName

		// Store route result in context
		ctx = ctxkeys.WithRouteResult(r.Context(), ctxkeys.RouteResult{
			AgentName:   target.AgentName,
			AgentURL:    target.AgentURL,
			IsStreaming: result.Method == "message/stream" || result.Method == "tasks/subscribe",
		})
		r = r.WithContext(ctx)

		// Forward to appropriate proxy
		var proxyErr error
		if result.Method == "message/stream" || result.Method == "tasks/subscribe" {
			maxStreams := s.getMaxStreams(target.AgentName)
			proxyErr = s.sseProxy.ProxyStream(w, r, target.AgentName, target.AgentURL, target.Path, maxStreams)
		} else {
			proxyErr = s.httpProxy.Forward(w, r, target.AgentURL, target.Path)
		}

		// Finalize audit
		if proxyErr != nil {
			s.finalizeAudit(r, "error")
		} else {
			s.finalizeAudit(r, "ok")
		}
	})

	// Build security pipeline
	pipelineCfg := s.buildSecurityPipelineConfig()
	middlewares := security.BuildPipeline(pipelineCfg)
	securedHandler := security.ApplyPipeline(mainHandler, middlewares)

	// Build final mux
	mux := http.NewServeMux()

	// Health and metrics endpoints bypass security
	mux.Handle(s.cfg.Health.LivenessPath, s.healthHandler)
	mux.Handle(s.cfg.Health.ReadinessPath, s.healthHandler)
	mux.HandleFunc("/metrics", s.metrics.Handler())

	// Everything else goes through security
	mux.Handle("/", securedHandler)

	return mux
}

// handleAgentCard serves the aggregated Agent Card.
func (s *Server) handleAgentCard(w http.ResponseWriter, r *http.Request) {
	card := s.cardManager.GetAggregatedCard()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(card)
}

// writeError writes an error response appropriate for the detected protocol.
func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	sentErr, ok := err.(*sentinelerrors.SentinelError)
	if !ok {
		sentErr = sentinelerrors.ErrAgentUnavailable
	}

	meta, hasMeta := ctxkeys.RequestMetaFrom(r.Context())
	if hasMeta && meta.Protocol == string(protocol.ProtocolJSONRPC) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(sentErr.Code)
		json.NewEncoder(w).Encode(sentinelerrors.ToJSONRPCError(sentErr, nil))
	} else {
		sentinelerrors.WriteHTTPError(w, sentErr)
	}
}

// finalizeAudit updates the audit entry and logs it.
func (s *Server) finalizeAudit(r *http.Request, status string) {
	auditEntry, ok := ctxkeys.AuditEntryFrom(r.Context())
	if !ok {
		return
	}
	auditEntry.Status = status

	// Update auth info in audit entry
	if authInfo, authOK := ctxkeys.AuthInfoFrom(r.Context()); authOK {
		auditEntry.AuthScheme = authInfo.Scheme
		auditEntry.AuthSubject = authInfo.Subject
	}

	s.auditLogger.LogRequest(r.Context())
}

// getMaxStreams returns the max_streams setting for an agent.
func (s *Server) getMaxStreams(agentName string) int {
	for _, a := range s.cfg.Agents {
		if a.Name == agentName {
			return a.MaxStreams
		}
	}
	return 10 // default
}

// buildSecurityPipelineConfig constructs the SecurityPipelineConfig from server config.
func (s *Server) buildSecurityPipelineConfig() security.SecurityPipelineConfig {
	pipelineCfg := security.SecurityPipelineConfig{
		Auth: security.AuthPipelineConfig{
			Mode:                 s.cfg.Security.Auth.Mode,
			AllowUnauthenticated: s.cfg.Security.Auth.AllowUnauthenticated,
		},
		RateLimit: security.RateLimitPipelineConfig{
			Enabled:             s.cfg.Security.RateLimit.Enabled,
			IPPerIP:             s.cfg.Security.RateLimit.IP.PerIP,
			IPBurst:             s.cfg.Security.RateLimit.IP.Burst,
			IPCleanupInterval:   s.cfg.Security.RateLimit.IP.CleanupInterval.Duration,
			UserPerUser:         s.cfg.Security.RateLimit.User.PerUser,
			UserBurst:           s.cfg.Security.RateLimit.User.Burst,
			UserCleanupInterval: s.cfg.Security.RateLimit.User.CleanupInterval.Duration,
		},
		Replay: security.ReplayDetectorConfig{
			Enabled:         s.cfg.Security.Replay.Enabled,
			Window:          s.cfg.Security.Replay.Window.Duration,
			NoncePolicy:     s.cfg.Security.Replay.NoncePolicy,
			CleanupInterval: s.cfg.Security.Replay.CleanupInterval.Duration,
		},
		GlobalRateLimit: s.cfg.Listen.GlobalRateLimit,
		TrustedProxies:  s.cfg.Listen.TrustedProxies,
		Push:            s.cfg.Security.Push,
		Logger:          s.logger,
	}

	// Add JWT config if in terminate mode
	if s.cfg.Security.Auth.Mode == "terminate" && len(s.cfg.Security.Auth.Schemes) > 0 {
		scheme := s.cfg.Security.Auth.Schemes[0]
		pipelineCfg.Auth.Issuer = scheme.JWT.Issuer
		pipelineCfg.Auth.Audience = scheme.JWT.Audience
		pipelineCfg.Auth.JWKSURL = scheme.JWT.JWKSURL
	}

	return pipelineCfg
}

// buildLogger creates an slog.Logger based on configuration.
func buildLogger(cfg *config.Config) *slog.Logger {
	var level slog.Level
	switch cfg.Logging.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}

	var output *os.File
	switch cfg.Logging.Output {
	case "stderr":
		output = os.Stderr
	default:
		output = os.Stdout
	}

	var handler slog.Handler
	switch cfg.Logging.Format {
	case "text":
		handler = slog.NewTextHandler(output, opts)
	default:
		handler = slog.NewJSONHandler(output, opts)
	}

	return slog.New(handler)
}

// ── LimitedListener ──

// limitedListener wraps a net.Listener to limit maximum concurrent connections.
type limitedListener struct {
	net.Listener
	sem chan struct{}
}

// newLimitedListener creates a listener that limits concurrent connections.
func newLimitedListener(l net.Listener, maxConns int) net.Listener {
	return &limitedListener{
		Listener: l,
		sem:      make(chan struct{}, maxConns),
	}
}

// Accept waits for and returns the next connection, blocking if at limit.
func (l *limitedListener) Accept() (net.Conn, error) {
	l.sem <- struct{}{}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitedConn{Conn: c, sem: l.sem}, nil
}

// limitedConn wraps a net.Conn to release the semaphore slot on close.
type limitedConn struct {
	net.Conn
	sem    chan struct{}
	closed sync.Once
}

// Close releases the connection and frees the semaphore slot.
func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.closed.Do(func() { <-c.sem })
	return err
}
