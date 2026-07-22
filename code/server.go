package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var unixPluginListener = "/run/spr-krun-plugin/spr-opencanary.sock"
var daemon = &DaemonManager{}

func jsonResponse(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		fmt.Println("failed to encode response:", err)
	}
}

func jsonError(w http.ResponseWriter, status int, err error) {
	jsonResponse(w, status, map[string]string{"Error": err.Error()})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}

type StatusResponse struct {
	DaemonStatus
	NodeID         string
	ActiveServices int
	WebhookEnabled bool
	Events24Hours  int
	UniqueSources  int
	LastEvent      time.Time `json:",omitempty"`
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	cfg := getConfig()
	status := daemon.Status()
	events, err := queryAlerts(1, "", "")
	if err != nil {
		fmt.Println("failed to read event stats:", err)
	}
	jsonResponse(w, http.StatusOK, StatusResponse{
		DaemonStatus:   status,
		NodeID:         cfg.NodeID,
		ActiveServices: activeServiceCount(cfg),
		WebhookEnabled: cfg.Webhook.Enabled,
		Events24Hours:  events.Last24Hours,
		UniqueSources:  events.UniqueSources,
		LastEvent:      events.LastEvent,
	})
}

func handleGetConfig(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusOK, configView(getConfig()))
}

func handlePutConfig(w http.ResponseWriter, r *http.Request) {
	var update ConfigUpdate
	if err := decodeJSON(w, r, &update); err != nil {
		jsonError(w, http.StatusBadRequest, err)
		return
	}
	view, err := applyConfigUpdate(update)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err)
		return
	}
	if err := daemon.Restart(); err != nil {
		jsonError(w, http.StatusBadGateway, fmt.Errorf("configuration saved but OpenCanary could not restart: %w", err))
		return
	}
	jsonResponse(w, http.StatusOK, view)
}

func handleDaemonAction(w http.ResponseWriter, r *http.Request) {
	var request struct{ Action string }
	if err := decodeJSON(w, r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err)
		return
	}
	var err error
	switch request.Action {
	case "start":
		err = daemon.Start()
	case "stop":
		err = daemon.Stop()
	case "restart":
		err = daemon.Restart()
	default:
		jsonError(w, http.StatusBadRequest, fmt.Errorf("Action must be start, stop, or restart"))
		return
	}
	if err != nil {
		jsonError(w, http.StatusBadGateway, err)
		return
	}
	jsonResponse(w, http.StatusOK, daemon.Status())
}

func handleEvents(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	events, err := queryAlerts(limit, r.URL.Query().Get("service"), r.URL.Query().Get("q"))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err)
		return
	}
	jsonResponse(w, http.StatusOK, events)
}

func handleClearEvents(w http.ResponseWriter, r *http.Request) {
	if err := clearAlerts(); err != nil {
		jsonError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func handleTopology(w http.ResponseWriter, r *http.Request) {
	cfg := getConfig()
	status := daemon.Status()
	jsonResponse(w, http.StatusOK, buildTopology(status.Running, status.CanaryIP, cfg.NodeID))
}

type spaHandler struct {
	root string
}

func (h spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clean := filepath.Clean("/" + r.URL.Path)
	relative := strings.TrimPrefix(clean, "/")
	path := filepath.Join(h.root, relative)
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		path = filepath.Join(h.root, "index.html")
	}
	w.Header().Set("Cache-Control", "no-store")
	http.ServeFile(w, r, path)
}

func requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline' data:; connect-src 'self'")
		start := time.Now()
		next.ServeHTTP(w, r)
		fmt.Printf("%s %s %s\n", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}

func routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", handleStatus)
	mux.HandleFunc("GET /config", handleGetConfig)
	mux.HandleFunc("PUT /config", handlePutConfig)
	mux.HandleFunc("POST /daemon", handleDaemonAction)
	mux.HandleFunc("GET /events", handleEvents)
	mux.HandleFunc("DELETE /events", handleClearEvents)
	mux.HandleFunc("GET /topology", handleTopology)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, map[string]bool{"OK": true})
	})
	// SPR normally strips this prefix while proxying the Unix socket. Keeping a
	// prefixed alias makes the bundled UI independently testable and supports
	// older proxy deployments that pass the original request path through.
	mux.Handle("/plugins/spr-opencanary/", http.StripPrefix("/plugins/spr-opencanary", mux))
	mux.Handle("/", spaHandler{root: "/ui"})
	return requestLog(mux)
}

func run() error {
	if testPrefix != "" {
		unixPluginListener = testPrefix + unixPluginListener
	}
	if err := initConfig(); err != nil {
		return err
	}
	if err := daemon.Start(); err != nil {
		// Keep the control plane available so an administrator can repair or
		// restart a failed daemon from the SPR UI.
		fmt.Println("OpenCanary failed to start:", err)
	}
	if err := os.MkdirAll(filepath.Dir(unixPluginListener), 0770); err != nil {
		return err
	}
	if err := os.Remove(unixPluginListener); err != nil && !os.IsNotExist(err) {
		return err
	}
	listener, err := net.Listen("unix", unixPluginListener)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chmod(unixPluginListener, 0770); err != nil {
		// Docker Desktop bind mounts do not support chmod on Unix sockets.
		// SPR's Linux host does; keep serving if the backing filesystem does not.
		fmt.Println("warning: could not chmod plugin socket:", err)
	}

	server := &http.Server{Handler: routes(), ReadHeaderTimeout: 5 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		_ = daemon.Stop()
	}()
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "spr-opencanary:", err)
		os.Exit(1)
	}
}
