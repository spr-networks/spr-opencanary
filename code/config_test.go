package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfigIsValid(t *testing.T) {
	cfg := defaultConfig()
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("default config is invalid: %v", err)
	}
	if got := activeServiceCount(cfg); got != 5 {
		t.Fatalf("active services = %d, want 5", got)
	}
	if len(cfg.Services) != len(serviceCatalog) {
		t.Fatalf("service catalog mismatch: %d != %d", len(cfg.Services), len(serviceCatalog))
	}
}

func TestValidateConfigRejectsDuplicateDisabledPort(t *testing.T) {
	cfg := defaultConfig()
	ftp := cfg.Services["ftp"]
	git := cfg.Services["git"]
	git.Port = ftp.Port
	git.Enabled = false
	cfg.Services["git"] = git
	if err := validateConfig(cfg); err == nil || !strings.Contains(err.Error(), "cannot both use port") {
		t.Fatalf("duplicate disabled port should be rejected, got %v", err)
	}
}

func TestRenderOpenCanaryConfigAndRedaction(t *testing.T) {
	cfg := defaultConfig()
	cfg.NodeID = "branch-files-01"
	cfg.Webhook = WebhookConfig{Enabled: true, Kind: "slack", URL: "https://hooks.slack.test/services/secret"}
	raw, err := renderOpenCanaryConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var rendered map[string]any
	if err := json.Unmarshal(raw, &rendered); err != nil {
		t.Fatal(err)
	}
	if rendered["device.node_id"] != cfg.NodeID {
		t.Fatalf("node ID not rendered: %v", rendered["device.node_id"])
	}
	logger := rendered["logger"].(map[string]any)
	kwargs := logger["kwargs"].(map[string]any)
	handlers := kwargs["handlers"].(map[string]any)
	fileHandler := handlers["file"].(map[string]any)
	if fileHandler["class"] != "logging.handlers.RotatingFileHandler" || int(fileHandler["maxBytes"].(float64)) != eventLogBytes {
		t.Fatalf("bounded rotating file handler not rendered: %#v", fileHandler)
	}
	if _, ok := handlers["slack"]; !ok {
		t.Fatalf("slack handler missing: %#v", handlers)
	}
	view := configView(cfg)
	if !view.Webhook.Configured || !view.Webhook.Enabled {
		t.Fatalf("webhook state not exposed: %+v", view.Webhook)
	}
	encoded, _ := json.Marshal(view)
	if strings.Contains(string(encoded), "secret") {
		t.Fatalf("webhook secret leaked through config view: %s", encoded)
	}
}

func TestApplyConfigUpdateKeepsWriteOnlyWebhook(t *testing.T) {
	temp := t.TempDir()
	oldConfigFile, oldOpenCanaryConfig := ConfigFile, OpenCanaryConfig
	ConfigFile = filepath.Join(temp, "config.json")
	OpenCanaryConfig = filepath.Join(temp, "opencanary.conf")
	t.Cleanup(func() {
		ConfigFile, OpenCanaryConfig = oldConfigFile, oldOpenCanaryConfig
	})

	cfg := defaultConfig()
	cfg.Webhook = WebhookConfig{Enabled: true, Kind: "generic", URL: "https://alerts.test/private"}
	configMu.Lock()
	currentConfig = cloneConfig(cfg)
	configMu.Unlock()

	update := ConfigUpdate{
		NodeID:    cfg.NodeID,
		IgnoreIPs: []string{"192.0.2.10"},
		Services:  cloneServices(cfg.Services),
		Webhook:   WebhookUpdate{Enabled: true, Kind: "generic"},
	}
	view, err := applyConfigUpdate(update)
	if err != nil {
		t.Fatal(err)
	}
	if !view.Webhook.Configured {
		t.Fatal("empty update should keep configured webhook")
	}
	if got := getConfig().Webhook.URL; got != cfg.Webhook.URL {
		t.Fatalf("webhook URL changed: %q", got)
	}
	data, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "private") {
		t.Fatalf("view leaked webhook: %s", data)
	}
}
