package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

const (
	stateDir        = "/state/plugins/spr-opencanary"
	configDir       = "/etc/opencanaryd"
	openCanaryVer   = "0.9.8"
	defaultCanaryIP = "172.30.119.2"
	eventLogBytes   = 20 * 1024 * 1024
	eventLogBackups = 2
)

var testPrefix = os.Getenv("TEST_PREFIX")

var (
	ConfigFile       = testPrefix + configDir + "/config.json"
	OpenCanaryConfig = testPrefix + configDir + "/opencanary.conf"
	EventLogFile     = testPrefix + stateDir + "/events.jsonl"
	ProcessLogFile   = testPrefix + stateDir + "/daemon.log"
	TLSCertFile      = testPrefix + stateDir + "/certs/opencanary.pem"
	TLSKeyFile       = testPrefix + stateDir + "/certs/opencanary.key"
)

//go:embed opencanary.base.json
var baseConfigJSON []byte

type ServiceConfig struct {
	Enabled bool
	Port    int
}

type WebhookConfig struct {
	Enabled bool
	Kind    string
	URL     string `json:",omitempty"`
}

type Config struct {
	NodeID    string
	IgnoreIPs []string
	Services  map[string]ServiceConfig
	Webhook   WebhookConfig
}

type WebhookView struct {
	Enabled    bool
	Kind       string
	Configured bool
}

type ConfigView struct {
	NodeID    string
	IgnoreIPs []string
	Services  map[string]ServiceConfig
	Webhook   WebhookView
}

type WebhookUpdate struct {
	Enabled bool
	Kind    string
	URL     string
	Clear   bool
}

type ConfigUpdate struct {
	NodeID    string
	IgnoreIPs []string
	Services  map[string]ServiceConfig
	Webhook   WebhookUpdate
}

type ServiceDefinition struct {
	Name        string
	Label       string
	Protocol    string
	DefaultPort int
}

var serviceCatalog = map[string]ServiceDefinition{
	"ftp":       {Name: "ftp", Label: "FTP", Protocol: "tcp", DefaultPort: 21},
	"git":       {Name: "git", Label: "Git", Protocol: "tcp", DefaultPort: 9418},
	"http":      {Name: "http", Label: "HTTP", Protocol: "tcp", DefaultPort: 80},
	"https":     {Name: "https", Label: "HTTPS", Protocol: "tcp", DefaultPort: 443},
	"httpproxy": {Name: "httpproxy", Label: "HTTP proxy", Protocol: "tcp", DefaultPort: 8080},
	"mongodb":   {Name: "mongodb", Label: "MongoDB", Protocol: "tcp", DefaultPort: 27017},
	"mssql":     {Name: "mssql", Label: "Microsoft SQL", Protocol: "tcp", DefaultPort: 1433},
	"mysql":     {Name: "mysql", Label: "MySQL", Protocol: "tcp", DefaultPort: 3306},
	"ntp":       {Name: "ntp", Label: "NTP", Protocol: "udp", DefaultPort: 123},
	"rdp":       {Name: "rdp", Label: "Remote Desktop", Protocol: "tcp", DefaultPort: 3389},
	"redis":     {Name: "redis", Label: "Redis", Protocol: "tcp", DefaultPort: 6379},
	"sip":       {Name: "sip", Label: "SIP", Protocol: "udp", DefaultPort: 5060},
	"snmp":      {Name: "snmp", Label: "SNMP", Protocol: "udp", DefaultPort: 161},
	"ssh":       {Name: "ssh", Label: "SSH", Protocol: "tcp", DefaultPort: 22},
	"tcpbanner": {Name: "tcpbanner", Label: "TCP banner", Protocol: "tcp", DefaultPort: 8001},
	"telnet":    {Name: "telnet", Label: "Telnet", Protocol: "tcp", DefaultPort: 23},
	"tftp":      {Name: "tftp", Label: "TFTP", Protocol: "udp", DefaultPort: 69},
	"vnc":       {Name: "vnc", Label: "VNC", Protocol: "tcp", DefaultPort: 5900},
}

var (
	configMu      sync.RWMutex
	currentConfig Config
	nodeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

func defaultConfig() Config {
	services := make(map[string]ServiceConfig, len(serviceCatalog))
	for name, definition := range serviceCatalog {
		services[name] = ServiceConfig{Port: definition.DefaultPort}
	}
	for _, name := range []string{"ftp", "http", "mysql", "redis", "ssh"} {
		service := services[name]
		service.Enabled = true
		services[name] = service
	}
	return Config{
		NodeID:    "spr-canary-01",
		IgnoreIPs: []string{},
		Services:  services,
		Webhook:   WebhookConfig{Kind: "generic"},
	}
}

func cloneServices(in map[string]ServiceConfig) map[string]ServiceConfig {
	out := make(map[string]ServiceConfig, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func cloneConfig(c Config) Config {
	c.IgnoreIPs = append([]string{}, c.IgnoreIPs...)
	c.Services = cloneServices(c.Services)
	return c
}

func configView(c Config) ConfigView {
	return ConfigView{
		NodeID:    c.NodeID,
		IgnoreIPs: append([]string{}, c.IgnoreIPs...),
		Services:  cloneServices(c.Services),
		Webhook: WebhookView{
			Enabled:    c.Webhook.Enabled,
			Kind:       c.Webhook.Kind,
			Configured: c.Webhook.URL != "",
		},
	}
}

func getConfig() Config {
	configMu.RLock()
	defer configMu.RUnlock()
	return cloneConfig(currentConfig)
}

func activeServiceCount(c Config) int {
	count := 0
	for _, service := range c.Services {
		if service.Enabled {
			count++
		}
	}
	return count
}

func validateConfig(c Config) error {
	if !nodeIDPattern.MatchString(c.NodeID) {
		return errors.New("NodeID must be 1-64 characters using letters, numbers, dots, dashes, or underscores")
	}
	if len(c.IgnoreIPs) > 128 {
		return errors.New("IgnoreIPs accepts at most 128 entries")
	}
	seenIgnore := map[string]bool{}
	for _, entry := range c.IgnoreIPs {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return errors.New("IgnoreIPs cannot contain an empty entry")
		}
		if _, err := netip.ParseAddr(entry); err != nil {
			if _, prefixErr := netip.ParsePrefix(entry); prefixErr != nil {
				return fmt.Errorf("IgnoreIPs: %q is not an IP address or CIDR", entry)
			}
		}
		if seenIgnore[entry] {
			return fmt.Errorf("IgnoreIPs contains duplicate %q", entry)
		}
		seenIgnore[entry] = true
	}

	if len(c.Services) != len(serviceCatalog) {
		return errors.New("Services must contain the complete supported service catalog")
	}
	active := 0
	ports := map[int]string{}
	for name, definition := range serviceCatalog {
		service, ok := c.Services[name]
		if !ok {
			return fmt.Errorf("Services is missing %q", name)
		}
		if service.Port < 1 || service.Port > 65535 {
			return fmt.Errorf("%s port must be between 1 and 65535", definition.Label)
		}
		// OpenCanary validates the complete service catalog, including disabled
		// modules, and requires every configured port to be globally unique.
		if other, exists := ports[service.Port]; exists {
			return fmt.Errorf("%s and %s cannot both use port %d", definition.Label, other, service.Port)
		}
		ports[service.Port] = definition.Label
		if service.Enabled {
			active++
		}
	}
	if other, exists := ports[5355]; exists {
		return fmt.Errorf("%s cannot use port 5355, which is reserved by OpenCanary's LLMNR module", other)
	}
	if active == 0 {
		return errors.New("enable at least one decoy service")
	}

	if c.Webhook.Kind == "" {
		c.Webhook.Kind = "generic"
	}
	switch c.Webhook.Kind {
	case "generic", "slack", "teams":
	default:
		return errors.New("Webhook.Kind must be generic, slack, or teams")
	}
	if c.Webhook.Enabled && c.Webhook.URL == "" {
		return errors.New("a webhook URL is required when notifications are enabled")
	}
	if c.Webhook.URL != "" {
		if len(c.Webhook.URL) > 2048 {
			return errors.New("webhook URL is too long")
		}
		parsed, err := url.Parse(c.Webhook.URL)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return errors.New("webhook URL must be an absolute http or https URL")
		}
	}
	return nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func renderOpenCanaryConfig(c Config) ([]byte, error) {
	var rendered map[string]any
	if err := json.Unmarshal(baseConfigJSON, &rendered); err != nil {
		return nil, fmt.Errorf("decode embedded OpenCanary config: %w", err)
	}
	rendered["device.node_id"] = c.NodeID
	rendered["ip.ignorelist"] = c.IgnoreIPs
	rendered["portscan.enabled"] = false
	rendered["smb.enabled"] = false

	for name, service := range c.Services {
		if name == "tcpbanner" {
			rendered["tcpbanner.enabled"] = service.Enabled
			rendered["tcpbanner_1.enabled"] = service.Enabled
			rendered["tcpbanner_1.port"] = service.Port
			continue
		}
		rendered[name+".enabled"] = service.Enabled
		rendered[name+".port"] = service.Port
	}

	handlers := map[string]any{
		"file": map[string]any{
			"class":       "logging.handlers.RotatingFileHandler",
			"filename":    EventLogFile,
			"maxBytes":    eventLogBytes,
			"backupCount": eventLogBackups,
			"encoding":    "utf-8",
		},
	}
	if c.Webhook.Enabled {
		switch c.Webhook.Kind {
		case "slack":
			handlers["slack"] = map[string]any{
				"class":       "opencanary.logger.SlackHandler",
				"webhook_url": c.Webhook.URL,
				"filters":     []string{"attacker_events"},
			}
		case "teams":
			handlers["teams"] = map[string]any{
				"class":       "opencanary.logger.TeamsHandler",
				"webhook_url": c.Webhook.URL,
				"filters":     []string{"attacker_events"},
			}
		default:
			handlers["webhook"] = map[string]any{
				"class":       "opencanary.logger.WebhookHandler",
				"url":         c.Webhook.URL,
				"method":      "POST",
				"data":        map[string]string{"message": "%(message)s"},
				"headers":     map[string]string{"Content-Type": "application/json"},
				"status_code": 200,
				"filters":     []string{"attacker_events"},
			}
		}
	}
	loggerKwargs := map[string]any{
		"formatters": map[string]any{
			"plain": map[string]string{"format": "%(message)s"},
		},
		"handlers": handlers,
	}
	if c.Webhook.Enabled {
		loggerKwargs["filters"] = map[string]any{
			"attacker_events": map[string]string{
				"()": "spr_opencanary_filters.WebhookAlertFilter",
			},
		}
	}
	rendered["logger"] = map[string]any{
		"class":  "PyLogger",
		"kwargs": loggerKwargs,
	}

	return json.MarshalIndent(rendered, "", "  ")
}

func persistConfig(c Config) error {
	privateJSON, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	upstreamJSON, err := renderOpenCanaryConfig(c)
	if err != nil {
		return err
	}
	if err := atomicWrite(ConfigFile, append(privateJSON, '\n'), 0600); err != nil {
		return fmt.Errorf("write plugin config: %w", err)
	}
	if err := atomicWrite(OpenCanaryConfig, append(upstreamJSON, '\n'), 0600); err != nil {
		return fmt.Errorf("write OpenCanary config: %w", err)
	}
	return nil
}

func initConfig() error {
	if err := os.MkdirAll(filepath.Dir(EventLogFile), 0750); err != nil {
		return err
	}
	data, err := os.ReadFile(ConfigFile)
	var cfg Config
	switch {
	case os.IsNotExist(err):
		cfg = defaultConfig()
	case err != nil:
		return err
	default:
		if err := json.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("parse %s: %w", ConfigFile, err)
		}
	}
	if cfg.Webhook.Kind == "" {
		cfg.Webhook.Kind = "generic"
	}
	if err := validateConfig(cfg); err != nil {
		return fmt.Errorf("invalid persisted config: %w", err)
	}
	if err := persistConfig(cfg); err != nil {
		return err
	}
	configMu.Lock()
	currentConfig = cloneConfig(cfg)
	configMu.Unlock()
	return nil
}

func applyConfigUpdate(update ConfigUpdate) (ConfigView, error) {
	configMu.Lock()
	defer configMu.Unlock()

	candidate := Config{
		NodeID:    strings.TrimSpace(update.NodeID),
		IgnoreIPs: make([]string, 0, len(update.IgnoreIPs)),
		Services:  cloneServices(update.Services),
		Webhook: WebhookConfig{
			Enabled: update.Webhook.Enabled,
			Kind:    update.Webhook.Kind,
			URL:     strings.TrimSpace(update.Webhook.URL),
		},
	}
	for _, entry := range update.IgnoreIPs {
		candidate.IgnoreIPs = append(candidate.IgnoreIPs, strings.TrimSpace(entry))
	}
	sort.Strings(candidate.IgnoreIPs)
	if candidate.Webhook.Kind == "" {
		candidate.Webhook.Kind = "generic"
	}
	if update.Webhook.Clear {
		candidate.Webhook.URL = ""
	} else if candidate.Webhook.URL == "" {
		candidate.Webhook.URL = currentConfig.Webhook.URL
	}
	if err := validateConfig(candidate); err != nil {
		return ConfigView{}, err
	}
	if err := persistConfig(candidate); err != nil {
		return ConfigView{}, err
	}
	currentConfig = cloneConfig(candidate)
	return configView(candidate), nil
}

func canaryIP() string {
	if value := strings.TrimSpace(os.Getenv("CANARY_IP")); value != "" {
		return value
	}
	return defaultCanaryIP
}
