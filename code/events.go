package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type rawAlert struct {
	DstHost           string         `json:"dst_host"`
	DstPort           int            `json:"dst_port"`
	LocalTime         string         `json:"local_time"`
	LocalTimeAdjusted string         `json:"local_time_adjusted"`
	LogData           map[string]any `json:"logdata"`
	LogType           int            `json:"logtype"`
	NodeID            string         `json:"node_id"`
	SrcHost           string         `json:"src_host"`
	SrcPort           int            `json:"src_port"`
	UTCTime           string         `json:"utc_time"`
}

type Alert struct {
	ID         string
	Timestamp  time.Time
	Service    string
	Event      string
	SourceIP   string
	SourcePort int
	DestPort   int
	Username   string `json:",omitempty"`
	Summary    string
	Severity   string
}

type EventsResponse struct {
	Events        []Alert
	Total         int
	FilteredTotal int
	Last24Hours   int
	UniqueSources int
	ByService     map[string]int
	Hourly        []int
	LastEvent     time.Time `json:",omitempty"`
}

var logTypeInfo = map[int]struct {
	service string
	event   string
}{
	2000:  {"ftp", "Login attempt"},
	2001:  {"ftp", "Authentication started"},
	3000:  {"http", "Page request"},
	3001:  {"http", "Login attempt"},
	3002:  {"http", "Unimplemented method"},
	3003:  {"http", "Redirect request"},
	4000:  {"ssh", "Connection"},
	4001:  {"ssh", "Client identified"},
	4002:  {"ssh", "Login attempt"},
	5000:  {"smb", "File opened"},
	5001:  {"portscan", "SYN scan"},
	5002:  {"portscan", "Nmap OS scan"},
	5003:  {"portscan", "NULL scan"},
	5004:  {"portscan", "XMAS scan"},
	5005:  {"portscan", "FIN scan"},
	6001:  {"telnet", "Login attempt"},
	6002:  {"telnet", "Connection"},
	7001:  {"httpproxy", "Proxy attempt"},
	8001:  {"mysql", "Login attempt"},
	9001:  {"mssql", "SQL login attempt"},
	9002:  {"mssql", "Windows login attempt"},
	9003:  {"mysql", "Connection"},
	10001: {"tftp", "File request"},
	11001: {"ntp", "Monlist request"},
	12001: {"vnc", "Login attempt"},
	13001: {"snmp", "OID request"},
	14001: {"rdp", "Connection"},
	15001: {"sip", "SIP request"},
	16001: {"git", "Clone request"},
	17001: {"redis", "Command"},
	18001: {"tcpbanner", "Connection"},
	18002: {"tcpbanner", "Keep-alive connection"},
	18003: {"tcpbanner", "Keep-alive secret"},
	18004: {"tcpbanner", "Keep-alive data"},
	18005: {"tcpbanner", "Data received"},
	19001: {"llmnr", "Name query"},
	20001: {"mongodb", "MongoDB activity"},
}

func parseAlertTime(raw rawAlert) time.Time {
	value := raw.UTCTime
	if value == "" {
		value = raw.LocalTimeAdjusted
	}
	for _, layout := range []string{
		"2006-01-02 15:04:05.999999",
		"2006-01-02 15:04:05",
		time.RFC3339Nano,
		time.RFC3339,
	} {
		if parsed, err := time.ParseInLocation(layout, value, time.UTC); err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}

func stringValue(data map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := data[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			if typed != "" {
				return typed
			}
		case float64:
			return strconv.FormatFloat(typed, 'f', -1, 64)
		default:
			encoded, _ := json.Marshal(typed)
			if len(encoded) > 0 && len(encoded) < 180 {
				return string(encoded)
			}
		}
	}
	return ""
}

func summarize(raw rawAlert, event string) (string, string) {
	username := stringValue(raw.LogData, "USERNAME", "username", "user")
	if username != "" && strings.Contains(strings.ToLower(event), "login") {
		return fmt.Sprintf("%s for user %s", event, username), username
	}
	if request := stringValue(raw.LogData, "REQUEST", "request", "url"); request != "" {
		return fmt.Sprintf("%s · %s", event, request), username
	}
	if action := stringValue(raw.LogData, "action", "cmd", "command", "filename", "oid"); action != "" {
		return fmt.Sprintf("%s · %s", event, action), username
	}
	return event, username
}

func alertFromLine(line []byte) (Alert, bool) {
	var raw rawAlert
	if err := json.Unmarshal(line, &raw); err != nil || raw.LogType < 2000 {
		return Alert{}, false
	}
	info, ok := logTypeInfo[raw.LogType]
	if !ok {
		info.service = "other"
		info.event = fmt.Sprintf("OpenCanary event %d", raw.LogType)
	}
	summary, username := summarize(raw, info.event)
	hash := sha256.Sum256(line)
	return Alert{
		ID:         hex.EncodeToString(hash[:6]),
		Timestamp:  parseAlertTime(raw),
		Service:    info.service,
		Event:      info.event,
		SourceIP:   raw.SrcHost,
		SourcePort: raw.SrcPort,
		DestPort:   raw.DstPort,
		Username:   username,
		Summary:    summary,
		Severity:   "high",
	}, true
}

func loadAlerts() ([]Alert, error) {
	alerts := []Alert{}
	paths := make([]string, 0, eventLogBackups+1)
	for index := eventLogBackups; index >= 1; index-- {
		paths = append(paths, fmt.Sprintf("%s.%d", EventLogFile, index))
	}
	paths = append(paths, EventLogFile)
	for _, path := range paths {
		file, err := os.Open(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			if alert, ok := alertFromLine(scanner.Bytes()); ok {
				alerts = append(alerts, alert)
			}
		}
		if err := scanner.Err(); err != nil {
			file.Close()
			return nil, err
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
	}
	sort.SliceStable(alerts, func(i, j int) bool {
		return alerts[i].Timestamp.After(alerts[j].Timestamp)
	})
	return alerts, nil
}

func queryAlerts(limit int, service, search string) (EventsResponse, error) {
	alerts, err := loadAlerts()
	if err != nil {
		return EventsResponse{}, err
	}
	now := time.Now().UTC()
	cutoff := now.Add(-24 * time.Hour)
	unique := map[string]bool{}
	byService := map[string]int{}
	hourly := make([]int, 24)
	filtered := make([]Alert, 0, len(alerts))
	search = strings.ToLower(strings.TrimSpace(search))

	response := EventsResponse{Total: len(alerts), Events: []Alert{}, ByService: byService, Hourly: hourly}
	for _, alert := range alerts {
		byService[alert.Service]++
		if !alert.Timestamp.IsZero() && !alert.Timestamp.Before(cutoff) {
			response.Last24Hours++
			if alert.SourceIP != "" {
				unique[alert.SourceIP] = true
			}
			hoursAgo := int(now.Sub(alert.Timestamp).Hours())
			if hoursAgo >= 0 && hoursAgo < 24 {
				hourly[23-hoursAgo]++
			}
		}
		if service != "" && service != "all" && alert.Service != service {
			continue
		}
		if search != "" {
			haystack := strings.ToLower(strings.Join([]string{alert.SourceIP, alert.Service, alert.Summary, alert.Username}, " "))
			if !strings.Contains(haystack, search) {
				continue
			}
		}
		filtered = append(filtered, alert)
	}
	response.UniqueSources = len(unique)
	response.FilteredTotal = len(filtered)
	if len(alerts) > 0 {
		response.LastEvent = alerts[0].Timestamp
	}
	if limit < 1 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	if len(filtered) > limit {
		filtered = filtered[:limit]
	}
	response.Events = filtered
	return response, nil
}

func clearAlerts() error {
	if err := os.Truncate(EventLogFile, 0); err != nil && !os.IsNotExist(err) {
		return err
	}
	for index := 1; index <= eventLogBackups; index++ {
		if err := os.Remove(fmt.Sprintf("%s.%d", EventLogFile, index)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
