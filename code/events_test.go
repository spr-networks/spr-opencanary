package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func eventLine(logType int, timestamp, source string, port int, data map[string]any) []byte {
	line, _ := json.Marshal(map[string]any{
		"dst_host":            "172.30.119.2",
		"dst_port":            port,
		"local_time":          timestamp,
		"local_time_adjusted": timestamp,
		"logdata":             data,
		"logtype":             logType,
		"node_id":             "spr-canary-01",
		"src_host":            source,
		"src_port":            54123,
		"utc_time":            timestamp,
	})
	return line
}

func TestAlertFromLineSummarizesLoginWithoutPassword(t *testing.T) {
	line := eventLine(4002, "2026-07-14 12:30:00.000000", "192.0.2.44", 22, map[string]any{
		"USERNAME": "root",
		"PASSWORD": "do-not-return",
	})
	alert, ok := alertFromLine(line)
	if !ok {
		t.Fatal("expected incident")
	}
	if alert.Service != "ssh" || alert.Username != "root" || alert.DestPort != 22 {
		t.Fatalf("unexpected alert: %+v", alert)
	}
	encoded, _ := json.Marshal(alert)
	if strings.Contains(string(encoded), "do-not-return") {
		t.Fatalf("password leaked through alert: %s", encoded)
	}
}

func TestQueryAlertsStatsAndFilters(t *testing.T) {
	temp := t.TempDir()
	oldEventLog := EventLogFile
	EventLogFile = filepath.Join(temp, "events.jsonl")
	t.Cleanup(func() { EventLogFile = oldEventLog })

	now := time.Now().UTC()
	recent := now.Add(-time.Hour).Format("2006-01-02 15:04:05.000000")
	old := now.Add(-48 * time.Hour).Format("2006-01-02 15:04:05.000000")
	lines := [][]byte{
		eventLine(4002, recent, "192.0.2.10", 22, map[string]any{"USERNAME": "admin"}),
		eventLine(3000, recent, "192.0.2.11", 80, map[string]any{"REQUEST": "GET /admin"}),
		eventLine(4000, old, "192.0.2.12", 22, map[string]any{}),
	}
	content := append([]byte{}, lines[0]...)
	for _, line := range lines[1:] {
		content = append(content, '\n')
		content = append(content, line...)
	}
	content = append(content, '\n')
	if err := os.WriteFile(EventLogFile, content, 0600); err != nil {
		t.Fatal(err)
	}

	response, err := queryAlerts(100, "ssh", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if response.Total != 3 || response.Last24Hours != 2 || response.UniqueSources != 2 {
		t.Fatalf("bad stats: %+v", response)
	}
	if response.FilteredTotal != 1 || len(response.Events) != 1 || response.Events[0].Service != "ssh" {
		t.Fatalf("bad filtered events: %+v", response.Events)
	}
	if response.ByService["ssh"] != 2 || response.ByService["http"] != 1 {
		t.Fatalf("bad service totals: %+v", response.ByService)
	}
}

func TestRotatedEventLogsAreReadAndCleared(t *testing.T) {
	temp := t.TempDir()
	oldEventLog := EventLogFile
	EventLogFile = filepath.Join(temp, "events.jsonl")
	t.Cleanup(func() { EventLogFile = oldEventLog })

	now := time.Now().UTC().Format("2006-01-02 15:04:05.000000")
	if err := os.WriteFile(EventLogFile+".1", append(eventLine(4000, now, "192.0.2.20", 22, nil), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(EventLogFile, append(eventLine(17001, now, "192.0.2.21", 6379, nil), '\n'), 0600); err != nil {
		t.Fatal(err)
	}

	response, err := queryAlerts(100, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if response.Total != 2 || len(response.Events) != 2 {
		t.Fatalf("rotated events not included: %+v", response)
	}
	if err := clearAlerts(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(EventLogFile + ".1"); !os.IsNotExist(err) {
		t.Fatalf("rotated event log was not removed: %v", err)
	}
}
