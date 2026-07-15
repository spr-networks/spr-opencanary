package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTopologyContract(t *testing.T) {
	topology := buildTopology(true, "172.30.119.2", "branch-files-01")
	if len(topology.Nodes) != 2 || len(topology.Edges) != 1 {
		t.Fatalf("unexpected graph: %+v", topology)
	}
	if topology.Nodes[0].ID != "root" || topology.Nodes[0].ConnType != "honeypot" {
		t.Fatalf("bad root anchor: %+v", topology.Nodes[0])
	}
	canary := topology.Nodes[1]
	if canary.Kind != "service" || canary.IP != "172.30.119.2" || !canary.Online {
		t.Fatalf("bad canary node: %+v", canary)
	}
	encoded, err := json.Marshal(buildTopology(false, "", "branch-files-01"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `"IP"`) {
		t.Fatalf("empty IP should be omitted: %s", encoded)
	}
}
