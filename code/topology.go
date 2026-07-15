package main

type TopoNode struct {
	ID       string
	Kind     string
	Name     string
	IP       string `json:",omitempty"`
	ConnType string `json:",omitempty"`
	Online   bool
}

type TopoEdge struct {
	From  string
	To    string
	Layer string
	Kind  string
}

type Topology struct {
	Nodes []TopoNode
	Edges []TopoEdge
}

func buildTopology(running bool, ip, nodeID string) Topology {
	return Topology{
		Nodes: []TopoNode{
			{ID: "root", ConnType: "honeypot", Online: true},
			{ID: "opencanary", Kind: "service", Name: nodeID, IP: ip, ConnType: "honeypot", Online: running},
		},
		Edges: []TopoEdge{{From: "root", To: "opencanary", Layer: "lan", Kind: "honeypot"}},
	}
}
