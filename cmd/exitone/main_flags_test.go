package main

import "testing"

func TestParseFlagsDoesNotConsumeFollowingFlag(t *testing.T) {
	positional, flags := parseFlags([]string{"target", "--tmux", "--session-name", "exitone-nexus", "--detach"})
	if len(positional) != 1 || positional[0] != "target" {
		t.Fatalf("positional = %#v", positional)
	}
	if _, ok := flags["tmux"]; !ok {
		t.Fatal("--tmux ausente")
	}
	if flags["session-name"] != "exitone-nexus" {
		t.Fatalf("session-name = %q", flags["session-name"])
	}
	if _, ok := flags["detach"]; !ok {
		t.Fatal("--detach ausente")
	}
}
