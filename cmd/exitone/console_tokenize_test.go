package main

import (
	"reflect"
	"testing"
)

func TestTokenizeConsoleLine(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"simple", "show hosts", []string{"show", "hosts"}},
		{"double quotes", `ask "what is open"`, []string{"ask", "what is open"}},
		{"single quotes", `search 'two words'`, []string{"search", "two words"}},
		{"key:value no quotes needed", "search host:192.168.72.130", []string{"search", "host:192.168.72.130"}},
		{"mixed quotes and filters", `search host:192.168.72.130 "free text"`, []string{"search", "host:192.168.72.130", "free text"}},
		{"backslash escape", `use foo\ bar`, []string{"use", "foo bar"}},
		{"escaped quote inside double quotes", `ask "she said \"hi\""`, []string{"ask", `she said "hi"`}},
		{"empty quoted token", `use ""`, []string{"use", ""}},
		{"extra whitespace collapses", "  show    services  ", []string{"show", "services"}},
		{"empty line", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tokenizeConsoleLine(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("tokenizeConsoleLine(%q) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}
