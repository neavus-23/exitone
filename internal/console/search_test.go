package console

import "testing"

func TestParseQuery_FreeTextOnly(t *testing.T) {
	q := ParseQuery([]string{"smb"})
	if q.Text != "smb" {
		t.Errorf("Text = %q, want smb", q.Text)
	}
	if len(q.Filters) != 0 {
		t.Errorf("Filters = %v, want empty", q.Filters)
	}
}

func TestParseQuery_TypeFilterPlusText(t *testing.T) {
	q := ParseQuery([]string{"type:service", "smb"})
	if q.Filters["type"] != "service" {
		t.Errorf("Filters[type] = %q, want service", q.Filters["type"])
	}
	if q.Text != "smb" {
		t.Errorf("Text = %q, want smb", q.Text)
	}
}

func TestParseQuery_StatusFilterOnly(t *testing.T) {
	q := ParseQuery([]string{"status:open"})
	if q.Filters["status"] != "open" {
		t.Errorf("Filters[status] = %q, want open", q.Filters["status"])
	}
	if q.Text != "" {
		t.Errorf("Text = %q, want empty", q.Text)
	}
}

func TestParseQuery_HostFilterAndCombination(t *testing.T) {
	q := ParseQuery([]string{"host:192.168.72.130", "type:service", "smb"})
	if q.Filters["host"] != "192.168.72.130" {
		t.Errorf("Filters[host] = %q", q.Filters["host"])
	}
	if q.Filters["type"] != "service" {
		t.Errorf("Filters[type] = %q", q.Filters["type"])
	}
	if q.Text != "smb" {
		t.Errorf("Text = %q, want smb", q.Text)
	}
}

func TestParseQuery_ColonWithoutKeyIsFreeText(t *testing.T) {
	q := ParseQuery([]string{":weird"})
	if _, ok := q.Filters[""]; ok {
		t.Error("empty key should not be treated as a filter")
	}
	if q.Text != ":weird" {
		t.Errorf("Text = %q, want :weird", q.Text)
	}
}
