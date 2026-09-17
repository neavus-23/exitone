package strategy

import "testing"

func TestParseProposalsFromFencedResponse(t *testing.T) {
	raw := "```json\n[{\"kind\":\"direction\",\"phase_key\":\"analysis\",\"intent_key\":\"inspect\",\"rationale\":\"gap\",\"confidence\":0.4,\"risk_level\":\"low\"}]\n```"
	items, err := parseProposals(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].PhaseKey != "analysis" {
		t.Fatalf("propuestas inesperadas: %+v", items)
	}
}
