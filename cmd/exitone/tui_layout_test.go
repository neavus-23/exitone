package main

import (
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/vt"

	credentialstore "exitone/internal/credential"
)

func TestTUILayoutStartsAtFiftyFifty(t *testing.T) {
	m := &tuiModel{splitRatio: defaultSplitRatio, focus: focusTerminal}
	m.width = 107 // 100 content cells + 4 borders + 2 scrollbars + divider.
	m.applySplit()

	if m.termWidth != 50 || m.sideWidth != 50 {
		t.Fatalf("expected 50/50 content split, got terminal=%d sidebar=%d", m.termWidth, m.sideWidth)
	}
	if m.termWidth+m.sideWidth+7 != m.width {
		t.Fatalf("layout does not fill the window: %d + %d + 7 != %d", m.termWidth, m.sideWidth, m.width)
	}
}

func TestScrollbarHasStableGeometry(t *testing.T) {
	for _, tc := range []struct {
		name               string
		total, height, top int
	}{
		{name: "fits", total: 5, height: 8},
		{name: "middle", total: 100, height: 10, top: 45},
		{name: "bottom", total: 100, height: 10, top: 90},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows := strings.Split(renderScrollbar(tc.total, tc.height, tc.top, true), "\n")
			if len(rows) != tc.height {
				t.Fatalf("expected %d rows, got %d", tc.height, len(rows))
			}
			for i, row := range rows {
				if got := lipgloss.Width(row); got != 1 {
					t.Fatalf("row %d width=%d, want 1", i, got)
				}
			}
		})
	}
}

func TestTerminalViewportUsesEmulatorScrollback(t *testing.T) {
	m := &tuiModel{splitRatio: defaultSplitRatio, focus: focusTerminal}
	m.termWidth = 12
	m.termHeight = 3
	m.emu = vt.NewEmulator(m.termWidth, m.termHeight)
	_, _ = m.emu.WriteString("one\r\ntwo\r\nthree\r\nfour")

	if m.terminalScrollbackLen() == 0 {
		t.Fatal("expected real emulator scrollback")
	}
	_, liveTop, _ := m.terminalViewport()
	m.scrollTerminal(1)
	_, historyTop, _ := m.terminalViewport()
	if historyTop >= liveTop {
		t.Fatalf("scroll up did not move into history: live=%d history=%d", liveTop, historyTop)
	}
}

func TestCompactNarrationIsBounded(t *testing.T) {
	input := "WHY: service discovery unlocks protocol-specific paths and version checks. AFTER: inspect every unrelated branch and continue with a long explanation that should not dominate the pane."
	got := compactNarration(input, 24, 3)
	rows := strings.Split(got, "\n")
	if len(rows) > 3 {
		t.Fatalf("narration uses %d lines, want at most 3", len(rows))
	}
	for i, row := range rows {
		if lipgloss.Width(row) > 24 {
			t.Fatalf("row %d width=%d, want <= 24", i, lipgloss.Width(row))
		}
	}
}

func TestTitledBoxUsesDisplayWidthForUnicode(t *testing.T) {
	box := renderTitledBox("▶ OPERADOR", 24, 2, renderViewportLines(nil, 24, 2), lipgloss.Color("6"))
	for i, row := range strings.Split(box, "\n") {
		if got := lipgloss.Width(row); got != 26 {
			t.Fatalf("row %d width=%d, want 26", i, got)
		}
	}
}

func TestChatKeepsComposerOutsideScrollableTranscript(t *testing.T) {
	m := &tuiModel{mode: sidebarChat, termHeight: 20, sideWidth: 42, focus: focusSidebar}
	if got := m.sidebarViewportHeight(); got != 15 {
		t.Fatalf("chat transcript height=%d, want 15 (20 - 2 header - 3 composer)", got)
	}
	composer := strings.Split(renderChatComposer(m, m.sideWidth), "\n")
	if len(composer) != 3 {
		t.Fatalf("composer rows=%d, want 3", len(composer))
	}
	for i, row := range composer {
		if got := lipgloss.Width(row); got != m.sideWidth {
			t.Fatalf("composer row %d width=%d, want %d", i, got, m.sideWidth)
		}
	}
}

func TestChatInputCursorRemainsVisibleWithUnicode(t *testing.T) {
	got := renderChatInput("scan café → 10.10.10.10", 23, 12, true)
	if width := lipgloss.Width(got); width != 12 {
		t.Fatalf("input width=%d, want 12", width)
	}
	if !strings.Contains(got, "\x1b[7m") {
		t.Fatal("focused input does not render a cursor")
	}
}

func TestRecentChatContextIsBoundedAndSkipsFailures(t *testing.T) {
	history := []chatTurn{
		{id: 1, question: "q1", answer: "a1"},
		{id: 2, question: "failed", err: errTestChat},
		{id: 3, question: "q3", answer: "a3"},
		{id: 4, question: "q4", answer: strings.Repeat("x", 200)},
	}
	got := recentChatContext(history, 2, 80)
	if strings.Contains(got, "failed") || strings.Contains(got, "q1") {
		t.Fatalf("context included failed or older turns: %q", got)
	}
	if len([]rune(got)) > 80 {
		t.Fatalf("context has %d runes, want <= 80", len([]rune(got)))
	}
}

func TestStaleChatAnswerCannotOverwriteActiveRequest(t *testing.T) {
	m := &tuiModel{
		chatAsking: true,
		chatActive: 2,
		chatHistory: []chatTurn{{
			id: 2, question: "same question", startedAt: time.Now(),
		}},
	}
	_, _ = m.Update(chatAnswerMsg{requestID: 1, answer: "stale"})
	if !m.chatAsking || m.chatHistory[0].answer != "" {
		t.Fatal("stale answer changed the active chat request")
	}
}

func TestChatLineEditingAndRecall(t *testing.T) {
	m := &tuiModel{chatInput: "enum web service", chatCursor: len([]rune("enum web service")), chatRecall: -1}
	m.deleteChatWord()
	if m.chatInput != "enum web " {
		t.Fatalf("Ctrl+W result=%q, want %q", m.chatInput, "enum web ")
	}
	m.chatHistory = []chatTurn{{question: "first"}, {question: "second"}}
	m.recallChatQuestion(-1)
	if m.chatInput != "second" {
		t.Fatalf("history up=%q, want second", m.chatInput)
	}
	m.recallChatQuestion(1)
	if m.chatInput != "enum web " {
		t.Fatalf("history down did not restore draft: %q", m.chatInput)
	}
}

func TestChatInputIsBounded(t *testing.T) {
	m := &tuiModel{chatRecall: -1}
	m.setChatInput(strings.Repeat("x", maxChatInputRunes+50))
	if got := len([]rune(m.chatInput)); got != maxChatInputRunes {
		t.Fatalf("input length=%d, want %d", got, maxChatInputRunes)
	}
	if m.chatCursor != maxChatInputRunes {
		t.Fatalf("cursor=%d, want %d", m.chatCursor, maxChatInputRunes)
	}
}

func TestSidebarTabsHaveMouseHitTargets(t *testing.T) {
	mode, ok := sidebarModeAtX(23, 42) // Overview=10, Graph=7, Vault=7; Chat starts at 24? boundary check below.
	if !ok || mode != sidebarVault {
		t.Fatalf("x=23 resolved to mode=%v ok=%v, want Vault", mode, ok)
	}
	mode, ok = sidebarModeAtX(25, 42)
	if !ok || mode != sidebarChat {
		t.Fatalf("x=25 resolved to mode=%v ok=%v, want Chat", mode, ok)
	}
}

func TestGraphBuildsHierarchyAndCollapseState(t *testing.T) {
	entities := map[string]graphEntity{
		"host":     {id: "host", entityType: "host", value: "10.0.0.1"},
		"service":  {id: "service", entityType: "service", value: "10.0.0.1:443/tcp", attrs: `{"state":"open"}`},
		"endpoint": {id: "endpoint", entityType: "endpoint", value: "/admin"},
	}
	relations := []graphRelation{
		{source: "host", target: "service", kind: "HAS_SERVICE", confidence: 1},
		{source: "service", target: "endpoint", kind: "HAS_ENDPOINT", confidence: 1},
	}
	visible := graphVisibleSet(entities, relations, "")
	rows := buildGraphRows(entities, relations, visible, map[string]bool{})
	if len(rows) != 3 || rows[0].entityID != "host" || rows[1].depth != 1 || rows[2].depth != 2 {
		t.Fatalf("unexpected expanded graph rows: %#v", rows)
	}
	rows = buildGraphRows(entities, relations, visible, map[string]bool{"host": true})
	if len(rows) != 1 || rows[0].expanded || rows[0].children != 1 {
		t.Fatalf("collapsed host should remain visible with child count: %#v", rows)
	}
}

func TestGraphFilterKeepsAncestorsAndDirectContext(t *testing.T) {
	entities := map[string]graphEntity{
		"host":  {id: "host", entityType: "host", value: "10.0.0.1"},
		"https": {id: "https", entityType: "service", value: "https"},
		"ssh":   {id: "ssh", entityType: "service", value: "ssh"},
		"admin": {id: "admin", entityType: "endpoint", value: "/admin"},
	}
	relations := []graphRelation{
		{source: "host", target: "https", kind: "HAS_SERVICE"},
		{source: "host", target: "ssh", kind: "HAS_SERVICE"},
		{source: "https", target: "admin", kind: "HAS_ENDPOINT"},
	}
	visible := graphVisibleSet(entities, relations, "https")
	for _, id := range []string{"host", "https", "admin"} {
		if !visible[id] {
			t.Fatalf("filter omitted %s context: %#v", id, visible)
		}
	}
	if visible["ssh"] {
		t.Fatalf("filter included unrelated sibling: %#v", visible)
	}
}

func TestGraphCyclesBecomeCrossLinks(t *testing.T) {
	entities := map[string]graphEntity{
		"a": {id: "a", entityType: "host", value: "a"},
		"b": {id: "b", entityType: "host", value: "b"},
	}
	relations := []graphRelation{{source: "a", target: "b", kind: "TESTED"}, {source: "b", target: "a", kind: "TESTED"}}
	rows := buildGraphRows(entities, relations, graphVisibleSet(entities, relations, ""), map[string]bool{})
	if len(rows) != 3 || !rows[2].crossLink {
		t.Fatalf("cycle should terminate as a cross-link: %#v", rows)
	}
}

func TestGraphFooterHasStableDetailRegion(t *testing.T) {
	m := &tuiModel{
		mode: sidebarGraph, focus: focusSidebar, sideWidth: 44,
		graphRows: []graphRow{{entityID: "svc", entityType: "service", value: "10.0.0.1:443/tcp", attrs: `{"state":"open","product":"nginx"}`, incoming: 1}},
	}
	footer := strings.Split(renderGraphFooter(m, m.sideWidth), "\n")
	if len(footer) != 4 {
		t.Fatalf("graph footer rows=%d, want 4", len(footer))
	}
	for i, row := range footer {
		if got := lipgloss.Width(row); got != m.sideWidth {
			t.Fatalf("footer row %d width=%d, want %d", i, got, m.sideWidth)
		}
	}
}

func TestSelectedGraphRowUsesMarkerAndExactWidth(t *testing.T) {
	row := graphRow{entityID: "host", entityType: "host", value: "very-long-hostname.internal.example", children: 3, expanded: true}
	got := renderGraphRow(row, true, true, 30)
	if width := lipgloss.Width(got); width != 30 {
		t.Fatalf("selected graph row width=%d, want 30", width)
	}
	if !strings.Contains(got, "›") {
		t.Fatal("selected row relies on color and has no explicit marker")
	}
}

func TestGraphLabelsStripTerminalControlSequences(t *testing.T) {
	row := graphRow{entityID: "host", entityType: "host", value: "safe\x1b]52;c;ZXZpbA==\a\nname\u202etest"}
	got := renderGraphRow(row, false, false, 50)
	plain := ansi.Strip(got)
	if strings.ContainsAny(plain, "\x1b\a\n\r") || strings.Contains(plain, "\u202e") {
		t.Fatalf("unsafe terminal controls survived rendering: %q", plain)
	}
	if !strings.Contains(plain, "safe") || !strings.Contains(plain, "name") {
		t.Fatalf("sanitization removed legitimate content: %q", plain)
	}
}

func TestVaultGroupsCredentialsAndPreservesUnlinked(t *testing.T) {
	identities := []vaultIdentity{
		{id: "alice-id", value: "alice", provenance: "confirmed"},
		{id: "bob-id", value: "bob", provenance: "via:nmap"},
	}
	credentials := []credentialstore.Credential{
		{ID: "cred-valid", Identity: "alice", Service: "ssh", Value: "P********", Status: "valid", CreatedAt: "2026-01-02"},
		{ID: "cred-orphan", Value: "T********", Status: "discovered", CreatedAt: "2026-01-03"},
	}
	rows := buildVaultRows(identities, credentials, nil, "", map[string]bool{})
	if len(rows) != 5 {
		t.Fatalf("vault rows=%d, want Alice+cred, Bob, Unlinked+cred: %#v", len(rows), rows)
	}
	if rows[0].kind != vaultIdentityRow || rows[1].kind != vaultCredentialRow || rows[3].identity != "UNLINKED" {
		t.Fatalf("unexpected vault hierarchy: %#v", rows)
	}
	rows = buildVaultRows(identities, credentials, nil, "", map[string]bool{"identity:alice-id": true})
	if len(rows) != 4 || rows[0].expanded {
		t.Fatalf("collapsed identity leaked its credential: %#v", rows)
	}
}

func TestVaultFilterExcludesSecretValues(t *testing.T) {
	identities := []vaultIdentity{{id: "alice-id", value: "alice", provenance: "confirmed"}}
	credentials := []credentialstore.Credential{{
		ID: "cred-1", Identity: "alice", Service: "ssh", Value: "P********", Status: "valid", Source: "loot",
	}}
	if rows := buildVaultRows(identities, credentials, nil, "ssh", map[string]bool{}); len(rows) != 2 {
		t.Fatalf("service filter should include identity context and credential: %#v", rows)
	}
	if rows := buildVaultRows(identities, credentials, nil, "P********", map[string]bool{}); len(rows) != 0 {
		t.Fatalf("secret-derived mask must not be searchable: %#v", rows)
	}
}

func TestVaultFooterKeepsSecretsEscapedAndFixed(t *testing.T) {
	m := &tuiModel{
		mode: sidebarVault, focus: focusSidebar, sideWidth: 48,
		vaultRows: []vaultRow{{
			kind: vaultCredentialRow, key: "credential:cred-1", credentialID: "cred-1",
			identity: "alice", service: "ssh", maskedValue: "P********", status: "valid",
		}},
		vaultRevealID: "cred-1", vaultRevealValue: "secret\x1b]52;c;ZXZpbA==\a",
		vaultRevealUntil: time.Now().Add(time.Minute),
	}
	footer := strings.Split(renderVaultFooter(m, m.sideWidth), "\n")
	if len(footer) != 5 {
		t.Fatalf("vault footer rows=%d, want 5", len(footer))
	}
	for i, row := range footer {
		if got := lipgloss.Width(row); got != m.sideWidth {
			t.Fatalf("vault footer row %d width=%d, want %d", i, got, m.sideWidth)
		}
	}
	plain := ansi.Strip(strings.Join(footer, "\n"))
	if strings.ContainsAny(plain, "\x1b\a") || !strings.Contains(plain, `\x1b`) {
		t.Fatalf("revealed control characters were not safely escaped: %q", plain)
	}
}

func TestVaultRevealExpiresAndNavigationClearsIt(t *testing.T) {
	m := &tuiModel{
		vaultRevealID: "cred-1", vaultRevealValue: "secret",
		vaultRevealUntil: time.Now().Add(-time.Second), vaultRevealArmed: "cred-1",
		vaultArmUntil: time.Now().Add(-time.Second),
	}
	m.expireVaultReveal()
	if m.vaultRevealID != "" || m.vaultRevealValue != "" || m.vaultRevealArmed != "" {
		t.Fatalf("expired reveal state was retained: %#v", m)
	}
}

func TestStaleVaultExpiryCannotHideNewReveal(t *testing.T) {
	currentUntil := time.Now().Add(time.Minute)
	m := &tuiModel{
		vaultRevealID: "cred-1", vaultRevealValue: "new-secret", vaultRevealUntil: currentUntil,
	}
	_, _ = m.Update(vaultRevealExpiredMsg{credentialID: "cred-1", until: currentUntil.Add(-time.Minute)})
	if m.vaultRevealValue != "new-secret" {
		t.Fatal("stale expiry message hid a newer reveal")
	}
}

var errTestChat = &chatTestError{}

type chatTestError struct{}

func (*chatTestError) Error() string { return "test error" }
