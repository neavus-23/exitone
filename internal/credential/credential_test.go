package credential

import "testing"

func TestMask(t *testing.T) {
	if got := Mask("Password123"); got == "Password123" || got != "P**********" {
		t.Fatalf("Mask inesperado: %q", got)
	}
}
