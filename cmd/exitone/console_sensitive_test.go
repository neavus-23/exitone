package main

import (
	"testing"

	"exitone/internal/console"
)

var sensitiveSpecForTest = console.CommandSpec{Name: "test-sensitive", Sensitive: true}

func TestIsSensitiveLine_PasswordFlag(t *testing.T) {
	if !isSensitiveLine(`ask --password foo`, nil) {
		t.Error("--password foo debería marcarse sensible")
	}
}

func TestIsSensitiveLine_PasswordFlagWithEquals(t *testing.T) {
	if !isSensitiveLine(`ask --password=foo`, nil) {
		t.Error("--password=foo debería marcarse sensible")
	}
}

func TestIsSensitiveLine_TokenFlag(t *testing.T) {
	if !isSensitiveLine(`ask --token foo`, nil) {
		t.Error("--token foo debería marcarse sensible")
	}
}

func TestIsSensitiveLine_PassiveIsNotAFalsePositive(t *testing.T) {
	if isSensitiveLine(`search --passive smb`, nil) {
		t.Error("--passive NO debería marcarse sensible (falso positivo por substring)")
	}
}

func TestIsSensitiveLine_SpecSensitiveFlagWins(t *testing.T) {
	if !isSensitiveLine(`show hosts`, &sensitiveSpecForTest) {
		t.Error("un CommandSpec.Sensitive=true debería marcar la línea como sensible sin importar el contenido")
	}
}
