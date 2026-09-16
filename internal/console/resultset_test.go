package console

import "testing"

func sampleResultSet() ResultSet {
	return ResultSet{
		{Type: Service, ID: "svc-0", Label: "22/ssh"},
		{Type: Service, ID: "svc-1", Label: "80/http"},
		{Type: Service, ID: "svc-2", Label: "445/smb"},
	}
}

func TestResolveIndex_ValidIndex(t *testing.T) {
	rs := sampleResultSet()
	ref, err := rs.ResolveIndex("2")
	if err != nil {
		t.Fatalf("ResolveIndex(2): %v", err)
	}
	if ref.ID != "svc-2" {
		t.Errorf("ResolveIndex(2).ID = %q, want svc-2", ref.ID)
	}
}

func TestResolveIndex_NonNumericToken(t *testing.T) {
	rs := sampleResultSet()
	if _, err := rs.ResolveIndex("H03"); err == nil {
		t.Error("ResolveIndex(H03) = nil error, want error (no es un índice numérico)")
	}
}

func TestResolveIndex_OutOfRange(t *testing.T) {
	rs := sampleResultSet()
	if _, err := rs.ResolveIndex("99"); err == nil {
		t.Error("ResolveIndex(99) = nil error, want error de fuera de rango")
	}
}

func TestResolveIndex_EmptyResultSet(t *testing.T) {
	var rs ResultSet
	if _, err := rs.ResolveIndex("0"); err == nil {
		t.Error("ResolveIndex sobre un ResultSet vacío = nil error, want error explícito")
	}
}
