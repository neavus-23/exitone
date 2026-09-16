package console

import "testing"

func TestRegister_AliasesResolveToSameSpec(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(CommandSpec{Name: "help", Aliases: []string{"?"}, Category: "Core"}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	byName, ok := r.Resolve("help")
	if !ok {
		t.Fatal("Resolve(help) no encontrado")
	}
	byAlias, ok := r.Resolve("?")
	if !ok {
		t.Fatal("Resolve(?) no encontrado")
	}
	if byName != byAlias {
		t.Errorf("Resolve(help) y Resolve(?) devolvieron specs distintos: %p vs %p", byName, byAlias)
	}
}

func TestRegister_DuplicateNameRejected(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(CommandSpec{Name: "show"}); err != nil {
		t.Fatalf("primer Register: %v", err)
	}
	if err := r.Register(CommandSpec{Name: "show"}); err == nil {
		t.Error("segundo Register con el mismo nombre debió fallar, no falló")
	}
}

func TestRegister_DuplicateAliasRejected(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(CommandSpec{Name: "hosts", Aliases: []string{"h"}}); err != nil {
		t.Fatalf("primer Register: %v", err)
	}
	if err := r.Register(CommandSpec{Name: "history", Aliases: []string{"h"}}); err == nil {
		t.Error("alias duplicado entre dos comandos distintos debió fallar, no falló")
	}
}

func TestRegister_AliasCollidingWithCommandNameRejected(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(CommandSpec{Name: "show"}); err != nil {
		t.Fatalf("primer Register: %v", err)
	}
	if err := r.Register(CommandSpec{Name: "info", Aliases: []string{"show"}}); err == nil {
		t.Error("alias que colisiona con un nombre de comando existente debió fallar")
	}
}

func TestByCategory_DoesNotOmitAnyCommand(t *testing.T) {
	r := NewRegistry()
	specs := []CommandSpec{
		{Name: "help", Category: "Core"},
		{Name: "show", Category: "Core"},
		{Name: "next", Category: "Strategy"},
		{Name: "workspace", Category: "Workspace"},
	}
	for _, s := range specs {
		if err := r.Register(s); err != nil {
			t.Fatalf("Register(%s): %v", s.Name, err)
		}
	}

	byCat := r.ByCategory()
	total := 0
	for _, list := range byCat {
		total += len(list)
	}
	if total != len(specs) {
		t.Errorf("ByCategory devolvió %d comandos en total, want %d", total, len(specs))
	}
	if len(byCat["Core"]) != 2 || len(byCat["Strategy"]) != 1 || len(byCat["Workspace"]) != 1 {
		t.Errorf("agrupación incorrecta: %+v", byCat)
	}
}

func TestValidIn_PrioritizesWithoutHiding(t *testing.T) {
	r := NewRegistry()
	r.Register(CommandSpec{Name: "info", ValidContexts: []ContextType{Hypothesis, Service}})
	r.Register(CommandSpec{Name: "help", ValidContexts: []ContextType{Workspace, Host, Service, Objective, Hypothesis, Candidate}})
	r.Register(CommandSpec{Name: "next", ValidContexts: []ContextType{Workspace, Host, Service, Objective, Hypothesis, Candidate}})

	valid := r.ValidIn(Service)
	names := map[string]bool{}
	for _, s := range valid {
		names[s.Name] = true
	}
	if !names["info"] || !names["help"] || !names["next"] {
		t.Errorf("ValidIn(Service) = %+v, want info/help/next presentes", names)
	}
	// All() debe seguir devolviendo TODO — ValidIn nunca oculta nada del listado global.
	if len(r.All()) != 3 {
		t.Errorf("All() = %d comandos, want 3 (ValidIn no debe afectar el registro completo)", len(r.All()))
	}
}

func TestSuggest_FindsCloseTypos(t *testing.T) {
	r := NewRegistry()
	r.Register(CommandSpec{Name: "show"})
	r.Register(CommandSpec{Name: "search"})
	r.Register(CommandSpec{Name: "use"})

	suggestions := r.Suggest("shwo")
	if len(suggestions) == 0 || suggestions[0] != "show" {
		t.Errorf("Suggest(shwo) = %v, want 'show' primero", suggestions)
	}

	if got := r.Suggest("zzzzzzzz"); len(got) != 0 {
		t.Errorf("Suggest(zzzzzzzz) = %v, want ninguna sugerencia", got)
	}
}
