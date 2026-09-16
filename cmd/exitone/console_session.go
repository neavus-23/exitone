package main

import (
	"exitone/internal/console"
	"exitone/internal/store"
)

// ConsoleSession es el estado en memoria de UNA sesión de la Control
// Console — vive mientras el proceso interactivo esté corriendo, nunca se
// persiste (la pila de contexto y el result set son puramente de
// presentación). Esto es exactamente lo que el self-exec-por-línea del REPL
// viejo no podía sostener entre comandos.
type ConsoleSession struct {
	Store    *store.Store
	SelfPath string

	// SessionID se cachea aquí explícitamente y solo cambia vía
	// SwitchWorkspace — nunca se relee de app_state en medio de un comando,
	// para que no haya ambigüedad sobre contra qué workspace corre una query.
	SessionID string

	Stack   *console.ContextStack
	Results console.ResultSet
}

// SwitchWorkspace es el ÚNICO punto que cambia de workspace activo — usado
// tanto por `workspace new` como por `workspace use`/`session new`/
// `session use`. Actualiza las TRES cosas que dependen del workspace a la
// vez: el SessionID cacheado, la pila de contexto (reemplazada por una base
// nueva, no solo "vuelta a la raíz del mismo workspace"), y el ResultSet
// (invalidado — un índice de un workspace anterior nunca debe resolver
// contra el nuevo, ver console_workspace_test.go).
func (cs *ConsoleSession) SwitchWorkspace(sessionID, label string) {
	cs.SessionID = sessionID
	root := console.ConsoleContext{Type: console.Workspace, ID: sessionID, Label: label}
	if cs.Stack == nil {
		cs.Stack = console.NewContextStack(root)
	} else {
		cs.Stack.ResetToRoot(root)
	}
	cs.Results = nil
}
