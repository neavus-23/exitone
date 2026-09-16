package main

import (
	"fmt"

	"exitone/internal/console"
)

// handleUse — `use` es navegación pura (sección 9 del pedido original): no
// ejecuta, no cambia focus, no acepta candidatos, no genera nada. Solo
// mueve el contexto de la consola.
func handleUse(cs *ConsoleSession, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("uso: use <índice|ID|token>")
	}
	token := args[0]

	// Precedencia EXPLÍCITA (sección F del plan): el índice numérico contra
	// el último result set SIEMPRE gana si es válido — solo si no lo es se
	// intenta resolución por identidad real. Esto importa especialmente
	// para `use 445` dentro de un host: si el result set activo tuviera
	// ≥446 filas, el índice 445 ganaría; en la práctica eso es raro y queda
	// documentado, no oculto.
	if ref, err := cs.Results.ResolveIndex(token); err == nil {
		ctx := console.ConsoleContext{Type: ref.Type, ID: ref.ID, Label: ref.Label}
		cs.Stack.Push(ctx)
		fmt.Println(statusLine("*", ansiCyan, "Using "+describeContext(ctx)))
		warnIfOutOfScope(cs, ctx)
		return nil
	}

	ctx, err := ResolveByIdentity(cs.Store, cs.SessionID, cs.Stack.Current(), token)
	if err != nil {
		return err
	}
	cs.Stack.Push(ctx)
	fmt.Println(statusLine("*", ansiCyan, "Using "+describeContext(ctx)))
	warnIfOutOfScope(cs, ctx)
	return nil
}

// warnIfOutOfScope — nunca bloquea la navegación, solo avisa (mismo
// principio de "marcar, nunca ocultar/impedir" de show/next). Pedido real de
// un flujo bug-bounty: es fácil perder de vista que un host resuelve al
// mismo rango pero está explícitamente fuera del programa.
func warnIfOutOfScope(cs *ConsoleSession, ctx console.ConsoleContext) {
	hostAddr := hostAddrForScopeCheck(cs, ctx)
	if hostAddr == "" {
		return
	}
	if scopeLabel(cs, hostAddr) == "OUT" {
		fmt.Println(statusLine("!", ansiYellow, fmt.Sprintf("%s está marcado como EXCLUIDO del scope — revisa 'scope list'.", hostAddr)))
	}
}

// hostAddrForScopeCheck resuelve la dirección de host relevante para
// chequear scope — directa en un contexto Host, o vía el join HAS_SERVICE en
// un contexto Service (el scope se define sobre hosts/dominios, no puertos).
func hostAddrForScopeCheck(cs *ConsoleSession, ctx console.ConsoleContext) string {
	switch ctx.Type {
	case console.Host:
		return ctx.Label
	case console.Service:
		var hostAddr string
		cs.Store.DB.QueryRow(`
			SELECT h.canonical_value FROM relationship r
			JOIN entity h ON h.id = r.source_entity_id
			WHERE r.target_entity_id = ? AND r.kind = 'HAS_SERVICE'`, ctx.ID).Scan(&hostAddr)
		return hostAddr
	default:
		return ""
	}
}

// handleBack — sección 10 del pedido original: nunca es destructivo, ni
// siquiera en la raíz.
func handleBack(cs *ConsoleSession, args []string) error {
	ctx, moved := cs.Stack.Pop()
	if !moved {
		fmt.Println(statusLine("*", ansiCyan, "Already at workspace context."))
		return nil
	}
	fmt.Println(statusLine("*", ansiCyan, "Back to "+describeContext(ctx)))
	return nil
}

func describeContext(ctx console.ConsoleContext) string {
	switch ctx.Type {
	case console.Host:
		return "host " + ctx.Label
	case console.Service:
		return "service " + ctx.Label
	case console.Objective:
		return "objective " + ctx.Label
	case console.Hypothesis:
		return "hypothesis " + ctx.Label
	case console.Candidate:
		return "candidate " + ctx.Label
	default:
		return "workspace " + ctx.Label
	}
}
