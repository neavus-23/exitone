package main

import (
	"context"
	"fmt"
	"time"

	"exitone/internal/llm"
)

// handleGuide — modo mentor "no sé por dónde seguir" (pedido explícito de
// un pentester real, no una idea abstracta): narra el candidato de mayor
// score que `next` ya calculó dentro del estado real de las etapas, en vez
// de que el operador tenga que interpretar la tabla de `stages` y el
// ranking de `next` por su cuenta.
func handleGuide(cs *ConsoleSession, args []string) error {
	if cs.SessionID == "" {
		return fmt.Errorf("no hay workspace activo — empieza con: workspace new <target>")
	}

	guideContext, err := llm.BuildGuideContext(cs.Store, cs.SessionID)
	if err != nil {
		return err
	}

	client := llm.New()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	fmt.Println(statusLine("*", ansiCyan, "Pensando por dónde seguir…"))
	answer, err := llm.Guide(ctx, client, guideContext)
	if err != nil {
		return fmt.Errorf("consulta al mentor falló: %w", err)
	}

	fmt.Println()
	fmt.Println(answer)
	fmt.Println()
	fmt.Println(colorize(ansiGray, "(basado en las etapas y el candidato de mayor score que ExitOne ya calculó — usa 'next'/'why' para el detalle exacto.)"))
	return nil
}
