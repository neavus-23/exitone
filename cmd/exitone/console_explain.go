package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"exitone/internal/console"
	"exitone/internal/llm"
)

// handleExplain — modo mentor (ver internal/llm/explain.go): la parte de
// PentestAgent/RedAmon/Pentest Copilot que SÍ se adopta (enseñar
// metodología, como HTB Coach/FreakLabs) sin adoptar la parte que no
// (planificar y ejecutar solos). Nunca modifica estado, nunca genera un
// candidate, nunca sugiere un comando — es puramente informativo.
func handleExplain(cs *ConsoleSession, args []string) error {
	subject := strings.Join(args, " ")
	if subject == "" {
		subject = subjectFromContext(cs)
	}
	if subject == "" {
		return fmt.Errorf("uso: explain <tecnología|servicio> (o entra primero a un contexto de service/objective/hypothesis)")
	}

	client := llm.New()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	fmt.Println(statusLine("*", ansiCyan, fmt.Sprintf("Consultando al mentor local sobre %q…", subject)))
	answer, err := llm.Explain(ctx, client, subject)
	if err != nil {
		return fmt.Errorf("consulta al mentor falló: %w", err)
	}

	fmt.Println()
	fmt.Println(answer)
	fmt.Println()
	fmt.Println(colorize(ansiGray, "(explicación genérica de la tecnología — no una afirmación sobre este target; para eso, 'exitone next'/'why'.)"))
	return nil
}

// subjectFromContext deriva un sujeto razonable del contexto de navegación
// activo, para que `explain` sin argumentos funcione dentro de
// `service(...) >`/`objective(...) >`/`hypothesis(...) >` sin retipear nada.
func subjectFromContext(cs *ConsoleSession) string {
	ctx := cs.Stack.Current()
	switch ctx.Type {
	case console.Service:
		var attrsJSON string
		cs.Store.DB.QueryRow(`SELECT attrs FROM entity WHERE id = ?`, ctx.ID).Scan(&attrsJSON)
		var attrs map[string]any
		json.Unmarshal([]byte(attrsJSON), &attrs)
		if product, ok := attrs["product"].(string); ok && product != "" {
			return product
		}
		if protocol, ok := attrs["protocol"].(string); ok && protocol != "" {
			return protocol
		}
		return ""
	case console.Objective:
		var intent string
		cs.Store.DB.QueryRow(`SELECT intent_key FROM methodology_objective WHERE id = ?`, ctx.ID).Scan(&intent)
		return intent
	case console.Hypothesis:
		var statement string
		cs.Store.DB.QueryRow(`SELECT statement FROM hypothesis WHERE id = ?`, ctx.ID).Scan(&statement)
		return statement
	default:
		return ""
	}
}
