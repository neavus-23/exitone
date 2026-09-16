package llm

import (
	"context"
	"fmt"
)

// explainSystemPrompt — modo mentor, inspirado en lo más logrado de HTB
// Coach y FreakLabs AI Mentor (enseñar metodología a un operador humano,
// nunca decidir ni ejecutar nada) y deliberadamente OPUESTO al patrón de
// PentestAgent/RedAmon/Pentest Copilot (agentes que planifican y EJECUTAN
// exploits por su cuenta) — ExitOne nunca cruza esa línea.
//
// A diferencia de askSystemPrompt (internal/llm/ask.go), Explain() NO
// recibe el estado de la sesión: solo ve el nombre de una tecnología. Esto
// es estructural, no una instrucción que el modelo podría ignorar — sin el
// contexto del target, es imposible que "confirme" una vulnerabilidad
// específica de ESTE host, solo puede hablar de la tecnología en general.
const explainSystemPrompt = `Eres un mentor de metodología de pentesting para un operador humano — nunca decides ni ejecutas nada, solo enseñas.
Te dan el nombre de una tecnología, protocolo o concepto detectado durante una investigación (ej. "Samba 3.X", "CUPS", "Jetty", "SSH").
Explica en términos GENÉRICOS (nunca sobre un target específico, porque no tienes esa evidencia):
1. Qué es, en 1-2 frases.
2. Por qué un pentester normalmente la investigaría (qué categoría de superficie de ataque representa).
3. Qué tipo de debilidades son HISTÓRICAMENTE comunes en esa familia de software — en general, sin
   inventar números de CVE específicos a menos que estés genuinamente seguro; si mencionas uno, agrega
   "(verificar — mi conocimiento puede estar desactualizado)".
Reglas estrictas:
- NUNCA afirmes que el target actual de la investigación tiene una vulnerabilidad específica — no tienes esa evidencia, solo el nombre de la tecnología.
- NUNCA sugieras un comando exacto a ejecutar (para eso existe 'exitone next'); esto es solo contexto educativo.
- Sé conciso (máximo 6-8 líneas). Responde en español.`

// Explain implementa el modo "mentor". Deliberadamente independiente del
// pipeline de Ask/BuildContextSummary — nunca toca *store.Store — para que
// sea imposible, por construcción, mezclar "enseñanza genérica" con
// "afirmación sobre el target".
func Explain(ctx context.Context, c *Client, subject string) (string, error) {
	if subject == "" {
		return "", fmt.Errorf("no hay nada que explicar")
	}
	return c.Chat(ctx, explainSystemPrompt, subject)
}
