package llm

import "context"

// Redactar el reporte final vía LLM se hace en llamadas PEQUEÑAS y ACOTADAS
// por sección — nunca una sola llamada pidiendo reescribir el documento
// entero. Validado en vivo contra un modelo local de 3B (Qwen2.5-3B):
// pedirle reproducir/reescribir un documento de ~100 líneas con tablas en
// una sola respuesta se corta antes de terminar por el límite de tokens Y
// corrompe datos (mezcló el texto de una celda de una sección con el de
// otra). Tres llamadas angostas — resumen ejecutivo, narrativa de un
// hallazgo, narrativa de la cronología — nunca reciben más que el pedazo de
// dato que deben narrar, así que no tienen dónde truncarse a mitad de una
// tabla ni de dónde importar texto ajeno.

const execSummarySystemPrompt = `Eres un pentester senior. Recibís la lista de hallazgos YA CONFIRMADOS de una investigación de seguridad autorizada (severidad y afectado ya fijados, no los inventes ni los cambies).
Escribe un RESUMEN EJECUTIVO de 3 a 5 frases, en español, para un lector no técnico: qué se logró, cuál fue el impacto máximo alcanzado, y la severidad general del hallazgo más grave.
Reglas estrictas: no inventes ningún hallazgo que no esté en la lista recibida; no inventes IPs, credenciales ni comandos; no agregues encabezados Markdown, solo el párrafo de prosa.`

const findingNarrativeSystemPrompt = `Eres un pentester senior redactando UN hallazgo del reporte final de una investigación de seguridad autorizada.
Recibís los datos YA VERIFICADOS de ese hallazgo puntual (afectado, severidad, prueba de impacto, y remediación si el operador ya la fijó).
Escribe 2 a 4 frases de prosa en español: causa raíz probable e impacto de negocio. Si el dato trae una remediación ya fijada, no la repitas (ya se muestra aparte) — enfócate en explicar el POR QUÉ importa. Si no trae remediación fijada, podés cerrar con una recomendación técnica razonable de un pentester senior (nunca un CVE específico que no te hayan dado).
Reglas estrictas: no inventes ningún dato que no esté en lo recibido (otro hallazgo, otra IP, otro comando, otra credencial); no agregues encabezados Markdown, solo el párrafo de prosa.`

const timelineNarrativeSystemPrompt = `Eres un pentester senior. Recibís la lista cronológica REAL de acciones y evidencia de una investigación de seguridad autorizada (una línea por paso, con su timestamp).
Escribe un párrafo narrativo en español (4 a 8 frases) contando cómo se llegó paso a paso de la superficie inicial al impacto final, como una historia coherente.
Reglas estrictas: nunca agregues un paso, herramienta o comando que no esté literalmente en la lista recibida; si la lista está vacía, decí explícitamente que no hay pasos registrados; no agregues encabezados Markdown, solo el párrafo de prosa.`

func SummarizeFindings(ctx context.Context, c *Client, findingsText string) (string, error) {
	return c.ChatWithMaxTokens(ctx, execSummarySystemPrompt, findingsText, 300)
}

func NarrateFinding(ctx context.Context, c *Client, findingText string) (string, error) {
	return c.ChatWithMaxTokens(ctx, findingNarrativeSystemPrompt, findingText, 250)
}

func NarrateTimeline(ctx context.Context, c *Client, timelineText string) (string, error) {
	return c.ChatWithMaxTokens(ctx, timelineNarrativeSystemPrompt, timelineText, 400)
}
