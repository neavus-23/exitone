package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// CandidateObservation es una observación de Nivel 2 (sección 6/8 del plan):
// el LLM la propone, pero NUNCA se convierte automáticamente en FACT. La
// confianza se acota agresivamente en código (maxConfidence), sin confiar en
// lo que el modelo reporte — el modelo puede alucinar seguridad, el cap no.
type CandidateObservation struct {
	Kind       string  `json:"kind"`  // endpoint | identity | technology | domain | other
	Value      string  `json:"value"`
	Confidence float64 `json:"confidence"`
}

const maxConfidence = 0.5

const extractSystemPrompt = `Eres un extractor de información estructurada para una herramienta de investigación de seguridad autorizada.
Recibes output crudo de una herramienta de línea de comandos que NO tiene un parser determinista todavía.
Tu única tarea es identificar hechos CONCRETOS y EXPLÍCITOS presentes en el texto — nunca inventar, nunca inferir más allá de lo que literalmente aparece.
Responde EXCLUSIVAMENTE con un array JSON, sin texto adicional, con este formato:
[{"kind": "endpoint|identity|technology|domain|other", "value": "...", "confidence": 0.0-1.0}]
Si no hay nada relevante, responde con un array vacío: []
Nunca incluyas explicaciones, nunca incluyas markdown, nunca incluyas texto fuera del array JSON.`

// ExtractObservations pide al LLM candidatos de observación sobre output
// crudo de una herramienta desconocida. La confianza devuelta SIEMPRE queda
// acotada a maxConfidence, sin importar lo que el modelo reporte — esto es
// lo que impide que una alucinación se trate como hecho confirmado.
func ExtractObservations(ctx context.Context, c *Client, toolNameHint, rawOutput string) ([]CandidateObservation, error) {
	userPrompt := fmt.Sprintf("Herramienta (posiblemente desconocida): %s\n\nOutput crudo:\n%s", toolNameHint, truncate(rawOutput, 4000))

	raw, err := c.Chat(ctx, extractSystemPrompt, userPrompt)
	if err != nil {
		return nil, err
	}

	jsonSlice := extractJSONArray(raw)
	if jsonSlice == "" {
		return nil, fmt.Errorf("el llm no devolvió un array JSON reconocible; respuesta cruda: %s", truncate(raw, 300))
	}

	var obs []CandidateObservation
	if err := json.Unmarshal([]byte(jsonSlice), &obs); err != nil {
		return nil, fmt.Errorf("parsear array de observaciones: %w (respuesta: %s)", err, truncate(jsonSlice, 300))
	}

	for i := range obs {
		if obs[i].Confidence > maxConfidence || obs[i].Confidence <= 0 {
			obs[i].Confidence = maxConfidence
		}
	}
	return obs, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "... [truncado]"
}

// extractJSONArray busca el primer '[' ... ']' balanceado en el texto — el
// modelo a veces envuelve la respuesta en texto o markdown pese a la
// instrucción explícita; esto es la mitigación defensiva de Nivel 2.
func extractJSONArray(s string) string {
	start := strings.Index(s, "[")
	if start == -1 {
		return ""
	}
	depth := 0
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}
