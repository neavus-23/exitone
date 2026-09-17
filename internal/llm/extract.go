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
	Kind       string  `json:"kind"` // endpoint | identity | technology | domain | credential | weakness | access | principal | privilege | objective | other
	Value      string  `json:"value"`
	Confidence float64 `json:"confidence"`
}

const maxConfidence = 0.5

// Los ejemplos concretos para access/principal/privilege se agregaron tras
// un bug real: sin ellos, un modelo de 3B nunca usaba esos tres kinds en la
// práctica (siempre caía en "identity" o "technology" para el mismo dato),
// así que ExitOne jamás creaba las entidades que el Stage Estimator necesita
// para reportar post_access/privilege_access como algo distinto de
// NOT_STARTED — aunque el acceso real sí hubiera ocurrido. Validado contra
// una transcripción real de HTB Nexus con shell como www-data y escalada a
// root vía SSH.
const extractSystemPrompt = `Eres un extractor de información estructurada para una herramienta de investigación de seguridad autorizada.
Recibes output crudo de una herramienta de línea de comandos que NO tiene un parser determinista todavía.
Tu única tarea es identificar hechos CONCRETOS y EXPLÍCITOS presentes en el texto — nunca inventar, nunca inferir más allá de lo que literalmente aparece.
Responde EXCLUSIVAMENTE con un array JSON, sin texto adicional, con este formato:
[{"kind": "endpoint|identity|technology|domain|credential|weakness|access|principal|privilege|objective|other", "value": "...", "confidence": 0.0-1.0}]

Guía de los kinds menos obvios, con ejemplos literales:
- "access": el texto muestra que se OBTUVO una sesión/shell interactiva en un sistema (un prompt de shell nuevo, un "$" o "#" después de una conexión, la salida de "whoami"/"id" ejecutada exitosamente tras una explotación). Ejemplo: la línea "www-data@nexus:~$ whoami" seguida de "www-data" → {"kind":"access","value":"shell www-data@nexus obtenida"}.
- "principal": un usuario/cuenta del sistema operativo o de una aplicación bajo el cual se confirmó que se está actuando (no una credencial suelta, sino la identidad ACTIVA de la sesión). Ejemplo: "uid=0(root) gid=0(root) groups=0(root)" → {"kind":"principal","value":"root"}.
- "privilege": una capacidad o nivel de privilegio confirmado explícitamente (salida de "sudo -l", "id" mostrando grupos privilegiados, una escalada de privilegios lograda). Ejemplo: "uid=0(root)" tras una cadena de explotación de escalada → {"kind":"privilege","value":"root (uid=0) obtenido via escalada de privilegios"}.
No uses "identity" para estos casos — "identity" es solo para nombres de usuario/cuentas mencionados sin confirmar que se esté actuando bajo ellos (ej. una lista de usuarios encontrada en una enumeración).

Cuando el texto trae un PAR usuario+contraseña (ej. "username: jsmith" seguido de "password: hunter2", o "DB_USERNAME=svc_app" seguido de "DB_PASSWORD=..."), reportalos como DOS observaciones separadas — nunca combines "usuario:contraseña" en un solo string de kind="credential". Ejemplo: "DB_USERNAME=svc_app" / "DB_PASSWORD=Tr0ub4dor&3" → [{"kind":"identity","value":"svc_app"},{"kind":"credential","value":"Tr0ub4dor&3"}]. Esto es importante: ExitOne vincula automáticamente la credencial a la identidad que aparece justo antes en el mismo output — si las combinás en un solo string, pierde esa asociación.

Si no hay nada relevante, responde con un array vacío: []
Nunca incluyas explicaciones, nunca incluyas markdown, nunca incluyas texto fuera del array JSON.`

// ExtractObservations pide al LLM candidatos de observación sobre output
// crudo de una herramienta desconocida. La confianza devuelta SIEMPRE queda
// acotada a maxConfidence, sin importar lo que el modelo reporte — esto es
// lo que impide que una alucinación se trate como hecho confirmado.
func ExtractObservations(ctx context.Context, c *Client, toolNameHint, rawOutput string) ([]CandidateObservation, error) {
	if c.IsRemote() {
		return nil, fmt.Errorf("la extracción de output crudo está bloqueada para endpoints LLM remotos para evitar exponer credenciales")
	}
	// 4000 truncaba desde el INICIO, perdiendo justo el final de
	// transcripciones de shell largas — que es sistemáticamente donde está
	// el resultado de una cadena de explotación (ej. el "uid=0(root)" y el
	// hash de root.txt al final de una escalada de privilegios). Bug real
	// encontrado validando ExitOne contra HTB Nexus: con 4000 el extractor
	// nunca llegó a ver el acceso a root, solo el intento previo de SSH.
	// 8000 alcanza para cubrir sin cortar la transcripción real que motivó
	// este fix (6495 bytes) con margen; el context size del sidecar local
	// ya se subió a 8192 tokens (ver server.go) para que quepa junto al
	// system prompt y la respuesta.
	userPrompt := fmt.Sprintf("Herramienta (posiblemente desconocida): %s\n\nOutput crudo:\n%s", toolNameHint, truncate(rawOutput, 8000))

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
