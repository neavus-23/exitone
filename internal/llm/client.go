// Package llm es el único punto de contacto entre ExitOne y un modelo local.
// Usa la API compatible con OpenAI que expone llama-server (sección J/O del
// plan) — nunca un modelo concreto acoplado por código; cambiar de modelo es
// cambiar el binario/flags de llama-server, no este cliente.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"exitone/internal/debuglog"
)

type Client struct {
	baseURL string
	model   string
	http    *http.Client
}

// New arma el cliente leyendo configuración de entorno con defaults
// razonables para el sidecar local (ver Phase 0c: mismo llama-server ya
// validado en el spike de recursos). EXITONE_LLM_URL / EXITONE_LLM_MODEL
// permiten apuntar a otro runtime sin tocar código (requisito explícito del
// plan: no acoplar a un modelo concreto).
func New() *Client {
	url := os.Getenv("EXITONE_LLM_URL")
	if url == "" {
		url = "http://127.0.0.1:8090/v1"
	}
	model := os.Getenv("EXITONE_LLM_MODEL")
	if model == "" {
		model = "qwen2.5-3b"
	}
	return &Client{
		baseURL: url,
		model:   model,
		http:    &http.Client{Timeout: 180 * time.Second},
	}
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
	MaxTokens   int           `json:"max_tokens"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
}

// Chat manda un único turno (system+user) y devuelve el texto de respuesta
// crudo. No hace streaming — las llamadas de ExitOne son cortas (extracción,
// explicación puntual), no un chat interactivo largo.
func (c *Client) Chat(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	return c.ChatWithMaxTokens(ctx, systemPrompt, userPrompt, 700)
}

// ChatWithMaxTokens es Chat con un límite de tokens explícito — para
// respuestas largas por naturaleza (ej. redactar el reporte final completo)
// donde el límite corto por defecto cortaría la respuesta a la mitad.
func (c *Client) ChatWithMaxTokens(ctx context.Context, systemPrompt, userPrompt string, maxTokens int) (string, error) {
	if err := c.validateLocality(); err != nil {
		return "", err
	}
	// El LLM es parte de ExitOne, no un complemento que el operador arranca
	// aparte: cada llamada garantiza primero que el sidecar esté vivo,
	// arrancándolo si hace falta (ver server.go). El costo en el camino
	// caliente (ya corriendo) es un GET local de ~1ms.
	if err := EnsureRunning(ctx, c.baseURL); err != nil {
		return "", fmt.Errorf("no se pudo asegurar el LLM local: %w", err)
	}

	reqBody := chatRequest{
		Model: c.model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		Temperature: 0.1, // extracción/explicación determinista, no creatividad
		MaxTokens:   maxTokens,
	}
	buf, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(buf))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := c.http.Do(req)
	elapsed := time.Since(start).Seconds()
	if err != nil {
		debuglog.LogError("llm_chat", err, map[string]any{"system_prompt_len": len(systemPrompt), "user_prompt_len": len(userPrompt), "elapsed_s": elapsed})
		return "", fmt.Errorf("llm request failed (¿está corriendo llama-server en %s?): %w", c.baseURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		debuglog.Log("llm_chat", map[string]any{
			"system_prompt_len": len(systemPrompt), "user_prompt_len": len(userPrompt), "elapsed_s": elapsed,
			"status_code": resp.StatusCode, "response_len": len(body),
		})
		return "", fmt.Errorf("llm respondió %d: %s", resp.StatusCode, string(body))
	}

	var cr chatResponse
	if err := json.Unmarshal(body, &cr); err != nil {
		debuglog.LogError("llm_chat_parse", err, map[string]any{"response_len": len(body)})
		return "", fmt.Errorf("parsear respuesta del llm: %w", err)
	}
	if len(cr.Choices) == 0 {
		debuglog.Log("llm_chat", map[string]any{"warning": "no choices", "response_len": len(body)})
		return "", fmt.Errorf("el llm no devolvió ninguna respuesta")
	}

	debuglog.Log("llm_chat", map[string]any{
		"system_prompt_len": len(systemPrompt), "user_prompt_len": len(userPrompt), "elapsed_s": elapsed,
		"response_len": len(cr.Choices[0].Message.Content),
	})
	return cr.Choices[0].Message.Content, nil
}

// validateLocality evita que contexto de investigación salga de la máquina
// por un simple cambio accidental de URL. Un endpoint remoto requiere el
// opt-in explícito EXITONE_ALLOW_REMOTE_LLM=1; aun así, los constructores de
// contexto nunca incluyen credential.secret_value.
func (c *Client) validateLocality() error {
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return fmt.Errorf("EXITONE_LLM_URL inválida: %w", err)
	}
	host := strings.ToLower(u.Hostname())
	local := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if !local && os.Getenv("EXITONE_ALLOW_REMOTE_LLM") != "1" {
		return fmt.Errorf("endpoint LLM remoto %q bloqueado; define EXITONE_ALLOW_REMOTE_LLM=1 para autorizar explícitamente la salida de contexto", host)
	}
	return nil
}

func (c *Client) IsRemote() bool {
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return true
	}
	host := strings.ToLower(u.Hostname())
	return host != "localhost" && host != "127.0.0.1" && host != "::1"
}
