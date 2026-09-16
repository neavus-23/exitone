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
	"os"
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
		http:    &http.Client{Timeout: 60 * time.Second},
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
	reqBody := chatRequest{
		Model: c.model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		Temperature: 0.1, // extracción/explicación determinista, no creatividad
		MaxTokens:   700,
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
		debuglog.LogError("llm_chat", err, map[string]any{"system_prompt": systemPrompt, "user_prompt": userPrompt, "elapsed_s": elapsed})
		return "", fmt.Errorf("llm request failed (¿está corriendo llama-server en %s?): %w", c.baseURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		debuglog.Log("llm_chat", map[string]any{
			"system_prompt": systemPrompt, "user_prompt": userPrompt, "elapsed_s": elapsed,
			"status_code": resp.StatusCode, "raw_response": string(body),
		})
		return "", fmt.Errorf("llm respondió %d: %s", resp.StatusCode, string(body))
	}

	var cr chatResponse
	if err := json.Unmarshal(body, &cr); err != nil {
		debuglog.LogError("llm_chat_parse", err, map[string]any{"raw_response": string(body)})
		return "", fmt.Errorf("parsear respuesta del llm: %w", err)
	}
	if len(cr.Choices) == 0 {
		debuglog.Log("llm_chat", map[string]any{"warning": "no choices", "raw_response": string(body)})
		return "", fmt.Errorf("el llm no devolvió ninguna respuesta")
	}

	debuglog.Log("llm_chat", map[string]any{
		"system_prompt": systemPrompt, "user_prompt": userPrompt, "elapsed_s": elapsed,
		"raw_response_content": cr.Choices[0].Message.Content,
	})
	return cr.Choices[0].Message.Content, nil
}
