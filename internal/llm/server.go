// EnsureRunning es lo que hace que el LLM sea parte de ExitOne y no un
// complemento aparte: antes de que Chat() haga cualquier petición, esta
// función garantiza que haya un servidor local respondiendo — arrancándolo
// como subproceso propio si hace falta — para que el operador nunca tenga
// que abrir una terminal separada y correr `llama-server` a mano.
package llm

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// llmDir es el directorio propio de ExitOne para el sidecar del LLM —
// convención análoga a ~/.exitone/history o ~/.exitone/exitone.db: todo lo
// que ExitOne necesita para funcionar vive bajo ~/.exitone, nunca en una
// ruta de un experimento aparte que el operador tenga que recordar.
func llmDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	dir := filepath.Join(home, ".exitone", "llm")
	os.MkdirAll(filepath.Join(dir, "bin"), 0o755)
	os.MkdirAll(filepath.Join(dir, "models"), 0o755)
	return dir
}

// EnsureRunning: si baseURL ya responde, no hace nada (camino caliente,
// costo de un GET local). Si no responde Y el operador no fijó
// EXITONE_LLM_URL explícitamente (lo que significaría que administra ese
// servidor él mismo, posiblemente remoto), localiza el binario+modelo,
// arranca el servidor como proceso propio y espera a que cargue el modelo.
func EnsureRunning(ctx context.Context, baseURL string) error {
	if healthy(baseURL) {
		return nil
	}

	if os.Getenv("EXITONE_LLM_URL") != "" {
		return fmt.Errorf("EXITONE_LLM_URL=%s no responde — esa URL la administra el operador, ExitOne no arranca nada ahí", baseURL)
	}

	bin, err := resolveServerBinary()
	if err != nil {
		return err
	}
	model, err := resolveModelPath()
	if err != nil {
		return err
	}
	port, err := portFromURL(baseURL)
	if err != nil {
		return err
	}

	if err := spawnServer(bin, model, port); err != nil {
		return err
	}

	return waitForHealth(ctx, baseURL, 120*time.Second)
}

func healthy(baseURL string) bool {
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	resp, err := client.Get(baseURL + "/models")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func waitForHealth(ctx context.Context, baseURL string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if healthy(baseURL) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(1500 * time.Millisecond):
		}
	}
	return fmt.Errorf("el LLM local no respondió tras %s de haberlo arrancado — revisa %s", timeout, filepath.Join(llmDir(), "server.log"))
}

// spawnServer lo arranca como un proceso propio, HUÉRFANO deliberadamente
// (Setpgid + sin Wait()): cuando este `exitone` termine (ej. un `exitone ask`
// de un solo comando), el servidor sigue vivo para la siguiente invocación —
// exactamente el comportamiento de un daemon que ExitOne posee, no de un
// subproceso efímero atado a un comando puntual.
func spawnServer(bin, model, port string) error {
	dir := llmDir()
	logFile, err := os.OpenFile(filepath.Join(dir, "server.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("abrir log del LLM: %w", err)
	}
	defer logFile.Close()

	cmd := exec.Command(bin, "-m", model, "--port", port, "-c", "4096")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("arrancar llama-server (%s): %w", bin, err)
	}
	_ = os.WriteFile(filepath.Join(dir, "server.pid"), []byte(strconv.Itoa(cmd.Process.Pid)), 0o644)
	return nil
}

func portFromURL(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("EXITONE_LLM_URL inválida: %w", err)
	}
	if p := u.Port(); p != "" {
		return p, nil
	}
	return "8090", nil
}

// resolveServerBinary busca, en orden: override explícito, la ubicación
// propia de ExitOne, y por último rutas de instalaciones previas/manuales
// (spikes de desarrollo, PATH del sistema) — para no romper un setup que ya
// funcionaba mientras se establece la convención definitiva.
func resolveServerBinary() (string, error) {
	if v := os.Getenv("EXITONE_LLM_SERVER_BIN"); v != "" {
		if fileExists(v) {
			return v, nil
		}
		return "", fmt.Errorf("EXITONE_LLM_SERVER_BIN=%s no existe", v)
	}

	owned := filepath.Join(llmDir(), "bin", "llama-server")
	if fileExists(owned) {
		return owned, nil
	}

	if home, err := os.UserHomeDir(); err == nil {
		if matches, _ := filepath.Glob(filepath.Join(home, "exitone-spike", "llm", "bin", "*", "llama-server")); len(matches) > 0 {
			return matches[0], nil
		}
	}

	if p, err := exec.LookPath("llama-server"); err == nil {
		return p, nil
	}

	return "", fmt.Errorf("no se encontró el binario llama-server — colócalo en %s o define EXITONE_LLM_SERVER_BIN", owned)
}

func resolveModelPath() (string, error) {
	if v := os.Getenv("EXITONE_LLM_MODEL_PATH"); v != "" {
		if fileExists(v) {
			return v, nil
		}
		return "", fmt.Errorf("EXITONE_LLM_MODEL_PATH=%s no existe", v)
	}

	ownedGlob := filepath.Join(llmDir(), "models", "*.gguf")
	if matches, _ := filepath.Glob(ownedGlob); len(matches) > 0 {
		return matches[0], nil
	}

	if home, err := os.UserHomeDir(); err == nil {
		if matches, _ := filepath.Glob(filepath.Join(home, "exitone-spike", "llm", "models", "*.gguf")); len(matches) > 0 {
			return matches[0], nil
		}
	}

	return "", fmt.Errorf("no se encontró un modelo .gguf — colócalo en %s o define EXITONE_LLM_MODEL_PATH", filepath.Join(llmDir(), "models"))
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
