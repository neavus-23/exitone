package main

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// consoleHandler es la firma de TODO comando de la Control Console — nuevo o
// legacy. Fuera de legacyAdapter (abajo), ningún comando usa panic/recover:
// esto es deliberado (ver plan, sección B) para que panic no se convierta en
// el contrato de error de la consola nueva.
type consoleHandler func(cs *ConsoleSession, args []string) error

// legacyAdapter es la ÚNICA función de toda la consola que usa panic/recover
// — un puente contenido y temporal para reutilizar los cmdXxx existentes
// (que llaman fatal()->os.Exit) sin matar la sesión interactiva. Llama
// dispatch() EN PROCESO (no como subproceso) porque los comandos legacy
// (next/why/accept/...) necesitan compartir *store.Store con el resto de la
// consola — a diferencia de watch/start/tui (ver subprocessAdapter), no
// toman control exclusivo de la terminal.
func legacyAdapter(cmdName string) consoleHandler {
	return func(cs *ConsoleSession, args []string) (err error) {
		defer func() {
			if r := recover(); r != nil {
				if msg, ok := r.(consoleAbort); ok {
					err = errors.New(string(msg))
					return
				}
				panic(r) // pánico real (bug) — nunca se enmascara como un error de usuario
			}
		}()
		prev := interactiveMode
		interactiveMode = true
		defer func() { interactiveMode = prev }()
		dispatch(cs.Store, cmdName, args)
		return nil
	}
}

// subprocessAdapter es para comandos que necesitan poseer la terminal por
// completo (alt-screen de la TUI, o un loop bloqueante como `watch`) —
// ejecutarlos in-process anidaría dos gestores de terminal en modo raw
// (readline + Bubble Tea) en el mismo proceso. Se ejecutan como subproceso
// real heredando stdio; la consola se congela hasta que el hijo termina y
// retoma su propio readline después.
func subprocessAdapter(cmdName string) consoleHandler {
	return func(cs *ConsoleSession, args []string) error {
		cmdArgs := append([]string{cmdName}, args...)
		c := exec.Command(cs.SelfPath, cmdArgs...)
		c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr

		// El hijo comparte el process group de la consola (default — sin
		// Setpgid), así que un Ctrl+C en la tty envía SIGINT a AMBOS. `tui`/
		// `start` ya lo manejan bien porque ponen la tty en raw mode (ISIG
		// desactivado: Ctrl+C les llega como byte, no como señal). Pero
		// `watch` (dashboard.go) es un loop simple sin raw mode ni manejo
		// propio de SIGINT — con disposición default, SIGINT lo mata, que es
		// justo lo que queremos. El único ajuste necesario es que la CONSOLA
		// no muera con esa misma señal mientras el hijo corre (bug real
		// encontrado en el smoke test manual: sin esto, Ctrl+C en `watch`
		// mataba también a la consola). Se drena por canal en vez de
		// signal.Ignore/Reset para no pisar el manejo de SIGINT que
		// reeflective/readline ya registra para su propio Ctrl+C.
		sigCh := make(chan os.Signal, 4)
		signal.Notify(sigCh, syscall.SIGINT)
		done := make(chan struct{})
		go func() {
			for {
				select {
				case <-sigCh:
				case <-done:
					return
				}
			}
		}()

		err := c.Run()
		signal.Stop(sigCh)
		close(done)
		return err
	}
}
