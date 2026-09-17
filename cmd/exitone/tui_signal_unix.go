//go:build !windows

package main

import (
	"os"
	"os/signal"
	"path/filepath"
	"runtime/pprof"
	"syscall"
)

// installGoroutineDumpHandler vuelca todas las goroutines cuando recibe
// SIGUSR1. Es deliberadamente una ayuda de diagnóstico solo para Unix.
func installGoroutineDumpHandler() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGUSR1)
	go func() {
		for range sigCh {
			home, _ := os.UserHomeDir()
			f, err := os.OpenFile(filepath.Join(home, ".exitone", "tui_goroutines.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				continue
			}
			_ = pprof.Lookup("goroutine").WriteTo(f, 2)
			_ = f.Close()
		}
	}()
}
