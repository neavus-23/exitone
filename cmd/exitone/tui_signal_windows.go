//go:build windows

package main

// Windows no ofrece SIGUSR1. La TUI sigue funcionando; únicamente se omite
// esta ayuda diagnóstica específica de Unix.
func installGoroutineDumpHandler() {}
