// Identidad visual propia de ExitOne — cian, prefijos [+]/[-]/[!]/[*], tablas
// "Section\n=======\n\nCol Col\n---- ----" — reutilizada tanto por la
// Control Console (console_shell.go) como por el resto del CLI. Nunca la
// estética de msfconsole (ASCII art, rojo de marca), solo su patrón de
// navegación cognitiva (ver plan, Contexto).
package main

import (
	"fmt"
	"strings"
)

// Paleta ANSI — msfconsole usa rojo para el banner/prompt y verde/rojo para
// resultados; aquí cian para la identidad de ExitOne (evita el cliché
// hacker verde-sobre-negro que la sección 28 del plan pide evitar) y el
// mismo verde/rojo/amarillo semántico de msfconsole para resultados.
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
	ansiGray   = "\033[90m"
)

func colorize(color, s string) string { return color + s + ansiReset }

const bannerWidth = 62

func printBanner() {
	top := "┌" + strings.Repeat("─", bannerWidth-2) + "┐"
	bot := "└" + strings.Repeat("─", bannerWidth-2) + "┘"
	fmt.Println(colorize(ansiCyan, top))
	fmt.Println(colorize(ansiCyan, "│") + centerText("E X I T O N E", bannerWidth-2, ansiBold+ansiCyan) + colorize(ansiCyan, "│"))
	fmt.Println(colorize(ansiCyan, "│") + centerText("exit code 1 — algo requiere investigación", bannerWidth-2, ansiDim) + colorize(ansiCyan, "│"))
	fmt.Println(colorize(ansiCyan, bot))
	fmt.Println(colorize(ansiDim, "  observa · correlaciona · sugiere — el humano decide y ejecuta"))
	fmt.Println()
}

func centerText(s string, width int, color string) string {
	pad := width - len([]rune(s))
	if pad < 0 {
		pad = 0
	}
	left := pad / 2
	right := pad - left
	return strings.Repeat(" ", left) + colorize(color, s) + strings.Repeat(" ", right)
}

func statusLine(symbol, color, text string) string {
	return fmt.Sprintf("%s[%s]%s %s", color, symbol, ansiReset, text)
}
