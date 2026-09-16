package console

import "strings"

// RenderTable reproduce el estilo visual propio de ExitOne
// ("Section\n=======\n\nCol Col\n---- ----"), nunca el de msfconsole.
func RenderTable(title string, headers []string, rows [][]string) string {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	var b strings.Builder
	if title != "" {
		b.WriteString(title)
		b.WriteString("\n")
		b.WriteString(strings.Repeat("=", len(title)))
		b.WriteString("\n\n")
	}

	writeRow := func(cells []string) {
		for i, cell := range cells {
			b.WriteString(padRight(cell, widths[i]))
			if i < len(cells)-1 {
				b.WriteString("  ")
			}
		}
		b.WriteString("\n")
	}

	writeRow(headers)
	dashes := make([]string, len(headers))
	for i, w := range widths {
		dashes[i] = strings.Repeat("-", w)
	}
	writeRow(dashes)

	if len(rows) == 0 {
		b.WriteString("\n")
		return b.String()
	}
	for _, row := range rows {
		writeRow(row)
	}
	return b.String()
}

func padRight(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}
