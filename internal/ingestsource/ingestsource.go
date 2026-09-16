// Package ingestsource define la interfaz EventSource mínima pedida por la
// Fase 5 del plan de arquitectura, y la única implementación justificada
// para MVP: FileWatchEventSource. Una fuente NUNCA decide qué es un hecho —
// solo entrega artefactos crudos a un ArtifactSink, exactamente como hoy
// hace contrib/exitone-hooks.zsh al invocar `exitone ingest <archivo>`.
//
// Deliberadamente NO se implementan BurpEventSource/BrowserEventSource/
// MetasploitEventSource dedicados: detectar que un archivo es JSON no
// equivale a entender la semántica de un export de Burp o BloodHound — eso
// requeriría un parser especializado real (ver Parser Registry en el plan,
// sección G), que no se construye todavía por falta de un caso de uso
// validado. El punto de extensión (un EventSource más, un parser más en el
// registry) queda documentado y disponible para cuando haga falta.
package ingestsource

import (
	"context"
	"os"
	"path/filepath"
	"time"
)

// ArtifactSink recibe una ruta de archivo cruda para el pipeline de ingest
// existente (`exitone ingest`) — nunca observaciones ya parseadas.
type ArtifactSink interface {
	Accept(path string) error
}

// EventSource es el contrato real pedido en la Fase 5: Run bloquea hasta que
// ctx se cancela, entregando cada artefacto nuevo al sink a medida que
// aparece. Name() sola (sin Run) no compromete a nada — no cuenta como esta
// interfaz.
type EventSource interface {
	Name() string
	Run(ctx context.Context, sink ArtifactSink) error
}

// FileWatchEventSource observa un directorio y entrega al sink cada archivo
// nuevo que aparece en él — útil para reportes que el operador exporta
// manualmente desde otra herramienta (ej. un JSON/XML de Burp o BloodHound)
// sin necesitar una integración dedicada por producto.
type FileWatchEventSource struct {
	Dir      string
	Interval time.Duration // por defecto 2s si es cero
}

func (f *FileWatchEventSource) Name() string { return "filewatch:" + f.Dir }

func (f *FileWatchEventSource) Run(ctx context.Context, sink ArtifactSink) error {
	interval := f.Interval
	if interval <= 0 {
		interval = 2 * time.Second
	}

	seen := map[string]bool{}
	// Los archivos que ya existían al arrancar no se reingieren — solo lo
	// nuevo que aparezca de aquí en adelante.
	if entries, err := os.ReadDir(f.Dir); err == nil {
		for _, e := range entries {
			seen[e.Name()] = true
		}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			entries, err := os.ReadDir(f.Dir)
			if err != nil {
				continue // directorio momentáneamente no listable, no es fatal
			}
			for _, e := range entries {
				if e.IsDir() || seen[e.Name()] {
					continue
				}
				seen[e.Name()] = true
				_ = sink.Accept(filepath.Join(f.Dir, e.Name()))
			}
		}
	}
}
