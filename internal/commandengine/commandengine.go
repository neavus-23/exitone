// Package commandengine renderiza comandos deterministas a partir de un
// intent_key (sección I del plan). Cada slot lleva su provenance
// (confirmed/inferred/user-provided) para que la UI de autocomplete pueda
// distinguirlos (mitiga el riesgo B7: nunca mostrar un valor inferido como
// si fuera confirmado).
package commandengine

import "fmt"

// Slot es un valor insertado en una plantilla de comando junto con su
// provenance — nunca se pierde de dónde salió ese valor.
type Slot struct {
	Value      string
	Provenance string // confirmed | inferred | user-provided
}

// Rendered es un comando ya armado a partir de un intent_key: el binario, la
// línea completa lista para mostrarle al operador, y cada slot que la
// compone con su provenance individual.
type Rendered struct {
	Tool    string
	Command string
	Slots   map[string]Slot
}

// templates: intent_key -> (tool, plantilla con %s para {target}).
// Slice 1 solo necesita smb; se amplía en Fase 2 con más tools/intents.
func Render(intentKey string, target Slot) (Rendered, error) {
	switch intentKey {
	case "enumerate_smb_shares_anonymous":
		cmd := fmt.Sprintf("smbclient -L //%s -N", target.Value)
		return Rendered{
			Tool:    "smbclient",
			Command: cmd,
			Slots:   map[string]Slot{"target": target},
		}, nil
	default:
		return Rendered{}, fmt.Errorf("no hay template determinista para intent %q (correspondería a LLM assist, fuera de Slice 1)", intentKey)
	}
}

// RenderPortScan es la primera acción posible desde estado VACÍO (bootstrap
// del objective 'initial_discovery' — ver methodology.OpenInitialDiscovery).
// Sin esto, ExitOne no puede proponer nada hasta que exista al menos una
// entidad, lo cual deja al operador sin guía en el primer paso real de
// cualquier investigación (gap encontrado validando el flujo CTF completo).
func RenderPortScan(target Slot) Rendered {
	cmd := fmt.Sprintf("nmap -sV -sC -p- %s -oG nmap_full_%s.txt", target.Value, sanitizeForFilename(target.Value))
	return Rendered{
		Tool:    "nmap",
		Command: cmd,
		Slots:   map[string]Slot{"target": target},
	}
}

func sanitizeForFilename(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '.' || r == ':' {
			out = append(out, '_')
			continue
		}
		out = append(out, r)
	}
	return string(out)
}

// RenderSSHAuthTest arma el comando de prueba de autenticación SSH para una
// identidad concreta (sección D1/Slice 3 — cada candidato de este tipo
// corresponde 1:1 a una identidad conocida en el momento de generarse).
func RenderSSHAuthTest(identity, target Slot) Rendered {
	cmd := fmt.Sprintf("ssh %s@%s", identity.Value, target.Value)
	return Rendered{
		Tool:    "ssh",
		Command: cmd,
		Slots:   map[string]Slot{"identity": identity, "target": target},
	}
}

// RenderEndpointFollowup sugiere una inspección genérica de un endpoint web
// descubierto (dirb/gobuster/ffuf, vía el extractor genérico de
// internal/parsers) que contiene una palabra clave de interés (panel de
// administración, backup, config, etc.) — un curl de solo lectura, nunca un
// intento de acceso o explotación.
func RenderEndpointFollowup(target Slot) Rendered {
	cmd := fmt.Sprintf("curl -s -i %s", target.Value)
	return Rendered{
		Tool:    "curl",
		Command: cmd,
		Slots:   map[string]Slot{"target": target},
	}
}

// FormatForShell añade un marcador visual para slots inferidos, para que el
// autocomplete de shell (Ctrl+Space) nunca inserte una inferencia como si
// fuera un hecho confirmado sin decirlo.
func (r Rendered) FormatForShell() string {
	for name, slot := range r.Slots {
		if slot.Provenance == "inferred" {
			return r.Command + fmt.Sprintf("  # %s inferido, verificar antes de ejecutar", name)
		}
	}
	return r.Command
}
