// Package parsers — detección agnóstica de herramienta (sección 6 del plan:
// "Universal Output Ingestion"). En vez de que el operador tenga que saber
// qué sub-parser usar para cada una de las ~100 herramientas comunes de
// pentesting/CTF (nmap, gobuster, ffuf, nikto, sqlmap, hydra, smbclient,
// enum4linux, whatweb, wpscan, dirb, sslscan/testssl, netexec/crackmapexec,
// john, hashcat, searchsploit, curl, wget, dig, whois, snmpwalk,
// smtp-user-enum, ldapsearch, rpcclient, showmount, wfuzz, amass, subfinder,
// nuclei, msfconsole resource logs...), `exitone ingest <archivo>` detecta el
// formato por contenido. Los parsers deterministas (Nivel 1) cubren las
// herramientas con salida más estructurada/frecuente; todo lo demás cae de
// forma agnóstica al camino de Nivel 2 (LLM) sin que el operador tenga que
// decidir nada — ese fallback es lo que hace el ingest verdaderamente
// agnóstico a la herramienta, no una lista cerrada de parsers.
package parsers

import (
	"encoding/json"
	"regexp"
	"strings"
)

type DetectedFormat string

const (
	FormatNmapGreppable    DetectedFormat = "nmap_greppable"
	FormatSmbclientListing DetectedFormat = "smbclient_listing"
	FormatUnknown          DetectedFormat = "unknown"
)

// Detect mira el contenido crudo (y opcionalmente el nombre de la herramienta,
// si el hook de captura lo pudo inferir del comando tecleado) y decide qué
// parser de Nivel 1 aplica. Si ninguno matchea, el llamador debe usar el
// camino de Nivel 2 (LLM) — eso es lo agnóstico: no hace falta ampliar esta
// función para que una herramienta nueva "funcione", solo para que tenga
// parsing determinista de mayor confianza.
func Detect(toolHint string, content []byte) DetectedFormat {
	s := string(content)
	hint := strings.ToLower(toolHint)

	if hint == "nmap" || looksLikeNmapGreppable(s) {
		if looksLikeNmapGreppable(s) {
			return FormatNmapGreppable
		}
	}
	if hint == "smbclient" || looksLikeSmbclientListing(s) {
		if looksLikeSmbclientListing(s) {
			return FormatSmbclientListing
		}
	}
	return FormatUnknown
}

func looksLikeNmapGreppable(s string) bool {
	return strings.Contains(s, "Host:") && strings.Contains(s, "Ports:")
}

func looksLikeSmbclientListing(s string) bool {
	return strings.Contains(s, "Sharename") && strings.Contains(s, "Type") ||
		strings.Contains(s, "Domain=[")
}

// Shape es la clasificación agnóstica-a-herramienta de un archivo de
// evidencia: no pregunta "¿qué herramienta produjo esto?" sino "¿qué forma
// tiene este contenido?". Es el reemplazo agnóstico de DetectedFormat para
// la ruta de extracción genérica (ver ExtractFromXML/JSON/GenericTable) —
// DetectedFormat/Detect se conservan intactos como red de seguridad.
type Shape int

const (
	ShapeUnknown Shape = iota
	ShapeXML
	ShapeJSON
	ShapeGenericTable
)

// DetectShape mira únicamente la forma sintáctica del contenido — nunca el
// nombre de una herramienta ni un substring propio de un formato de salida
// específico. XML/JSON se detectan por su primer token no-whitespace; la
// tabla genérica se detecta por presencia de tokens con forma de
// dirección/puerto, sin exigir encabezados literales de ninguna herramienta.
//
// Antes de intentar tabla genérica se descarta explícitamente la forma
// "transcripción de shell interactiva" (looksLikeShellTranscript) — ver esa
// función para el bug real que motivó este orden.
func DetectShape(content []byte) Shape {
	trimmed := strings.TrimSpace(string(content))
	if trimmed == "" {
		return ShapeUnknown
	}
	first := trimmed[0]
	if first == '<' {
		return ShapeXML
	}
	// Empezar con "{" o "[" no es prueba suficiente de que sea JSON — texto
	// real de herramientas (líneas de log con timestamp "[23:26:22] [INFO]
	// ...", listas markdown, etc.) también puede empezar así. Se exige que
	// además parsee como JSON válido antes de clasificarlo.
	if (first == '{' || first == '[') && json.Valid(content) {
		return ShapeJSON
	}
	if looksLikeShellTranscript(trimmed) {
		return ShapeUnknown
	}
	if looksLikeGenericTable(trimmed) {
		return ShapeGenericTable
	}
	return ShapeUnknown
}

// looksLikeShellTranscript reconoce una transcripción de sesión de shell
// interactiva (múltiples comandos tecleados por el operador, no la salida de
// una sola herramienta de escaneo) — nunca debe clasificarse como tabla
// genérica aunque contenga, de paso, un par IP:puerto o una URL con código
// de estado (ej. el print de un script de prueba de login, o la IP propia
// del operador en un "connect to [IP] from ..." de una reverse shell).
//
// Bug real encontrado validando ExitOne contra HTB Nexus: la transcripción
// completa de la sesión SSH + escalada de privilegios a root (con el hash
// real de root.txt, el resultado de `id`, la clave SSH usada, etc.) traía
// una sola línea de un script Python imprimiendo "status=302
// http://billing.nexus.htb/admin/login" — suficiente para que
// looksLikeGenericTable la clasificara entera como ShapeGenericTable. El
// extractor de tabla se quedó solo con esa URL y descartó TODO lo demás: el
// acceso a la shell, las credenciales confirmadas, la escalada a root. El
// archivo nunca llegó al extractor de Nivel 2 (LLM), así que ExitOne nunca
// registró ninguna entidad access_context/principal/privilege para el post-
// acceso real que sí ocurrió — el estimador de cobertura (`internal/stage`)
// se quedó "ciego" a esa fase no porque nadie la hubiera confirmado, sino
// porque el archivo que la documentaba nunca llegó al único camino capaz de
// extraerla.
//
// La señal usada es la FORMA del archivo (marcador de autocaptura de
// ExitOne, o múltiples líneas con pinta de prompt de shell), nunca su
// contenido semántico — consistente con el resto de este paquete.
var (
	exitoneCaptureMarker = "[exitone] capturando"
	shellPromptRe        = regexp.MustCompile(`(?m)^\s*\S+@\S+:\S*[$#%]\s*$|^\s*[\w.-]+@[\w.-]+:\S*[$#%]`)
)

func looksLikeShellTranscript(s string) bool {
	if strings.Contains(s, exitoneCaptureMarker) {
		return true
	}
	return len(shellPromptRe.FindAllString(s, 2)) >= 2
}

func looksLikeGenericTable(s string) bool {
	looksLikePortTable := ipv4Re.MatchString(s) && (slashPortRe.MatchString(s) || plainPortLineRe.MatchString(s))
	looksLikeWebEnumTable := urlRe.MatchString(s) && statusCodeRe.MatchString(s)
	return looksLikePortTable || looksLikeWebEnumTable
}
