package parsers

import (
	"regexp"
	"strings"
)

var macAddressRe = regexp.MustCompile(`^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$`)

// HostFact y ServiceFact son hechos reconocidos por FORMA de dato + alias de
// campo (ver xml.go/json.go/table.go), nunca por qué herramienta los produjo.
// Cualquier XML/JSON/tabla que use estas claves (address/addr/ip,
// port/portid, proto/protocol, state/status, name/service/servicename,
// product+version+extrainfo+banner) se reconoce igual, sea nmap, masscan,
// rustscan o cualquier otro escáner.
type HostFact struct {
	Address  string
	Hostname string
	Attrs    map[string]string
}

type ServiceFact struct {
	HostAddress string
	Protocol    string
	Port        int
	State       string
	Name        string
	Version     string // product+version+extrainfo+banner concatenados, como el campo "info" de Metasploit
}

// EndpointFact es la forma equivalente de HostFact/ServiceFact pero para
// herramientas de enumeración web (dirb, gobuster, ffuf, ...): una URL con
// código de estado HTTP y opcionalmente tamaño de respuesta. Es una forma
// distinta a host/puerto (no hay noción de protocolo/puerto de red aquí),
// así que se modela aparte en vez de forzarla dentro de ServiceFact.
type EndpointFact struct {
	URL        string
	StatusCode int
	Size       int
}

type ScanResult struct {
	Hosts     []HostFact
	Services  []ServiceFact
	Endpoints []EndpointFact
}

func (r ScanResult) Empty() bool {
	return len(r.Hosts) == 0 && len(r.Services) == 0 && len(r.Endpoints) == 0
}

// Alias de campo reconocidos por los tres extractores (XML/JSON/tabla).
var (
	addressAliases  = []string{"address", "addr", "ip"}
	portAliases     = []string{"port", "portid"}
	protoAliases    = []string{"proto", "protocol"}
	stateAliases    = []string{"state", "status"}
	nameAliases     = []string{"name", "service", "servicename"}
	// "name" cuenta como hostname solo en contexto de host (ver xml.go/json.go:
	// nunca se evalúa dentro de un subárbol ya identificado como servicio).
	hostnameAliases = []string{"hostname", "name"}
	versionAliases  = []string{"product", "version", "extrainfo", "banner"}

	// Alias de campo para la forma "enumeración web" (dirb/gobuster/ffuf y
	// similares): URL + código de estado HTTP + tamaño de respuesta.
	urlAliases        = []string{"url", "input", "path"}
	statusCodeAliases = []string{"status", "statuscode", "code"}
	sizeAliases       = []string{"length", "size"}
)

// isPlausibleHostAddress filtra valores que técnicamente calzan un alias de
// dirección pero no son una dirección de red utilizable como canonical key
// de un Host — el caso real encontrado validando contra un XML de nmap: un
// host reporta DOS elementos con alias "addr" (uno "addrtype=ipv4" y otro
// "addrtype=mac" para la MAC del adaptador), y sin este filtro la MAC se
// trataba como un segundo Host. La regla es genérica por FORMA, no por
// herramienta: se descarta cualquier valor con forma de MAC address, y si el
// propio nodo declara un "addrtype" (o alias equivalente), se exige que sea
// ipv4/ipv6 — nunca se asume que el atributo se llama justo así.
func isPlausibleHostAddress(addr string, ownFields map[string]string) bool {
	if macAddressRe.MatchString(addr) {
		return false
	}
	if kind, ok := getFirst(ownFields, "addrtype", "type"); ok {
		switch strings.ToLower(kind) {
		case "ipv4", "ipv6", "":
			// ok
		default:
			return false
		}
	}
	return true
}

// getFirst busca el primer alias presente (y no vacío) en un mapa de campos
// ya aplanado a minúsculas.
func getFirst(m map[string]string, keys ...string) (string, bool) {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != "" {
			return v, true
		}
	}
	return "", false
}

// concatVersion arma el equivalente al campo "info" de Metasploit: concatena
// todo alias de versión/banner presente, en vez de asumir un único campo.
func concatVersion(m map[string]string) string {
	var parts []string
	seen := map[string]bool{}
	for _, k := range versionAliases {
		if v, ok := m[k]; ok && v != "" && !seen[v] {
			parts = append(parts, v)
			seen[v] = true
		}
	}
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += " "
		}
		out += p
	}
	return out
}
