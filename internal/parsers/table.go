package parsers

import (
	"regexp"
	"strconv"
	"strings"
)

// Patrones de FORMA de texto, no de herramienta: cualquier salida de texto
// tabular que use direcciones IPv4 y campos puerto/proto/estado en alguno de
// estos dos layouts comunes se reconoce igual, sin importar qué escáner la
// generó.
var (
	ipv4Re = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	// layout tipo "greppable": port/state/proto (orden usado por varios
	// escaneres de línea de comandos al reportar puertos separados por "/").
	slashPortRe = regexp.MustCompile(`\b(\d{1,5})/(open|closed|filtered)/(tcp|udp)\b`)
	// variante extendida del mismo layout con más campos por registro:
	// port/state/proto/owner/service/rpc_info/version/ (campos vacíos
	// permitidos entre slashes) — reconoce el registro completo, no solo los
	// primeros tres campos, para no perder nombre de servicio ni versión
	// cuando el archivo trae esta forma más rica. Es un patrón de FORMA
	// (cuántos campos slash-delimitados trae cada registro), no un parser
	// dedicado a una herramienta.
	richSlashRecordRe = regexp.MustCompile(`\b(\d{1,5})/(open|closed|filtered)/(tcp|udp)/([^/,]*)/([^/,]*)/([^/,]*)/([^/,]*)/`)
	// layout tipo tabla humana: "22/tcp   open   ssh   OpenSSH 7.6p1 ..."
	// (?m) para que ^/$ trabajen línea por línea, no sobre todo el archivo.
	plainPortLineRe = regexp.MustCompile(`(?m)^\s*(\d{1,5})/(tcp|udp)\s+(\S+)(?:\s+(\S+))?\s*(.*)$`)

	// Forma "enumeración web" (dirb/gobuster/ffuf en modo texto y similares):
	// una URL absoluta en la línea, junto con un código de estado HTTP y
	// opcionalmente un tamaño — sin exigir el literal "CODE:"/"Status:" de
	// ninguna herramienta en particular, solo la palabra genérica
	// status/code/size seguida de un número cerca de la URL.
	urlRe        = regexp.MustCompile(`https?://\S+`)
	statusCodeRe = regexp.MustCompile(`(?i)(?:status|code)\D{0,12}(\d{3})\b`)
	sizeValRe    = regexp.MustCompile(`(?i)(?:size|length)\D{0,12}(\d+)`)
)

// ExtractFromGenericTable reconoce hosts/services en texto tabular por forma
// (tokens IPv4 + tokens puerto/proto/estado), sin exigir encabezados
// literales de ninguna herramienta. Cubre tanto layouts "greppable"
// (host + varios campos port/state/proto en una sola línea) como layouts de
// tabla humana (una línea por puerto, con un host de contexto fijado por la
// última línea que mostró una IP).
func ExtractFromGenericTable(content []byte) (ScanResult, bool) {
	hosts := map[string]*HostFact{}
	var services []ServiceFact
	var endpoints []EndpointFact
	currentAddr := ""

	for _, line := range strings.Split(string(content), "\n") {
		// La forma "enumeración web" trae su propio host embebido en la URL,
		// así que se evalúa antes del guard de currentAddr (no depende de
		// que una línea previa haya fijado un host de contexto).
		if urlMatch := urlRe.FindString(line); urlMatch != "" {
			if scMatch := statusCodeRe.FindStringSubmatch(line); scMatch != nil {
				code, _ := strconv.Atoi(scMatch[1])
				ep := EndpointFact{URL: strings.TrimRight(urlMatch, ",;)]"), StatusCode: code}
				if szMatch := sizeValRe.FindStringSubmatch(line); szMatch != nil {
					ep.Size, _ = strconv.Atoi(szMatch[1])
				}
				endpoints = append(endpoints, ep)
			}
		}

		if ip := ipv4Re.FindString(line); ip != "" {
			currentAddr = ip
			if hosts[ip] == nil {
				hosts[ip] = &HostFact{Address: ip}
			}
		}
		if currentAddr == "" {
			continue
		}

		if richMatches := richSlashRecordRe.FindAllStringSubmatch(line, -1); len(richMatches) > 0 {
			// El registro rico trae service/version — se usa en vez del
			// patrón simple de 3 campos para no perder esa información
			// (evita también contar el mismo puerto dos veces).
			for _, m := range richMatches {
				port, err := strconv.Atoi(m[1])
				if err != nil {
					continue
				}
				name := m[5]
				version := strings.TrimSpace(m[7])
				services = append(services, ServiceFact{
					HostAddress: currentAddr,
					Port:        port,
					State:       strings.ToLower(m[2]),
					Protocol:    strings.ToLower(m[3]),
					Name:        strings.ToLower(name),
					Version:     version,
				})
			}
		} else {
			for _, m := range slashPortRe.FindAllStringSubmatch(line, -1) {
				port, err := strconv.Atoi(m[1])
				if err != nil {
					continue
				}
				services = append(services, ServiceFact{
					HostAddress: currentAddr,
					Port:        port,
					State:       strings.ToLower(m[2]),
					Protocol:    strings.ToLower(m[3]),
				})
			}
		}

		if m := plainPortLineRe.FindStringSubmatch(line); m != nil {
			port, err := strconv.Atoi(m[1])
			if err == nil {
				name := m[4]
				services = append(services, ServiceFact{
					HostAddress: currentAddr,
					Port:        port,
					Protocol:    strings.ToLower(m[2]),
					State:       strings.ToLower(m[3]),
					Name:        strings.ToLower(name),
					Version:     strings.TrimSpace(m[5]),
				})
			}
		}
	}

	result := ScanResult{Services: services, Endpoints: endpoints}
	for _, h := range hosts {
		result.Hosts = append(result.Hosts, *h)
	}
	return result, !result.Empty()
}
