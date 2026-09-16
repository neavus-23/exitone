// Package parsers implementa parsers deterministas de Nivel 1 (sección 6 del
// spec original / sección D del plan). Empezamos por nmap en formato greppable
// (-oG), que es trivial de parsear de forma fiable sin ambigüedad.
package parsers

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// OpenPort es una observación determinista extraída de un escaneo nmap.
type OpenPort struct {
	Host     string
	Port     int
	Proto    string // tcp | udp
	Service  string // ej. smb, ssh, http
	Product  string // ej. "OpenSSH 8.9p1" si -sV lo reportó
}

// ParseNmapGreppable lee salida `nmap -oG -` y devuelve los puertos abiertos.
// Formato de línea relevante:
//   Host: 10.10.11.42 ()	Ports: 22/open/tcp//ssh//OpenSSH 8.9p1/, 445/open/tcp//microsoft-ds///
func ParseNmapGreppable(r io.Reader) ([]OpenPort, error) {
	var results []OpenPort
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "Host:") {
			continue
		}
		hostPart, portsPart, ok := splitHostAndPorts(line)
		if !ok {
			continue
		}
		for _, portField := range splitPortFields(portsPart) {
			op, ok := parsePortField(hostPart, portField)
			if ok {
				results = append(results, op)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan nmap output: %w", err)
	}
	return results, nil
}

func splitHostAndPorts(line string) (host string, ports string, ok bool) {
	// "Host: 10.10.11.42 ()	Ports: 22/open/tcp//ssh//.../"
	idx := strings.Index(line, "Ports:")
	if idx == -1 {
		return "", "", false
	}
	hostSection := strings.TrimPrefix(line[:idx], "Host:")
	fields := strings.Fields(hostSection)
	if len(fields) == 0 {
		return "", "", false
	}
	host = fields[0]
	ports = strings.TrimSpace(line[idx+len("Ports:"):])
	return host, ports, true
}

func splitPortFields(portsPart string) []string {
	raw := strings.Split(portsPart, ",")
	out := make([]string, 0, len(raw))
	for _, f := range raw {
		f = strings.TrimSpace(f)
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// parsePortField parsea un campo individual: "445/open/tcp//microsoft-ds///"
// Layout nmap: port/state/protocol/owner/service/rpc_info/version
func parsePortField(host, field string) (OpenPort, bool) {
	parts := strings.Split(field, "/")
	if len(parts) < 5 {
		return OpenPort{}, false
	}
	state := parts[1]
	if state != "open" {
		return OpenPort{}, false
	}
	port, err := strconv.Atoi(parts[0])
	if err != nil {
		return OpenPort{}, false
	}
	proto := parts[2]
	service := parts[4]
	product := ""
	if len(parts) >= 7 {
		product = strings.TrimSpace(parts[6])
	}
	return OpenPort{
		Host:    host,
		Port:    port,
		Proto:   proto,
		Service: service,
		Product: product,
	}, true
}
