package parsers

import (
	"bufio"
	"io"
	"regexp"
	"strings"
)

type Share struct {
	Name    string
	Type    string
	Comment string
}

type SmbclientListing struct {
	Domain string
	OS     string
	Server string
	Shares []Share
}

var domainLineRe = regexp.MustCompile(`Domain=\[([^\]]*)\]\s*OS=\[([^\]]*)\]\s*Server=\[([^\]]*)\]`)

// validShareTypes: whitelist real de smbclient. Sin esto, líneas de texto
// libre que aparecen tras la tabla en versiones/reconexiones reales (ej.
// "Reconnecting with SMB1 for workgroup listing.") se cuelan como si fueran
// filas de share — bug encontrado probando contra Metasploitable3 real
// (sección B4 del plan: los parsers deterministas siguen siendo frágiles
// ante variaciones reales de una herramienta, hay que endurecerlos con datos
// reales, no solo con el formato "de manual").
var validShareTypes = map[string]bool{
	"Disk":    true,
	"IPC":     true,
	"Printer": true,
	"Special": true,
}

// ParseSmbclientListing parsea la salida de `smbclient -L //host -N`.
// Formato típico:
//
//	Domain=[CORP] OS=[Windows Server 2019] Server=[Samba 4.x]
//
//		Sharename       Type      Comment
//		---------       ----      -------
//		print$          Disk      Printer Drivers
//		backup          Disk
//		IPC$            IPC       IPC Service (Samba Server)
func ParseSmbclientListing(r io.Reader) (SmbclientListing, error) {
	var out SmbclientListing
	scanner := bufio.NewScanner(r)
	inTable := false

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if m := domainLineRe.FindStringSubmatch(line); m != nil {
			out.Domain, out.OS, out.Server = m[1], m[2], m[3]
			continue
		}
		if strings.HasPrefix(trimmed, "Sharename") {
			inTable = true
			continue
		}
		if strings.HasPrefix(trimmed, "---------") {
			continue
		}
		if !inTable || trimmed == "" {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			inTable = false // línea sin forma de fila de share: fin de la tabla
			continue
		}
		if !validShareTypes[fields[1]] {
			// No es una fila de share real (footer, mensaje de reconexión,
			// aviso de versión, etc.) — cierra la tabla, no la registra.
			inTable = false
			continue
		}
		share := Share{Name: fields[0], Type: fields[1]}
		if len(fields) > 2 {
			share.Comment = strings.Join(fields[2:], " ")
		}
		out.Shares = append(out.Shares, share)
	}
	return out, scanner.Err()
}
