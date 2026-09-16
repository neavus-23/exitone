package parsers

import "testing"

// sampleNmapXML es un fragmento real de `nmap -sV -oX` (recortado). El
// extractor no debe saber que esto es "nmap" — solo debe reconocer los
// alias de campo (addr, portid, protocol, state, name, product, version).
const sampleNmapXML = `<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="192.168.72.130" addrtype="ipv4"/>
    <hostnames><hostname name="ubuntu-lab" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="7.6p1" extrainfo="Ubuntu Linux"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache httpd" version="2.4.29"/>
      </port>
      <port protocol="tcp" portid="9999">
        <state state="filtered" reason="no-response"/>
        <service name="unknown"/>
      </port>
    </ports>
  </host>
</nmaprun>`

// sampleNmapXMLWithMAC reproduce el bug real encontrado validando contra un
// escaneo de Metasploitable3: nmap reporta un SEGUNDO <address> con
// addrtype="mac" para la MAC del adaptador (además del addrtype="ipv4"). Sin
// filtrar por addrtype/forma, la MAC se trataba como un segundo Host.
const sampleNmapXMLWithMAC = `<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="192.168.72.130" addrtype="ipv4"/>
    <address addr="00:0C:29:3C:6A:77" addrtype="mac" vendor="VMware"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="6.6.1p1"/>
      </port>
    </ports>
  </host>
</nmaprun>`

func TestExtractFromXML_IgnoresMACAddress(t *testing.T) {
	result, ok := ExtractFromXML([]byte(sampleNmapXMLWithMAC))
	if !ok {
		t.Fatalf("expected extractor to recognize the content, got ok=false")
	}
	if len(result.Hosts) != 1 {
		t.Fatalf("expected exactly 1 host (MAC address must be filtered out), got %d: %+v", len(result.Hosts), result.Hosts)
	}
	if result.Hosts[0].Address != "192.168.72.130" {
		t.Errorf("host address = %q, want 192.168.72.130 (not the MAC)", result.Hosts[0].Address)
	}
	for _, s := range result.Services {
		if s.HostAddress != "192.168.72.130" {
			t.Errorf("service attributed to wrong host: %+v", s)
		}
	}
}

func TestExtractFromXML_GenericNmapShape(t *testing.T) {
	result, ok := ExtractFromXML([]byte(sampleNmapXML))
	if !ok {
		t.Fatalf("expected extractor to recognize the content, got ok=false")
	}
	if len(result.Hosts) != 1 {
		t.Fatalf("expected 1 host, got %d: %+v", len(result.Hosts), result.Hosts)
	}
	h := result.Hosts[0]
	if h.Address != "192.168.72.130" {
		t.Errorf("host address = %q, want 192.168.72.130", h.Address)
	}
	if h.Hostname != "ubuntu-lab" {
		t.Errorf("hostname = %q, want ubuntu-lab", h.Hostname)
	}
	if len(result.Services) != 3 {
		t.Fatalf("expected 3 services, got %d: %+v", len(result.Services), result.Services)
	}

	byPort := map[int]ServiceFact{}
	for _, s := range result.Services {
		byPort[s.Port] = s
	}

	ssh, ok := byPort[22]
	if !ok {
		t.Fatalf("missing service on port 22: %+v", result.Services)
	}
	if ssh.HostAddress != "192.168.72.130" || ssh.Protocol != "tcp" || ssh.State != "open" || ssh.Name != "ssh" {
		t.Errorf("ssh service mismatch: %+v", ssh)
	}
	if ssh.Version != "OpenSSH 7.6p1 Ubuntu Linux" {
		t.Errorf("ssh version = %q, want concatenated product+version+extrainfo", ssh.Version)
	}

	http, ok := byPort[80]
	if !ok || http.Name != "http" || http.Version != "Apache httpd 2.4.29" {
		t.Errorf("http service mismatch: %+v", http)
	}

	filtered, ok := byPort[9999]
	if !ok || filtered.State != "filtered" {
		t.Errorf("filtered service mismatch: %+v", filtered)
	}
}

// sampleGenericJSON simula la salida de un escaner JSON DISTINTO de nmap
// (ej. tipo masscan/rustscan) que usa los mismos alias de campo pero una
// forma completamente distinta (arreglo plano, no árbol anidado con "host").
const sampleGenericJSON = `[
  {"ip": "10.0.0.5", "ports": [
    {"port": 22, "proto": "tcp", "status": "open", "service": "ssh"},
    {"port": 445, "proto": "tcp", "status": "open", "service": "microsoft-ds"}
  ]}
]`

func TestExtractFromJSON_GenericScannerShape(t *testing.T) {
	result, ok := ExtractFromJSON([]byte(sampleGenericJSON))
	if !ok {
		t.Fatalf("expected extractor to recognize the content, got ok=false")
	}
	if len(result.Hosts) != 1 || result.Hosts[0].Address != "10.0.0.5" {
		t.Fatalf("unexpected hosts: %+v", result.Hosts)
	}
	if len(result.Services) != 2 {
		t.Fatalf("expected 2 services, got %d: %+v", len(result.Services), result.Services)
	}
	for _, s := range result.Services {
		if s.HostAddress != "10.0.0.5" {
			t.Errorf("service host mismatch: %+v", s)
		}
	}
}

// sampleGenericTable simula una tabla de texto tipo "-oN" (host de contexto
// + filas port/proto), sin encabezados de ninguna herramienta específica.
const sampleGenericTable = `Scan report for 172.16.0.9
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu
80/tcp   open  http    Apache httpd 2.4.52
443/tcp  closed https
`

func TestExtractFromGenericTable_Shape(t *testing.T) {
	result, ok := ExtractFromGenericTable([]byte(sampleGenericTable))
	if !ok {
		t.Fatalf("expected extractor to recognize the content, got ok=false")
	}
	if len(result.Services) != 3 {
		t.Fatalf("expected 3 services, got %d: %+v", len(result.Services), result.Services)
	}
	byPort := map[int]ServiceFact{}
	for _, s := range result.Services {
		byPort[s.Port] = s
	}
	if s, ok := byPort[22]; !ok || s.HostAddress != "172.16.0.9" || s.Name != "ssh" || s.Version != "OpenSSH 8.9p1 Ubuntu" {
		t.Errorf("port 22 mismatch: %+v", s)
	}
	if s, ok := byPort[443]; !ok || s.State != "closed" {
		t.Errorf("port 443 mismatch: %+v", s)
	}
}

// sampleGreppableLine reproduce el registro real encontrado validando el
// flujo de auto-captura vía hooks contra Metasploitable3 (`-oG`): sin el
// registro "rico" de 7 campos, el extractor perdía el nombre de servicio y
// la versión, capturando solo port/state/proto.
const sampleGreppableLine = `Host: 192.168.72.130 ()	Ports: 21/open/tcp//ftp//ProFTPD 1.3.5/, 22/open/tcp//ssh//OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)/, 3000/closed/tcp//ppp///`

func TestExtractFromGenericTable_GreppableRichFields(t *testing.T) {
	result, ok := ExtractFromGenericTable([]byte(sampleGreppableLine))
	if !ok {
		t.Fatalf("expected extractor to recognize the content, got ok=false")
	}
	byPort := map[int]ServiceFact{}
	for _, s := range result.Services {
		byPort[s.Port] = s
	}
	ftp, ok := byPort[21]
	if !ok || ftp.Name != "ftp" || ftp.Version != "ProFTPD 1.3.5" {
		t.Errorf("port 21 mismatch (service name/version must survive): %+v", ftp)
	}
	ssh, ok := byPort[22]
	if !ok || ssh.Name != "ssh" || ssh.Version != "OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)" {
		t.Errorf("port 22 mismatch: %+v", ssh)
	}
	closedPort, ok := byPort[3000]
	if !ok || closedPort.State != "closed" || closedPort.Name != "ppp" {
		t.Errorf("port 3000 mismatch: %+v", closedPort)
	}
}

// sampleDirbOutput es el output real capturado validando contra
// Metasploitable3 (`dirb http://192.168.72.130/ small.txt`).
const sampleDirbOutput = `-----------------
DIRB v2.22
By The Dark Raver
-----------------

OUTPUT_FILE: /tmp/dirb_out.txt
START_TIME: Tue Sep 15 23:26:08 2026
URL_BASE: http://192.168.72.130/
WORDLIST_FILES: /usr/share/dirb/wordlists/small.txt

-----------------

GENERATED WORDS: 959

---- Scanning URL: http://192.168.72.130/ ----
+ http://192.168.72.130/cgi-bin/ (CODE:403|SIZE:289)
==> DIRECTORY: http://192.168.72.130/chat/
==> DIRECTORY: http://192.168.72.130/phpmyadmin/
==> DIRECTORY: http://192.168.72.130/uploads/

-----------------
END_TIME: Tue Sep 15 23:26:09 2026
DOWNLOADED: 959 - FOUND: 1`

func TestExtractFromGenericTable_DirbShape(t *testing.T) {
	if got := DetectShape([]byte(sampleDirbOutput)); got != ShapeGenericTable {
		t.Fatalf("DetectShape(dirb) = %v, want ShapeGenericTable", got)
	}
	result, ok := ExtractFromGenericTable([]byte(sampleDirbOutput))
	if !ok {
		t.Fatalf("expected extractor to recognize the content, got ok=false")
	}
	if len(result.Endpoints) != 1 {
		t.Fatalf("expected exactly 1 endpoint (only the CODE/SIZE line qualifies), got %d: %+v", len(result.Endpoints), result.Endpoints)
	}
	ep := result.Endpoints[0]
	if ep.URL != "http://192.168.72.130/cgi-bin/" || ep.StatusCode != 403 || ep.Size != 289 {
		t.Errorf("endpoint mismatch: %+v", ep)
	}
}

// sampleFfufJSON simula la forma real de `ffuf -o out.json -of json`.
const sampleFfufJSON = `{
  "results": [
    {"input": {"FUZZ": "admin"}, "position": 1, "status": 200, "length": 1256, "words": 45, "lines": 15, "content-type": "text/html", "url": "http://192.168.72.130/admin", "host": "192.168.72.130"},
    {"input": {"FUZZ": "backup"}, "position": 2, "status": 403, "length": 289, "words": 10, "lines": 5, "content-type": "text/html", "url": "http://192.168.72.130/backup", "host": "192.168.72.130"}
  ]
}`

func TestExtractFromJSON_FfufShape(t *testing.T) {
	result, ok := ExtractFromJSON([]byte(sampleFfufJSON))
	if !ok {
		t.Fatalf("expected extractor to recognize the content, got ok=false")
	}
	if len(result.Endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d: %+v", len(result.Endpoints), result.Endpoints)
	}
	byURL := map[string]EndpointFact{}
	for _, e := range result.Endpoints {
		byURL[e.URL] = e
	}
	if e, ok := byURL["http://192.168.72.130/admin"]; !ok || e.StatusCode != 200 || e.Size != 1256 {
		t.Errorf("admin endpoint mismatch: %+v", e)
	}
	if e, ok := byURL["http://192.168.72.130/backup"]; !ok || e.StatusCode != 403 || e.Size != 289 {
		t.Errorf("backup endpoint mismatch: %+v", e)
	}
}

// Regresión: sqlmap/strings/aircrack/unix-privesc-check NO deben clasificarse
// como ShapeGenericTable solo por mencionar una IP o una URL suelta sin
// código de estado — validado contra el output real de la sesión anterior.
func TestDetectShape_NonScannerToolsStayUnknown(t *testing.T) {
	sqlmapLike := `[23:26:23] [INFO] testing for SQL injection on POST parameter 'enter'
[23:26:23] [WARNING] POST parameter 'enter' does not seem to be injectable
[23:26:24] [ERROR] all tested parameters do not appear to be injectable for http://192.168.72.130/chat/index.php`
	if got := DetectShape([]byte(sqlmapLike)); got != ShapeUnknown {
		t.Errorf("DetectShape(sqlmap-like) = %v, want ShapeUnknown (no status code present)", got)
	}
}

func TestDetectShape(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    Shape
	}{
		{"xml", sampleNmapXML, ShapeXML},
		{"json", sampleGenericJSON, ShapeJSON},
		{"table", sampleGenericTable, ShapeGenericTable},
		{"unknown", "just some free text with no structure at all", ShapeUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectShape([]byte(tc.content))
			if got != tc.want {
				t.Errorf("DetectShape(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}
