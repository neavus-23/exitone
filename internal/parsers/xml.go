package parsers

import (
	"encoding/xml"
	"strconv"
	"strings"
)

// xmlNode es un árbol XML genérico (patrón estándar de Go para decodificar
// XML sin conocer el schema de antemano). Deliberadamente no tiene ningún
// campo con nombre de herramienta ni de tag esperado.
type xmlNode struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:",any,attr"`
	Nodes   []xmlNode  `xml:",any"`
}

// ExtractFromXML reconoce hosts/services dentro de CUALQUIER XML que use los
// alias de campo de scanresult.go como nombres de atributo, sin importar el
// nombre de los tags ni qué herramienta lo generó. Un nodo se interpreta como
// "host" cuando alguno de sus propios atributos coincide con un alias de
// dirección; se interpreta como "service" cuando, en su propio subárbol,
// aparece un alias de puerto — en ese caso se aplanan todos los atributos de
// ese subárbol (el equivalente XML de "toda la información sobre este
// puerto", sin importar si vino en el mismo tag o en tags hijos como
// <state>/<service> en nmap).
func ExtractFromXML(content []byte) (ScanResult, bool) {
	var root xmlNode
	if err := xml.Unmarshal(content, &root); err != nil {
		return ScanResult{}, false
	}

	hosts := map[string]*HostFact{}
	var services []ServiceFact
	ctx := &xmlWalkState{currentAddr: ""}

	walkXML(root, ctx, hosts, &services)

	result := ScanResult{Services: services}
	for _, h := range hosts {
		result.Hosts = append(result.Hosts, *h)
	}
	return result, !result.Empty()
}

type xmlWalkState struct {
	currentAddr string
}

func walkXML(n xmlNode, ctx *xmlWalkState, hosts map[string]*HostFact, services *[]ServiceFact) {
	own := attrMap(n.Attrs)

	if addr, ok := getFirst(own, addressAliases...); ok && isPlausibleHostAddress(addr, own) {
		ctx.currentAddr = addr
		if hosts[addr] == nil {
			hosts[addr] = &HostFact{Address: addr}
		}
	}
	// El hostname suele venir en un elemento hermano/hijo separado del que
	// trae la dirección (ej. nmap: <address addr="X"/> y <hostname name="Y"/>
	// bajo el mismo <host>), así que se resuelve contra el host "actual" del
	// recorrido, no solo cuando ambos alias caen en el mismo nodo. Como los
	// nodos dentro de un subárbol de puerto nunca se visitan individualmente
	// aquí (se aplanan y se corta la recursión antes), un alias "name" visto
	// en este punto del recorrido nunca es el nombre de un servicio.
	if hn, ok := getFirst(own, hostnameAliases...); ok && ctx.currentAddr != "" {
		if hf := hosts[ctx.currentAddr]; hf != nil {
			hf.Hostname = hn
		}
	}

	if _, ok := getFirst(own, portAliases...); ok {
		flat := map[string]string{}
		flattenXMLSubtree(n, flat)
		if svc, ok := buildServiceFact(ctx.currentAddr, flat); ok {
			*services = append(*services, svc)
		}
		return // subárbol ya aplanado, no hace falta bajar de nuevo por los hijos
	}

	for _, c := range n.Nodes {
		walkXML(c, ctx, hosts, services)
	}
}

func attrMap(attrs []xml.Attr) map[string]string {
	m := make(map[string]string, len(attrs))
	for _, a := range attrs {
		key := strings.ToLower(a.Name.Local)
		if _, exists := m[key]; !exists {
			m[key] = a.Value
		}
	}
	return m
}

// flattenXMLSubtree aplana todos los atributos de un nodo y sus descendientes
// en un único mapa clave→valor (primera ocurrencia gana), sin importar en
// qué tag hijo esté cada atributo.
func flattenXMLSubtree(n xmlNode, out map[string]string) {
	for _, a := range n.Attrs {
		key := strings.ToLower(a.Name.Local)
		if _, exists := out[key]; !exists {
			out[key] = a.Value
		}
	}
	for _, c := range n.Nodes {
		flattenXMLSubtree(c, out)
	}
}

func buildServiceFact(hostAddr string, flat map[string]string) (ServiceFact, bool) {
	portStr, ok := getFirst(flat, portAliases...)
	if !ok || hostAddr == "" {
		return ServiceFact{}, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return ServiceFact{}, false
	}
	svc := ServiceFact{HostAddress: hostAddr, Port: port}
	if proto, ok := getFirst(flat, protoAliases...); ok {
		svc.Protocol = strings.ToLower(proto)
	} else {
		svc.Protocol = "tcp"
	}
	if state, ok := getFirst(flat, stateAliases...); ok {
		svc.State = strings.ToLower(state)
	}
	if name, ok := getFirst(flat, nameAliases...); ok {
		svc.Name = strings.ToLower(name)
	}
	svc.Version = concatVersion(flat)
	return svc, true
}
