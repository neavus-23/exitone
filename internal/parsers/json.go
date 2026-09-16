package parsers

import (
	"encoding/json"
	"strconv"
	"strings"
)

// ExtractFromJSON aplica exactamente los mismos alias de campo que
// ExtractFromXML (ver scanresult.go) sobre un árbol JSON arbitrario —
// arreglos de objetos, objetos anidados, cualquier forma — sin asumir el
// esquema de ninguna herramienta en particular (rustscan, masscan -oJ,
// cualquier scanner que emita JSON con estas claves funciona igual).
func ExtractFromJSON(content []byte) (ScanResult, bool) {
	var v any
	if err := json.Unmarshal(content, &v); err != nil {
		return ScanResult{}, false
	}

	hosts := map[string]*HostFact{}
	var services []ServiceFact
	var endpoints []EndpointFact
	ctx := &jsonWalkState{}

	walkJSON(v, ctx, hosts, &services, &endpoints)

	result := ScanResult{Services: services, Endpoints: endpoints}
	for _, h := range hosts {
		result.Hosts = append(result.Hosts, *h)
	}
	return result, !result.Empty()
}

type jsonWalkState struct {
	currentAddr string
}

func walkJSON(v any, ctx *jsonWalkState, hosts map[string]*HostFact, services *[]ServiceFact, endpoints *[]EndpointFact) {
	switch t := v.(type) {
	case map[string]any:
		own := jsonScalarFields(t)
		if addr, ok := getFirst(own, addressAliases...); ok && isPlausibleHostAddress(addr, own) {
			ctx.currentAddr = addr
			hf := hosts[addr]
			if hf == nil {
				hf = &HostFact{Address: addr}
				hosts[addr] = hf
			}
			if hn, ok := getFirst(own, hostnameAliases...); ok {
				hf.Hostname = hn
			}
		}
		if _, ok := getFirst(own, portAliases...); ok {
			flat := map[string]string{}
			flattenJSONSubtree(t, flat)
			if svc, ok := buildServiceFact(ctx.currentAddr, flat); ok {
				*services = append(*services, svc)
			}
			return
		}
		// Forma "enumeración web" (ffuf -of json, gobuster -o json y
		// similares): un objeto con alias de URL — nunca requiere alias de
		// puerto, así que no compite con la detección de servicio de arriba.
		if urlVal, ok := getFirst(own, urlAliases...); ok && urlVal != "" {
			ep := EndpointFact{URL: urlVal}
			if sc, ok := getFirst(own, statusCodeAliases...); ok {
				if n, err := strconv.Atoi(sc); err == nil {
					ep.StatusCode = n
				}
			}
			if sz, ok := getFirst(own, sizeAliases...); ok {
				if n, err := strconv.Atoi(sz); err == nil {
					ep.Size = n
				}
			}
			*endpoints = append(*endpoints, ep)
			return
		}
		for _, val := range t {
			walkJSON(val, ctx, hosts, services, endpoints)
		}
	case []any:
		for _, item := range t {
			walkJSON(item, ctx, hosts, services, endpoints)
		}
	}
}

// jsonScalarFields aplana solo los campos escalares del NIVEL ACTUAL de un
// objeto (no desciende) — usado para detectar si este objeto en particular
// representa un host o un puerto antes de decidir cómo procesarlo.
func jsonScalarFields(obj map[string]any) map[string]string {
	out := make(map[string]string, len(obj))
	for k, v := range obj {
		if s, ok := scalarToString(v); ok {
			out[strings.ToLower(k)] = s
		}
	}
	return out
}

// flattenJSONSubtree aplana TODOS los campos escalares de un objeto y sus
// descendientes (objetos/arreglos anidados) en un único mapa, igual que
// flattenXMLSubtree — primera ocurrencia gana.
func flattenJSONSubtree(v any, out map[string]string) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if s, ok := scalarToString(val); ok {
				key := strings.ToLower(k)
				if _, exists := out[key]; !exists {
					out[key] = s
				}
				continue
			}
			flattenJSONSubtree(val, out)
		}
	case []any:
		for _, item := range t {
			flattenJSONSubtree(item, out)
		}
	}
}

func scalarToString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10), true
		}
		return strconv.FormatFloat(t, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(t), true
	default:
		return "", false
	}
}
