// Package console implementa las piezas puras de la nueva Control Console
// estilo msfconsole (registro de comandos, pila de contexto de navegación,
// último result set indexable, parseo de búsqueda, render de tablas).
// Deliberadamente NO conoce handlers de dominio ni importa cmd/exitone —
// eso vive enteramente en cmd/exitone (ver plan, sección D/E). Esto evita
// tanto un ciclo de import como la interfaz "HandlerContext" descartada en
// una ronda anterior de diseño por sobre-arquitectura.
package console

import "fmt"

// ContextType — los objetos que la consola puede "usar" (navegar). No es lo
// mismo que `focus` (internal/focus): esto es presentación/navegación,
// focus es prioridad de Strategy. Ver plan, Contexto.
type ContextType string

const (
	Workspace  ContextType = "workspace"
	Host       ContextType = "host"
	Service    ContextType = "service"
	Objective  ContextType = "objective"
	Hypothesis ContextType = "hypothesis"
	Candidate  ContextType = "candidate"
)

// CommandSpec describe un comando para help/autocompletado/agrupación —
// nunca su implementación. cmd/exitone mantiene un slice único
// (commandDefinition) que alimenta tanto el Registry como el mapa real de
// handlers, así que Registry y ejecución no pueden desincronizarse.
type CommandSpec struct {
	Name          string
	Aliases       []string
	Usage         string
	Description   string
	Category      string
	ValidContexts []ContextType // solo para ordenar help/completado, nunca para bloquear ejecución
	Sensitive     bool          // si true, la línea nunca se guarda en el historial persistente
}

// Registry resuelve nombre/alias → spec, sin conocer nunca un handler real.
type Registry struct {
	specs   map[string]*CommandSpec // por nombre canónico
	aliases map[string]string       // alias -> nombre canónico
	order   []string                // orden de registro, para listados estables
}

func NewRegistry() *Registry {
	return &Registry{
		specs:   map[string]*CommandSpec{},
		aliases: map[string]string{},
	}
}

// Register agrega un comando. Devuelve error si el nombre o cualquiera de
// sus alias ya existe — nunca se permite un duplicado silencioso (a
// diferencia del comportamiento previo del REPL, donde help y dispatch
// podían desincronizarse sin que nada lo detectara).
func (r *Registry) Register(spec CommandSpec) error {
	if spec.Name == "" {
		return fmt.Errorf("console: CommandSpec sin Name")
	}
	if _, exists := r.specs[spec.Name]; exists {
		return fmt.Errorf("console: comando %q ya registrado", spec.Name)
	}
	if _, exists := r.aliases[spec.Name]; exists {
		return fmt.Errorf("console: %q ya está registrado como alias", spec.Name)
	}
	for _, a := range spec.Aliases {
		if _, exists := r.specs[a]; exists {
			return fmt.Errorf("console: alias %q colisiona con un comando existente", a)
		}
		if _, exists := r.aliases[a]; exists {
			return fmt.Errorf("console: alias %q ya registrado", a)
		}
	}

	specCopy := spec
	r.specs[spec.Name] = &specCopy
	for _, a := range spec.Aliases {
		r.aliases[a] = spec.Name
	}
	r.order = append(r.order, spec.Name)
	return nil
}

// Resolve busca por nombre canónico o alias.
func (r *Registry) Resolve(name string) (*CommandSpec, bool) {
	if spec, ok := r.specs[name]; ok {
		return spec, true
	}
	if canonical, ok := r.aliases[name]; ok {
		return r.specs[canonical], true
	}
	return nil, false
}

// All devuelve todos los specs en el orden en que se registraron.
func (r *Registry) All() []*CommandSpec {
	out := make([]*CommandSpec, 0, len(r.order))
	for _, name := range r.order {
		out = append(out, r.specs[name])
	}
	return out
}

// ByCategory agrupa los specs — usado por `help` (sección 15 del pedido
// original: "Core Commands"/"Strategy Commands"/"Workspace Commands"/...).
func (r *Registry) ByCategory() map[string][]*CommandSpec {
	out := map[string][]*CommandSpec{}
	for _, name := range r.order {
		spec := r.specs[name]
		out[spec.Category] = append(out[spec.Category], spec)
	}
	return out
}

// ValidIn devuelve los specs cuyo ValidContexts incluye ctx — usado por `?`
// y por el completado contextual para priorizar, NUNCA para ocultar el
// resto (sección 25 del pedido original).
func (r *Registry) ValidIn(ctx ContextType) []*CommandSpec {
	var out []*CommandSpec
	for _, name := range r.order {
		spec := r.specs[name]
		for _, vc := range spec.ValidContexts {
			if vc == ctx {
				out = append(out, spec)
				break
			}
		}
	}
	return out
}

// Suggest implementa el "Did you mean?" de la sección 26 del pedido
// original: distancia de edición (Levenshtein) ≤2 contra nombres y alias.
func (r *Registry) Suggest(input string) []string {
	type scored struct {
		name  string
		score int
	}
	var candidates []scored
	seen := map[string]bool{}
	consider := func(name string) {
		if seen[name] {
			return
		}
		seen[name] = true
		d := levenshtein(input, name)
		if d <= 2 {
			candidates = append(candidates, scored{name, d})
		}
	}
	for _, name := range r.order {
		consider(name)
	}
	for alias := range r.aliases {
		consider(alias)
	}

	// Orden estable por score ascendente (inserción simple — la cantidad de
	// comandos es pequeña, no hace falta sort.Slice con más dependencias).
	for i := 1; i < len(candidates); i++ {
		for j := i; j > 0 && candidates[j].score < candidates[j-1].score; j-- {
			candidates[j], candidates[j-1] = candidates[j-1], candidates[j]
		}
	}
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		out = append(out, c.name)
	}
	return out
}

func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost
			min := del
			if ins < min {
				min = ins
			}
			if sub < min {
				min = sub
			}
			curr[j] = min
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}
