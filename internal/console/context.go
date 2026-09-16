package console

// ConsoleContext es un objeto de navegación — nunca de estrategia. `use`
// solo manipula esto; `focus` (internal/focus) es una cosa completamente
// distinta y este paquete nunca lo referencia.
type ConsoleContext struct {
	Type  ContextType
	ID    string
	Label string
}

// ContextStack es la pila de navegación en memoria de una sesión de
// consola — nunca se persiste en SQLite (no hace falta: es puramente de
// presentación). La base (índice 0) siempre es el workspace activo.
type ContextStack struct {
	items []ConsoleContext
}

// NewContextStack crea una pila con `root` (normalmente Workspace) como
// única entrada.
func NewContextStack(root ConsoleContext) *ContextStack {
	return &ContextStack{items: []ConsoleContext{root}}
}

// Push navega hacia un contexto más profundo (ej. de Host a Service).
func (s *ContextStack) Push(c ConsoleContext) {
	s.items = append(s.items, c)
}

// Pop vuelve al contexto anterior. Si ya está en la raíz, devuelve
// (contexto-raíz, false) SIN error — `back` en la raíz nunca es una
// operación destructiva ni un error (sección 10 del pedido original).
func (s *ContextStack) Pop() (ConsoleContext, bool) {
	if len(s.items) <= 1 {
		return s.items[0], false
	}
	s.items = s.items[:len(s.items)-1]
	return s.items[len(s.items)-1], true
}

// Current devuelve el contexto activo (el tope de la pila).
func (s *ContextStack) Current() ConsoleContext {
	return s.items[len(s.items)-1]
}

// ResetToRoot reemplaza TODA la pila por una base nueva — usado al cambiar
// de workspace (ConsoleSession.SwitchWorkspace), no solo al "volver a la
// raíz del mismo workspace" (por eso recibe el nuevo root explícito, en vez
// de ser un Pop repetido).
func (s *ContextStack) ResetToRoot(newRoot ConsoleContext) {
	s.items = []ConsoleContext{newRoot}
}

// Depth es útil para pruebas / diagnósticos.
func (s *ContextStack) Depth() int {
	return len(s.items)
}
