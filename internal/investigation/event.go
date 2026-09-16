package investigation

// nullableString convierte una cadena vacía en NULL SQL — usado tanto para
// evidence.event_id como para relationship.supporting_observation_id. Fase 1
// del plan de arquitectura: cerrar la cadena de provenance
// Event→Evidence→Observation→Entity/Relationship, que hasta ahora quedaba
// rota en la práctica porque todo camino de ingesta insertaba
// evidence.event_id=NULL sin excepción (pese a que los shell hooks sí
// conocen qué comando produjo cada evidencia) y las relationships HAS_SERVICE/
// HAS_ENDPOINT se creaban con supporting_observation_id=NULL pese a existir
// una observation en la misma transacción. Cuando el llamador no tiene un
// valor real que vincular (ej. un archivo caído por FileWatchEventSource sin
// comando asociado), NULL sigue siendo legítimo — esto no fuerza una
// referencia donde no existe, solo deja de descartar la que sí existe.
func nullableString(v string) any {
	if v == "" {
		return nil
	}
	return v
}
