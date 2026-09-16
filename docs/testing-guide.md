# Guía de prueba manual — ExitOne (estado actual, post-TUI)

## 0. Lo más importante: cómo arrancar

```bash
exitone start 192.168.72.130
```

Esto te deja **directo dentro de la app**: una sola ventana con terminal real embebida a la izquierda (tu shell de siempre) y un panel de correlación en vivo a la derecha. No hace falta tmux, no hace falta abrir nada más.

Si prefieres el layout viejo de dos paneles de tmux (por si algo raro pasa con la terminal embebida): `exitone start 192.168.72.130 --tmux`.

## 1. Trabaja normal en el panel izquierdo

Corre lo que correrías siempre — `nmap`, `smbclient`, `hydra`, `curl`, lo que sea. **No necesitas decirle a ExitOne qué herramienta es.** Si el comando manda su output a un archivo (`-o`, `-oG`, `--output`, o `>`), se auto-ingiere solo; si no, igual se captura completo vía el stream del pane y se procesa en segundo plano (verás un aviso `[exitone] capturando output completo de '<herramienta>'...`).

**Ya es seguro correr `exitone <lo que sea>` desde dentro de esta misma terminal** (`status`, `accept`, `resolve`, `ingest`, `ask`) — el freeze que había antes está corregido.

## 2. El panel derecho (dashboard en vivo)

Se actualiza solo cada ~2s. Tiene 3 vistas, cambia entre ellas con **F2**:

- **OVERVIEW** (default): etapas de la investigación + top-4 sugerencias + objectives abiertos.
- **GRAPH**: árbol del attack surface (host → servicios/shares/dominio).
- **VAULT**: identidades descubiertas, con su procedencia (`confirmed` / `via:fuente` / `llm(confianza)`).

Otros atajos://
- **Ctrl+Space** — inserta la sugerencia de mayor score en tu prompt (nunca la ejecuta, sigue siendo tuyo pulsar Enter).
- **Ctrl+P** — pausa/reanuda el refresco del panel (para leer tranquilo algo que está por cambiar).
- **F1** — ayuda con todos los atajos; cualquier tecla la cierra.
- **Ctrl+Q** — salir de ExitOne (el shell embebido se cierra con él).

## 3. El loop básico de comandos (todos corren dentro de la terminal embebida)

```bash
exitone next              # sugerencias rankeadas
exitone why <id>          # por qué (prefijo del id)
exitone accept <id>       # registra la acción — NO ejecuta nada
exitone resolve <action-id> --result fail|success   # tras probar algo (ej. SSH)
exitone dismiss <id>      # descartar una sugerencia obsoleta
```

## 4. Identidades → metodología SSH

```bash
echo "usuario" > /tmp/ident.txt
exitone ingest identities /tmp/ident.txt --source <de-dónde-salió>
```

Si después aparece OTRA identidad nueva, deberías ver `⚠ Hipótesis reabiertas por evidencia estructural nueva` — es el comportamiento más importante a validar (reapertura sin interpretar texto, solo comparación de conjuntos).

## 5. Preguntas en lenguaje natural

```bash
exitone ask "¿qué falta por investigar?"
exitone ask "¿debería reintentar SSH? ¿con qué identidad y por qué?"
exitone ask "¿qué herramienta dio mejores resultados?"
```

Prueba preguntas que crucen varias piezas de información — es donde vale la pena estresarlo. Si responde "no tengo esa información" cuando SÍ debería saberlo, o si inventa algo que no está en el estado real, es un hallazgo real, avísame.

## 6. Herramienta sin parser propio

Si algo cae al LLM (verás `Formato no reconocido... usando extracción Nivel 2`), la calidad de extracción puede ser floja — es esperado con un modelo de 3B, es justo lo que quiero que midas. Las entidades que salgan de ahí quedan marcadas `INFERRED-LLM`, nunca como hecho confirmado.

## Qué reportarme

No hace falta que expliques en detalle — solo dime cuándo llevas un rato probando, o antes si ves:

- una sugerencia sin sentido dado lo que ya se sabe,
- el mismo comando repetido para algo ya resuelto,
- un `why`/`ask` que no cuadra con los datos reales,
- el dashboard sin actualizarse, o la terminal embebida rara (esto lo tratamos con prioridad — es la pieza más nueva y compleja),
- cualquier `error:` o crash.

Todo queda en `~/.exitone/ultra_debug.log` (cada comando, cada score, todo el tráfico con el LLM) — lo reviso directo ahí.
