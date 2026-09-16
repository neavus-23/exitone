# ExitOne — captura de shell (sección C1/D3 del plan) + auto-ingesta.
# Basado en el hook validado en el spike de Phase 0b (zmodload zsh/datetime
# es obligatorio, ver bug documentado en la sección P/changelog del plan).
#
# Responsabilidades:
#   1. Loggear cada comando como EVENT estructurado (command/cwd/exit_code/duration).
#   2. Detectar de forma AGNÓSTICA A LA HERRAMIENTA si un comando produjo un
#      archivo de salida (flags de output comunes, o redirección '>'), y
#      disparar `exitone ingest <archivo> --tool <hint>`.
#   3. NUEVO — captura completa vía pipe-pane: para comandos que NO
#      redirigieron a un archivo (la mayoría, en uso real: whoami, id, cat,
#      curl sin -o, salida normal de hydra, etc.), se recorta del stream
#      crudo del pane exactamente el fragmento correspondiente a ESE comando
#      y se manda por el mismo pipeline de ingesta. Esto cierra el hueco
#      encontrado al probar el flujo completo: sin esto, ExitOne solo
#      "veía" lo que el operador decidía redirigir a un archivo, no todo lo
#      que realmente pasaba en la terminal (sección D3 del plan, validado
#      en el spike de Phase 0b pero nunca conectado al pipeline real hasta
#      ahora).
#   4. Cargar el widget de autocomplete (Ctrl+Space).
#
# Nota de diseño: la extracción Nivel 2 (LLM) de la captura completa corre
# en SEGUNDO PLANO (no bloquea el prompt) porque tarda varios segundos: si
# corriera en línea, cada comando sin parser determinista congelaría la
# terminal. El resultado queda en ~/.exitone/background_ingest.log y en la
# DB — revisar con `exitone status`/`exitone ask` después, no aparece al
# instante como el auto-ingest de archivo explícito.

zmodload zsh/datetime

typeset -g EXITONE_EVENTS_LOG="${EXITONE_EVENTS_LOG:-$HOME/.exitone/events.jsonl}"
mkdir -p "$HOME/.exitone/streams"
typeset -g __exitone_cmd=""
typeset -g __exitone_start_epoch=0
typeset -g __exitone_cwd=""
typeset -g __exitone_stream_start_offset=0
# Nombre de archivo saneado (sin el '%' de tmux ni espacios) — el pane id
# crudo de tmux causó un bug real de "No such file" por un espacio colado
# en el nombre al construirlo directamente con $TMUX_PANE.
typeset -g __exitone_pane_id="${TMUX_PANE#%}"
__exitone_pane_id="${__exitone_pane_id//[^0-9]/}"
typeset -g EXITONE_STREAM_FILE="$HOME/.exitone/streams/pane${__exitone_pane_id:-none}.log"

# Arranca pipe-pane UNA vez por pane (evita el toggle-off de tmux si se
# vuelve a invocar sin cambiar el comando — por eso se comprueba primero).
if [[ -n "$TMUX_PANE" ]]; then
  __exitone_already_piped="$(tmux display-message -p -t "$TMUX_PANE" '#{pane_pipe}' 2>/dev/null)"
  if [[ "$__exitone_already_piped" != "1" ]]; then
    tmux pipe-pane -o -t "$TMUX_PANE" "cat >> '$EXITONE_STREAM_FILE'" 2>/dev/null
  fi
  unset __exitone_already_piped
fi

__exitone_json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  print -r -- "$s"
}

__exitone_preexec() {
  __exitone_cmd="$1"
  __exitone_start_epoch=$EPOCHREALTIME
  __exitone_cwd="$PWD"
  __exitone_stream_start_offset=0
  [[ -f "$EXITONE_STREAM_FILE" ]] && __exitone_stream_start_offset=$(wc -c < "$EXITONE_STREAM_FILE" 2>/dev/null)
  [[ -z "$__exitone_stream_start_offset" ]] && __exitone_stream_start_offset=0
}

__exitone_extract_output_file() {
  # Busca, en orden, los flags de salida más comunes entre herramientas de
  # pentesting/CTF (nmap -oG/-oN/-oX, ffuf/gobuster/nuclei -o, muchas otras
  # --output), y como último recurso una redirección '>' — cubre la enorme
  # mayoría sin necesitar una regla por herramienta.
  local cmd="$1" file=""
  local -a patterns=('-oG' '-oN' '-oX' '-oJ' '-o' '--output')
  local pat rest
  for pat in "${patterns[@]}"; do
    if [[ "$cmd" == *" $pat "* || "$cmd" == *" $pat"[^[:space:]]* ]]; then
      rest="${cmd#*$pat}"
      rest="${rest## }"
      file="${rest%% *}"
      [[ -n "$file" ]] && break
    fi
  done
  if [[ -z "$file" && "$cmd" =~ '>[[:space:]]*([^[:space:]]+)' ]]; then
    file="${match[1]}"
  fi
  print -r -- "$file"
}

__exitone_first_word() {
  # Nombre del binario tecleado (sin ruta). Bug real encontrado probando con
  # comandos de una sola palabra sin argumentos (ej. "whoami"): la forma
  # anidada ${${(z)cmd}[1]:t} indexa por CARÁCTER en vez de por elemento de
  # array cuando (z) produce un solo elemento — devolvía "w" en vez de
  # "whoami". Forzar la asignación a un array explícito lo evita.
  local -a __words
  __words=(${(z)1})
  print -r -- "${__words[1]:t}"
}

__exitone_extract_host() {
  local cmd="$1"
  if [[ "$cmd" =~ '([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})' ]]; then
    print -r -- "${match[1]}"
  fi
}

# Devuelve 0 (éxito) si encontró y procesó un archivo de salida explícito —
# el llamador usa esto para NO duplicar con la captura de pipe-pane de abajo.
__exitone_maybe_autoingest_file() {
  local cmd="$1" exit_code="$2"
  [[ $exit_code -ne 0 ]] && return 1
  [[ "$cmd" == exitone* ]] && return 1

  local file host toolname
  file="$(__exitone_extract_output_file "$cmd")"
  [[ -z "$file" || ! -f "$file" ]] && return 1

  host="$(__exitone_extract_host "$cmd")"
  toolname="$(__exitone_first_word "$cmd")"

  print -P "%F{cyan}[exitone]%f auto-ingiriendo salida de '$toolname': $file"
  if [[ -n "$host" ]]; then
    exitone ingest "$file" --tool "$toolname" --host "$host" 2>&1 | sed 's/^/[exitone] /'
  else
    exitone ingest "$file" --tool "$toolname" 2>&1 | sed 's/^/[exitone] /'
  fi
  return 0
}

# Lista de comandos triviales/ruidosos que nunca vale la pena mandar al
# pipeline de ingesta (ni siquiera al LLM) — evita spam y llamadas al LLM
# sin ningún valor de evidencia.
__exitone_is_noise_command() {
  local first_word="$1"
  case "$first_word" in
    cd|ls|pwd|echo|clear|export|exitone|history|man|less|more|vim|vi|nano|source|alias|unset|which|type|true|false|help|htop|top|tmux|reset|zsh|bash|sh)
      return 0 ;;
  esac
  return 1
}

# Captura completa vía pipe-pane: fallback para comandos que NO
# redirigieron a un archivo. Recorta el fragmento del stream del pane
# correspondiente a este comando (por offset de bytes) y lo manda al mismo
# pipeline de ingesta agnóstico, en segundo plano para no bloquear el prompt.
__exitone_maybe_capture_full_output() {
  local cmd="$1" exit_code="$2"
  [[ $exit_code -ne 0 ]] && return
  [[ "$cmd" == exitone* ]] && return
  [[ -z "$TMUX_PANE" || ! -f "$EXITONE_STREAM_FILE" ]] && return

  local first_word="$(__exitone_first_word "$cmd")"
  __exitone_is_noise_command "$first_word" && return

  local end_offset
  end_offset=$(wc -c < "$EXITONE_STREAM_FILE" 2>/dev/null)
  [[ -z "$end_offset" ]] && return
  local start=$__exitone_stream_start_offset
  local size=$((end_offset - start))
  # Umbral mínimo: menos de ~60 bytes casi seguro es solo el eco del prompt,
  # no output real que valga la pena mandar al LLM.
  [[ $size -lt 60 ]] && return

  local slice_file
  slice_file=$(mktemp "${TMPDIR:-/tmp}/exitone_slice.XXXXXX") || return
  tail -c +"$((start + 1))" "$EXITONE_STREAM_FILE" 2>/dev/null | head -c "$size" > "$slice_file"

  print -P "%F{gray}[exitone] capturando output completo de '$first_word' en segundo plano (Nivel 2 si no hay parser)...%f"
  (
    exitone ingest "$slice_file" --tool "$first_word" >> "$HOME/.exitone/background_ingest.log" 2>&1
    rm -f "$slice_file"
  ) &
  disown
}

__exitone_precmd() {
  local exit_code=$?
  if [[ -z "$__exitone_cmd" ]]; then
    return
  fi
  local end_epoch=$EPOCHREALTIME
  local duration
  duration=$(awk -v s="$__exitone_start_epoch" -v e="$end_epoch" 'BEGIN{printf "%.3f", e-s}')
  local esc_cmd esc_cwd
  esc_cmd=$(__exitone_json_escape "$__exitone_cmd")
  esc_cwd=$(__exitone_json_escape "$__exitone_cwd")
  {
    printf '{'
    printf '"pane":"%s",' "${TMUX_PANE:-none}"
    printf '"pid":%d,' "$$"
    printf '"command":"%s",' "$esc_cmd"
    printf '"cwd":"%s",' "$esc_cwd"
    printf '"started_at":%s,' "$__exitone_start_epoch"
    printf '"ended_at":%s,' "$end_epoch"
    printf '"duration_s":%s,' "$duration"
    printf '"exit_code":%d' "$exit_code"
    printf '}\n'
  } >> "$EXITONE_EVENTS_LOG"

  if ! __exitone_maybe_autoingest_file "$__exitone_cmd" "$exit_code"; then
    __exitone_maybe_capture_full_output "$__exitone_cmd" "$exit_code"
  fi
  __exitone_cmd=""
}

autoload -Uz add-zsh-hook
add-zsh-hook preexec __exitone_preexec
add-zsh-hook precmd __exitone_precmd

PROMPT='%n@%m:%~%# '

[[ -f "$HOME/.exitone/exitone-widget.zsh" ]] && source "$HOME/.exitone/exitone-widget.zsh"
