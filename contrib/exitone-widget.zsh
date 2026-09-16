# ExitOne — integración de shell (sección I del plan).
# Ctrl+Space inserta la sugerencia top-1 en el buffer de línea de comando.
# NUNCA ejecuta — el humano sigue teniendo que pulsar Enter (principio
# "human decides, human executes").

exitone-suggest-widget() {
  local suggestion
  suggestion="$(exitone next --raw 2>/dev/null)"
  if [[ -n "$suggestion" ]]; then
    LBUFFER="$suggestion"
  fi
  zle reset-prompt
}
zle -N exitone-suggest-widget
bindkey '^@' exitone-suggest-widget   # Ctrl+Space en la mayoría de terminales
bindkey '^ ' exitone-suggest-widget   # alias por si el terminal manda Ctrl+Space distinto
