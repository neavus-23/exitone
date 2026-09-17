# Guía de validación observable de ExitOne

Esta guía valida el producto como compañero cognitivo local durante todo el ciclo de una investigación autorizada. ExitOne observa, recuerda, correlaciona y recomienda; el operador humano ejecuta cada acción.

## 1. Verificación previa

```bash
go test ./...
go vet ./...
go build -o exitone ./cmd/exitone
```

Use un workspace desechable y protéjalo como material sensible:

```bash
umask 077
mkdir -p ~/.exitone/runs/<engagement>
```

Compruebe además Go 1.27+, Zsh, tmux, SQLite y las herramientas autorizadas para el engagement.

## 2. Sesión visible y persistente

```bash
exitone start <target> --tmux --session-name exitone-validation --detach
tmux attach -t exitone-validation
```

El layout contiene:

```text
OPERATOR | EXITONE LIVE
         | EVIDENCE & EVENTS
         | VALIDATION CONTROL
```

Todo comando contra el target se escribe exclusivamente en `OPERATOR`. Para observar sin tomar control:

```bash
tmux attach -r -t exitone-validation
```

Desconectarse de tmux no detiene la prueba. Antes de cada acción muestre fase, objetivo, acción, razón, evidencia esperada y si modifica el target. Después muestre exit code, evidencia, relaciones, hipótesis afectadas, outcome y siguiente recomendación.

## 3. Loop que debe validarse

```text
candidate → decisión humana → Enter → event → evidence → outcome → strategy revision
```

1. Revise `exitone next` y `exitone why <candidate>`.
2. Escriba y ejecute la acción desde `OPERATOR`; no invoque el comando desde ExitOne.
3. Confirme que `exitone events` conserva también errores y ejecuciones sin output.
4. Una coincidencia única debe enlazarse; varias coincidencias deben quedar `ambiguous`; ninguna coincidencia debe quedar como trabajo realizado sin inventar acción.
5. Use `accept`, `resolve` y `ingest --for-action` solo como fallback o para una decisión explícita.
6. Confirme que la revisión sube, los candidatos deterministas aparecen de inmediato y el job LLM corre en background sin bloquear la ingesta.

## 4. Fases y conocimiento

Valide que las fases son no bloqueantes: `discovery`, `enumeration`, `analysis`, `hypotheses`, `validation`, `exploitation_guidance`, `post_access`, `privilege_access` y `objectives`.

- La evidencia cruda no debe aparecer como hecho por sí sola.
- Una observación LLM queda pendiente y con confianza limitada hasta `observation confirm`.
- Las hipótesis conservan evidencia de soporte y contradicción.
- Los candidatos muestran tipo, fase, fuente, confianza, riesgo, asunciones y evidencia esperada.
- Un resultado fallido reduce repetición; nueva evidencia puede justificar reapertura.
- `ask`, `why` y `guide` deben basarse en el grafo persistido, no en un playbook del target.

## 5. Credenciales y privacidad

```bash
exitone credential add --identity <ref> --service <ref> --source <evidence> --value '<secret>'
exitone credential list
exitone credential list --reveal
exitone credential attempt <id> --service <ref> --result fail
```

El primer listado debe estar enmascarado. `--reveal` es deliberado. El valor se almacena en texto plano dentro de la base local; aplique permisos `0700` al directorio y `0600` a bases, logs y transcripciones. Verifique que secretos no aparezcan en debug logs, explicaciones ni prompts de estrategia. Un endpoint LLM no-loopback requiere `EXITONE_ALLOW_REMOTE_LLM=1` y nunca recibe evidencia cruda ni valores de credenciales.

## 6. Checkpoints modificadores

Solo lectura puede continuar una vez visible. Antes de login autenticado, requests modificadores, uploads, listeners/payloads, creación de repositorio, creación de objetos, push o escritura derivada, deje un checkpoint visible en `VALIDATION CONTROL`. Registre después el outcome y cualquier cambio de principal.

## 7. VPN de laboratorio

Antes de iniciarla, inspeccione interfaces `tun`, procesos OpenVPN y rutas. Reutilice una VPN válida si el target ya está correctamente enrutado. Si debe iniciar una:

1. Arranque un único perfil en un panel visible, con PID y log conocidos.
2. Verifique `Initialization Sequence Completed`, interfaz tun e `ip route get <target>`.
3. Haga una comprobación limitada de conectividad.
4. Si falla, detenga solo ese PID y retire únicamente sus rutas antes de probar el perfil alternativo.
5. Nunca mantenga dos perfiles activos ni cambie permanentemente NetworkManager, DNS o rutas.

## 8. Aceptación y cierre

```bash
go test ./...
go vet ./...
```

La prueba pasa si ExitOne acompaña todas las fases, evita repetición injustificada, correlaciona identidades/credenciales/aplicaciones/principales, separa evidencia de inferencia, conserva provenance y cronología, y ningún componente ejecuta candidatos.

Guarde un resumen con revisiones, eventos, intentos, ramas, hipótesis y outcomes. Después detenga solo la VPN creada por la prueba, retire credenciales y claves temporales, elimine la copia temporal del código y conserve únicamente los artefactos acordados.
