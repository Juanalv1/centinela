# Prueba de viabilidad — caso "minero en un servidor"

Fecha: 2026-10-24 · Rama: `feat/feasibility-miner`

## 1. ¿Funcionó de punta a punta?

**Sí.** En la nube (Render), dos corridas completas:

1. `attack.py` lanzó un job que solo consume CPU en el servidor víctima.
2. Claude vio el proceso nuevo y propuso `matar_proceso`. Justificación real del modelo: la línea de comandos usa un pool `stratum+tcp` con `--threads`, típico de criptominería, y el proceso consume ~50% de CPU.
3. El ejecutor determinista validó la propuesta contra el menú y la lista de procesos protegidos, y mató el proceso.
4. El panel confirmó que el proceso desapareció.

Además, en el modo "IA comprometida" (`/api/simulate-compromised`), el ejecutor **rechazó** una propuesta falsificada de matar la base de datos: `target 'db-sim' is a protected process`. En la prueba local también se verificó la segunda capa: aunque se saltara al ejecutor, el kernel responde `403 EPERM`, porque la API corre como usuario sin privilegios y `db-sim` corre como root.

## 2. URLs públicas

- Panel de Centinela: https://centinela-lyiy.onrender.com
- Servidor víctima: https://centinela-victim.onrender.com (`/health`, `/metrics`)

## 3. Tiempos medidos (nube)

| Corrida | Detección | Contención | Proceso confirmado eliminado | Latencia del modelo |
|---|---|---|---|---|
| 1 | 6,16 s | 6,22 s | 7,76 s | 2,50 s |
| 2 | 5,44 s | 5,49 s | 6,83 s | 2,71 s |

Se mide desde que arranca el proceso atacante. Cómo se reparte el tiempo: unos 2 s hasta que el monitor ve el pid nuevo, otros 2 s para que el % de CPU sea significativo, y unos 2,5 s de llamada al modelo. Bajar `POLL_SECONDS` a 1 lo acercaría a ~4 s.

## 4. Qué fue fácil, qué costó y qué bloquea escalar

**Fácil**
- Separar a la IA de las llaves. El agente no tiene credenciales; solo el ejecutor tiene `EXECUTOR_TOKEN`.
- La capa del kernel: `setpriv` viene en `python:3.11-slim`, así que root y no-root conviven sin instalar nada.
- El deploy en Render por API, con dos servicios Docker.

**Costó**
- Render exigió una tarjeta en el workspace antes de crear servicios en un plan pago.
- `psutil` da 0% de CPU en la primera lectura de un proceso, así que hay que juzgarlo una muestra después.
- En `claude-sonnet-5-5`, forzar `tool_choice` devolvió 400; se usa `tool_choice: auto` con una herramienta `strict` y la instrucción en el prompt.
- Hubo que limpiar con `wait()` los procesos hijos matados para que no quedaran como zombis.

**Riesgos y bloqueos para el segundo caso (app web + inyección)**
- **La lista de protegidos es una lista negra.** En Render apareció un proceso del propio proveedor (`portdetectorv2`) que no estaba en ninguna lista. La IA lo juzgó normal, pero el ejecutor *habría permitido* matarlo. Antes del caso 2 hay que pasar a una **lista blanca**: solo se pueden matar procesos lanzados por el job runner.
- **La bitácora vive en `/tmp`** y se pierde si el contenedor se reinicia. Para la demo conviene guardarla en Postgres o en un disco de Render.
- **El caso 2 necesita algo distinto:** acciones nuevas en el menú (revocar clave, bloquear IP), logs HTTP donde el atacante escriba (User-Agent) y una credencial de base de datos con `GRANT` mínimos.
- **La señal del minero es fácil.** Hoy la IA lo detecta sobre todo por la cadena del pool; un atacante real la ocultaría. Para que la IA aporte criterio de verdad, la demo debería incluir señales más ambiguas.

## 5. Secretos y credenciales

| Secreto | Dónde vive |
|---|---|
| `ANTHROPIC_API_KEY` | Variable de entorno del servicio `centinela` en Render. En local, en `hackaton/.env` (fuera del repo) |
| `EXECUTOR_TOKEN` | Generado al azar al desplegar; vive solo en las variables de entorno de Render de ambos servicios |
| `RENDER_API_KEY` | En `hackaton/.env`, fuera del repo; solo se usó para crear los servicios |

Verificado: `grep` de `sk-ant` y `rnd_` sobre el repo → 0 resultados. `.env` está en `.gitignore`.

## 6. Costo aproximado

- **Render:** 2 servicios en plan Starter, pagados con los créditos de la hackatón. Según los precios públicos de Render, ~$7/mes cada uno, prorrateado por uso. Verificar en el dashboard.
- **API de Claude:** no se midió el consumo de tokens. El monitor llama al modelo cuando aparece un pid nuevo o cada 30 s (latido), unas 120 llamadas por hora con snapshots chicos. Revisar el costo real en la consola de Anthropic. Si importa, se puede bajar el latido o usar un modelo más barato para los latidos.
