# Propuesta técnica

**Centinela detecta cuándo otra persona usa tus credenciales y las revoca.**

Una regla ve lo raro; la IA entiende si es un robo.

## Problema

El robo de credenciales es la primera vía de entrada en el 22 % de las brechas (Verizon DBIR 2025). El atacante entra con una credencial válida: no hay errores ni logins fallidos, y ninguna regla salta (caso Snowflake 2024). Las soluciones que existen (Akamai/Neosec, Traceable, Salt) son productos enterprise. Cloudflare solo recomienda límites de volumen, y por sesión solo en su plan Enterprise.

## Cliente objetivo

Startups y empresas que exponen una API con credenciales para sus clientes o integraciones y no tienen equipo de seguridad.

## Cómo funciona

1. **Registro:** cada uso de una credencial queda registrado: qué credencial, IP, endpoint, código, bytes y hora.
2. **Perfil (código determinista):** de cada credencial guarda desde dónde, cuándo, qué endpoints usa y cuánto volumen mueve. Solo aprende actividad de más de 24 h que no fue marcada como sospechosa.
3. **Contexto del sistema:** la gravedad de cada endpoint: crítico, datos sensibles o normal.
4. **Juicio (IA):** cuando algo se desvía del perfil, la IA decide entre `revoke`, `allow` o `ask_human`, y explica por qué.
5. **Acción:** el bloqueo lo aplica el propio sistema del cliente. La IA no tiene permisos.

El perfil no lo arma la IA, por cuatro razones:
- **Costo:** procesar millones de líneas con un modelo es caro y lento.
- **Precisión:** un modelo de lenguaje cuenta mal.
- **Auditabilidad:** el código da siempre el mismo perfil.
- **Seguridad:** el atacante controla parte de lo que llega a los logs y podría manipular a una IA que los lea.

**El código cuenta; la IA juzga.**

## Integración

Un solo componente en la app del cliente: un **middleware** que envía eventos y aplica bloqueos.

```python
from centinela import CentinelaMiddleware
app.add_middleware(CentinelaMiddleware, token=os.environ["CENTINELA_TOKEN"],
                   key_from=lambda req: req.headers["x-api-key"])
```

| Paso | Qué hace el cliente | Tiempo estimado |
|---|---|---|
| 1. Instalar | Agrega el middleware con su token | Minutos |
| 2. Contexto | Pega la URL de su especificación OpenAPI. La IA propone la gravedad de cada endpoint y el cliente la revisa en el panel | Minutos |
| 3. Aprender | Nada. Centinela observa y arma los perfiles; solo recomienda | Días |
| 4. Actuar | Activa el modo automático para las acciones reversibles | Un clic |

### Qué se envía

- **Sí:** identificador de la credencial (nunca su valor), IP, método, endpoint, código, bytes y hora.
- **No:** cuerpos de peticiones, datos de clientes ni valores de claves.

### Cómo se bloquea

Centinela no entra al sistema del cliente ni tiene acceso a su base de datos. Cuando decide actuar, publica "credencial X bloqueada" o "IP Y bloqueada". El middleware consulta esa lista y rechaza esas peticiones con 401.

- **Si Centinela se cae:** la app sigue funcionando. El middleware envía en segundo plano y nunca frena una petición esperando respuesta.
- **Si el cliente no quiere tocar código:** lee el log de nginx con `forward_nginx.py`, y nginx consulta la lista de bloqueo.
- **Para desinstalar:** basta con quitar una línea.

### Respuestas posibles

| Situación | Respuesta |
|---|---|
| Robo claro, como una descarga masiva desde una red desconocida | Bloquea la IP del atacante, cierra sus sesiones y revoca la credencial |
| Uso raro pero plausible, como el dueño de viaje | Pregunta al dueño de la credencial: "¿fuiste tú?" |
| Cualquier desviación en un endpoint crítico, como un cambio de cuenta bancaria | Revoca de inmediato, aunque sea una sola petición |

La red de la oficina del cliente nunca se bloquea (por política). Las acciones graves, como suspender un usuario, siempre pasan por un humano.

## Validación

Evaluación de la idea, independiente del código del servicio (`evals/key_judgment/`, resultados en `docs/evals/key-judgment.md`).

- **Casos:** 27 casos sintéticos, en 9 familias de 3: 5 de uso legítimo pero raro y 4 de robo. Uno de cada familia es difícil.
- **Método:** la IA corre 3 veces por caso (modelo `claude-sonnet-5-5`, esfuerzo bajo) y se compara con una regla que revoca cuando hay 2 o más desviaciones.

| | Regla | IA |
|---|---|---|
| Robos revocados | 8/12 | 21/36 |
| Robos que pasaron sin aviso | 4/12 | 0/36 |
| Usos legítimos revocados por error | 10/15 (67 %) | 8/45 (18 %, todos en casos difíciles) |
| Enviados a revisión humana | 0 | 44/81 |
| Misma decisión en las 3 corridas | — | 25/27 casos |

**Conclusión:** la tesis queda parcialmente validada.

- **A favor:** la IA nunca dejó pasar un robo en silencio, y revoca por error muchas menos veces que la regla.
- **En contra:** pide revisión humana demasiado seguido.

**Siguiente paso:** medir con el contexto del sistema (gravedad de endpoints) y con más esfuerzo de razonamiento.

En la nube, con el producto actual (prueba A3): 5/5 credenciales robadas revocadas, 0/5 falsos positivos y ~13 s hasta revocar.

## Estado

| Pieza | Estado |
|---|---|
| Recibir eventos (`POST /api/ingest/access`) | Hecho |
| Lector de logs de nginx (`forward_nginx.py`) | Hecho |
| Perfil por credencial y panel de Credenciales | Hecho |
| Botón "Esto era normal" | Hecho |
| Funciona aunque la fuente de métricas esté caída | Hecho |
| Middleware que envía y bloquea | Por hacer |
| Lista de bloqueo consultada por el middleware | Por hacer |
| Leer OpenAPI y clasificar endpoints | Por hacer |
| Preguntar al dueño de la credencial ("¿fuiste tú?") | Por hacer |
| Confirmar `block_ip` y `close_sessions` de punta a punta | Por verificar |
