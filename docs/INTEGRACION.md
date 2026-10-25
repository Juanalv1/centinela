# Cómo se integra Centinela en un sistema

Resumen: conectas tus registros, le das credenciales mínimas para ejecutar y lo pones a aprender.

## Arquitectura (modelo híbrido)

```
  INFRAESTRUCTURA DEL CLIENTE                      CENTINELA (nube)
 ┌───────────────────────────────┐               ┌──────────────────────┐
 │ Registros que ya existen       │──metadatos──► │ Línea base + IA      │
 │ (proxy, CloudTrail, app, SaaS) │   (sin datos  │ (razona y propone)   │
 │                                │  de clientes) └──────────┬───────────┘
 │ Ejecutor de Centinela          │◄──── propuesta ──────────┘
 │ (contenedor del cliente,       │
 │  con credenciales mínimas)     │──► revoca / bloquea / mata, solo lo permitido
 └───────────────────────────────┘
```

Las credenciales nunca salen de la infraestructura del cliente. La IA solo recibe metadatos y solo puede proponer acciones de un menú cerrado.

## Pasos de integración

1. **Conectar la ingesta (solo lectura).** Registros que el sistema ya genera:
   - proxy o balanceador (nginx, Cloudflare, AWS ALB): IP, endpoint, hora y bytes de cada petición;
   - auditoría de la nube (AWS CloudTrail): cada llamada hecha con una clave;
   - auditoría de servicios SaaS (historial de logins y consultas);
   - la propia app, con un middleware que registra cada petición.
2. **Instalar el ejecutor** como contenedor dentro de la infraestructura del cliente.
3. **Dar credenciales mínimas al ejecutor**, una por acción. Ejemplos: un rol de AWS que solo desactiva claves; un rol de base de datos con `UPDATE` solo sobre el estado de las credenciales. El cliente crea y controla esos permisos.
4. **Configurar reglas:** acciones habilitadas, recursos protegidos y canal de aprobaciones.
5. **Ponerlo a aprender** (ver abajo) y adoptarlo de forma gradual:
   - período de aprendizaje: construye la línea base;
   - modo recomendación: todo pasa por un humano;
   - modo automático: solo para las acciones reversibles que el cliente active.

## Ingesta de accesos (formato normalizado)

Toda fuente (la API víctima del demo, un proxy, la propia app) se traduce a un mismo evento de acceso antes de llegar a la línea base por clave. Solo metadatos: qué credencial (su id y su etiqueta, nunca su valor), desde qué IP, cuándo, qué ruta y cuántos bytes devolvió. Nunca cuerpos ni cadenas de consulta; de la consulta solo se lee el valor de `page`. Los campos que no están en el formato se ignoran y no se guardan.

| Campo | Tipo | Obligatorio | Contenido |
|---|---|---|---|
| `id` | texto (≤ 128) o entero | sí | id del evento, único dentro de la fuente |
| `ts` | número | sí | hora en segundos Unix |
| `key_id` | entero | sí | id de la credencial (nunca la clave) |
| `ip` | texto | sí | IP del cliente |
| `path` | texto | sí | ruta absoluta; si trae `?...`, se descarta salvo `page` |
| `status` | entero | sí | código HTTP (solo se aprende lo que respondió 2xx) |
| `bytes` | entero | no | bytes de la respuesta |
| `method` | texto | no | método HTTP |
| `page` | texto o entero | no | página pedida (detecta exportaciones paginadas) |
| `key_label` | texto | no | nombre legible de la credencial |

**Endpoint:** `POST /api/ingest/access` con `Authorization: Bearer <INGEST_TOKEN>`. Sin `INGEST_TOKEN` configurado, el endpoint no existe (404).

```http
POST /api/ingest/access
Authorization: Bearer <INGEST_TOKEN>
Content-Type: application/json

{"source": "nginx-edge",
 "events": [{"id": "5f1c...", "ts": 1792954605.0, "key_id": 2, "ip": "198.51.100.23",
             "method": "GET", "path": "/api/customers", "page": "1", "status": 200,
             "bytes": 4000, "key_label": "ana-integration"}]}
```

Respuesta `200`: `{"received": 1, "new": 1}`. `new` cuenta solo lo que no se había visto: reenviar el mismo lote no aprende nada dos veces (se compara por fuente e id). Errores:

- `401`: token ausente o incorrecto (comparación en tiempo constante);
- `413`: más de 1000 eventos o más de 1 MB por petición;
- `422`: un evento inválido rechaza el lote completo (`{"error": "key_id: ...", "index": 1}`); `source` debe usar letras, dígitos, `.`, `_` o `-`, y `victim` está reservado para el adaptador del demo;
- `400`: el cuerpo no es JSON.

**Reenviador de nginx (`forward_nginx.py`, solo biblioteca estándar).** La app indica qué credencial usó cada petición con una cabecera de respuesta (`X-Centinela-Key-Id`, solo el id) que nginx registra y oculta al cliente:

```nginx
log_format centinela escape=json '{"request_id":"$request_id","msec":"$msec",'
  '"remote_addr":"$remote_addr","request_method":"$request_method",'
  '"request_uri":"$request_uri","status":"$status","body_bytes_sent":"$body_bytes_sent",'
  '"key_id":"$upstream_http_x_centinela_key_id","key_label":"$upstream_http_x_centinela_key_label"}';
access_log /var/log/nginx/centinela.json centinela;
proxy_hide_header X-Centinela-Key-Id;
proxy_hide_header X-Centinela-Key-Label;
```

```sh
CENTINELA_INGEST_TOKEN=... python forward_nginx.py --log /var/log/nginx/centinela.json \
  --url https://centinela.example.com --source nginx-edge --state /var/lib/centinela/offset --follow
```

Envía lotes de 500 eventos; omite las líneas sin `key_id` (tráfico anónimo o de sesión). Guarda en `--state` hasta qué byte entregó, así un reinicio continúa ahí; si un envío falla, reintenta desde el último lote entregado. El token se lee del entorno, nunca de la línea de comandos.

Límites actuales: el id de la credencial debe ser entero; las métricas de procesos y el estado de las claves (revocada o activa) siguen viniendo del adaptador de la víctima.

## Cómo aprende

"Aprender" no significa reentrenar el modelo de IA. Son dos piezas separadas:

1. **Línea base (código determinista).** Durante el período de aprendizaje, Centinela registra el comportamiento normal de cada entidad (cada clave de API, usuario o proceso): desde qué IPs se conecta, en qué horario, qué endpoints usa, cuánto volumen mueve, qué procesos corren en cada servidor. Es estadística simple y auditable.
2. **Razonamiento (IA).** Con el comportamiento actual delante, la IA recibe la comparación ("esta clave: IP nunca vista, 3 AM, 40 exportaciones; su historial: oficina, 9-18 h, 2 consultas al día") y decide si las pistas juntas son un ataque. El modelo no se modifica; lo que cambia con el tiempo es la línea base.

**Retroalimentación (no implementada aún):** cuando un humano rechaza una propuesta, ese comportamiento puede incorporarse a la línea base como normal, para no volver a marcarlo.

## Plug and play (deseable, no prioritario)

Objetivo: integrar Centinela en minutos. Versión mínima que sumaría puntos de ejecución como producto:

1. **Ingesta en una línea:** un middleware instalable (`pip install centinela-agent`) que se agrega a la app y envía los metadatos de cada petición.
2. **Ejecutor en un comando:** `docker run centinela/executor` con las credenciales mínimas como variables de entorno.
3. **Modo recomendación por defecto:** arranca sin actuar; el cliente activa el modo automático cuando confía.

Estado: backlog. Solo se hace si sobra tiempo después de A1–A3.

## Qué muestra el demo y qué no

| Pieza | En el demo | En producción |
|---|---|---|
| Ingesta | Registro de accesos de la API víctima, más `POST /api/ingest/access` y el reenviador de nginx | Además, conectores a CloudTrail y SaaS |
| Ejecutor | Servicio en Render con `EXECUTOR_TOKEN` | Contenedor en la infraestructura del cliente |
| Credenciales mínimas | Rol de Postgres y token del ejecutor | Roles IAM y API tokens del cliente |
| Línea base | Historial sembrado de laboratorio y ventana corta | Período de aprendizaje real |
| Retroalimentación | No | Sí |
