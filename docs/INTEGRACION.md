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

## Cómo aprende

"Aprender" no significa reentrenar el modelo de IA. Son dos piezas separadas:

1. **Línea base (código determinista).** Durante el período de aprendizaje, Centinela registra el comportamiento normal de cada entidad (cada clave de API, usuario o proceso): desde qué IPs se conecta, en qué horario, qué endpoints usa, cuánto volumen mueve, qué procesos corren en cada servidor. Es estadística simple y auditable.
2. **Razonamiento (IA).** Con el comportamiento actual delante, la IA recibe la comparación ("esta clave: IP nunca vista, 3 AM, 40 exportaciones; su historial: oficina, 9-18 h, 2 consultas al día") y decide si las pistas juntas son un ataque. El modelo no se modifica; lo que cambia con el tiempo es la línea base.

**Retroalimentación (no implementada aún):** cuando un humano rechaza una propuesta, ese comportamiento puede incorporarse a la línea base como normal, para no volver a marcarlo.

## Qué muestra el demo y qué no

| Pieza | En el demo | En producción |
|---|---|---|
| Ingesta | Middleware en la API víctima | Conectores a proxy, CloudTrail y SaaS |
| Ejecutor | Servicio en Render con `EXECUTOR_TOKEN` | Contenedor en la infraestructura del cliente |
| Credenciales mínimas | Rol de Postgres y token del ejecutor | Roles IAM y API tokens del cliente |
| Línea base | Historial sembrado de laboratorio y ventana corta | Período de aprendizaje real |
| Retroalimentación | No | Sí |
