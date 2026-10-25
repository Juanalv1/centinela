# Guion del demo (3 minutos)

Caso: credencial robada, patrón Snowflake 2024. Una sola historia, un solo ataque en vivo y un cierre de seguridad.

## Antes de subir

- [ ] Ambos servicios despiertos: `/health` en la víctima y en Centinela.
- [ ] Sin deploys a `main` desde 30 min antes (un deploy reinicia los servicios).
- [ ] `/dashboard` abierto en el proyector con sesión de administrador, en la sección **Credenciales**.
- [ ] Laptop del atacante conectada al **hotspot de un teléfono** (IP que la clave de ana nunca usó), con `ANA_KEY` cargada y este comando listo:
  `python lab/attack/stolen_key_attack.py --victim https://centinela-victim.onrender.com --pages 30 --delay 4`
- [ ] Ensayo completo hecho en la nube el mismo día, con tiempo de detección anotado.

## Guion

| Tiempo | Quién | Pantalla | Qué se dice |
|---|---|---|---|
| 0:00–0:30 | Presentador | Título: Snowflake 2024 | "En 2024 robaron datos de más de 100 millones de personas de unas 165 empresas. No hubo exploit: usaron contraseñas válidas robadas años antes. Ninguna regla saltó, porque el login era correcto." |
| 0:30–0:50 | Presentador | Credenciales: clave de ana | "Centinela aprende cómo se usa cada credencial. Esta es la clave de Ana: entra de lunes a viernes, en horario de oficina, desde la oficina, y consulta sus facturas." |
| 0:50–1:00 | Atacante | Panel | "Ahora yo soy el atacante. Tengo la clave de Ana, que es válida." Ejecuta `lab/attack/stolen_key_attack.py`: en su consola se ve cada petición respondida con 200. |
| 1:00–1:40 | Presentador | Credenciales: ana pasa a sospechosa | Mientras espera: "No hay errores ni logins fallidos, y va por debajo del rate limit. Una regla no ve nada." Cuando aparece, lee la justificación de la IA: IP nunca vista, fuera de horario, endpoint nuevo, volumen muy superior a lo normal. |
| 1:40–2:00 | Presentador | Panel: clave revocada | "La clave quedó revocada en N segundos, sin esperar a un humano." En la consola del atacante, las peticiones pasan a 401/403 y el comando se detiene solo. |
| 2:00–2:40 | Presentador | Botón "IA comprometida" | "¿Y si alguien engaña a la IA? La IA no tiene permisos: solo propone desde un menú cerrado." Pulsa el botón: la propuesta indebida se rechaza y el panel muestra en qué capa. |
| 2:40–3:00 | Presentador | Resultados | "En la nube, 5 de 5 claves robadas revocadas y 0 de 5 falsos positivos con una clave legítima. La IA detecta y propone; nunca tiene permisos para actuar." |

## Plan B

- Si la detección tarda más de 60 s: seguir hablando del caso real y mostrar el panel cuando llegue. No relanzar el ataque (mezcla ventanas).
- Si un servicio no responde: video grabado del ensayo en la nube.

## Pendiente para que este guion funcione

- Medir de nuevo el tiempo de detección después de `fe25d15` (Christian). Si no baja de ~38 s, el tramo 1:00–1:40 se alarga.
- Ensayo en la nube con `lab/attack/stolen_key_attack.py` y la sección Credenciales en el proyector: confirmar que se lee desde el fondo de la sala.
- Confirmar el número final de la diapositiva de resultados (hoy: A3 5/5 y 0/5).
