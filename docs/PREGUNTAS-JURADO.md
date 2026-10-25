# Preguntas probables del jurado

Respuestas cortas. Solo afirmar lo marcado como verificado; lo pendiente se dice como pendiente.

## Producto

**¿Qué es Centinela?**
Una IA que vigila tus sistemas, detecta ataques por comportamiento y los contiene sola, sin tener permisos para actuar: propone, y un ejecutor determinista con permisos mínimos decide.

**¿Qué problema resuelve?**
Las empresas sin equipo de seguridad tardan horas en responder a un ataque, y darle permisos a una IA para que responda sola es riesgoso (Replit, 2025: su agente borró una base de datos de producción).

**¿Por qué IA y no reglas?**
Las reglas solo detectan lo previsto. En Snowflake (2024) los logins eran válidos y ninguna regla saltó. Centinela compara cada credencial con su propio historial y conecta pistas débiles: IP nueva, horario raro, consultas que nunca hizo.

**¿En qué se diferencia de otras herramientas?**
- Las reglas no razonan.
- Los agentes de IA con permisos pueden ser engañados y hacer daño real.
- Las herramientas enterprise suponen un equipo humano que atienda las alertas.
- Centinela razona y responde sola, pero el peor caso está acotado por diseño.

**¿Qué es lo original?**
El principio de mínimo privilegio para agentes ya se recomienda en la industria. Nuestro aporte es aplicarlo de punta a punta: detección por comportamiento, ejecución separada, permisos que lo hacen cumplir (kernel y base de datos) y una medición de qué capa frena cada intento.

## Alcance

**¿Qué tipo de ataques detectan?**
Ataques que usan accesos válidos para no ser detectados. Probamos tres, con sus técnicas en MITRE ATT&CK y ATLAS:

| Tipo | Caso real | Estado |
|---|---|---|
| Credencial robada usada para extraer datos (T1078 Valid Accounts) | Snowflake 2024 | Verificado: 5/5 detectados, 0/5 falsos positivos, ~13 s |
| Abuso de recursos o minero oculto (T1496 Resource Hijacking) | Tesla 2018 | Verificado: 5/5 detectados, 0/5 falsos positivos, ~30 s |
| Manipulación de la propia IA (ATLAS AML.T0051 Prompt Injection) | Replit 2025 | Verificado: el ejecutor rechaza la acción |

**¿Y lo que no cubren?**
No reemplazamos al antivirus ni al firewall. Somos la capa que actúa cuando el atacante ya pasó por ellos, que es donde hoy las empresas tardan meses en darse cuenta. No cubrimos cada forma de entrar, sino lo que el atacante hace después:

| Entrada | Quién protege la entrada | Lo que hace después el atacante |
|---|---|---|
| Phishing | MFA, filtros de correo | Usa la credencial robada: detectado (A3) |
| Explotación de vulnerabilidades | Parches, WAF | Lanza un proceso nuevo o un backdoor: *pendiente de prueba (T4)* |
| Ransomware | Backups, EDR | Escribe en disco de forma masiva: la señal de I/O existe, *sin probar* |
| DDoS | CDN, rate limiting | Fuera de alcance: no es una intrusión |

**¿Detectan backdoors?**
*No verificado.* Ya recibimos las señales de un backdoor de tipo reverse shell: un proceso nuevo, lanzado por el servicio web, con una conexión saliente persistente. Pero la IA hoy pondera sobre todo el uso de CPU, y un backdoor casi no consume CPU. No afirmar hasta que T4 pase (5/5 detectados, 0/5 falsos positivos). Tampoco cubrimos aún la persistencia que crea claves o usuarios nuevos.

## Impacto

**¿Qué impacto tiene?**

| Tipo | Dato | Fuente |
|---|---|---|
| Credencial robada | Primera vía de entrada: 22 % de las brechas | Verizon DBIR 2025 |
| Credencial robada | Costo promedio de una brecha: USD 4,44 M | IBM Cost of a Data Breach 2025 |
| Credencial robada | USD 4,67 M y ~292 días hasta detectarla y contenerla | IBM 2025 citado por SpyCloud; *confirmar en el informe original antes de usarlo* |
| Minero oculto | La víctima paga ~USD 53 en nube por cada USD 1 minado | Sysdig 2022, una sola campaña (estimación) |

Frase: el robo de credenciales es la entrada número uno y tarda meses en detectarse; Centinela lo detecta y lo contiene en ~13 s.

Fuentes: [Verizon DBIR 2025](https://www.verizon.com/business/resources/articles/credential-stuffing-attacks-2025-dbir-research/), [IBM 2025 (Infosecurity)](https://www.infosecurity-magazine.com/news/data-breach-costs-fall/), [IBM 2025 (SpyCloud)](https://spycloud.com/blog/6-takeaways-from-ibm-data-breach-report-2025/), [Sysdig (BleepingComputer)](https://www.bleepingcomputer.com/news/security/cryptominers-hijack-53-worth-of-system-resources-to-earn-1).

## Seguridad de la propia IA

**¿Qué pasa si engañan a la IA con prompt injection?**
Lo peor que logran es una propuesta indebida. El ejecutor la rechaza en tres capas independientes de la IA: menú cerrado, política de recursos protegidos y permisos de la base de datos o el sistema operativo. Se demuestra en vivo con el modo "IA comprometida". *(Verificado.)*

**¿La IA puede filtrar datos?**
No tiene datos que filtrar: recibe solo metadatos resumidos (IP, horario, endpoint, volumen), nunca registros de clientes ni valores de claves. Tampoco tiene herramientas de salida: su única salida es una propuesta del menú.

**Si el agente no ejecuta, ¿cómo frena el ataque?**
El ejecutor ejecuta solo las acciones reversibles (por ejemplo, revocar una clave) en segundos, sin esperar a un humano. Lo grave (suspender un usuario) requiere aprobación.

**¿Necesita acceso a la base de datos?**
No a los datos de clientes. Lee registros de acceso y actúa con credenciales de un solo permiso (por ejemplo, cambiar el estado de una clave).

## Integración

**¿Cómo lo instala una empresa?**
Conecta sus registros (solo lectura), instala el ejecutor como contenedor en su infraestructura, le da credenciales mínimas y lo pone a aprender. Las credenciales nunca salen de su infraestructura. Detalle: `docs/INTEGRACION.md`.

**¿De dónde salen los registros?**
De lo que el sistema ya genera: proxy o balanceador, auditoría de la nube (CloudTrail), auditoría de SaaS o un middleware en la app. En el demo, un middleware en la API víctima.

**¿Cómo aprende?**
No se reentrena el modelo. Código determinista construye una línea base del comportamiento normal de cada clave, usuario o proceso; la IA compara el comportamiento actual con esa línea base y decide. Lo aprendido es auditable.

**¿Cómo se adopta sin miedo?**
De forma gradual: período de aprendizaje, luego solo recomendaciones, luego modo automático para las acciones reversibles que el cliente elija.

## Números

**¿Qué tan rápido responde?**
- Credencial robada: detectada y revocada en ~13 s en la nube, después de la corrección `fe25d15` (antes 9-38 s). *(Verificado, A3 y nueva medición.)*
- Minero oculto: detectado en 28-30 s. *(Verificado, T3.)*
- Proceso con señales obvias: contención en 5-7 s. *(Verificado.)*

**¿Detecta ataques sofisticados?**
Sí, en nuestras pruebas en la nube, sin señales obvias. Son 5 corridas de cada caso:
- Credencial robada (patrón Snowflake): 5/5 revocadas y 0/5 falsos positivos con la clave legítima.
- Minero sin nombre sospechoso: 5/5 detectados y 0/5 falsos positivos con un backup legítimo de alto uso de CPU.
- Antes de agregar la telemetría de comportamiento, la detección sin señales obvias daba 0/9.

Ver `odd/tasks/behavioral-signals.md` y `docs/evals/process-detection-baseline.md`. No decir "100 %": son 5 corridas por caso.

**¿Cuánto cuesta?**
*No medido.* No dar cifras. Si preguntan: la infraestructura son servicios pequeños y el costo principal son las llamadas al modelo, que se pueden reducir con la línea base como filtro.

## Demo vs. producción

**¿Qué es real y qué es simulado?**
Real: la IA, el ejecutor, los permisos mínimos, la bitácora y los ataques del público en un entorno controlado. Laboratorio: el historial de uso sembrado para la línea base. No construido: conectores a CloudTrail o Snowflake, ejecutor como contenedor del cliente y retroalimentación.
