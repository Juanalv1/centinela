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
Contención en 5-7 s medida en la nube para el caso de procesos. *(Verificado.)* Para el caso de credenciales: *pendiente de la prueba A3.*

**¿Detecta ataques sofisticados?**
*Pendiente.* Medición base: sin señales obvias, la versión anterior no contenía nada (0/9) y no tuvo falsos positivos (0/27). La telemetría de comportamiento está en curso; solo se afirma si A3 pasa (5/5 detectados, 0 falsos positivos). Ver `docs/evals/process-detection-baseline.md`.

**¿Cuánto cuesta?**
*No medido.* No dar cifras. Si preguntan: la infraestructura son servicios pequeños y el costo principal son las llamadas al modelo, que se pueden reducir con la línea base como filtro.

## Demo vs. producción

**¿Qué es real y qué es simulado?**
Real: la IA, el ejecutor, los permisos mínimos, la bitácora y los ataques del público en un entorno controlado. Laboratorio: el historial de uso sembrado para la línea base. No construido: conectores a CloudTrail o Snowflake, ejecutor como contenedor del cliente y retroalimentación.
