Canary es una plataforma web de ciberseguridad pensada para proteger aplicaciones en tres fases continuas: diagnóstico preciso, reparación guiada o automática, y defensa activa en tiempo real. Su diseño resuelve uno de los mayores problemas al usar Inteligencia Artificial en seguridad informática: las respuestas inventadas o falsos positivos.

Para lograrlo, la plataforma funciona mediante una separación clara de responsabilidades entre herramientas de software tradicionales y modelos de lenguaje.

1. Escáner Determinista de Reconocimiento

El proceso inicia cuando el usuario ingresa la URL de su aplicación web. El escáner no utiliza Inteligencia Artificial para inspeccionar el sitio, sino scripts y herramientas de programación tradicionales que realizan peticiones directas a la aplicación.

Este motor extrae datos 100% reales en pocos segundos, identificando:

Las tecnologías, lenguajes, frameworks y servidores web utilizados, junto con sus versiones públicas.

La configuración de seguridad en las cabeceras HTTP y el estado de las cookies de sesión.

La validez y cifrado de los certificados HTTPS.

El cruce automático entre las versiones detectadas y bases de datos públicas de vulnerabilidades conocidas.

Al finalizar, toda esta información se consolida en un reporte de evidencia técnica pura sin ningún tipo de alucinación.

2. Motor de Inteligencia Artificial para Diagnóstico y Remedación

Con el reporte de evidencia cruda listo, la Inteligencia Artificial entra en juego para analizar e interpretar los datos:

Security Score: Calcula una puntuación global de seguridad de 0 a 100, ponderando la gravedad de cada falla encontrada.

Priorización de Riesgos: Organiza los problemas desde los más críticos hasta los de menor impacto para que el equipo de desarrollo sepa qué resolver primero.

Guías Paso a Paso: Explica en lenguaje claro en qué consiste cada vulnerabilidad y entrega instrucciones detalladas adaptadas al lenguaje o framework que usa la aplicación para solucionarla manualmente.

Generación de Parches (Auto-Fix): Redacta bloques de código o archivos de configuración listos para copiar y pegar, como configuraciones de servidor o reglas de encabezados de seguridad, corrigiendo la falla de inmediato.

3. Defensa Activa y Respuesta Automática

Para completar el ciclo, la plataforma enseña e implementa mecanismos de defensa activa adaptados a las tecnologías que el escáner detectó en la primera fase.

A través de un paquete liviano que el usuario integra en su servidor, la plataforma despliega trampas conocidas como honeypots:

Si la aplicación usa WordPress, crea un falso panel de inicio de sesión.

Si usa Node.js o Python, genera rutas falsas de depuración o archivos de configuración expuestos ficticios.

Cuando un atacante o bot intenta explorar una de estas trampas, la plataforma reacciona de forma automática en tiempo real:

Bloqueo Inmediato: Registra la dirección IP del atacante y le deniega el acceso a la aplicación de inmediato o envía una orden de bloqueo al cortafuegos web.

Ralentización de Bots: Puede responder a las peticiones del atacante con pausas intencionadas para consumir sus recursos y frenar escaneos masivos.

Alertas en Vivo: Notifica al administrador en un panel de control mostrando quién intentó atacar, qué técnica usó y la medida defensiva que se aplicó automáticamente para neutralizarlo# Nuestra plataforma — Seguridad inteligente para aplicaciones web

Vamos a desarrollar una *plataforma web de ciberseguridad capaz de analizar una aplicación, identificar sus riesgos, ayudar a solucionarlos y posteriormente implementar mecanismos de defensa adaptados a la tecnología utilizada por la aplicación.*

El proyecto estará dividido en *tres grandes módulos:*

---

## 1. 🔎 Escáner de seguridad

El usuario introduce la URL de una aplicación que tiene autorización para analizar.

La plataforma realiza un reconocimiento de la aplicación y obtiene información como:

* Tecnologías utilizadas.
* Frameworks.
* Servidor web.
* Lenguajes y librerías detectables.
* Versiones expuestas públicamente.
* Headers de seguridad.
* Configuración de cookies.
* TLS/HTTPS.
* Información expuesta.
* Recursos y configuraciones potencialmente inseguras.
* Vulnerabilidades y malas prácticas detectables.

El objetivo no es solamente decir “esta página tiene una vulnerabilidad”, sino construir un *perfil de seguridad de la aplicación*.

Por ejemplo:

> *Tecnologías detectadas*
>
> React — versión detectada
> Node.js — versión detectada
> Express — versión detectada
> Nginx — versión detectada

Y posteriormente:

> ⚠️ Express desactualizado
> ⚠️ Falta de determinados headers de seguridad
> ⚠️ Cookie de sesión con configuración insegura
> ⚠️ Configuración CORS potencialmente permisiva

Cada hallazgo tendrá una severidad:

*CRITICAL / HIGH / MEDIUM / LOW / INFO*

---

# 2. 🤖 AI Security Advisor + Auto Fix

Una vez terminado el escaneo, la IA recibe los resultados estructurados y genera un análisis general de seguridad.

La plataforma mostrará un:

## Security Score

Por ejemplo:

> *Security Score: 63/100*
>
> 🔴 2 problemas críticos
> 🟠 3 problemas altos
> 🟡 4 problemas medios
> 🟢 6 recomendaciones

La IA explicará:

* Qué significa cada problema.
* Por qué representa un riesgo.
* Qué tan importante es solucionarlo.
* Qué podría ocurrir si no se corrige.
* Qué medidas preventivas se recomiendan.

---

### 🛠️ Corrección automática

Para vulnerabilidades que puedan corregirse de forma segura y determinista, el usuario tendrá la opción:

> *✨ Fix with AI*

La IA analizará el código o configuración correspondiente y propondrá un cambio.

El usuario podrá revisar:

*Código actual → Código corregido*

y decidir si quiere aplicarlo.

Después de aplicar el cambio, el sistema volverá a ejecutar las comprobaciones para verificar que el problema haya desaparecido.

---

### 📚 Corrección manual asistida

Si el usuario no quiere utilizar Auto Fix, podrá seleccionar:

> *How do I fix this?*

La IA le mostrará una guía específica para su aplicación.

Por ejemplo:

> *Problema:* Cookie de sesión sin una configuración de seguridad adecuada.
>
> *Ubicación:* server/auth/session.js
>
> *Paso 1:* Abre el archivo...
>
> *Paso 2:* Busca la configuración de la cookie...
>
> *Paso 3:* Modifica la configuración...
>
> *Paso 4:* Reinicia la aplicación...
>
> *Paso 5:* Ejecuta nuevamente el Security Scan.

La explicación estará adaptada a la tecnología detectada.

No sería simplemente una guía genérica de seguridad.

---

# 3. 🪤 AI Active Defense

Esta será la parte más experimental y diferenciadora del proyecto.

Después de analizar la aplicación, la plataforma podrá recomendar mecanismos de defensa adecuados para *la tecnología específica que utiliza la aplicación*.

Por ejemplo:

> *Tecnología detectada:* Node.js + Express
>
> *Defensas recomendadas:*
>
> • Rate limiting
> • Honeypot de formularios
> • Endpoints señuelo
> • Detección de comportamiento anormal
> • Registro de eventos sospechosos

Si la aplicación utiliza otra tecnología, las recomendaciones pueden cambiar.

La IA analizará el stack tecnológico y propondrá *qué tipo de deception/honeypot tiene sentido implementar y dónde colocarlo.*

---

## 🪤 Honeypots adaptados a la aplicación

La plataforma podrá generar una propuesta de defensa.

Por ejemplo:

> *Honeypot recomendado*
>
> Tipo: Endpoint señuelo
> Tecnología: Express.js
>
> Ubicación recomendada: rutas de la API
> Objetivo: detectar enumeración automatizada de endpoints.
>
> Acción al activarse:
>
> * Registrar evento.
> * Aumentar Risk Score.
> * Monitorizar la sesión.
> * Aplicar rate limiting si continúa el comportamiento sospechoso.

La plataforma también explicará *cómo implementarlo manualmente* o podrá generar el código necesario cuando sea seguro hacerlo.

---

# 🧠 Sistema de Risk Score

Las trampas no significarán automáticamente:

> "Honeypot activado = atacante."

En su lugar, cada evento será una señal.

Por ejemplo:

*Honeypot activado:* +30
*Número anormal de solicitudes:* +20
*Acceso repetido a recursos señuelo:* +25
*Patrón automatizado:* +20

El sistema calcula:

> *Risk Score: 95/100 — CRITICAL*

Entonces puede recomendar o ejecutar una respuesta configurada:

*LOW → Registrar*

*MEDIUM → Monitorizar*

*HIGH → Limitar*

*CRITICAL → Bloquear sesión*

La IA explicará por qué el comportamiento fue considerado sospechoso.

---

# 🔄 El ciclo completo

Nuestro proyecto tendrá un flujo completo:

*SCAN*

↓

*DETECT*

↓

*SECURITY SCORE*

↓

*AI ANALYSIS*

↓

*PREVENTION*

↓

*AUTO FIX / MANUAL FIX*

↓

*VERIFY*

↓

*ACTIVE DEFENSE*

↓

*MONITOR*

↓

*DETECT SUSPICIOUS BEHAVIOR*

↓

*RESPOND*

---

# 🎯 ¿Qué queremos demostrar?

No queremos construir simplemente un scanner de vulnerabilidades.

Queremos demostrar que una aplicación puede pasar por un *ciclo de seguridad asistido por IA*:

> *1. Descubrimos qué tecnología utiliza.*
>
> *2. Identificamos sus problemas de seguridad.*
>
> *3. Calculamos su nivel de seguridad.*
>
> *4. La IA explica los problemas y propone prevenciones.*
>
> *5. El usuario puede corregirlos manualmente con una guía paso a paso o utilizar Auto Fix.*
>
> *6. Volvemos a analizar la aplicación para comprobar las mejoras.*
>
> *7. Finalmente implementamos una capa de defensa adaptada a su tecnología.*
>
> *8. La plataforma monitoriza el comportamiento y detecta posibles abusos.*

El objetivo es que la aplicación no solamente sea *analizada*, sino que pueda pasar de:

> 🔴 *Vulnerable*

a

> 🟢 *Corregida + protegida*

utilizando una única plataforma.

