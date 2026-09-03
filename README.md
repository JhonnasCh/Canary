# 🛡️ Canary Sentinel - CyberShield AI

Plataforma de ciberseguridad defensiva que combina **análisis estático de código (SAST)**, un **asistente de Inteligencia Artificial para auto-parchado y explicaciones pedagógicas**, y un **Guardián de Protección 24/7 (RASP/WAF)** con monitoreo de integridad de archivos (FIM) para proteger aplicaciones web y los datos de sus clientes.

---

## 🚀 Características Principales

1. **Auditor de Código SAST (Static Application Security Testing)**:
   - Detección precisa de vulnerabilidades críticas basadas en **OWASP Top 10 y CWE**:
     - Inyecciones SQL (SQLi)
     - Cross-Site Scripting basado en DOM (DOM-XSS)
     - Salto de Directorio Arbitrario (Path Traversal / LFI)
     - Inyección de Comandos del Sistema Operativo (RCE)
     - Secretos, API Keys y Tokens Hardcodeados
     - Contraseñas almacenadas en texto plano sin hash
     - Configuraciones inseguras de CORS y uso peligroso de `eval()`
   - Cálculo automático de **Puntaje de Salud de Seguridad (Health Score 0-100)** y resumen de severidad.

2. **Explorador y Auditor de Repositorios Git (GitHub Connect)**:
   - Conexión a repositorios **públicos o privados** usando URLs o identificadores (`usuario/repositorio`).
   - Gestión de **permisos seguros**: tokens de solo lectura (`contents:read` o `repo:read`) procesados en memoria sin guardarse.
   - **Explorador de Árbol de Archivos**: visualiza todas las carpetas del repositorio, con filtros por extensión y tamaño.
   - **Auditoría Individual o Global**: permite abrir cualquier archivo en el editor para auditarlo o ejecutar un **escaneo masivo de todo el repositorio** con Reporte Ejecutivo consolidado.

3. **Motor de Inteligencia Artificial con 3 Modos de Operación**:
   - **Explicación Pedagógica**: Diagnóstico profundo sobre por qué ocurre la vulnerabilidad, cómo opera el vector de ataque y cuál es su impacto real.
   - **Auto-Parchador Seguro con Diff Interactivo**: Genera el parche seguro y muestra los cambios visuales en formato Diff antes/después con opción de aplicarlo al código en 1 solo clic.
   - **Protocolo de Honestidad y Transparencia**: Si un hallazgo involucra secretos comprometidos o cambios de infraestructura que la IA no debe asumir a ciegas (para no romper sesiones ni provocar falsa sensación de seguridad), la IA explica con total honestidad por qué no puede aplicar un parche ciego y proporciona la guía paso a paso de remediación manual.

4. **Guardián de Protección 24/7 en Tiempo Real**:
   - Inspección continua de tráfico web y bloqueo automático con **HTTP 403 Forbidden**.
   - **File Integrity Monitoring (FIM)**: Supervisión criptográfica con hash SHA-256 de archivos críticos del proyecto para alertar de inyecciones o alteraciones.
   - **Feed en vivo (Server-Sent Events - SSE)** con transmisión de incidentes al Centro de Operaciones (SOC).
   - **Simulador de Ciberataques Integrado**: Permite disparar sondas seguras (SQLi, XSS, Traversal, RCE, Bots) para observar cómo el Guardián las neutraliza al instante.

4. **Integración Fácil con la Web del Cliente**:
   - Incluye el SDK/Middleware `src/guardian-agent/sentinel-agent.js` para conectar cualquier aplicación Express / Node.js con solo 2 líneas de código.

5. **Adaptador Universal de IA**:
   - Funciona de inmediato sin costos ni llaves gracias a su **Motor Semántico Local**.
   - Listo para conectar tu propia **API Key** (OpenAI GPT-4o, Google Gemini 1.5, o Endpoint Personalizado) en el panel de configuración cuando lo desees.

---

## 📦 Instalación y Ejecución

```bash
# 1. Instalar dependencias
npm install

# 2. Ejecutar suite de pruebas automatizadas
npm test

# 3. Iniciar el servidor
npm start
```

Abre en tu navegador:
👉 **`http://localhost:3000`**

---

## 🔌 Cómo Proteger la Web de tus Clientes 24/7

Para conectar la página web de un cliente a Canary Sentinel, añade el middleware en su servidor web:

```javascript
const express = require('express');
const { canaryGuardian } = require('./src/guardian-agent/sentinel-agent');

const app = express();

// Activar el Guardián 24/7
app.use(canaryGuardian({
  hubUrl: 'http://localhost:3000', // URL de tu servidor Canary Sentinel
  blockMode: true                  // Bloquea ataques hostiles con HTTP 403
}));
```

---

## 🧠 Configurar tu API de IA (Cuando la tengas)

Puedes configurar tu API de IA de dos formas:
1. Desde la interfaz gráfica en la pestaña **"Conectar Mi Web & Ajustes"**.
2. O en tu archivo `.env`:
   ```env
   AI_PROVIDER=gemini
   AI_API_KEY=tu_clave_aqui
   AI_MODEL_NAME=gemini-1.5-pro
   ```
