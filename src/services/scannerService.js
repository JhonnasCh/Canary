const crypto = require('crypto');

/**
 * Reglas de análisis estático (SAST) para detección de vulnerabilidades
 */
const SECURITY_RULES = [
  {
    id: 'SQL_INJECTION',
    cwe: 'CWE-89',
    owasp: 'A03:2021 - Injection',
    title: 'Inyección SQL Crítica por Concatenación de Parámetros',
    severity: 'CRITICAL',
    category: 'Inyección de Datos',
    canAutoPatch: true,
    patterns: [
      /db\.query\s*\(\s*["'`].*SELECT.*FROM.*["'`]\s*\+/i,
      /db\.query\s*\(\s*`.*SELECT.*FROM.*\$\{.*\}/i,
      /query\s*\(\s*["'`].*INSERT\s+INTO.*["'`]\s*\+/i,
      /query\s*\(\s*`.*INSERT\s+INTO.*\$\{.*\}/i,
      /["'`]\s*SELECT\s+.*FROM\s+.*WHERE\s+.*=\s*['"]?\s*\+/i,
      /["'`]\s*SELECT\s+.*FROM\s+.*["'`]\s*\+\s*[a-zA-Z0-9_\.]+/i,
      /["'`]\s*UPDATE\s+.*SET\s+.*=\s*['"]?\s*\+/i,
      /["'`]\s*DELETE\s+FROM\s+.*WHERE\s+.*=\s*['"]?\s*\+/i,
      /query\s*\(\s*["'`].*WHERE\s+.*=\s*['"]?\s*\+/i,
      /query\s*\(\s*`.*WHERE\s+.*=\s*['"]?\$\{.*\}/i,
      /sqlite3.*run\s*\(\s*`.*WHERE.*\$\{/i
    ],
    description: 'Se detectó la construcción dinámica de sentencias SQL mediante concatenación directa o interpolación de variables no sanitizadas. Un atacante puede alterar la lógica de la consulta e ingresar comandos maliciosos.',
    impact: 'Extracción completa de la base de datos, omisión de mecanismos de login y borrado arbitrario de datos.',
    recommendation: 'Reemplazar la concatenación por consultas parametrizadas (Prepared Statements / Parameterized Queries).',
    suggestedFixType: 'parameterize_sql'
  },
  {
    id: 'HARDCODED_SECRET',
    cwe: 'CWE-798',
    owasp: 'A07:2021 - Identification and Authentication Failures',
    title: 'Clave Secreta o Token Hardcodeado en Código Fuente',
    severity: 'HIGH',
    category: 'Criptografía y Secretos',
    canAutoPatch: false, // Disparador para el protocolo de honestidad de la IA
    patterns: [
      /(?:jwt_secret|jwtSecret|JWT_SECRET|secretKey|SECRET_KEY)\s*[:=]\s*['"][a-zA-Z0-9_\-@#$%^&*!]{4,}['"]/i,
      /(?:aws_secret_access_key|AWS_SECRET|api_key|apiKey|API_KEY)\s*[:=]\s*['"][a-zA-Z0-9_\-]{8,}['"]/i,
      /['"]AKIA[0-9A-Z]{16}['"]/i,
      /password\s*[:=]\s*['"][^'"]{3,}['"]/i
    ],
    description: 'Se encontraron credenciales, secretos criptográficos o claves de acceso sensibles escritas directamente en texto plano dentro del código fuente.',
    impact: 'Cualquier persona o atacante con acceso de lectura al repositorio puede falsificar tokens JWT, descifrar datos privados o acceder a servicios en la nube a nombre de la empresa.',
    recommendation: 'Extraer los secretos hacia variables de entorno seguras (ej. archivo .env protegido o gestor de secretos como AWS Secrets Manager o HashiCorp Vault) y rotar inmediatamente la clave expuesta.',
    suggestedFixType: 'extract_env_manual_rotation'
  },
  {
    id: 'DOM_XSS',
    cwe: 'CWE-79',
    owasp: 'A03:2021 - Injection',
    title: 'Cross-Site Scripting basado en DOM (DOM-XSS)',
    severity: 'HIGH',
    category: 'Seguridad del Cliente (XSS)',
    canAutoPatch: true,
    patterns: [
      /\.innerHTML\s*=\s*(?:location|document\.location|window\.location|params|userInput|req\.|data\.|[a-zA-Z0-9_]+Input)/i,
      /\.innerHTML\s*=\s*.*['"`]\s*\+/i,
      /\.innerHTML\s*=\s*`.*\$\{/i,
      /document\.write\s*\(/i,
      /\$\([^)]+\)\.html\s*\(\s*(?:userInput|params|data|[a-zA-Z0-9_]+Input)/i,
      /dangerouslySetInnerHTML\s*=\s*\{\s*__html\s*:\s*(?:userInput|props\.|state\.)/i
    ],
    description: 'Inserción directa de datos proporcionados por el usuario en el DOM mediante innerHTML o document.write sin sanitización ni codificación HTML previa.',
    impact: 'Robo de tokens de sesión (Cookies / LocalStorage), secuestro de cuentas de usuario, redirecciones a sitios de phishing y desfiguración web.',
    recommendation: 'Utilizar textContent o innerText en lugar de innerHTML, o aplicar bibliotecas de sanitización confiables como DOMPurify.',
    suggestedFixType: 'sanitize_dom'
  },
  {
    id: 'COMMAND_INJECTION',
    cwe: 'CWE-78',
    owasp: 'A03:2021 - Injection',
    title: 'Inyección de Comandos del Sistema Operativo',
    severity: 'CRITICAL',
    category: 'Inyección de Datos',
    canAutoPatch: true,
    patterns: [
      /(?:child_process\.)?exec\s*\(\s*`.*\$\{/i,
      /(?:child_process\.)?exec\s*\(\s*["'`].*["'`]\s*\+/i,
      /(?:child_process\.)?execSync\s*\(\s*`.*\$\{/i,
      /(?:child_process\.)?execSync\s*\(\s*["'`].*["'`]\s*\+/i
    ],
    description: 'Ejecución de llamadas a la shell del sistema operativo concatenando entradas de usuario sin verificación estricta ni escapado.',
    impact: 'Ejecución remota de código (RCE), compromiso total del servidor anfitrión e instalación de malware o backdoors.',
    recommendation: 'Usar child_process.execFile o child_process.spawn pasando los argumentos como un arreglo en lugar de invocar una shell directa.',
    suggestedFixType: 'spawn_safely'
  },
  {
    id: 'PATH_TRAVERSAL',
    cwe: 'CWE-22',
    owasp: 'A01:2021 - Broken Access Control',
    title: 'Salto de Directorio Arbitrario (Path Traversal / LFI)',
    severity: 'HIGH',
    category: 'Control de Acceso y Archivos',
    canAutoPatch: true,
    patterns: [
      /path\.join\([^)]*req\.(?:query|params|body)/i,
      /path\.resolve\([^)]*req\.(?:query|params|body)/i,
      /fs\.readFile(?:Sync)?\s*\(\s*(?:path\.join\([^)]*req\.|req\.query|req\.params|req\.body|filename)/i,
      /fs\.createReadStream\s*\(\s*(?:path\.join\([^)]*req\.|req\.query|req\.params|req\.body)/i,
      /res\.sendFile\s*\(\s*(?:path\.join\([^)]*req\.|req\.query|req\.params|req\.body)/i
    ],
    description: 'Acceso al sistema de archivos local utilizando nombres de archivo controlados por el usuario sin validar si contienen secuencias de escape como "../".',
    impact: 'Lectura de archivos sensibles del sistema (ej. /etc/passwd, configuraciones de bases de datos, claves SSH privadas y código fuente).',
    recommendation: 'Sanitizar nombres de archivo mediante path.basename() y verificar que la ruta absoluta resuelta pertenezca al directorio permitido (con startsWith).',
    suggestedFixType: 'sanitize_path'
  },
  {
    id: 'UNHASHED_PASSWORD',
    cwe: 'CWE-256',
    owasp: 'A02:2021 - Cryptographic Failures',
    title: 'Almacenamiento o Comparación de Contraseñas en Texto Plano',
    severity: 'HIGH',
    category: 'Autenticación y Criptografía',
    canAutoPatch: true,
    patterns: [
      /user\.password\s*===?\s*(?:req\.body\.password|password)/i,
      /storedUser\.pass\s*===?\s*(?:req\.body\.pass|pass)/i,
      /crypto\.createHash\s*\(\s*['"]md5['"]\s*\)/i,
      /crypto\.createHash\s*\(\s*['"]sha1['"]\s*\)/i
    ],
    description: 'Se detectó comparación directa de contraseñas en texto plano o el uso de algoritmos obsoletos y vulnerables (MD5 / SHA-1) para almacenar credenciales.',
    impact: 'Exposición inmediata de contraseñas en caso de fuga de datos o accesos no autorizados a la base de datos.',
    recommendation: 'Implementar algoritmos de derivación de claves diseñados para contraseñas como bcrypt, argon2 o scrypt con factor de costo adecuado.',
    suggestedFixType: 'bcrypt_auth'
  },
  {
    id: 'INSECURE_CORS',
    cwe: 'CWE-942',
    owasp: 'A05:2021 - Security Misconfiguration',
    title: 'Configuración Insegura de CORS (Permiso Global con Credenciales)',
    severity: 'MEDIUM',
    category: 'Configuración de Seguridad',
    canAutoPatch: true,
    patterns: [
      /Access-Control-Allow-Origin['"],\s*['"]\*['"]/i,
      /cors\s*\(\s*\{\s*origin\s*:\s*['"]\*['"]\s*,\s*credentials\s*:\s*true/i,
      /setHeader\s*\(\s*['"]Access-Control-Allow-Origin['"]\s*,\s*['"]\*['"]\s*\)/i
    ],
    description: 'La política de CORS permite solicitudes desde cualquier origen de internet (*) mientras que la aplicación maneja sesiones o credenciales autenticadas.',
    impact: 'Sitios web externos maliciosos pueden enviar peticiones en nombre de usuarios autenticados y robar respuestas privadas mediante CSRF cruzado.',
    recommendation: 'Especificar dominios de origen autorizados explícitos mediante una lista blanca (whitelist) en lugar del comodín (*).',
    suggestedFixType: 'restrict_cors'
  },
  {
    id: 'DANGEROUS_EVAL',
    cwe: 'CWE-95',
    owasp: 'A03:2021 - Injection',
    title: 'Uso Inseguro de eval() o Compilación Dinámica de Código',
    severity: 'CRITICAL',
    category: 'Inyección de Datos',
    canAutoPatch: false, // Requiere reestructuración lógica del programa
    patterns: [
      /\beval\s*\(\s*[^)]+\)/i,
      /new\s+Function\s*\(\s*[^)]+\)/i,
      /setTimeout\s*\(\s*['"`][^'"`]+['"`]\s*,/i
    ],
    description: 'Ejecución de cadenas de texto como código JavaScript activo. Si cualquier fragmento de la cadena proviene de una fuente externa, permite ejecución arbitraria.',
    impact: 'Ejecución remota de código en el entorno de ejecución, control total de la sesión o del proceso del servidor.',
    recommendation: 'Eliminar el uso de eval(). Usar deserializadores estructurados como JSON.parse() o refactorizar la lógica con mapeos de funciones.',
    suggestedFixType: 'refactor_eval_manual'
  }
];

/**
 * Analiza un bloque de código o archivo y retorna las vulnerabilidades encontradas
 */
function analyzeCode(code, filename = 'app.js') {
  if (!code || typeof code !== 'string') {
    return {
      vulnerabilities: [],
      stats: { total: 0, critical: 0, high: 0, medium: 0, low: 0, healthScore: 100 },
      scannedAt: new Date().toISOString()
    };
  }

  const lines = code.split(/\r?\n/);
  const detected = [];
  const seenVulnerabilities = new Set();

  lines.forEach((line, index) => {
    const lineNumber = index + 1;

    for (const rule of SECURITY_RULES) {
      for (const pattern of rule.patterns) {
        if (pattern.test(line)) {
          const vulnKey = `${rule.id}-${lineNumber}`;
          if (!seenVulnerabilities.has(vulnKey)) {
            seenVulnerabilities.add(vulnKey);

            // Extraer fragmento de contexto (2 líneas antes y 2 después)
            const startLine = Math.max(0, index - 2);
            const endLine = Math.min(lines.length - 1, index + 2);
            const contextSnippet = lines.slice(startLine, endLine + 1).map((l, idx) => {
              const num = startLine + idx + 1;
              const isTarget = num === lineNumber;
              return `${num.toString().padStart(4, ' ')} ${isTarget ? '>>>' : '   '} | ${l}`;
            }).join('\n');

            detected.push({
              id: 'vuln_' + crypto.randomBytes(4).toString('hex'),
              ruleId: rule.id,
              cwe: rule.cwe,
              owasp: rule.owasp,
              title: rule.title,
              severity: rule.severity,
              category: rule.category,
              canAutoPatch: rule.canAutoPatch,
              filename: filename,
              line: lineNumber,
              offendingLine: line.trim(),
              codeSnippet: contextSnippet,
              description: rule.description,
              impact: rule.impact,
              recommendation: rule.recommendation,
              suggestedFixType: rule.suggestedFixType
            });
          }
        }
      }
    }
  });

  // Estadísticas y puntuación de salud (Health Score de 0 a 100)
  const stats = {
    total: detected.length,
    critical: detected.filter(v => v.severity === 'CRITICAL').length,
    high: detected.filter(v => v.severity === 'HIGH').length,
    medium: detected.filter(v => v.severity === 'MEDIUM').length,
    low: detected.filter(v => v.severity === 'LOW').length
  };

  // Cálculo de penalización de seguridad
  const penalty = (stats.critical * 35) + (stats.high * 20) + (stats.medium * 10) + (stats.low * 5);
  stats.healthScore = Math.max(0, 100 - penalty);

  return {
    filename,
    linesCount: lines.length,
    vulnerabilities: detected,
    stats,
    scannedAt: new Date().toISOString()
  };
}

module.exports = {
  SECURITY_RULES,
  analyzeCode
};
