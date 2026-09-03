/**
 * CanaryEngine - Vulnerability Classifier & Technical Diagnosis
 * Genera el diagnóstico técnico, impacto, pasos manuales y parches auto-fix
 * priorizados según la escala estándar de ciberseguridad.
 */

const {
  generateHeaderAutoFix,
  generateCookieAutoFix,
  generateSSLAutoFix,
  generateCVEAutoFix
} = require('./autofix');

const SEVERITY_WEIGHT = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1
};

function buildVulnerabilities(evidence, scoringResult, stack) {
  const vulnerabilities = [];

  // 1. CVEs Detectados
  for (const cve of evidence.detected_cves || []) {
    const sev = (cve.severity || 'MEDIUM').toUpperCase();
    const autoFix = generateCVEAutoFix(cve, stack);

    vulnerabilities.push({
      id: `VULN-${cve.cve_id || 'CVE-UNKNOWN'}`,
      title: `Vulnerabilidad conocida ${cve.cve_id} en componente ${cve.component}`,
      severity: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(sev) ? sev : 'HIGH',
      category: 'CVE',
      description: `Se detectó la vulnerabilidad pública ${cve.cve_id} afectando directamente al componente '${cve.component}'.`,
      impact: `Un atacante remoto podría explotar fallos documentados en ${cve.component} para ejecutar código arbitrario, escalar privilegios o causar denegación de servicio.`,
      manual_fix_steps: [
        `Identificar la versión vulnerable actual del componente '${cve.component}'.`,
        `Revisar el boletín de seguridad oficial asociado a ${cve.cve_id} para conocer la versión parcheada recomendada.`,
        `Actualizar la dependencia en el gestor de paquetes correspondiente a una versión no vulnerable.`,
        `Ejecutar pruebas de regresión unitarias e integración para validar que la actualización no rompe funcionalidades existentes.`
      ],
      auto_fix: autoFix
    });
  }

  // 2. Cabeceras Faltantes Clave
  const missingHeaders = scoringResult.missing_key_headers || [];

  if (missingHeaders.includes('Content-Security-Policy')) {
    vulnerabilities.push({
      id: 'VULN-HDR-CSP',
      title: 'Ausencia de cabecera Content-Security-Policy (CSP)',
      severity: 'HIGH',
      category: 'Headers',
      description: 'El servidor web no emite la cabecera Content-Security-Policy en las respuestas HTTP hacia los clientes.',
      impact: 'Permite ataques de Cross-Site Scripting (XSS), inyección de scripts externos maliciosos, robo de tokens de sesión y exfiltración de datos confidenciales.',
      manual_fix_steps: [
        'Definir una política de orígenes de confianza para scripts, estilos, fuentes e imágenes.',
        'Prohibir la ejecución de scripts en línea sin nonce ni hash (deshabilitar unsafe-inline en producción).',
        'Configurar la directiva default-src en self y restringir object-src a none.',
        'Agregar la directiva al archivo de configuración del servidor o middleware de la aplicación.'
      ],
      auto_fix: generateHeaderAutoFix('Content-Security-Policy', stack)
    });
  }

  if (missingHeaders.includes('Strict-Transport-Security')) {
    vulnerabilities.push({
      id: 'VULN-HDR-HSTS',
      title: 'Ausencia de cabecera Strict-Transport-Security (HSTS)',
      severity: 'HIGH',
      category: 'Headers',
      description: 'El servidor no exige conexiones HTTPS forzosas mediante el estándar HSTS.',
      impact: 'Facilita ataques Man-in-the-Middle (MitM), degradación de protocolo (SSL Stripping) e interceptación de tráfico no cifrado en redes no seguras.',
      manual_fix_steps: [
        'Verificar que todo el tráfico HTTP redireccione a HTTPS con código 301.',
        'Establecer la cabecera Strict-Transport-Security con un max-age de al menos 31536000 segundos (1 año).',
        'Incluir las directivas includeSubDomains y preload.',
        'Enviar el dominio al registro HSTS Preload de Google Chromium si aplica.'
      ],
      auto_fix: generateHeaderAutoFix('Strict-Transport-Security', stack)
    });
  }

  if (missingHeaders.includes('X-Frame-Options')) {
    vulnerabilities.push({
      id: 'VULN-HDR-XFO',
      title: 'Ausencia de cabecera X-Frame-Options',
      severity: 'MEDIUM',
      category: 'Headers',
      description: 'El encabezado X-Frame-Options no está configurado, permitiendo que la aplicación se cargue dentro de elementos <iframe> o <frame>.',
      impact: 'Permite ataques de UI Redressing (Clickjacking), donde un usuario es engañado para interactuar con botones ocultos en capas transparentes superpuestas.',
      manual_fix_steps: [
        'Evaluar si la aplicación necesita ser embebida en plataformas externas.',
        'En caso negativo, configurar la cabecera con el valor DENY.',
        'Si requiere ser embebida por el mismo dominio, configurar con SAMEORIGIN.',
        'Complementar con la directiva frame-ancestors en Content-Security-Policy.'
      ],
      auto_fix: generateHeaderAutoFix('X-Frame-Options', stack)
    });
  }

  if (missingHeaders.includes('X-Content-Type-Options')) {
    vulnerabilities.push({
      id: 'VULN-HDR-XCTO',
      title: 'Ausencia de cabecera X-Content-Type-Options',
      severity: 'LOW',
      category: 'Headers',
      description: 'No se encuentra configurada la cabecera X-Content-Type-Options en las respuestas HTTP.',
      impact: 'Navegadores antiguos o vulnerables pueden ignorar el MIME type declarado por el servidor e intentar adivinar el contenido (MIME sniffing), ejecutando código HTML/JS oculto en archivos estáticos.',
      manual_fix_steps: [
        'Agregar la cabecera HTTP X-Content-Type-Options con el valor estricto nosniff en todas las respuestas del servidor.',
        'Verificar que los archivos estáticos tengan su Content-Type correcto asignado por el servidor.'
      ],
      auto_fix: generateHeaderAutoFix('X-Content-Type-Options', stack)
    });
  }

  // 3. Cookies Inseguras
  const insecureCookies = scoringResult.insecure_cookies || [];
  if (insecureCookies.length > 0) {
    const missingFlags = [];
    if (insecureCookies.some(c => !c.http_only)) missingFlags.push('HttpOnly');
    if (insecureCookies.some(c => !c.secure)) missingFlags.push('Secure');

    vulnerabilities.push({
      id: 'VULN-COOKIE-INSECURE',
      title: `Cookies configuradas sin banderas de seguridad (${missingFlags.join(', ')})`,
      severity: 'HIGH',
      category: 'Cookies',
      description: `Se detectaron ${insecureCookies.length} cookie(s) (${insecureCookies.map(c => c.name).join(', ')}) que carecen de las banderas HttpOnly o Secure requeridas para sesiones seguras.`,
      impact: 'La falta de HttpOnly expone las cookies a robo mediante ataques XSS. La falta de Secure permite que las credenciales de sesión se transmitan en texto claro si la petición ocurre por HTTP.',
      manual_fix_steps: [
        'Localizar el archivo de configuración de sesión o el middleware de manejo de cookies de la aplicación.',
        'Habilitar el atributo HttpOnly = true en todas las cookies de autenticación o sensibles.',
        'Habilitar el atributo Secure = true para obligar la transmisión exclusiva a través de canales TLS/HTTPS.',
        'Configurar el atributo SameSite en Strict o Lax para mitigar Cross-Site Request Forgery (CSRF).'
      ],
      auto_fix: generateCookieAutoFix(stack, insecureCookies)
    });
  }

  // 4. SSL / TLS Inválido o Ausente
  if (!evidence.ssl_tls || !evidence.ssl_tls.valid) {
    vulnerabilities.push({
      id: 'VULN-SSL-INVALID',
      title: 'Certificado SSL/TLS inválido, vencido o ausente',
      severity: 'CRITICAL',
      category: 'SSL',
      description: `El servidor no provee un canal de transporte TLS válido y de confianza (Emisor actual: ${evidence.ssl_tls?.issuer || 'No detectado'}).`,
      impact: 'Todo el tráfico entre el usuario y la plataforma viaja en texto claro o con advertencias de seguridad del navegador, exponiendo credenciales, datos personales y sesiones completas a interceptación pasiva y activa.',
      manual_fix_steps: [
        'Generar un certificado SSL/TLS con una Autoridad Certificadora (CA) pública de confianza (ej. Let\'s Encrypt o DigiCert).',
        'Instalar los certificados intermedios y el certificado de hoja en la configuración del servidor web.',
        'Deshabilitar protocolos obsoletos (SSLv2, SSLv3, TLS 1.0, TLS 1.1) y mantener únicamente TLS 1.2 y TLS 1.3.',
        'Configurar redirección obligatoria de HTTP (puerto 80) a HTTPS (puerto 443).'
      ],
      auto_fix: generateSSLAutoFix(stack)
    });
  }

  // Ordenar vulnerabilidades por severidad: CRITICAL > HIGH > MEDIUM > LOW
  vulnerabilities.sort((a, b) => {
    const weightA = SEVERITY_WEIGHT[a.severity] || 0;
    const weightB = SEVERITY_WEIGHT[b.severity] || 0;
    return weightB - weightA;
  });

  return vulnerabilities;
}

module.exports = { buildVulnerabilities };
