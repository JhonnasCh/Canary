/**
 * CanaryEngine - Input Validator & Sanitizer
 * Garantiza que la evidencia técnica cruda cumpla con los tipos esperados y
 * normaliza nombres de cabeceras y estructuras sin alterar los datos reales.
 */

function validateAndSanitizeInput(rawInput) {
  if (!rawInput || typeof rawInput !== 'object') {
    throw new Error('El cuerpo de la solicitud debe ser un objeto JSON válido.');
  }

  const sanitized = {
    target_url: typeof rawInput.target_url === 'string' && rawInput.target_url.trim().length > 0
      ? rawInput.target_url.trim()
      : 'https://unknown-target.local',
    technologies: Array.isArray(rawInput.technologies)
      ? rawInput.technologies.map(tech => ({
          name: String(tech?.name || 'Unknown').trim(),
          version: String(tech?.version || '').trim()
        }))
      : [],
    security_headers: {},
    cookies: Array.isArray(rawInput.cookies)
      ? rawInput.cookies.map(c => ({
          name: String(c?.name || 'session_id'),
          http_only: Boolean(c?.http_only),
          secure: Boolean(c?.secure),
          same_site: String(c?.same_site || 'None')
        }))
      : [],
    ssl_tls: {
      valid: Boolean(rawInput.ssl_tls?.valid),
      issuer: String(rawInput.ssl_tls?.issuer || 'Unknown')
    },
    detected_cves: Array.isArray(rawInput.detected_cves)
      ? rawInput.detected_cves.map(cve => ({
          cve_id: String(cve?.cve_id || '').toUpperCase().trim(),
          severity: String(cve?.severity || 'MEDIUM').toUpperCase().trim(),
          component: String(cve?.component || 'Core').trim()
        }))
      : []
  };

  // Normalizar nombres de cabeceras (case-insensitive a formato estándar)
  if (rawInput.security_headers && typeof rawInput.security_headers === 'object') {
    const headerMapping = {
      'content-security-policy': 'Content-Security-Policy',
      'strict-transport-security': 'Strict-Transport-Security',
      'hsts': 'Strict-Transport-Security',
      'x-frame-options': 'X-Frame-Options',
      'x-content-type-options': 'X-Content-Type-Options',
      'referrer-policy': 'Referrer-Policy',
      'permissions-policy': 'Permissions-Policy'
    };

    for (const [key, value] of Object.entries(rawInput.security_headers)) {
      const lowerKey = key.toLowerCase().trim();
      const normalizedKey = headerMapping[lowerKey] || key;
      sanitized.security_headers[normalizedKey] = Boolean(value);
    }
  }

  return sanitized;
}

module.exports = { validateAndSanitizeInput };
