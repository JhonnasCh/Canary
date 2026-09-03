/**
 * Canary Sentinel - Agente Conectable 24/7 (Middleware SDK)
 * 
 * Agrega este middleware a cualquier servidor Express / Node.js del cliente
 * para protegerlo activamente en tiempo real contra ataques y reportar incidentes al Hub Central.
 * 
 * USO RÁPIDO EN TU WEB:
 * 
 * const express = require('express');
 * const { canaryGuardian } = require('./sentinel-agent');
 * 
 * const app = express();
 * app.use(canaryGuardian({
 *   hubUrl: 'http://localhost:3000',
 *   secretKey: 'canary-guard-sec-8f4b912c0e7a',
 *   blockMode: true // Bloquea con 403 Forbidden los ataques
 * }));
 */

const THREAT_PATTERNS = [
  {
    type: 'SQL_INJECTION',
    name: 'Inyección SQL (SQLi)',
    regex: /(?:'|\%27)\s*(?:or|and)\s*.*?=.*?(?:--|\#|\%23)|union\s+(?:all\s+)?select|information_schema|waitfor\s+delay|sleep\s*\(\d+\)|drop\s+table/i
  },
  {
    type: 'CROSS_SITE_SCRIPTING',
    name: 'Cross-Site Scripting (XSS)',
    regex: /<script[\s\S]*?>[\s\S]*?<\/script>|javascript:|onerror\s*=|onload\s*=|document\.cookie|<svg.*?onload/i
  },
  {
    type: 'PATH_TRAVERSAL',
    name: 'Path Traversal / LFI',
    regex: /(?:\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%252e%252e%252f)/i
  },
  {
    type: 'COMMAND_INJECTION',
    name: 'Remote Command Execution (RCE)',
    regex: /(?:;|\||`|\$\().*?(?:cat\s+\/etc\/|whoami|id|wget\s+|curl\s+|bash\s+-i|cmd\.exe)/i
  },
  {
    type: 'MALICIOUS_SCANNER',
    name: 'Escaneo Automatizado de Vulnerabilidades',
    regex: /sqlmap|nikto|acunetix|dirbuster|nmap|masscan|havij/i
  }
];

function canaryGuardian(options = {}) {
  const {
    hubUrl = 'http://localhost:3000',
    secretKey = 'canary-guard-sec-8f4b912c0e7a',
    blockMode = true,
    customBlockedResponse = null
  } = options;

  return function (req, res, next) {
    const ip = req.ip || req.connection.remoteAddress || '127.0.0.1';
    const method = req.method;
    const url = req.originalUrl || req.url;
    const userAgent = req.headers['user-agent'] || '';
    const bodyStr = req.body ? (typeof req.body === 'string' ? req.body : JSON.stringify(req.body)) : '';

    const rawPayload = `${url} ${bodyStr} ${userAgent}`;
    let decodedPayload = rawPayload;
    try {
      decodedPayload = decodeURIComponent(rawPayload.replace(/\+/g, ' '));
    } catch (e) {}

    const payload = `${rawPayload} ${decodedPayload}`;

    for (const threat of THREAT_PATTERNS) {
      if (threat.regex.test(payload)) {
        // Notificar asíncronamente al Hub Central de Canary Sentinel
        const eventData = {
          threatType: threat.type,
          threatName: threat.name,
          severity: threat.type === 'SQL_INJECTION' || threat.type === 'COMMAND_INJECTION' ? 'CRITICAL' : 'HIGH',
          action: blockMode ? 'BLOCKED_403' : 'ALERT_ONLY',
          attackerIp: ip,
          method: method,
          targetPath: url,
          payloadSnippet: payload.slice(0, 150),
          secretKey: secretKey,
          timestamp: new Date().toISOString()
        };

        fetch(`${hubUrl}/api/guardian/telemetry`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(eventData)
        }).catch(err => {
          // Registro silencioso para no degradar el rendimiento del servidor del cliente
          console.warn('[Canary Guardian] Alerta enviada con aviso de conexión.');
        });

        if (blockMode) {
          res.setHeader('X-Protected-By', 'Canary-Sentinel-24-7');
          res.status(403);

          if (typeof customBlockedResponse === 'function') {
            return customBlockedResponse(req, res, threat);
          }

          return res.json({
            error: 'Forbidden',
            status: 403,
            message: 'Acceso bloqueado por Canary Sentinel 24/7 Security Shield.',
            threatDetected: threat.name,
            incidentId: 'INC-' + Math.random().toString(36).substring(2, 9).toUpperCase(),
            timestamp: new Date().toISOString()
          });
        }
      }
    }

    // Inyectar cabecera de auditoría defensiva
    res.setHeader('X-Canary-Sentinel', 'Protected-24-7');
    next();
  };
}

module.exports = {
  canaryGuardian,
  THREAT_PATTERNS
};
