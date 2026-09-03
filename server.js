const express = require('express');
const cors = require('cors');
const path = require('path');
const { analyzeEvidence } = require('./engine/analyzer');
const { threatIntel } = require('./engine/threat-intel');
const { canaryDefenseMiddleware } = require('./engine/defense-agent');
const { gitHubIntegrator } = require('./engine/github-integrator');
const { tokenManager } = require('./engine/canary-tokens');
const { redTeamSimulator } = require('./engine/red-team-simulator');
const { rollbackManager } = require('./engine/rollback-manager');
const { geoThreatIntel } = require('./engine/geo-intel');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '5mb' }));

// 🛡️ ACTIVACIÓN DEL SENSOR PERIMETRAL DE DEFENSA 24/7
app.use(canaryDefenseMiddleware({ enableTarpit: true }));

// Servir archivos estáticos
app.use(express.static(path.join(__dirname, 'public')));

// POST /api/analyze - Núcleo de procesamiento determinista post-escaneo
app.post('/api/analyze', (req, res) => {
  try {
    const rawEvidence = req.body;
    if (!rawEvidence || Object.keys(rawEvidence).length === 0) {
      return res.status(400).json({
        error: 'JSON de evidencia no proporcionado o vacío.'
      });
    }

    const report = analyzeEvidence(rawEvidence);
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    return res.status(200).json(report);
  } catch (error) {
    console.error('[CanaryEngine Error]', error);
    return res.status(500).json({
      error: 'Error interno al procesar el reporte de evidencia.',
      details: error.message
    });
  }
});

// GET /api/samples - Presets deterministas
app.get('/api/samples', (req, res) => {
  const samples = {
    critical_node: {
      name: 'API Node.js/Express - Riesgo Crítico',
      description: 'CVE Crítico en dependencia, falta de CSP/HSTS y cookies sin flags de seguridad.',
      data: {
        target_url: 'https://api.fintech-gateway.internal',
        technologies: [
          { name: 'Node.js', version: '18.12.0' },
          { name: 'Express', version: '4.18.2' },
          { name: 'Nginx', version: '1.22.0' }
        ],
        security_headers: {
          'Content-Security-Policy': false,
          'Strict-Transport-Security': false,
          'X-Frame-Options': false,
          'X-Content-Type-Options': true
        },
        cookies: [
          { name: 'auth_jwt', http_only: false, secure: false, same_site: 'Lax' }
        ],
        ssl_tls: {
          valid: false,
          issuer: 'Self-Signed Untrusted Certificate'
        },
        detected_cves: [
          { cve_id: 'CVE-2023-26159', severity: 'CRITICAL', component: 'follow-redirects' },
          { cve_id: 'CVE-2024-21508', severity: 'HIGH', component: 'mysql2' }
        ]
      }
    },
    wordpress_breach: {
      name: 'Portal WordPress - Alto Riesgo',
      description: 'Cabeceras de protección ausentes, cookies inseguras y superficie WP expuesta.',
      data: {
        target_url: 'https://corporate-blog.enterprise.com',
        technologies: [
          { name: 'WordPress', version: '6.2.2' },
          { name: 'PHP', version: '8.1.10' },
          { name: 'Apache', version: '2.4.52' }
        ],
        security_headers: {
          'Content-Security-Policy': false,
          'Strict-Transport-Security': false,
          'X-Frame-Options': false,
          'X-Content-Type-Options': false
        },
        cookies: [
          { name: 'wordpress_logged_in_hash', http_only: false, secure: false, same_site: 'None' }
        ],
        ssl_tls: {
          valid: true,
          issuer: "Let's Encrypt Authority X3"
        },
        detected_cves: [
          { cve_id: 'CVE-2023-2745', severity: 'HIGH', component: 'wp-core' }
        ]
      }
    },
    django_hardened: {
      name: 'Plataforma Django - Hardened (Limpio)',
      description: 'Buenas prácticas implementadas, cabeceras completas y TLS válido.',
      data: {
        target_url: 'https://banking-core.security-bank.com',
        technologies: [
          { name: 'Django', version: '5.0.3' },
          { name: 'Python', version: '3.12.2' },
          { name: 'Nginx', version: '1.24.0' }
        ],
        security_headers: {
          'Content-Security-Policy': true,
          'Strict-Transport-Security': true,
          'X-Frame-Options': true,
          'X-Content-Type-Options': true
        },
        cookies: [
          { name: '__Host-sessionid', http_only: true, secure: true, same_site: 'Strict' }
        ],
        ssl_tls: {
          valid: true,
          issuer: 'DigiCert Global Root G2'
        },
        detected_cves: []
      }
    }
  };

  res.json(samples);
});

// ==========================================
// 🛡️ TELEMETRÍA Y DEFENSA ACTIVA 24/7 (COBERTURA GLOBAL)
// ==========================================

app.get('/api/defense/status', (req, res) => {
  const activeThreats = threatIntel.getActiveThreats();
  res.json({
    status: 'ACTIVE_24_7',
    sensor_health: 'OPTIMAL',
    blocked_ips_count: activeThreats.length,
    active_threats: activeThreats,
    whitelist: threatIntel.getWhitelist(),
    audit_events: threatIntel.auditLog.slice(0, 50),
    canary_tokens_active: tokenManager.getActiveTokens().length
  });
});

app.post('/api/defense/simulate-attack', (req, res) => {
  const { ip, trapPath } = req.body || {};
  
  // Genera una IP aleatoria de cualquier país del mundo si no se especifica
  let targetIp = ip;
  if (!targetIp) {
    const randomHost = geoThreatIntel.generateRandomGlobalIp();
    targetIp = randomHost.ip;
  }

  const trapsPool = ['/.env', '/wp-login.php', '/api/v1/debug', '/storage/logs/laravel.log', '/config.json', '/actuator/env'];
  const targetTrap = trapPath || trapsPool[Math.floor(Math.random() * trapsPool.length)];

  const userAgentsPool = [
    'Go-http-client/1.1 (MassScan/Vulnerability Scanner)',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (Nikto/2.1.6)',
    'sqlmap/1.7.2#stable (https://sqlmap.org)',
    'Python-urllib/3.10 (Automated-C2-Beacon)',
    'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0 (BurpSuitePro/2023.10)'
  ];
  const selectedUa = userAgentsPool[Math.floor(Math.random() * userAgentsPool.length)];

  const blockRecord = threatIntel.registerIntrusion({
    ip: targetIp,
    trapPath: targetTrap,
    userAgent: selectedUa,
    method: 'GET'
  });

  res.json({
    message: 'Ataque global interceptado con éxito.',
    action: 'IP neutralizada de forma autónoma.',
    record: blockRecord
  });
});

// Ficha forense detallada de una IP específica
app.get('/api/forensic/threat/:ip', (req, res) => {
  const ip = req.params.ip;
  const threats = threatIntel.getActiveThreats();
  const found = threats.find(t => t.ip === ip);

  if (!found) {
    return res.status(404).json({ error: 'IP no encontrada en registro de amenazas activas.' });
  }

  res.json(found);
});

// Whitelist / Lista Blanca de IPs
app.get('/api/firewall/whitelist', (req, res) => {
  res.json({ whitelist: threatIntel.getWhitelist() });
});

app.post('/api/firewall/whitelist/add', (req, res) => {
  const { ip } = req.body || {};
  if (!ip) return res.status(400).json({ error: 'IP requerida.' });
  threatIntel.addToWhitelist(ip);
  res.json({ success: true, message: `IP ${ip} añadida a la lista blanca de seguridad.` });
});

app.post('/api/firewall/whitelist/remove', (req, res) => {
  const { ip } = req.body || {};
  if (!ip) return res.status(400).json({ error: 'IP requerida.' });
  threatIntel.removeFromWhitelist(ip);
  res.json({ success: true, message: `IP ${ip} removida de la lista blanca.` });
});

app.get('/api/firewall/rules', (req, res) => {
  const format = req.query.format || 'nginx';
  const rules = threatIntel.exportRules(format);

  if (format === 'cloudflare') {
    res.setHeader('Content-Type', 'application/json');
  } else {
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  }

  res.send(rules);
});

app.post('/api/firewall/unblock', (req, res) => {
  const { ip } = req.body || {};
  if (!ip) {
    return res.status(400).json({ error: 'Direccion IP requerida.' });
  }

  const removed = threatIntel.unblockIp(ip);
  res.json({ success: removed, ip: ip, message: removed ? 'IP desbloqueada.' : 'IP no encontrada en lista negra.' });
});

// ==========================================
// 🎯 CANARY RED TEAM EXPLOIT SIMULATOR
// ==========================================

app.post('/api/redteam/test', async (req, res) => {
  try {
    const { vulnId, targetUrl, patchApplied } = req.body || {};
    const result = await redTeamSimulator.simulateExploitVector({
      vulnId: vulnId || 'VULN-HDR-CSP',
      targetUrl: targetUrl || 'https://target-audit.local',
      patchApplied: patchApplied !== false
    });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// ⏪ RESGUARDOS Y ROLLBACK EN 1-CLIC
// ==========================================

app.post('/api/rollback/create-snapshot', (req, res) => {
  const { vulnId, fileTarget, repo, originalContent } = req.body || {};
  const snapshot = rollbackManager.createSnapshot({ vulnId, fileTarget, originalContent, repo });
  res.json({ success: true, snapshot });
});

app.get('/api/rollback/data/:snapshotId', (req, res) => {
  const data = rollbackManager.getRollbackData(req.params.snapshotId);
  res.json(data);
});

app.post('/api/rollback/execute', (req, res) => {
  const { snapshotId, vulnId, repo } = req.body || {};
  const data = rollbackManager.getRollbackData(snapshotId);
  rollbackManager.markRestored(snapshotId);

  res.json({
    success: true,
    message: `Cápsula de reversión aplicada. Parche para ${vulnId || 'vulnerabilidad'} revertido exitosamente.`,
    restoredBranch: `canary/rollback-${(vulnId || 'patch').toLowerCase()}`,
    prUrl: `https://github.com/${repo || 'empresa/web-backend'}/pull/${Math.floor(Math.random() * 50) + 120}`,
    data
  });
});

// ==========================================
// 🍯 CANARY TOKENS & HONEY-CREDENTIALS
// ==========================================

app.get('/api/tokens/track/:token', (req, res) => {
  const tokenId = req.params.token;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  
  const result = tokenManager.triggerToken(tokenId, {
    ip: clientIp,
    userAgent: req.headers['user-agent']
  });

  res.json({
    alert: 'CANARY_TRACKER_TRIPPED',
    message: 'Credencial señuelo interceptada. Origen hostil identificado.',
    token: tokenId
  });
});

app.post('/api/tokens/simulate-detonation', (req, res) => {
  const fakeTokenId = `tok_demo_${Date.now().toString(36)}`;
  // Genera IP de cualquier parte del mundo
  const randomHost = geoThreatIntel.generateRandomGlobalIp();
  const fakeIp = randomHost.ip;

  const result = tokenManager.triggerToken(fakeTokenId, {
    ip: fakeIp,
    userAgent: 'Python-requests/2.28 (AWS-Credential-Tester/Exploit)'
  });

  threatIntel.registerIntrusion({
    ip: fakeIp,
    trapPath: `Honey-Credential-Use (${fakeTokenId})`,
    userAgent: 'Python-requests/2.28 (AWS-Credential-Tester/Exploit)',
    method: 'API_PROBE'
  });

  res.json({
    message: 'Canary Token detonado con éxito. Alerta SEV-0 emitida.',
    geo: randomHost.geo,
    result
  });
});

// ==========================================
// 🚀 AUTO-REMEDIACIÓN GITHUB (PULL REQUESTS)
// ==========================================

app.post('/api/github/create-pr', async (req, res) => {
  try {
    const { token, repo, baseBranch, labels, fileTarget, patchCode, vulnId, vulnTitle, severity } = req.body || {};

    if (!patchCode || !fileTarget) {
      return res.status(400).json({ error: 'Faltan campos requeridos (patchCode, fileTarget).' });
    }

    const result = await gitHubIntegrator.createSecurityPullRequest({
      token: token || 'demo_token',
      repo: repo || 'tu-organizacion/web-app',
      baseBranch: baseBranch || 'main',
      labels: labels || ['security', 'canary-autofix', 'remediation'],
      fileTarget,
      patchCode,
      vulnId: vulnId || 'CANARY-FIX',
      vulnTitle: vulnTitle || 'Parche de Seguridad',
      severity: severity || 'HIGH'
    });

    // Crear automáticamente una cápsula de rollback
    const snapshot = rollbackManager.createSnapshot({
      vulnId: vulnId || 'CANARY-FIX',
      fileTarget,
      repo: repo || 'tu-organizacion/web-app',
      originalContent: `// Backup original previo a inyección de ${vulnId}\n`
    });

    res.json({
      ...result,
      rollback_snapshot_id: snapshot.id
    });
  } catch (err) {
    console.error('[GitHub PR Error]', err);
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// ⚡ SDK 1-LINE INSTALLATION GENERATOR
// ==========================================

app.get('/api/sdk/install-command', (req, res) => {
  const stack = (req.query.stack || 'node').toLowerCase();
  const apiKey = `cnry_live_${Buffer.from(Date.now().toString()).toString('base64').slice(0, 16)}`;

  let command = `npx @canary-ai/shield init --key=${apiKey}`;
  let snippet = `const canary = require('@canary-ai/shield')({ apiKey: '${apiKey}' });\napp.use(canary);`;

  if (stack === 'python' || stack === 'django') {
    command = `pip install canary-shield && canary-init --key=${apiKey}`;
    snippet = `# settings.py\nMIDDLEWARE.insert(0, 'canary.middleware.CanaryShieldMiddleware')\nCANARY_API_KEY = '${apiKey}'`;
  } else if (stack === 'php' || stack === 'laravel') {
    command = `composer require canary/shield && php artisan canary:protect --key=${apiKey}`;
    snippet = `// bootstrap/app.php o Kernel.php\n$middleware->prepend(\\Canary\\Shield\\Middleware\\Protect::class);`;
  } else if (stack === 'nginx') {
    command = `curl -sSL https://canary-defense.io/nginx-install.sh | bash -s -- --key=${apiKey}`;
    snippet = `# En tu bloque server {} de nginx.conf:\ninclude /etc/nginx/canary-shield.conf;`;
  }

  res.json({
    stack,
    apiKey,
    oneLineCommand: command,
    integrationSnippet: snippet
  });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'operational', engine: 'CanaryEngine v4.0 (Global Threat Intelligence)', mode: 'zero-hallucinations' });
});

app.listen(PORT, () => {
  console.log(`[CanaryEngine] Servidor activo en http://localhost:${PORT}`);
});
