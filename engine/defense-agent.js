/**
 * CanaryEngine - Active Defense Agent & Sensor Middleware (24/7 Protection)
 * Ahora con inyección de Honey-Credentials activas (Canary Tokens).
 */

const { threatIntel } = require('./threat-intel');
const { tokenManager } = require('./canary-tokens');

const ACTIVE_HONEYPOT_PATHS = [
  '/.env',
  '/.env.local',
  '/.env.production',
  '/.git/config',
  '/wp-login.php',
  '/xmlrpc.php',
  '/api/v1/debug',
  '/_debug',
  '/storage/logs/laravel.log',
  '/__debug__/',
  '/admin/login/',
  '/actuator/health',
  '/actuator/env',
  '/swagger-ui.html',
  '/.aws/credentials'
];

const EXCLUDED_MANAGEMENT_ROUTES = [
  '/api/firewall/unblock',
  '/api/firewall/rules',
  '/api/defense/status',
  '/api/defense/simulate-attack',
  '/api/tokens/active',
  '/api/tokens/track',
  '/api/samples',
  '/api/analyze',
  '/api/github/create-pr',
  '/index.html',
  '/index.css',
  '/app.js',
  '/'
];

function canaryDefenseMiddleware(options = {}) {
  const customHoneypots = options.additionalHoneypots || [];
  const allTraps = new Set([...ACTIVE_HONEYPOT_PATHS, ...customHoneypots]);
  const enableTarpit = options.enableTarpit !== false;
  const whitelistIps = new Set(options.whitelistIps || []);

  return (req, res, next) => {
    const clientIp = req.headers['x-forwarded-for'] 
      ? req.headers['x-forwarded-for'].split(',')[0].trim() 
      : (req.socket.remoteAddress || '127.0.0.1');

    const cleanIp = String(clientIp).replace('::ffff:', '').trim();
    const requestPath = req.path.toLowerCase();

    // Endpoints administrativos exentos
    const isManagementRoute = EXCLUDED_MANAGEMENT_ROUTES.some(route => 
      requestPath === route.toLowerCase() || 
      requestPath.startsWith('/api/firewall') || 
      requestPath.startsWith('/api/defense') ||
      requestPath.startsWith('/api/tokens') ||
      requestPath.startsWith('/api/github')
    );

    // 1. REVISAR SI LA IP ESTÁ BLOQUEADA
    if (!isManagementRoute && !whitelistIps.has(cleanIp) && threatIntel.isBlocked(cleanIp)) {
      res.setHeader('X-Canary-Defense', 'IP_BLOCKED_HOSTILE_ACTOR');
      return res.status(403).json({
        error: 'ACCESS_DENIED_BY_CANARY_DEFENSE',
        message: 'Tu direccion IP ha sido clasificada como hostil debido a actividades de intrusion previas.',
        action: 'Contacta al equipo de seguridad si consideras que se trata de un falso positivo.'
      });
    }

    // 2. VERIFICAR SI LA PETICIÓN ENTRANTE APUNTA A UNA RUTA TRAMPA (HONEYPOT)
    const isHoneypotTriggered = Array.from(allTraps).some(trap => requestPath === trap.toLowerCase() || requestPath.startsWith(trap.toLowerCase() + '/'));

    if (isHoneypotTriggered) {
      threatIntel.registerIntrusion({
        ip: cleanIp,
        trapPath: req.path,
        userAgent: req.headers['user-agent'],
        method: req.method,
        headers: req.headers
      });

      const delay = enableTarpit ? 1500 : 0;

      setTimeout(() => {
        res.setHeader('X-Canary-Trap', 'TRIGGERED');
        res.setHeader('Connection', 'close');

        if (requestPath.includes('.env')) {
          // Generar señuelo con Canary Tokens rastreables
          const credentials = tokenManager.generateHoneyCredentials(req.hostname || 'Target-Protected');
          res.setHeader('Content-Type', 'text/plain; charset=utf-8');
          return res.status(200).send(credentials.envPayload);
        }

        if (requestPath.includes('login') || requestPath.includes('admin')) {
          return res.status(401).json({ error: 'Credenciales invalidas.', trap_detected: true });
        }

        return res.status(403).json({
          error: 'ACCESS_PROHIBITED',
          trap_triggered: req.path,
          status: 'HOSTILE_ORIGIN_BLOCKED'
        });
      }, delay);

      return;
    }

    next();
  };
}

module.exports = {
  canaryDefenseMiddleware,
  ACTIVE_HONEYPOT_PATHS
};
