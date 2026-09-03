/**
 * Canary Sentinel - Servicio de Pasarela WAF Reverse Proxy y Protección Activa 24/7
 * Permite conectar sitios web reales de clientes, inspeccionar cada solicitud en tiempo real
 * y reenviar tráfico limpio al servidor de destino sin que el cliente modifique su código.
 */

const { inspectRequest, recordEvent } = require('./guardianService');

// Almacén en memoria de sitios web conectados
const connectedSites = new Map();

/**
 * Registra y valida la conexión hacia un sitio web real
 */
async function registerSite(siteData) {
  const { name = 'Mi Sitio Web', targetUrl } = siteData;

  if (!targetUrl || typeof targetUrl !== 'string') {
    throw new Error('Debes proporcionar una URL válida para conectar la web.');
  }

  // Normalizar URL (remover slash final)
  let cleanUrl = targetUrl.trim().replace(/\/+$/, '');
  if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
    cleanUrl = 'http://' + cleanUrl;
  }

  // Probar conectividad inicial (ping)
  const healthCheck = await checkSiteHealth(cleanUrl);

  const siteId = 'site_' + Math.random().toString(36).substring(2, 8);
  const newSite = {
    id: siteId,
    name: name.trim() || 'Sitio Protegido',
    targetUrl: cleanUrl,
    shieldPath: `/shield/${siteId}`,
    createdAt: new Date().toISOString(),
    status: healthCheck.online ? 'ONLINE' : 'UNREACHABLE',
    lastLatencyMs: healthCheck.latencyMs,
    lastChecked: new Date().toISOString(),
    stats: {
      totalRequests: 0,
      cleanRequestsForwarded: 0,
      threatsBlocked: 0
    }
  };

  connectedSites.set(siteId, newSite);
  return newSite;
}

/**
 * Obtiene todos los sitios registrados
 */
function getConnectedSites() {
  return Array.from(connectedSites.values());
}

/**
 * Obtiene un sitio por su ID
 */
function getSiteById(siteId) {
  return connectedSites.get(siteId) || null;
}

/**
 * Elimina un sitio conectado
 */
function removeSite(siteId) {
  return connectedSites.delete(siteId);
}

/**
 * Comprueba disponibilidad (uptime y latencia) de un sitio web
 */
async function checkSiteHealth(url) {
  const startTime = Date.now();
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000); // 5s timeout

    const res = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
      headers: {
        'User-Agent': 'Canary-Sentinel-Health-Monitor/1.0'
      }
    });
    clearTimeout(timeoutId);

    const latencyMs = Date.now() - startTime;
    return {
      online: true,
      statusCode: res.status,
      latencyMs
    };
  } catch (err) {
    return {
      online: false,
      statusCode: 0,
      latencyMs: Date.now() - startTime,
      error: err.message
    };
  }
}

/**
 * Manejador central del WAF Reverse Proxy:
 * 1. Inspecciona la petición con el motor heurístico del Guardián.
 * 2. Si es hostil: bloquea con 403 Forbidden y registra la telemetría en tiempo real.
 * 3. Si es limpia: reenvía la petición al sitio real del cliente y devuelve la respuesta.
 */
async function handleProxyRequest(req, res, siteId, subPath = '') {
  const site = connectedSites.get(siteId);
  if (!site) {
    return res.status(404).json({
      error: 'Not Found',
      message: `El sitio protegido con ID "${siteId}" no existe o fue desconectado.`
    });
  }

  site.stats.totalRequests += 1;

  // 1. Extraer datos de la petición para inspección profunda
  const clientIp = req.ip || req.connection.remoteAddress || '127.0.0.1';
  const rawQuery = req.url.includes('?') ? req.url.split('?')[1] : '';
  const inspectData = {
    ip: clientIp,
    path: '/' + subPath,
    method: req.method,
    query: rawQuery,
    body: req.body,
    userAgent: req.headers['user-agent'] || ''
  };

  // 2. Inspección defensiva con el Guardián 24/7
  const inspection = inspectRequest(inspectData);

  if (inspection.blocked) {
    site.stats.threatsBlocked += 1;

    res.setHeader('X-Shield-Action', 'BLOCKED');
    res.setHeader('X-Protected-By', 'Canary-Sentinel-WAF-24-7');
    return res.status(403).json({
      error: 'Forbidden',
      status: 403,
      shield: 'Canary Sentinel Active Web Shield',
      siteProtected: site.name,
      threatDetected: inspection.threat || inspection.reason,
      incidentId: 'INC-' + Math.random().toString(36).substring(2, 9).toUpperCase(),
      message: 'Acceso denegado: Se detectó una carga hostil y fue interceptada antes de alcanzar el servidor del cliente.',
      timestamp: new Date().toISOString()
    });
  }

  // 3. Petición limpia: Reenviar al sitio web real del cliente (Reverse Proxy)
  site.stats.cleanRequestsForwarded += 1;
  const targetFullUrl = `${site.targetUrl}/${subPath}${rawQuery ? '?' + rawQuery : ''}`;

  try {
    const forwardHeaders = { ...req.headers };
    delete forwardHeaders.host;
    delete forwardHeaders.connection;
    delete forwardHeaders['content-length'];

    // Inyectar cabeceras de auditoría y procedencia
    forwardHeaders['x-forwarded-for'] = clientIp;
    forwardHeaders['x-canary-shield'] = 'Verified-Clean';

    const fetchOptions = {
      method: req.method,
      headers: forwardHeaders
    };

    // Agregar cuerpo en métodos POST, PUT, PATCH
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) && req.body) {
      if (typeof req.body === 'object' && Object.keys(req.body).length > 0) {
        fetchOptions.body = JSON.stringify(req.body);
        forwardHeaders['content-type'] = 'application/json';
      } else if (typeof req.body === 'string' && req.body.length > 0) {
        fetchOptions.body = req.body;
      }
    }

    const responseFromTarget = await fetch(targetFullUrl, fetchOptions);

    // Replicar código de estado y encabezados permitidos
    res.status(responseFromTarget.status);
    responseFromTarget.headers.forEach((val, key) => {
      if (!['transfer-encoding', 'connection', 'content-encoding'].includes(key.toLowerCase())) {
        res.setHeader(key, val);
      }
    });

    res.setHeader('X-Canary-Protected', 'True');
    res.setHeader('X-Shield-Site', site.name);

    // Transmitir cuerpo de respuesta
    const contentType = responseFromTarget.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      const json = await responseFromTarget.json();
      return res.json(json);
    } else {
      const text = await responseFromTarget.text();
      return res.send(text);
    }

  } catch (err) {
    return res.status(502).json({
      error: 'Bad Gateway',
      status: 502,
      message: `No fue posible conectar con el servidor de destino (${site.targetUrl}): ${err.message}`,
      hint: 'Asegúrate de que el servidor de tu web esté encendido y accesible en esa URL.'
    });
  }
}

// Sondeo periódico en segundo plano para verificar uptime de sitios conectados cada 30 segundos
setInterval(async () => {
  for (const site of connectedSites.values()) {
    const check = await checkSiteHealth(site.targetUrl);
    site.status = check.online ? 'ONLINE' : 'UNREACHABLE';
    site.lastLatencyMs = check.latencyMs;
    site.lastChecked = new Date().toISOString();
  }
}, 30000);

module.exports = {
  registerSite,
  getConnectedSites,
  getSiteById,
  removeSite,
  checkSiteHealth,
  handleProxyRequest
};
