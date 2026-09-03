/**
 * CanaryEngine - Active Defense & Adaptive Honeypot Recommender
 * Genera trampas activas contextuales basadas en el stack tecnológico real detectado,
 * acompañadas de reglas operativas de respuesta a incidentes y auto-bloqueo.
 */

function generateHoneypots(technologies, dominantStack) {
  const techNames = (technologies || []).map(t => (t.name || '').toLowerCase());
  const traps = [];

  // Mapeo contextual por tecnologías específicas
  if (techNames.some(t => t.includes('wordpress'))) {
    traps.push({
      path: '/wp-login.php',
      type: 'Authentication Trap',
      reason: 'Atrae ataques masivos de fuerza bruta y sprays de contraseñas dirigidos contra endpoints de autenticación administrativa de WordPress.'
    });
    traps.push({
      path: '/xmlrpc.php',
      type: 'Amplification & Pingback Trap',
      reason: 'Objetivo frecuente de atacantes para amplificación de denegación de servicio (DDoS) y ataques de fuerza bruta en segundo plano.'
    });
  }

  if (dominantStack === 'express' || techNames.some(t => t.includes('node') || t.includes('express'))) {
    traps.push({
      path: '/.env',
      type: 'Credential & Secrets Trap',
      reason: 'Los escáneres maliciosos automatizados buscan activamente archivos de variables de entorno expuestos para sustraer secretos de JWT, bases de datos y claves AWS.'
    });
    traps.push({
      path: '/api/v1/debug',
      type: 'Privileged Debug Trap',
      reason: 'Sondeo común de actores hostiles que buscan endpoints de diagnóstico no protegidos para extraer volcados de memoria y rutas de servidor.'
    });
  }

  if (dominantStack === 'laravel' || techNames.some(t => t.includes('laravel') || t.includes('php'))) {
    traps.push({
      path: '/storage/logs/laravel.log',
      type: 'Log File Exposure Trap',
      reason: 'Los atacantes intentan leer los registros internos de Laravel para obtener credenciales, tokens de depuración y stack traces con información sensible.'
    });
    traps.push({
      path: '/.env',
      type: 'Configuration File Trap',
      reason: 'Frecuentemente solicitado por crawlers maliciosos para extraer APP_KEY y cadenas de conexión de base de datos.'
    });
  }

  if (dominantStack === 'django' || techNames.some(t => t.includes('django') || t.includes('python'))) {
    traps.push({
      path: '/__debug__/',
      type: 'Debug Toolbar Trap',
      reason: 'Atrae intentos de explotación de la interfaz Django Debug Toolbar expuesta indebidamente en entornos productivos.'
    });
    traps.push({
      path: '/admin/login/',
      type: 'Credential Harvest Trap',
      reason: 'Punto focal para ataques de diccionario dirigidos a cuentas de superusuario de Django.'
    });
  }

  if (dominantStack === 'nextjs' || techNames.some(t => t.includes('next'))) {
    traps.push({
      path: '/.env.local',
      type: 'Environment Secrets Trap',
      reason: 'Atrae peticiones que buscan extraer variables secretas de Next.js que nunca deben ser públicas en el cliente.'
    });
    traps.push({
      path: '/api/internal/health',
      type: 'Internal Service Recon Trap',
      reason: 'Identifica actividad de reconocimiento orientada a microservicios internos y endpoints no documentados.'
    });
  }

  // Fallbacks genéricos altamente efectivos para cualquier infraestructura
  if (traps.length < 2) {
    traps.push({
      path: '/.git/config',
      type: 'Source Code Exposure Trap',
      reason: 'Detecta actores de amenazas que intentan clonar repositorios completos expuestos en la raíz pública del servidor web.'
    });
  }

  if (traps.length < 2) {
    traps.push({
      path: '/actuator/health',
      type: 'Microservices Framework Trap',
      reason: 'Identifica escaneos dirigidos a interfaces de monitoreo de Spring/Microservicios en busca de fuga de información de heap y métricas internas.'
    });
  }

  const autoBlockingRules = 
    'Si un origen emite al menos 1 solicitud HTTP a cualquiera de las rutas trampa identificadas: ' +
    '1. Descartar la petición con código HTTP 403 o tarpit simulado; ' +
    '2. Registrar inmediatamente la dirección IP de origen, cabeceras HTTP y fingerprint TLS en la base de datos de telemetría de Canary; ' +
    '3. Emitir una directiva de bloqueo automático de IP por 86,400 segundos (24 horas) en el WAF/iptables y clasificar al actor como Hostil en el SOC.';

  return {
    recommended_honeypots: traps.slice(0, 3), // Máximo 3 de alta relevancia
    auto_blocking_rules: autoBlockingRules
  };
}

module.exports = { generateHoneypots };
