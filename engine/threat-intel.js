/**
 * CanaryEngine - Dynamic Threat Intelligence & Hostile IP Registry (v2.5)
 * Memoria activa con TTL de 24h, Geo-Intel Global, Whitelist y Ficha Forense de Intrusión.
 */

const { geoThreatIntel } = require('./geo-intel');

class ThreatIntelligenceRegistry {
  constructor() {
    // Mapa: ip -> { ip, status, reason, trapPath, blockedAt, expiresAt, userAgent, method, attackCount, geo, forensic }
    this.blockedIps = new Map();
    // Conjunto de IPs de confianza (Lista Blanca)
    this.whitelist = new Set(['127.0.0.1', '::1', 'localhost']);
    // Auditoría de eventos
    this.auditLog = [];
    // TTL por defecto: 24 horas en milisegundos
    this.DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;
  }

  isBlocked(ip) {
    if (this.whitelist.has(ip)) return false;

    const record = this.blockedIps.get(ip);
    if (!record) return false;

    if (Date.now() > record.expiresAtTimestamp) {
      this.blockedIps.delete(ip);
      this.logAudit(ip, 'UNBLOCKED_AUTO_EXPIRED', 'El TTL de 24 horas expiro.');
      return false;
    }

    return true;
  }

  addToWhitelist(ip) {
    if (!ip) return false;
    this.whitelist.add(ip);
    if (this.blockedIps.has(ip)) {
      this.blockedIps.delete(ip);
    }
    this.logAudit(ip, 'WHITELISTED', 'IP anadida a la lista blanca de administracion.');
    return true;
  }

  removeFromWhitelist(ip) {
    return this.whitelist.delete(ip);
  }

  getWhitelist() {
    return Array.from(this.whitelist);
  }

  registerIntrusion({ ip, trapPath, userAgent, method, rawHeaders }) {
    if (this.whitelist.has(ip)) {
      return { status: 'IGNORED_WHITELIST', ip };
    }

    const now = Date.now();
    const expiresAtTimestamp = now + this.DEFAULT_TTL_MS;
    const existing = this.blockedIps.get(ip);
    const attackCount = existing ? existing.attackCount + 1 : 1;

    // Enriquecimiento de inteligencia con cobertura global
    const geo = geoThreatIntel.resolveIp(ip);

    // Ficha forense técnica de la intrusión
    const forensic = {
      rawUserAgent: userAgent || 'Unknown Attack Tool',
      httpMethod: method || 'GET',
      targetedTrap: trapPath,
      firstSeen: existing ? existing.blockedAt : new Date(now).toISOString(),
      lastSeen: new Date(now).toISOString(),
      tlsVersion: 'TLSv1.3 (Probing ciphers)',
      attackVectorsTested: ['Directory Traversal', 'Sensitive File Reconnaissance'],
      simulatedTarpitDelay: '1500ms'
    };

    const record = {
      ip,
      status: 'BLOCKED',
      reason: `Intento de acceso no autorizado a Honeypot: ${trapPath}`,
      trapPath,
      userAgent: userAgent || 'Unknown-Scanner/1.0',
      method: method || 'GET',
      attackCount,
      blockedAt: new Date(now).toISOString(),
      expiresAt: new Date(expiresAtTimestamp).toISOString(),
      expiresAtTimestamp,
      geo,
      forensic
    };

    this.blockedIps.set(ip, record);
    this.logAudit(ip, 'BLOCKED_24H', `Acceso hostil detectado en trampa adaptativa: ${trapPath}`);

    return record;
  }

  unblockIp(ip) {
    if (this.blockedIps.has(ip)) {
      this.blockedIps.delete(ip);
      this.logAudit(ip, 'UNBLOCKED_MANUAL', 'Desbloqueo manual emitido desde el SOC.');
      return true;
    }
    return false;
  }

  getActiveThreats() {
    const now = Date.now();
    const active = [];

    for (const [ip, record] of this.blockedIps.entries()) {
      if (now > record.expiresAtTimestamp) {
        this.blockedIps.delete(ip);
      } else {
        active.push(record);
      }
    }

    return active.sort((a, b) => b.expiresAtTimestamp - a.expiresAtTimestamp);
  }

  logAudit(ip, action, details) {
    this.auditLog.unshift({
      timestamp: new Date().toISOString(),
      ip,
      action,
      details
    });

    if (this.auditLog.length > 200) {
      this.auditLog.pop();
    }
  }

  exportRules(format = 'nginx') {
    const active = this.getActiveThreats();
    if (format === 'nginx') {
      if (active.length === 0) return '# No hay atacantes hostiles activos.\n';
      return '# Directivas generadas por Canary AI Threat Intelligence 24/7\n' +
        active.map(t => `deny ${t.ip}; # ${t.geo.flag} ${t.geo.country} (${t.geo.org}) - Neutralizado en ${t.trapPath}`).join('\n') + '\n';
    }

    if (format === 'iptables') {
      if (active.length === 0) return '# No hay reglas iptables pendientes.\n';
      return '# Reglas de cortafuegos de kernel Linux generadas por CanaryEngine\n' +
        active.map(t => `iptables -I INPUT -s ${t.ip} -j DROP -m comment --comment "Canary-Blocked-${t.geo.code}"`).join('\n') + '\n';
    }

    if (format === 'cloudflare') {
      return JSON.stringify({
        waf_expression: active.length > 0 ? `(ip.src in {${active.map(t => `"${t.ip}"`).join(' ')}})` : '(false)',
        action: 'block',
        description: 'Regla WAF sincronizada por Canary AI SOC'
      }, null, 2);
    }

    return '# Formato no reconocido';
  }
}

const threatIntel = new ThreatIntelligenceRegistry();

module.exports = { threatIntel };
