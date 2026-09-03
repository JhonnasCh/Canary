/**
 * CanaryEngine - Canary Tokens & Honey-Credentials Generator
 * Genera credenciales señuelo activas (falsas pero rastreables) para atraer,
 * engañar y rastrear a los atacantes cuando intentan usar las claves sustraídas.
 */

class CanaryTokenManager {
  constructor() {
    // Mapa de tokens activos: tokenId -> { createdAt, targetSite, trapType, triggerCount, triggers: [] }
    this.tokens = new Map();
  }

  /**
   * Genera un paquete de credenciales señuelo vinculadas a un token rastreador
   */
  generateHoneyCredentials(targetSite = 'cliente-web') {
    const tokenId = `tok_${Date.now().toString(36)}_${Math.random().toString(36).substr(2, 6)}`;
    const trackingEndpoint = `http://localhost:3000/api/tokens/track/${tokenId}`;

    const tokenRecord = {
      id: tokenId,
      targetSite,
      createdAt: new Date().toISOString(),
      trackingEndpoint,
      triggerCount: 0,
      triggers: []
    };

    this.tokens.set(tokenId, tokenRecord);

    const envPayload = 
`# -------------------------------------------------------------
# Canary Defense - Automated Honeytrap Decoy Environment File
# -------------------------------------------------------------
NODE_ENV=production
APP_NAME="${targetSite}"
APP_KEY="base64:${Buffer.from(tokenId).toString('base64')}="
DATABASE_URL="postgres://canary_trap_${tokenId.slice(0, 8)}:p4ssw0rd_decoy@db.canary-defense.internal:5432/production"
STRIPE_SECRET_KEY="sk_live_canary_${tokenId}"
AWS_ACCESS_KEY_ID="AKIA_CANARY_${tokenId.toUpperCase()}"
AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
CANARY_TRACK_BEACON="${trackingEndpoint}"
`;

    return {
      tokenId,
      trackingEndpoint,
      envPayload
    };
  }

  /**
   * Registra cuando un atacante intenta utilizar o verificar la credencial trampa
   */
  triggerToken(tokenId, clientInfo = {}) {
    let record = this.tokens.get(tokenId);

    if (!record) {
      // Si el token es simulado o nuevo, registrarlo
      record = {
        id: tokenId,
        targetSite: 'Plataforma Protegida',
        createdAt: new Date().toISOString(),
        triggerCount: 0,
        triggers: []
      };
      this.tokens.set(tokenId, record);
    }

    record.triggerCount += 1;
    const triggerEvent = {
      timestamp: new Date().toISOString(),
      ip: clientInfo.ip || '127.0.0.1',
      userAgent: clientInfo.userAgent || 'Unknown Tool/Exploit',
      action: 'ATTEMPTED_CREDENTIAL_REUSE',
      severity: 'CRITICAL_SEV_0',
      message: `El atacante intentó activar la credencial señuelo [${tokenId}]. Telemetría forense activada.`
    };

    record.triggers.unshift(triggerEvent);
    console.log(`🚨 [CANARY TOKEN BUSTED] Token trampa detonado: ${tokenId} | IP: ${clientInfo.ip}`);

    return {
      success: true,
      alert: 'SEV_0_CREDENTIAL_TRAP_TRIGGERED',
      event: triggerEvent
    };
  }

  getActiveTokens() {
    return Array.from(this.tokens.values());
  }
}

const tokenManager = new CanaryTokenManager();

module.exports = { tokenManager };
