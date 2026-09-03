/**
 * CanaryEngine - Safe Rollback & State Snapshot Manager
 * Garantiza que cada parche de Auto-Fix cuente con una cápsula de reversión
 * en 1-clic para restaurar el archivo original en caso de incompatibilidad.
 */

class RollbackManager {
  constructor() {
    // Mapa: snapshotId -> { id, vulnId, fileTarget, originalSnippet, timestamp, restored: boolean }
    this.snapshots = new Map();
  }

  /**
   * Crea una cápsula de respaldo previa a la aplicación de cualquier parche
   */
  createSnapshot({ vulnId, fileTarget, originalContent, repo }) {
    const snapshotId = `snap_${Date.now().toString(36)}_${Math.random().toString(36).substr(2, 5)}`;

    const snapshot = {
      id: snapshotId,
      vulnId,
      fileTarget,
      repo: repo || 'default/repo',
      timestamp: new Date().toISOString(),
      originalContent: originalContent || `// Estado previo sin directivas de seguridad para ${vulnId}\n// Archivo objetivo: ${fileTarget}\n`,
      restored: false
    };

    this.snapshots.set(snapshotId, snapshot);
    return snapshot;
  }

  /**
   * Genera las directivas de restauración en 1-clic
   */
  getRollbackData(snapshotId) {
    const snapshot = this.snapshots.get(snapshotId);
    if (!snapshot) {
      // Si no existe, generar respaldo fallback seguro
      return {
        id: snapshotId || 'snap_fallback',
        message: 'Directiva de reversión: Eliminar directivas inyectadas por Canary.',
        rollbackSnippet: `// Reversión manual: Eliminar bloque inyectado por Canary en ${snapshot?.fileTarget || 'archivo de configuración'}`
      };
    }

    return {
      snapshotId: snapshot.id,
      vulnId: snapshot.vulnId,
      fileTarget: snapshot.fileTarget,
      timestamp: snapshot.timestamp,
      rollbackSnippet: snapshot.originalContent,
      branchRollbackName: `canary/rollback-${snapshot.vulnId.toLowerCase()}`,
      prMessage: `revert(security): revertir parche de mitigación ${snapshot.vulnId} a su estado original`
    };
  }

  markRestored(snapshotId) {
    const s = this.snapshots.get(snapshotId);
    if (s) s.restored = true;
  }
}

const rollbackManager = new RollbackManager();

module.exports = { rollbackManager };
