/**
 * Canary Sentinel - Controlador del Guardián 24/7 y Simulador de Ciberataques
 */

let eventSource = null;
let totalBlockedCounter = 0;
let connectedSitesList = [];

document.addEventListener('DOMContentLoaded', () => {
  initializeGuardianStream();
  fetchGuardianStats();
  fetchConnectedSites();
  setInterval(fetchGuardianStats, 10000);
  setInterval(fetchConnectedSites, 15000);

  // Vincular botones del simulador de ataques
  const simButtons = document.querySelectorAll('.btn-trigger-attack');
  simButtons.forEach(btn => {
    btn.addEventListener('click', async () => {
      const type = btn.getAttribute('data-sim');
      await triggerSimulatedAttack(type, btn);
    });
  });

  // Botón para autocompletar web demo de cliente
  const btnQuickDemo = document.getElementById('btn-quick-fill-demo-site');
  if (btnQuickDemo) {
    btnQuickDemo.addEventListener('click', () => {
      const nameInput = document.getElementById('input-site-name');
      const urlInput = document.getElementById('input-site-url');
      if (nameInput) nameInput.value = 'TechNova Store (Cliente Demo)';
      if (urlInput) urlInput.value = 'http://localhost:8080';
      window.showToast?.('Datos de la web demo (:8080) cargados. Haz clic en "Blindar Web 24/7".', 'info');
    });
  }

  // Formulario de conexión de sitio web real
  const formConnectSite = document.getElementById('form-connect-site');
  if (formConnectSite) {
    formConnectSite.addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = document.getElementById('input-site-name').value.trim();
      const targetUrl = document.getElementById('input-site-url').value.trim();
      const submitBtn = document.getElementById('btn-submit-site');

      submitBtn.disabled = true;
      submitBtn.innerHTML = `${Icons.spinner()} <span>Conectando...</span>`;
      window.showToast?.('Verificando conectividad y configurando escudo pasarela...', 'info');

      try {
        const res = await fetch('/api/sites/connect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, targetUrl })
        });
        const data = await res.json();

        if (data.success) {
          window.showToast?.(data.message, 'success');
          document.getElementById('input-site-name').value = '';
          document.getElementById('input-site-url').value = '';
          await fetchConnectedSites();
        } else {
          window.showToast?.(data.error || 'Error al conectar el sitio', 'error');
        }
      } catch (err) {
        window.showToast?.('Error al conectar con el servidor', 'error');
      } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = `${Icons.shield()} <span>Blindar Web 24/7</span>`;
      }
    });
  }
});

/**
 * Conecta al stream SSE en tiempo real para recibir alertas de ataques neutralizados
 */
function initializeGuardianStream() {
  try {
    eventSource = new EventSource('/api/guardian/events');

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.threatType) {
          handleIncomingAttackEvent(data);
        }
      } catch (err) {
        console.warn('[SSE] Mensaje recibido no parseable:', event.data);
      }
    };

    eventSource.onerror = () => {
      console.warn('[SSE] Desconexión temporal del stream de telemetría. Reconectando...');
    };
  } catch (err) {
    console.warn('[SSE] No fue posible inicializar EventSource:', err.message);
  }
}

/**
 * Procesa un nuevo ataque neutralizado recibido en tiempo real
 */
function handleIncomingAttackEvent(eventData) {
  totalBlockedCounter++;
  const metricCounter = document.getElementById('metric-threats-blocked');
  if (metricCounter) {
    metricCounter.textContent = totalBlockedCounter;
  }

  const container = document.getElementById('live-events-container');
  if (!container) return;

  // Si tiene el mensaje de placeholder inicial, limpiarlo
  if (container.querySelector('div[style*="text-align: center"]')) {
    container.innerHTML = '';
  }

  const eventRow = document.createElement('div');
  const sevClass = (eventData.severity || 'high').toLowerCase();
  eventRow.className = `event-row ${sevClass}`;

  const timeStr = new Date(eventData.timestamp).toLocaleTimeString();

  eventRow.innerHTML = `
    <div class="event-info-main">
      <div class="event-threat-name">
        <span style="color: var(--canary-gold);">${Icons.shield()}</span>
        <span>${escapeHtml(eventData.threatName)}</span>
        <small style="color: var(--text-dim); font-size: 0.72rem;">[${timeStr}]</small>
      </div>
      <div class="event-details-text">
        IP: <span style="color: var(--neon-cyan);">${escapeHtml(eventData.attackerIp)}</span> &bull; 
        Objetivo: <span style="color: #cbd5e1;">${escapeHtml(eventData.method)} ${escapeHtml(eventData.targetPath)}</span> &bull; 
        Payload: <span style="color: #f87171;">${escapeHtml(eventData.payloadSnippet || '')}</span>
      </div>
    </div>
    <div>
      <span class="event-action-badge">403 BLOQUEADO</span>
    </div>
  `;

  // Insertar al inicio de la lista con animación
  container.insertBefore(eventRow, container.firstChild);

  // Mantener un máximo de 30 eventos en el DOM
  while (container.children.length > 30) {
    container.removeChild(container.lastChild);
  }
}

/**
 * Consulta estadísticas del Guardián y actualiza la tabla de Integridad de Archivos (FIM)
 */
async function fetchGuardianStats() {
  try {
    const res = await fetch('/api/guardian/stats');
    const stats = await res.json();

    // Actualizar contadores
    if (stats.totalAttacksBlocked > totalBlockedCounter) {
      totalBlockedCounter = stats.totalAttacksBlocked;
    }
    const metricCounter = document.getElementById('metric-threats-blocked');
    if (metricCounter) metricCounter.textContent = totalBlockedCounter;

    // Actualizar tabla FIM
    const fimTableBody = document.getElementById('fim-table-body');
    if (fimTableBody && stats.fileIntegrity) {
      fimTableBody.innerHTML = '';
      stats.fileIntegrity.forEach(file => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td class="fim-file-path">${Icons.file()} ${escapeHtml(file.path)}</td>
          <td><span class="fim-status-ok"><svg class="svg-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg> Íntegro (SHA-256)</span></td>
        `;
        fimTableBody.appendChild(tr);
      });
    }

    // Si hay eventos históricos y el feed está vacío, cargarlos
    const container = document.getElementById('live-events-container');
    if (container && container.querySelector('div[style*="text-align: center"]') && stats.recentEvents && stats.recentEvents.length > 0) {
      container.innerHTML = '';
      stats.recentEvents.forEach(evt => handleIncomingAttackEvent(evt));
    }
  } catch (err) {
    console.warn('Error consultando estadísticas del Guardián:', err.message);
  }
}

/**
 * Ejecuta una simulación controlada de ataque contra el Guardián
 */
async function triggerSimulatedAttack(type, btnElement) {
  const originalText = btnElement.innerHTML;
  btnElement.disabled = true;
  btnElement.innerHTML = `${Icons.spinner()} <span>Disparando sonda...</span>`;

  try {
    const res = await fetch('/api/guardian/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type })
    });
    const data = await res.json();

    if (data.simulated && data.result.blocked) {
      window.showToast?.(`Sonda de ataque neutralizada con HTTP 403 Forbidden: ${data.result.threat}`, 'success');
    } else {
      window.showToast?.('Simulación procesada.', 'info');
    }
  } catch (err) {
    window.showToast?.('Error al disparar la simulación', 'error');
  } finally {
    setTimeout(() => {
      btnElement.disabled = false;
      btnElement.innerHTML = originalText;
    }, 800);
  }
}

/**
 * Consulta la lista de sitios web conectados al WAF Reverse Proxy
 */
async function fetchConnectedSites() {
  try {
    const res = await fetch('/api/sites');
    const data = await res.json();
    if (data.success) {
      connectedSitesList = data.sites;
      renderConnectedSites(data.sites);
    }
  } catch (err) {
    console.warn('Error al consultar sitios web conectados:', err.message);
  }
}

/**
 * Renderiza las tarjetas de sitios web protegidos en el DOM
 */
function renderConnectedSites(sites) {
  const container = document.getElementById('connected-sites-list');
  if (!container) return;

  if (!sites || sites.length === 0) {
    container.innerHTML = `
      <div style="text-align: center; color: var(--text-muted); padding: 24px; font-size: 0.88rem; background: rgba(0,0,0,0.2); border-radius: 8px;">
        <span style="display: block; margin-bottom: 6px; color: var(--canary-gold);">${Icons.globe('icon-lg')}</span>
        No hay sitios web conectados aún. Puedes ingresar la URL de tu sitio arriba o presionar "Cargar Web Demo (:8080)" para conectar una web de prueba en vivo.
      </div>
    `;
    return;
  }

  container.innerHTML = '';
  const currentOrigin = window.location.origin;

  sites.forEach(site => {
    const card = document.createElement('div');
    const isOnline = site.status === 'ONLINE';
    card.className = `site-card ${isOnline ? '' : 'unreachable'}`;

    const shieldFullUrl = `${currentOrigin}${site.shieldPath}`;

    card.innerHTML = `
      <div class="site-card-header">
        <div class="site-card-title">
          <span style="color: ${isOnline ? 'var(--neon-emerald)' : 'var(--neon-crimson)'};">
            ${isOnline ? Icons.checkCircle() : Icons.xCircle()}
          </span>
          <h3>${escapeHtml(site.name)}</h3>
          <span style="font-size: 0.75rem; padding: 2px 8px; border-radius: 4px; ${isOnline ? 'background: rgba(16,185,129,0.15); color:#34d399;' : 'background: rgba(239,68,68,0.15); color:#f87171;'}">
            ${isOnline ? 'EN LÍNEA (24/7 ACTIVO)' : 'INACCESIBLE'}
          </span>
        </div>
        <button class="btn-disconnect-site" data-site-id="${site.id}" title="Desconectar este sitio del escudo">
          ${Icons.close()} Desconectar
        </button>
      </div>

      <div style="font-size: 0.82rem; color: var(--text-muted);">
        Servidor Web Real de Destino: <code style="color: #cbd5e1;">${escapeHtml(site.targetUrl)}</code>
      </div>

      <div class="shield-url-container">
        <div>
          <div style="font-size: 0.72rem; color: var(--text-muted); text-transform: uppercase; margin-bottom: 2px; display: flex; align-items: center; gap: 6px;">
            ${Icons.shield()} <span>URL Pasarela Protegida (WAF Reverse Proxy):</span>
          </div>
          <a href="${shieldFullUrl}" target="_blank" rel="noopener" class="shield-url-text">
            ${shieldFullUrl}
          </a>
        </div>
        <button class="btn-copy-code" style="position: static;" onclick="navigator.clipboard.writeText('${shieldFullUrl}').then(() => window.showToast('URL del Escudo copiada', 'info'))">
          ${Icons.copy()} Copiar URL
        </button>
      </div>

      <div class="site-telemetry-row">
        <div class="site-telemetry-item">Peticiones Atendidas: <strong>${site.stats.totalRequests}</strong></div>
        <div class="site-telemetry-item">Tráfico Limpio Reenviado: <strong style="color: #34d399;">${site.stats.cleanRequestsForwarded}</strong></div>
        <div class="site-telemetry-item">Ataques Neutralizados: <strong style="color: #f87171;">${site.stats.threatsBlocked}</strong></div>
        <div class="site-telemetry-item">Latencia: <strong>${site.lastLatencyMs || 0} ms</strong></div>
      </div>

      <div class="site-actions-bar">
        <span style="font-size: 0.8rem; color: var(--text-muted); align-self: center;">Probar Pasarela en Vivo:</span>
        <button class="btn-test-legit" data-site-id="${site.id}">
          ${Icons.checkCircle()} <span>Enviar Tráfico Legítimo (GET /api/products)</span>
        </button>
        <button class="btn-test-attack" data-site-id="${site.id}">
          ${Icons.bolt()} <span>Enviar Ataque Hostil (SQLi Probe)</span>
        </button>
      </div>
    `;

    container.appendChild(card);
  });

  // Vincular eventos de desconexión
  container.querySelectorAll('.btn-disconnect-site').forEach(btn => {
    btn.addEventListener('click', async () => {
      const siteId = btn.getAttribute('data-site-id');
      if (confirm('¿Deseas desconectar este sitio del escudo protector 24/7?')) {
        await disconnectSite(siteId);
      }
    });
  });

  // Vincular pruebas de tráfico legítimo
  container.querySelectorAll('.btn-test-legit').forEach(btn => {
    btn.addEventListener('click', async () => {
      const siteId = btn.getAttribute('data-site-id');
      await testLegitimateTraffic(siteId, btn);
    });
  });

  // Vincular pruebas de ataque hostil
  container.querySelectorAll('.btn-test-attack').forEach(btn => {
    btn.addEventListener('click', async () => {
      const siteId = btn.getAttribute('data-site-id');
      await testAttackTraffic(siteId, btn);
    });
  });
}

/**
 * Prueba el envío de una petición legítima a través del Escudo Pasarela
 */
async function testLegitimateTraffic(siteId, btn) {
  const originalHtml = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `${Icons.spinner()} <span>Enviando a través del escudo...</span>`;

  try {
    const res = await fetch(`/shield/${siteId}/api/products`);
    const status = res.status;
    const data = await res.json().catch(() => null);

    if (status === 200) {
      window.showToast?.(`Tráfico legítimo verificado (HTTP 200 OK). La web del cliente respondió con sus datos intactos.`, 'success');
    } else {
      window.showToast?.(`Respuesta de la web del cliente: HTTP ${status}`, 'info');
    }
    await fetchConnectedSites();
  } catch (err) {
    window.showToast?.('Error al conectar a través del escudo: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = originalHtml;
  }
}

/**
 * Prueba el envío de un ataque hostil a través del Escudo Pasarela
 */
async function testAttackTraffic(siteId, btn) {
  const originalHtml = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `${Icons.spinner()} <span>Enviando carga maliciosa...</span>`;

  try {
    const res = await fetch(`/shield/${siteId}/api/search?q=%27%20OR%20%271%27=%271%27--`);
    const status = res.status;
    const data = await res.json().catch(() => null);

    if (status === 403) {
      window.showToast?.(`ATAQUE DETENIDO POR EL ESCUDO (HTTP 403 Forbidden). La web del cliente quedó a salvo.`, 'success');
    } else {
      window.showToast?.(`Resultado: HTTP ${status}`, 'warning');
    }
    await fetchConnectedSites();
  } catch (err) {
    window.showToast?.('Error durante la prueba defensiva', 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = originalHtml;
  }
}

/**
 * Desconecta un sitio web
 */
async function disconnectSite(siteId) {
  try {
    const res = await fetch(`/api/sites/${siteId}`, { method: 'DELETE' });
    const data = await res.json();
    if (data.success) {
      window.showToast?.('Sitio desconectado del escudo 24/7.', 'info');
      await fetchConnectedSites();
    }
  } catch (err) {
    window.showToast?.('Error al desconectar sitio', 'error');
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

window.fetchGuardianStats = fetchGuardianStats;
window.fetchConnectedSites = fetchConnectedSites;
