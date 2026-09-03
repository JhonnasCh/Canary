/**
 * Canary — Scanner UI Module
 * Connects the frontend scan form to the backend API
 * and renders real scan results in the page.
 */

// Current language helper
function getLang() {
  return localStorage.getItem('canary-lang') || (navigator.language.startsWith('es') ? 'es' : 'en');
}

// Localized text helper
function t(en, es) {
  return getLang() === 'es' ? es : en;
}

// ==========================================
// SCAN API CALL
// ==========================================
async function runScan(url) {
  try {
    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    
    if (!response.ok) {
      let data;
      try {
        data = await response.json();
      } catch {
        throw new Error(t(`Server responded with HTTP ${response.status}`, `El servidor respondió con HTTP ${response.status}`));
      }
      const msg = getLang() === 'es' ? data.message_es : data.message_en;
      throw new Error(msg || t('Server error during scan', 'Error en el servidor durante el escaneo'));
    }

    const data = await response.json();
    if (data.error) {
      const msg = getLang() === 'es' ? data.message_es : data.message_en;
      throw new Error(msg || 'Unknown error');
    }
    return data.data;
  } catch (err) {
    if (err.message && (err.message.includes('Failed to fetch') || err.message.includes('NetworkError'))) {
      throw new Error(t('Could not connect to scanner server. Please make sure the server is running on http://localhost:3000', 'No se pudo conectar con el servidor de escaneo. Asegúrate de que el servidor esté activo en http://localhost:3000'));
    }
    throw err;
  }
}

// ==========================================
// SEVERITY HELPERS
// ==========================================
const severityColors = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
  INFO: '#3b82f6',
};

const severityLabels = {
  CRITICAL: { en: 'Critical', es: 'Crítico' },
  HIGH: { en: 'High', es: 'Alto' },
  MEDIUM: { en: 'Medium', es: 'Medio' },
  LOW: { en: 'Low', es: 'Bajo' },
  INFO: { en: 'Info', es: 'Info' },
};

function severityLabel(sev) {
  const label = severityLabels[sev];
  return label ? t(label.en, label.es) : (sev || 'INFO');
}

// ==========================================
// RENDER RESULTS MODAL
// ==========================================
function createResultsModal() {
  const existing = document.getElementById('scan-results-modal');
  if (existing) existing.remove();

  const modal = document.createElement('div');
  modal.id = 'scan-results-modal';
  modal.innerHTML = `
    <div class="modal-overlay" id="modal-overlay"></div>
    <div class="modal-content" id="modal-content">
      <button class="modal-close" id="modal-close" aria-label="Close">✕</button>
      <div class="modal-body" id="modal-body"></div>
    </div>
  `;
  document.body.appendChild(modal);

  document.getElementById('modal-close').addEventListener('click', closeModal);
  document.getElementById('modal-overlay').addEventListener('click', closeModal);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeModal();
  });

  return document.getElementById('modal-body');
}

function closeModal() {
  const modal = document.getElementById('scan-results-modal');
  if (modal) {
    modal.classList.add('closing');
    setTimeout(() => modal.remove(), 300);
  }
  document.body.style.overflow = '';
}

function showLoading() {
  const body = createResultsModal();
  document.body.style.overflow = 'hidden';

  body.innerHTML = `
    <div class="scan-loading">
      <div class="scan-spinner"></div>
      <h3>${t('Scanning your application...', 'Escaneando tu aplicación...')}</h3>
      <p>${t('Analyzing headers, cookies, TLS, DNS, technologies, and vulnerabilities', 'Analizando headers, cookies, TLS, DNS, tecnologías y vulnerabilidades')}</p>
    </div>
  `;

  const modal = document.getElementById('scan-results-modal');
  modal.classList.add('open');
}

function showError(message) {
  const body = document.getElementById('modal-body');
  if (!body) return;

  body.innerHTML = `
    <div class="scan-error">
      <div class="scan-error-icon">⚠️</div>
      <h3>${t('Scan Failed', 'Error en el Escaneo')}</h3>
      <p>${message}</p>
      <button class="btn btn-primary" id="retry-btn">
        ${t('Try Again', 'Intentar de Nuevo')}
      </button>
    </div>
  `;

  const retryBtn = document.getElementById('retry-btn');
  if (retryBtn) {
    retryBtn.addEventListener('click', () => {
      closeModal();
    });
  }
}

// ==========================================
// RENDER SCAN RESULTS
// ==========================================
function renderResults(results) {
  const body = document.getElementById('modal-body');
  if (!body || !results) return;

  const lang = getLang();
  const score = typeof results.score === 'number' ? results.score : 0;
  const scoreColor = score >= 75 ? '#22c55e' : score >= 50 ? '#eab308' : '#ef4444';

  const circumference = 502;
  const offset = circumference - (circumference * score / 100);

  const summary = results.summary || { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const technologies = Array.isArray(results.technologies) ? results.technologies : [];
  const vulnerabilities = Array.isArray(results.vulnerabilities) ? results.vulnerabilities : [];
  const findings = Array.isArray(results.findings) ? results.findings : [];
  const cookies = Array.isArray(results.cookies) ? results.cookies : [];
  const headersSecurity = Array.isArray(results.headers?.security) ? results.headers.security : [];
  const headersMissing = Array.isArray(results.headers?.missing) ? results.headers.missing : [];

  body.innerHTML = `
    <div class="results-container">

      <!-- HEADER: Score + Summary -->
      <div class="results-header">
        <div class="results-score-circle">
          <svg viewBox="0 0 180 180" width="140" height="140">
            <circle cx="90" cy="90" r="80" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="10"/>
            <circle cx="90" cy="90" r="80" fill="none" stroke="${scoreColor}" stroke-width="10"
              stroke-linecap="round" stroke-dasharray="${circumference}" stroke-dashoffset="${offset}"
              style="transform: rotate(-90deg); transform-origin: center; filter: drop-shadow(0 0 8px ${scoreColor}40); transition: stroke-dashoffset 1.2s ease;" />
          </svg>
          <div class="results-score-value">
            <span class="results-score-num" style="color:${scoreColor}">${score}</span>
            <span class="results-score-max">/100</span>
          </div>
        </div>
        <div class="results-summary">
          <h2>${t('Security Score', 'Puntuación de Seguridad')}: <span class="rating-badge rating-${results.rating || 'C'}">${results.rating || 'C'}</span></h2>
          <p class="results-url">${results.url || ''}</p>
          <div class="results-counts">
            ${summary.critical > 0 ? `<span class="count-badge" style="--c:${severityColors.CRITICAL}">🔴 ${summary.critical} ${t('critical', 'críticos')}</span>` : ''}
            ${summary.high > 0 ? `<span class="count-badge" style="--c:${severityColors.HIGH}">🟠 ${summary.high} ${t('high', 'altos')}</span>` : ''}
            ${summary.medium > 0 ? `<span class="count-badge" style="--c:${severityColors.MEDIUM}">🟡 ${summary.medium} ${t('medium', 'medios')}</span>` : ''}
            ${summary.low > 0 ? `<span class="count-badge" style="--c:${severityColors.LOW}">🟢 ${summary.low} ${t('low', 'bajos')}</span>` : ''}
            ${summary.info > 0 ? `<span class="count-badge" style="--c:${severityColors.INFO}">🔵 ${summary.info} info</span>` : ''}
          </div>
          <p class="results-time">${t('Scanned in', 'Escaneado en')} ${results.scanDuration || 0}ms</p>
        </div>
      </div>

      <!-- FRAUD, SCAM & PHISHING MALICIOUS ALERT BANNER -->
      ${results.phishingScamAnalysis && results.phishingScamAnalysis.isSuspicious ? `
      <div class="results-section phishing-alert-banner">
        <div class="phishing-banner-header">
          <span class="phishing-icon">🚨</span>
          <div>
            <h3>${t('MALICIOUS / FRAUDULENT SITE ALERT', 'ALERTA DE SITIO FRAUDULENTO O PHISHING')}</h3>
            <p>${t('This application exhibits high indicators of credential theft, brand impersonation, or scam tactics.', 'Esta aplicación presenta altos indicadores de robo de datos, suplantación de identidad o estafa.')}</p>
          </div>
          <span class="phishing-score-tag">Riesgo ${results.phishingScamAnalysis.scamScore}/100</span>
        </div>
        <ul class="phishing-reasons-list">
          ${(results.phishingScamAnalysis.reasons || []).map(r => `<li>⚠️ <span>${r}</span></li>`).join('')}
        </ul>
      </div>
      ` : ''}

      <!-- WEBSHELLS & MALWARE DETECTED -->
      ${Array.isArray(results.malwareThreats) && results.malwareThreats.length > 0 ? `
      <div class="results-section malware-threat-section">
        <div class="section-title-row">
          <h3 style="color: #ef4444;">🦠 ${t('Active Webshells / Backdoors Detected', 'Webshells y Puertas Traseras Activas Detectadas')} (${results.malwareThreats.length})</h3>
          <span class="finding-sev-badge" style="background: rgba(239, 68, 68, 0.2); color: #ef4444;">HOST COMPROMISED</span>
        </div>
        <div class="secrets-grid">
          ${results.malwareThreats.map(ws => `
            <div class="secret-card" style="border-left-color: #ef4444;">
              <div class="secret-header">
                <strong>🚨 Webshell / Backdoor Interface</strong>
                <span class="finding-sev-badge" style="background: #ef444420; color: #ef4444;">CRITICAL</span>
              </div>
              <code class="leak-path">${ws.path} (Firma: ${ws.signature})</code>
            </div>
          `).join('')}
        </div>
      </div>
      ` : ''}

      <!-- PAYMENT SECURITY & DATA EXFILTRATION -->
      ${results.paymentSecurity && (results.paymentSecurity.hasCardInputs || results.paymentSecurity.exfiltrationTargets.length > 0 || results.paymentSecurity.skimmingDetected) ? `
      <div class="results-section payment-security-section">
        <div class="section-title-row">
          <h3>💳 ${t('Payment Forms & Data Exfiltration Analysis', 'Formularios de Pago y Exfiltración de Datos')}</h3>
          <span class="finding-sev-badge" style="background: ${results.paymentSecurity.status === 'CRITICAL' ? 'rgba(239,68,68,0.2)' : 'rgba(234,179,8,0.2)'}; color: ${results.paymentSecurity.status === 'CRITICAL' ? '#ef4444' : '#eab308'};">
            ${results.paymentSecurity.status === 'CRITICAL' ? 'DATA EXFILTRATION RISK' : 'SENSITIVE PAYMENT FORM'}
          </span>
        </div>
        <div class="infra-grid">
          <div class="infra-card">
            <h4>💳 ${t('Card / Financial Fields', 'Campos de Tarjeta / Bancarios')}</h4>
            <div class="infra-item">
              <span>${t('Status', 'Estado')}:</span>
              <strong class="${results.paymentSecurity.hasCardInputs ? 'tls-bad' : 'tls-ok'}">${results.paymentSecurity.hasCardInputs ? '⚠️ ' + t('Detected in DOM', 'Detectados en DOM') : '✓ ' + t('None', 'Ninguno')}</strong>
            </div>
          </div>
          <div class="infra-card">
            <h4>📤 ${t('External Submission', 'Envío a Dominio Externo')}</h4>
            <div class="infra-item">
              <span>${t('Destination', 'Destino')}:</span>
              <strong class="${results.paymentSecurity.exfiltrationTargets.length > 0 ? 'tls-bad' : 'tls-ok'}">
                ${results.paymentSecurity.exfiltrationTargets.length > 0 ? '🚨 ' + results.paymentSecurity.exfiltrationTargets.map(e => e.targetHost).join(', ') : '✓ ' + t('Internal / Same Domain', 'Interno / Mismo Dominio')}
              </strong>
            </div>
          </div>
          <div class="infra-card">
            <h4>🪤 ${t('Magecart / Keylogger Check', 'Inspección Magecart / Keylogger')}</h4>
            <div class="infra-item">
              <span>${t('Script Skimming', 'Skimming en Scripts')}:</span>
              <strong class="${results.paymentSecurity.skimmingDetected ? 'tls-bad' : 'tls-ok'}">
                ${results.paymentSecurity.skimmingDetected ? '🚨 ' + t('Malicious Pattern', 'Patrón Malicioso') : '✓ ' + t('Clean', 'Limpio')}
              </strong>
            </div>
          </div>
        </div>
      </div>
      ` : ''}

      <!-- EXPOSED ADMIN PANELS & API DOCS -->
      ${Array.isArray(results.adminSurface) && results.adminSurface.length > 0 ? `
      <div class="results-section admin-surface-section">
        <div class="section-title-row">
          <h3>🚪 ${t('Exposed Administrative & API Surface', 'Paneles de Administración y APIs Expuestas')} (${results.adminSurface.length})</h3>
          <span class="section-subtitle-tag">${t('Publicly reachable management interfaces', 'Interfaces de gestión accesibles públicamente')}</span>
        </div>
        <div class="subdomains-grid">
          ${results.adminSurface.map(adm => `
            <div class="subdomain-card subdomain-dev">
              <div class="subdomain-header">
                <span class="subdomain-name">${adm.name}</span>
                <span class="subdomain-dev-badge">🚪 ${adm.type}</span>
              </div>
              <code class="leak-path">${adm.path}</code>
            </div>
          `).join('')}
        </div>
      </div>
      ` : ''}

      <!-- TECHNOLOGIES -->
      ${technologies.length > 0 ? `
      <div class="results-section">
        <div class="section-title-row">
          <h3>🔎 ${t('Technologies & Stack Detected', 'Tecnologías y Stack Detectado')} (${technologies.length})</h3>
          <span class="section-subtitle-tag">${t('With version & vulnerability verification', 'Con verificación de versión y vulnerabilidad')}</span>
        </div>
        <div class="tech-grid">
          ${technologies.map(tech => `
            <div class="tech-chip tech-${tech.status || 'detected'}">
              <span class="tech-icon">${tech.icon || '📦'}</span>
              <div class="tech-details">
                <div class="tech-header-row">
                  <strong>${tech.name}</strong>
                  ${tech.version ? `<span class="tech-version">v${tech.version}</span>` : `<span class="tech-unknown">${t('version unexposed', 'versión oculta')}</span>`}
                </div>
                <div class="tech-sub-row">
                  <span class="tech-cat">${tech.category || ''}</span>
                  <span class="tech-status-badge tech-badge-${tech.status || 'detected'}">
                    ${tech.statusIcon || 'ℹ️'} ${lang === 'es' ? (tech.statusLabel || 'Activo') : (tech.statusLabel_en || tech.statusLabel || 'Active')}
                  </span>
                </div>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
      ` : ''}

      <!-- STRUCTURE -->
      ${results.structure ? `
      <div class="results-section">
        <h3>🏗️ ${t('Application Structure', 'Estructura de la Aplicación')}</h3>
        <div class="structure-info">
          <div class="structure-type">
            <span class="structure-label">${t('Type', 'Tipo')}</span>
            <span class="structure-value">${lang === 'es' ? (results.structure.type_es || results.structure.type) : results.structure.type}</span>
          </div>
          ${Array.isArray(results.structure.indicators) && results.structure.indicators.length > 0 ? `
          <div class="structure-indicators">
            <span class="structure-label">${t('Indicators', 'Indicadores')}</span>
            <div class="indicator-chips">
              ${results.structure.indicators.map(ind => `<span class="indicator-chip">${ind}</span>`).join('')}
            </div>
          </div>
          ` : ''}
        </div>
      </div>
      ` : ''}

      <!-- KNOWN VULNERABILITIES (CVEs) -->
      ${vulnerabilities.length > 0 ? `
      <div class="results-section">
        <h3>🚨 ${t('Known Vulnerabilities (CVEs)', 'Vulnerabilidades Conocidas (CVEs)')}</h3>
        <div class="vuln-list">
          ${vulnerabilities.map(vuln => `
            <div class="vuln-item" style="--sev-color: ${severityColors[vuln.severity] || '#ef4444'}">
              <div class="vuln-header">
                <span class="finding-sev-badge" style="background: ${severityColors[vuln.severity] || '#ef4444'}20; color: ${severityColors[vuln.severity] || '#ef4444'}">${severityLabel(vuln.severity)}</span>
                <span class="vuln-cve">${vuln.cve || 'CVE'}</span>
              </div>
              <h4>${lang === 'es' && vuln.title_es ? vuln.title_es : vuln.title}</h4>
              <div class="vuln-versions">
                <span class="vuln-detected">⚠️ ${t('Detected', 'Detectada')}: <strong>${vuln.technology} v${vuln.detectedVersion}</strong></span>
                <span class="vuln-fix">✅ ${t('Fixed in', 'Corregido en')}: <strong>v${vuln.fixedIn}+</strong></span>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
      ` : ''}

      <!-- EXPOSED SECRETS & API KEYS HARVESTED -->
      ${Array.isArray(results.secrets) && results.secrets.length > 0 ? `
      <div class="results-section secrets-leak-section">
        <div class="section-title-row">
          <h3 style="color: #ef4444;">🔑 ${t('Exposed Secrets & API Keys in Client Code', 'Secretos y Claves API Filtradas en el Cliente')} (${results.secrets.length})</h3>
          <span class="finding-sev-badge" style="background: rgba(239, 68, 68, 0.15); color: #ef4444;">CRITICAL EXPOSURE</span>
        </div>
        <div class="secrets-grid">
          ${results.secrets.map(sec => `
            <div class="secret-card">
              <div class="secret-header">
                <strong>${sec.type}</strong>
                <span class="finding-sev-badge" style="background: ${severityColors[sec.severity] || '#ef4444'}20; color: ${severityColors[sec.severity] || '#ef4444'}">${sec.severity}</span>
              </div>
              <div class="secret-token-box">
                <code>${sec.masked}</code>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
      ` : ''}

      <!-- SOURCE CODE & BACKUP FILE LEAKS -->
      ${Array.isArray(results.sourceLeaks) && results.sourceLeaks.length > 0 ? `
      <div class="results-section source-leaks-section">
        <div class="section-title-row">
          <h3 style="color: #f97316;">📂 ${t('Source Code & Backup Leaks Detected', 'Fugas de Código Fuente y Respaldos')} (${results.sourceLeaks.length})</h3>
          <span class="finding-sev-badge" style="background: rgba(249, 115, 22, 0.15); color: #f97316;">EXPOSED FILES</span>
        </div>
        <div class="source-leaks-grid">
          ${results.sourceLeaks.map(leak => `
            <div class="source-leak-card">
              <div class="source-leak-header">
                <strong>${lang === 'es' && leak.name_es ? leak.name_es : leak.name}</strong>
                <span class="finding-sev-badge" style="background: ${severityColors[leak.severity] || '#f97316'}20; color: ${severityColors[leak.severity] || '#f97316'}">${leak.severity}</span>
              </div>
              <code class="leak-path">${leak.path}</code>
            </div>
          `).join('')}
        </div>
      </div>
      ` : ''}

      <!-- INFRASTRUCTURE HEALTH (DNS, WAF, CORS, REPUTATION, SECURITY.TXT, CLICKJACKING) -->
      ${(results.dns || results.waf || results.performance || results.corsAnalysis || results.reputation || results.securityTxt || results.clickjacking) ? `
      <div class="results-section">
        <h3>🌐 ${t('Infrastructure & Threat Intelligence', 'Infraestructura e Inteligencia de Amenazas')}</h3>
        <div class="infra-grid">
          ${results.clickjacking ? `
          <div class="infra-card">
            <h4>🖼️ ${t('Clickjacking & Framing', 'Clickjacking y Enmarcado')}</h4>
            <div class="infra-item">
              <span>${t('Frame Defense', 'Defensa de Frames')}:</span>
              <strong class="${results.clickjacking.canBeFramed ? 'tls-bad' : 'tls-ok'}">${results.clickjacking.canBeFramed ? '⚠️ ' + t('Vulnerable', 'Vulnerable') : '✓ ' + (lang === 'es' ? results.clickjacking.status_es : results.clickjacking.status)}</strong>
            </div>
            <div class="infra-item">
              <span>X-Frame-Options:</span>
              <strong style="font-size: var(--fs-xs);">${results.clickjacking.xfo || t('None', 'Ninguno')}</strong>
            </div>
          </div>
          ` : ''}

          ${results.dns ? `
          <div class="infra-card">
            <h4>📨 ${t('Email / DNS Security', 'Seguridad DNS / Email')}</h4>
            <div class="infra-item">
              <span>SPF Record:</span>
              <strong class="${results.dns.hasSPF ? 'tls-ok' : 'tls-bad'}">${results.dns.hasSPF ? '✓ Present' : '✕ Missing'}</strong>
            </div>
            <div class="infra-item">
              <span>DMARC:</span>
              <strong class="${results.dns.hasDMARC ? 'tls-ok' : 'tls-bad'}">${results.dns.hasDMARC ? '✓ Present' : '✕ Missing'}</strong>
            </div>
          </div>
          ` : ''}

          ${results.reputation ? `
          <div class="infra-card">
            <h4>🛡️ ${t('Domain Threat Reputation', 'Reputación de Dominio')}</h4>
            <div class="infra-item">
              <span>${t('Status', 'Estado')}:</span>
              <strong class="${results.reputation.clean ? 'tls-ok' : 'tls-bad'}">${results.reputation.clean ? '✓ ' + t('Clean / No Blacklists', 'Limpio / Sin Listas Negras') : '🚨 ' + t('Blacklisted', 'En Lista Negra')}</strong>
            </div>
            <div class="infra-item">
              <span>${t('Threat Feeds', 'Fuentes')}:</span>
              <strong style="font-size: var(--fs-xs);">Spamhaus, SURBL</strong>
            </div>
          </div>
          ` : ''}

          ${results.corsAnalysis && results.corsAnalysis.tested ? `
          <div class="infra-card">
            <h4>🔄 ${t('CORS Origin Security', 'Seguridad CORS Activa')}</h4>
            <div class="infra-item">
              <span>${t('Origin Reflection', 'Reflejo de Origen')}:</span>
              <strong class="${results.corsAnalysis.originReflected ? 'tls-bad' : 'tls-ok'}">${results.corsAnalysis.originReflected ? '⚠️ ' + t('Reflected', 'Reflejado') : '✓ ' + t('Blocked', 'Bloqueado')}</strong>
            </div>
            <div class="infra-item">
              <span>Credentials:</span>
              <strong class="${results.corsAnalysis.allowCredentials && results.corsAnalysis.originReflected ? 'tls-bad' : 'tls-ok'}">${results.corsAnalysis.allowCredentials ? 'true (Vulnerable)' : 'false (Safe)'}</strong>
            </div>
          </div>
          ` : ''}

          ${results.securityTxt ? `
          <div class="infra-card">
            <h4>📜 security.txt (RFC 9116)</h4>
            <div class="infra-item">
              <span>${t('Policy File', 'Archivo de Política')}:</span>
              <strong class="${results.securityTxt.present ? (results.securityTxt.isExpired ? 'tls-bad' : 'tls-ok') : 'tls-bad'}">
                ${results.securityTxt.present ? (results.securityTxt.isExpired ? '⚠️ ' + t('Expired', 'Vencido') : '✓ ' + t('Valid', 'Válido')) : '✕ ' + t('Missing', 'Ausente')}
              </strong>
            </div>
            ${results.securityTxt.contact ? `
            <div class="infra-item">
              <span>${t('Contact', 'Contacto')}:</span>
              <strong style="font-size: var(--fs-xs); word-break: break-all;">${results.securityTxt.contact.substring(0, 24)}...</strong>
            </div>
            ` : ''}
          </div>
          ` : ''}

          ${results.waf && results.waf.length > 0 ? `
          <div class="infra-card">
            <h4>🛡️ ${t('WAF / CDN Protection', 'Protección WAF / CDN')}</h4>
            <div class="infra-item">
              <span>${t('Active Provider', 'Proveedor Activo')}:</span>
              <strong>${results.waf.map(w => (w.icon || '🛡️') + ' ' + w.name).join(', ')}</strong>
            </div>
          </div>
          ` : `
          <div class="infra-card">
            <h4>🛡️ ${t('WAF / CDN Protection', 'Protección WAF / CDN')}</h4>
            <div class="infra-item">
              <span>${t('Status', 'Estado')}:</span>
              <strong class="tls-bad">${t('No WAF detected', 'Sin WAF detectado')}</strong>
            </div>
          </div>
          `}

          ${results.performance ? `
          <div class="infra-card">
            <h4>⚡ ${t('Performance & Optimization', 'Rendimiento y Optimización')}</h4>
            <div class="infra-item">
              <span>${t('Compression', 'Compresión')}:</span>
              <strong class="${results.performance.compression ? 'tls-ok' : 'tls-bad'}">${results.performance.compression || t('None', 'Ninguna')}</strong>
            </div>
            <div class="infra-item">
              <span>${t('Page Size', 'Tamaño HTML')}:</span>
              <strong>${results.performance.pageSizeKB} KB</strong>
            </div>
          </div>
          ` : ''}
        </div>
      </div>
      ` : ''}

      <!-- SUBDOMAINS DISCOVERED (ATTACK SURFACE) -->
      ${Array.isArray(results.subdomains) && results.subdomains.length > 0 ? `
      <div class="results-section">
        <div class="section-title-row">
          <h3>🛰️ ${t('Discovered Subdomains & Attack Surface', 'Subdominios Descubiertos & Superficie de Ataque')} (${results.subdomains.length})</h3>
          <span class="section-subtitle-tag">${t('Pre-production, administrative & service endpoints', 'Endpoints de preproducción, administración y servicios')}</span>
        </div>
        <div class="subdomains-grid">
          ${results.subdomains.map(sub => `
            <div class="subdomain-card ${sub.isDev ? 'subdomain-dev' : ''}">
              <div class="subdomain-header">
                <span class="subdomain-name">${sub.fqdn}</span>
                ${sub.isDev ? `<span class="subdomain-dev-badge">⚠️ ${t('Pre-prod / Admin', 'Pruebas / Admin')}</span>` : `<span class="subdomain-live-badge">✓ Active</span>`}
              </div>
              <span class="subdomain-ip">IP: ${(sub.ips || []).join(', ')}</span>
            </div>
          `).join('')}
        </div>
      </div>
      ` : ''}

      <!-- TLS/SSL & DEEP CRYPTOGRAPHIC AUDIT -->
      ${results.tls ? `
      <div class="results-section">
        <h3>🔒 ${t('TLS / SSL & Cryptographic Suite Audit', 'Auditoría TLS / SSL y Criptografía')}</h3>
        <div class="tls-info">
          <div class="tls-item">
            <span class="tls-label">${t('Valid', 'Válido')}</span>
            <span class="tls-value ${results.tls.valid ? 'tls-ok' : 'tls-bad'}">${results.tls.valid ? '✓ Yes' : '✕ No'}</span>
          </div>
          ${results.tls.protocol ? `<div class="tls-item"><span class="tls-label">${t('Protocol', 'Protocolo')}</span><span class="tls-value">${results.tls.protocol}</span></div>` : ''}
          ${results.deepTLS && results.deepTLS.cipherName ? `<div class="tls-item"><span class="tls-label">${t('Cipher Suite', 'Cifrado')}</span><span class="tls-value ${results.deepTLS.isWeakCipher ? 'tls-bad' : 'tls-ok'}" style="font-size: var(--fs-xs);">${results.deepTLS.cipherName}</span></div>` : ''}
          ${results.deepTLS && results.deepTLS.keyBits ? `<div class="tls-item"><span class="tls-label">${t('Key Length', 'Longitud Clave')}</span><span class="tls-value">${results.deepTLS.keyBits} bits</span></div>` : ''}
          ${results.deepTLS && results.deepTLS.alpnProtocol ? `<div class="tls-item"><span class="tls-label">ALPN / HTTP</span><span class="tls-value tls-ok">${results.deepTLS.alpnProtocol.toUpperCase()}</span></div>` : ''}
          ${results.tls.issuer ? `<div class="tls-item"><span class="tls-label">${t('Issuer', 'Emisor')}</span><span class="tls-value">${results.tls.issuer}</span></div>` : ''}
          ${results.tls.daysUntilExpiry !== null && results.tls.daysUntilExpiry !== undefined ? `<div class="tls-item"><span class="tls-label">${t('Expires in', 'Expira en')}</span><span class="tls-value ${results.tls.daysUntilExpiry < 30 ? 'tls-bad' : 'tls-ok'}">${results.tls.daysUntilExpiry} ${t('days', 'días')}</span></div>` : ''}
        </div>
      </div>
      ` : ''}

      <!-- COOKIES -->
      ${cookies.length > 0 ? `
      <div class="results-section">
        <h3>🍪 Cookies</h3>
        <div class="cookies-table">
          <div class="cookie-header">
            <span>${t('Name', 'Nombre')}</span>
            <span>HttpOnly</span>
            <span>Secure</span>
            <span>SameSite</span>
          </div>
          ${cookies.map(c => `
            <div class="cookie-row">
              <span class="cookie-name">${c.name}</span>
              <span class="${c.httpOnly ? 'flag-ok' : 'flag-bad'}">${c.httpOnly ? '✓' : '✕'}</span>
              <span class="${c.secure ? 'flag-ok' : 'flag-bad'}">${c.secure ? '✓' : '✕'}</span>
              <span class="${c.sameSite && c.sameSite !== 'none' ? 'flag-ok' : 'flag-bad'}">${c.sameSite || '—'}</span>
            </div>
          `).join('')}
        </div>
      </div>
      ` : ''}

      <!-- FINDINGS -->
      ${findings.length > 0 ? `
      <div class="results-section">
        <h3>📋 ${t('Findings', 'Hallazgos')} (${findings.length})</h3>
        <div class="findings-list">
          ${['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(sev =>
            findings.filter(f => f.severity === sev).map(finding => `
              <div class="finding-item" style="--sev-color: ${severityColors[finding.severity] || '#64748b'}">
                <div class="finding-item-header">
                  <span class="finding-sev-badge" style="background: ${severityColors[finding.severity] || '#64748b'}20; color: ${severityColors[finding.severity] || '#64748b'}">
                    ${severityLabel(finding.severity)}
                  </span>
                  <h4>${lang === 'es' && finding.title_es ? finding.title_es : finding.title}</h4>
                </div>
                <p>${lang === 'es' && finding.description_es ? finding.description_es : (finding.description_en || '')}</p>
                ${finding.fix_en || finding.fix_es ? `
                  <div class="finding-fix">
                    <strong>💡 ${t('Fix', 'Solución')}:</strong> ${lang === 'es' && finding.fix_es ? finding.fix_es : (finding.fix_en || '')}
                  </div>
                ` : ''}
              </div>
            `).join('')
          ).join('')}
        </div>
      </div>
      ` : ''}

      <!-- SECURITY HEADERS TABLE -->
      <div class="results-section">
        <h3>🛡️ ${t('Security Headers', 'Headers de Seguridad')}</h3>
        <div class="headers-table">
          ${headersSecurity.map(h => `
            <div class="header-row header-ok">
              <span class="header-status">✓</span>
              <span class="header-name">${h.name}</span>
              <span class="header-value">${(h.value || '').length > 60 ? (h.value || '').substring(0, 60) + '...' : (h.value || '')}</span>
            </div>
          `).join('')}
          ${headersMissing.map(h => `
            <div class="header-row header-missing">
              <span class="header-status">✕</span>
              <span class="header-name">${h.name}</span>
              <span class="header-value missing-label">${t('Missing', 'Ausente')}</span>
            </div>
          `).join('')}
        </div>
      </div>

      <!-- DYNAMIC EXECUTIVE SECURITY REPORT -->
      ${results.executiveSummary ? `
      <div class="results-section executive-summary-section">
        <div class="exec-header">
          <div>
            <h3>📑 ${t('Executive Security Summary', 'Resumen Ejecutivo de Seguridad')}</h3>
            <p class="exec-subtitle">${t('Contextual evaluation generated specifically for this application', 'Evaluación contextual generada específicamente para esta aplicación')}</p>
          </div>
          <span class="exec-badge">🎯 ${t('Tailored Diagnosis', 'Diagnóstico Personalizado')}</span>
        </div>

        <div class="exec-card">
          <div class="exec-narrative">
            ${(lang === 'es' ? results.executiveSummary.narrative_es : results.executiveSummary.narrative_en)
              .split('\n\n')
              .map(p => `<p class="exec-p">${p.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')}</p>`)
              .join('')}
          </div>

          ${results.executiveSummary.strengths_es && results.executiveSummary.strengths_es.length > 0 ? `
          <div class="exec-strengths-box">
            <h4>✅ ${t('Observed Security Strengths', 'Fortalezas de Seguridad Observadas')}</h4>
            <ul class="exec-strengths-list">
              ${(lang === 'es' ? results.executiveSummary.strengths_es : results.executiveSummary.strengths_en)
                .map(s => `<li><span class="strength-check">✓</span> <span>${s}</span></li>`)
                .join('')}
            </ul>
          </div>
          ` : ''}

          ${results.executiveSummary.actionPlan && results.executiveSummary.actionPlan.length > 0 ? `
          <div class="exec-actions-box">
            <h4>🎯 ${t('Prioritized Remediation Roadmap', 'Hoja de Ruta Priorizada de Corrección')}</h4>
            <div class="action-plan-list">
              ${results.executiveSummary.actionPlan.map(item => `
                <div class="action-plan-item">
                  <span class="action-priority-tag priority-${item.priority.substring(0, 2).toLowerCase()}">${lang === 'es' ? item.priority : item.priority_en}</span>
                  <div class="action-plan-text">
                    <strong>${lang === 'es' ? item.title_es : item.title_en}</strong>
                    <p>${lang === 'es' ? item.action_es : item.action_en}</p>
                  </div>
                </div>
              `).join('')}
            </div>
          </div>
          ` : ''}
        </div>
      </div>
      ` : ''}

    </div>
  `;

  // Save to history
  saveScanToHistory(results);
}

// ==========================================
// HISTORY MANAGER (LOCALSTORAGE)
// ==========================================
function saveScanToHistory(results) {
  if (!results || !results.url) return;
  try {
    const raw = localStorage.getItem('canary_scan_history');
    let history = raw ? JSON.parse(raw) : [];

    // Filter out previous duplicate of same URL to place latest on top
    history = history.filter(h => h.url !== results.url);

    history.unshift({
      url: results.url,
      score: results.score,
      rating: results.rating,
      summary: results.summary,
      techCount: (results.technologies || []).length,
      timestamp: new Date().toISOString(),
    });

    // Keep up to 25 latest scans
    if (history.length > 25) history = history.slice(0, 25);
    localStorage.setItem('canary_scan_history', JSON.stringify(history));
  } catch {}
}

function renderHistoryUI() {
  const container = document.getElementById('history-body');
  if (!container) return;

  const raw = localStorage.getItem('canary_scan_history');
  const history = raw ? JSON.parse(raw) : [];

  if (history.length === 0) {
    container.innerHTML = `
      <div style="text-align: center; padding: 40px 20px; color: var(--text-tertiary);">
        <p style="font-size: 2rem; margin-bottom: 10px;">📜</p>
        <p style="font-size: var(--fs-base); font-weight: 600;">No hay escaneos guardados aún</p>
        <p style="font-size: var(--fs-xs);">Escanea cualquier página web para comenzar a registrar el historial y la evolución de seguridad.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
      <span style="font-size: var(--fs-xs); color: var(--text-tertiary);">${history.length} escaneos registrados</span>
      <button id="clear-history-btn" class="btn" style="padding: 4px 10px; font-size: var(--fs-xs); background: rgba(239,68,68,0.1); color: #ef4444; border: 1px solid rgba(239,68,68,0.25);">🗑️ Borrar Historial</button>
    </div>
    <div class="history-list" style="display: flex; flex-direction: column; gap: 10px;">
      ${history.map(item => `
        <div class="history-item" style="display: flex; justify-content: space-between; align-items: center; padding: 12px 16px; background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: var(--radius-sm);">
          <div style="display: flex; align-items: center; gap: 12px;">
            <span class="rating-badge rating-${item.rating || 'C'}" style="font-size: 0.9rem; padding: 4px 10px;">${item.score}/100</span>
            <div>
              <strong style="font-size: var(--fs-sm); color: var(--text-primary); word-break: break-all;">${item.url}</strong>
              <div style="font-size: var(--fs-xs); color: var(--text-tertiary); margin-top: 2px;">
                <span>🕒 ${new Date(item.timestamp).toLocaleString()}</span> • 
                <span>📦 ${item.techCount} tecnologías</span> • 
                <span style="color: ${item.summary && item.summary.critical > 0 ? '#ef4444' : '#22c55e'};">${item.summary && item.summary.critical > 0 ? `🚨 ${item.summary.critical} críticos` : '✓ 0 críticos'}</span>
              </div>
            </div>
          </div>
          <button class="btn btn-primary rescan-btn" data-url="${item.url}" style="padding: 6px 12px; font-size: var(--fs-xs);">🔄 Re-escanear</button>
        </div>
      `).join('')}
    </div>
  `;

  // Attach rescan handlers
  container.querySelectorAll('.rescan-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const url = btn.getAttribute('data-url');
      const histModal = document.getElementById('history-modal');
      if (histModal) histModal.classList.remove('active');
      const scanInput = document.getElementById('scan-url-input');
      if (scanInput) scanInput.value = url;
      const scanBtn = document.getElementById('scan-btn');
      if (scanBtn) scanBtn.click();
    });
  });

  // Attach clear history
  const clearBtn = document.getElementById('clear-history-btn');
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      localStorage.removeItem('canary_scan_history');
      renderHistoryUI();
    });
  }
}

// ==========================================
// SIDE-BY-SIDE COMPARATOR
// ==========================================
async function runComparison(url1, url2) {
  const container = document.getElementById('compare-results-container');
  if (!container) return;

  container.innerHTML = `
    <div style="text-align: center; padding: 30px;">
      <div class="spinner" style="width: 40px; height: 40px; margin: 0 auto 15px;"></div>
      <p style="font-weight: 600;">Analizando y contrastando ambos sitios web en paralelo...</p>
      <p style="font-size: var(--fs-xs); color: var(--text-tertiary);">${url1} vs ${url2}</p>
    </div>
  `;

  try {
    const [res1, res2] = await Promise.all([
      runScan(url1),
      runScan(url2),
    ]);

    const winner = res1.score > res2.score ? url1 : res2.score > res1.score ? url2 : 'Empate';

    container.innerHTML = `
      <div class="compare-verdict" style="padding: 14px; background: rgba(34,197,94,0.06); border: 1px solid rgba(34,197,94,0.25); border-radius: var(--radius-sm); text-align: center; margin-bottom: 20px;">
        <span style="font-size: var(--fs-xs); text-transform: uppercase; letter-spacing: 0.05em; color: #22c55e; font-weight: 700;">Ganador de Seguridad</span>
        <h3 style="color: var(--text-primary); font-size: var(--fs-base); margin-top: 4px;">🏆 ${winner === 'Empate' ? 'Empate Técnico' : winner}</h3>
      </div>

      <div class="compare-table-wrapper" style="overflow-x: auto;">
        <table style="width: 100%; border-collapse: collapse; font-size: var(--fs-xs);">
          <thead>
            <tr style="border-bottom: 2px solid var(--border-color);">
              <th style="padding: 10px; text-align: left;">Métrica de Seguridad</th>
              <th style="padding: 10px; text-align: center; background: rgba(255,215,0,0.04);">${url1}</th>
              <th style="padding: 10px; text-align: center; background: rgba(59,130,246,0.04);">${url2}</th>
            </tr>
          </thead>
          <tbody>
            <tr style="border-bottom: 1px solid var(--border-color);">
              <td style="padding: 10px; font-weight: 700;">Security Score</td>
              <td style="padding: 10px; text-align: center;"><span class="rating-badge rating-${res1.rating || 'C'}">${res1.score}/100</span></td>
              <td style="padding: 10px; text-align: center;"><span class="rating-badge rating-${res2.rating || 'C'}">${res2.score}/100</span></td>
            </tr>
            <tr style="border-bottom: 1px solid var(--border-color);">
              <td style="padding: 10px;">Fallas Críticas (P0)</td>
              <td style="padding: 10px; text-align: center; color: ${res1.summary && res1.summary.critical > 0 ? '#ef4444' : '#22c55e'}; font-weight: 700;">${res1.summary ? res1.summary.critical : 0}</td>
              <td style="padding: 10px; text-align: center; color: ${res2.summary && res2.summary.critical > 0 ? '#ef4444' : '#22c55e'}; font-weight: 700;">${res2.summary ? res2.summary.critical : 0}</td>
            </tr>
            <tr style="border-bottom: 1px solid var(--border-color);">
              <td style="padding: 10px;">Cifrado HTTPS / TLS</td>
              <td style="padding: 10px; text-align: center;">${res1.tls && res1.tls.valid ? '✓ Válido (' + (res1.tls.protocol || 'TLS') + ')' : '✕ Inseguro'}</td>
              <td style="padding: 10px; text-align: center;">${res2.tls && res2.tls.valid ? '✓ Válido (' + (res2.tls.protocol || 'TLS') + ')' : '✕ Inseguro'}</td>
            </tr>
            <tr style="border-bottom: 1px solid var(--border-color);">
              <td style="padding: 10px;">Protección WAF</td>
              <td style="padding: 10px; text-align: center;">${res1.waf && res1.waf.length > 0 ? '✓ ' + res1.waf.map(w => w.name).join(', ') : '✕ Sin WAF'}</td>
              <td style="padding: 10px; text-align: center;">${res2.waf && res2.waf.length > 0 ? '✓ ' + res2.waf.map(w => w.name).join(', ') : '✕ Sin WAF'}</td>
            </tr>
            <tr style="border-bottom: 1px solid var(--border-color);">
              <td style="padding: 10px;">Defensa Clickjacking</td>
              <td style="padding: 10px; text-align: center;">${res1.clickjacking && !res1.clickjacking.canBeFramed ? '✓ Protegido' : '⚠️ Vulnerable'}</td>
              <td style="padding: 10px; text-align: center;">${res2.clickjacking && !res2.clickjacking.canBeFramed ? '✓ Protegido' : '⚠️ Vulnerable'}</td>
            </tr>
            <tr style="border-bottom: 1px solid var(--border-color);">
              <td style="padding: 10px;">DNS SPF / DMARC</td>
              <td style="padding: 10px; text-align: center;">${res1.dns && res1.dns.hasSPF && res1.dns.hasDMARC ? '✓ Configurado' : '⚠️ Incompleto'}</td>
              <td style="padding: 10px; text-align: center;">${res2.dns && res2.dns.hasSPF && res2.dns.hasDMARC ? '✓ Configurado' : '⚠️ Incompleto'}</td>
            </tr>
            <tr style="border-bottom: 1px solid var(--border-color);">
              <td style="padding: 10px;">Tecnologías Detectadas</td>
              <td style="padding: 10px; text-align: center;">${(res1.technologies || []).length} componentes</td>
              <td style="padding: 10px; text-align: center;">${(res2.technologies || []).length} componentes</td>
            </tr>
          </tbody>
        </table>
      </div>
    `;
  } catch (err) {
    container.innerHTML = `
      <div style="padding: 15px; background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.25); color: #ef4444; border-radius: var(--radius-sm); text-align: center;">
        Error al comparar sitios: ${err.message}
      </div>
    `;
  }
}

// ==========================================
// INITIALIZE SCANNER UI
// ==========================================
function initScannerUI() {
  const scanBtn = document.getElementById('scan-btn');
  const scanInput = document.getElementById('scan-url-input');

  if (scanBtn && scanInput) {
    async function handleScan() {
      let url = scanInput.value.trim();
      if (!url) {
        scanInput.focus();
        return;
      }

      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url;
        scanInput.value = url;
      }

      showLoading();

      try {
        const results = await runScan(url);
        renderResults(results);
      } catch (err) {
        showError(err.message || t('Scan failed. Check URL and try again.', 'Error en el escaneo. Revisa la URL e inténtalo de nuevo.'));
      }
    }

    scanBtn.addEventListener('click', handleScan);
    scanInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        handleScan();
      }
    });
  }

  // History modal handlers
  const openHistBtn = document.getElementById('open-history-btn');
  const histModal = document.getElementById('history-modal');
  const histCloseBtn = document.getElementById('history-close-btn');
  const histBackdrop = document.getElementById('history-backdrop');

  if (openHistBtn && histModal) {
    openHistBtn.addEventListener('click', () => {
      renderHistoryUI();
      histModal.classList.add('active');
    });
    if (histCloseBtn) histCloseBtn.addEventListener('click', () => histModal.classList.remove('active'));
    if (histBackdrop) histBackdrop.addEventListener('click', () => histModal.classList.remove('active'));
  }

  // Compare modal handlers
  const openCompBtn = document.getElementById('open-compare-btn');
  const compModal = document.getElementById('compare-modal');
  const compCloseBtn = document.getElementById('compare-close-btn');
  const compBackdrop = document.getElementById('compare-backdrop');
  const startCompBtn = document.getElementById('start-compare-btn');
  const compUrl1 = document.getElementById('compare-url-1');
  const compUrl2 = document.getElementById('compare-url-2');

  if (openCompBtn && compModal) {
    openCompBtn.addEventListener('click', () => compModal.classList.add('active'));
    if (compCloseBtn) compCloseBtn.addEventListener('click', () => compModal.classList.remove('active'));
    if (compBackdrop) compBackdrop.addEventListener('click', () => compModal.classList.remove('active'));

    if (startCompBtn && compUrl1 && compUrl2) {
      startCompBtn.addEventListener('click', () => {
        let u1 = compUrl1.value.trim();
        let u2 = compUrl2.value.trim();
        if (!u1 || !u2) {
          alert('Por favor ingresa ambas URLs para comparar.');
          return;
        }
        if (!u1.startsWith('http://') && !u1.startsWith('https://')) u1 = 'https://' + u1;
        if (!u2.startsWith('http://') && !u2.startsWith('https://')) u2 = 'https://' + u2;
        compUrl1.value = u1;
        compUrl2.value = u2;
        runComparison(u1, u2);
      });
    }
  }
}

export { initScannerUI };
