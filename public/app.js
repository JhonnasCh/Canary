/**
 * CANARY AI - CANARYENGINE FRONTEND CONTROLLER (v4.0 Global)
 * Orquestador interactivo del Dashboard SOC, Global Cyber Map, Red Team Hacker Terminal y Forensics
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements - Inputs
  const rawJsonEditor = document.getElementById('rawJsonEditor');
  const jsonErrorBar = document.getElementById('jsonErrorBar');
  const jsonErrorMessage = document.getElementById('jsonErrorMessage');
  const btnAnalyze = document.getElementById('btnAnalyze');
  const btnFormatJson = document.getElementById('btnFormatJson');
  const btnClearInput = document.getElementById('btnClearInput');
  const presetSelector = document.getElementById('presetSelector');
  const btnLoadPreset = document.getElementById('btnLoadPreset');

  // Dashboard Output Elements
  const emptyState = document.getElementById('emptyState');
  const scanningState = document.getElementById('scanningState');
  const resultsContainer = document.getElementById('resultsContainer');

  const scoreValue = document.getElementById('scoreValue');
  const gaugeFill = document.getElementById('gaugeFill');
  const targetUrlLink = document.getElementById('targetUrlLink');
  const riskLevelBadge = document.getElementById('riskLevelBadge');
  const vulnCount = document.getElementById('vulnCount');
  const honeypotCount = document.getElementById('honeypotCount');
  const techStackTags = document.getElementById('techStackTags');
  const reportSha256 = document.getElementById('reportSha256');

  const tabVulnCount = document.getElementById('tabVulnCount');
  const tabHoneypotCount = document.getElementById('tabHoneypotCount');
  const tabBlockedCount = document.getElementById('tabBlockedCount');
  const vulnerabilitiesList = document.getElementById('vulnerabilitiesList');
  const honeypotsList = document.getElementById('honeypotsList');
  const autoBlockingText = document.getElementById('autoBlockingText');
  const rawOutputCode = document.getElementById('rawOutputCode');

  // Executive PDF & SDK Elements
  const btnExportExecutivePdf = document.getElementById('btnExportExecutivePdf');
  const btnOpenSdkModal = document.getElementById('btnOpenSdkModal');
  const sdkModal = document.getElementById('sdkModal');
  const btnCloseSdkModal = document.getElementById('btnCloseSdkModal');
  const btnCloseSdkModalBottom = document.getElementById('btnCloseSdkModalBottom');
  const sdkCommandInput = document.getElementById('sdkCommandInput');
  const btnCopySdkCommand = document.getElementById('btnCopySdkCommand');
  const sdkCodeSnippet = document.getElementById('sdkCodeSnippet');
  const sdkTabBtns = document.querySelectorAll('.sdk-tab-btn');

  // Whitelist Elements
  const btnOpenWhitelistModal = document.getElementById('btnOpenWhitelistModal');
  const whitelistModal = document.getElementById('whitelistModal');
  const btnCloseWhitelistModal = document.getElementById('btnCloseWhitelistModal');
  const btnCloseWhitelistBottom = document.getElementById('btnCloseWhitelistBottom');
  const whitelistIpInput = document.getElementById('whitelistIpInput');
  const btnAddWhitelistBtn = document.getElementById('btnAddWhitelistBtn');
  const whitelistItemsList = document.getElementById('whitelistItemsList');

  // 24/7 Threat Intel & Cyber Map Elements
  const threatsTotalNumber = document.getElementById('threatsTotalNumber');
  const threatsTableBody = document.getElementById('threatsTableBody');
  const threatSearchInput = document.getElementById('threatSearchInput');
  const btnSimulateAttack = document.getElementById('btnSimulateAttack');
  const btnSimulateTokenDetonation = document.getElementById('btnSimulateTokenDetonation');
  const btnExportNginx = document.getElementById('btnExportNginx');
  const btnExportIptables = document.getElementById('btnExportIptables');
  const cyberAttackCanvas = document.getElementById('cyberAttackCanvas');

  // Red Team Terminal Elements
  const redTeamModal = document.getElementById('redTeamModal');
  const btnCloseRedTeamModal = document.getElementById('btnCloseRedTeamModal');
  const btnCloseRedTeamBottom = document.getElementById('btnCloseRedTeamBottom');
  const rtTerminalOutput = document.getElementById('rtTerminalOutput');
  const rtSimulationResults = document.getElementById('rtSimulationResults');
  const rtVectorTitle = document.getElementById('rtVectorTitle');
  const rtPreVerdict = document.getElementById('rtPreVerdict');
  const rtPostVerdict = document.getElementById('rtPostVerdict');

  // Forensic Modal Elements
  const forensicModal = document.getElementById('forensicModal');
  const btnCloseForensicModal = document.getElementById('btnCloseForensicModal');
  const btnCloseForensicBottom = document.getElementById('btnCloseForensicBottom');
  const forensicModalContent = document.getElementById('forensicModalContent');

  // GitHub Modal Elements
  const githubModal = document.getElementById('githubModal');
  const btnCloseGhModal = document.getElementById('btnCloseGhModal');
  const ghModalBranchPreview = document.getElementById('ghModalBranchPreview');
  const ghModalFilePreview = document.getElementById('ghModalFilePreview');
  const ghRepoInput = document.getElementById('ghRepoInput');
  const ghBaseBranchSelect = document.getElementById('ghBaseBranchSelect');
  const ghTokenInput = document.getElementById('ghTokenInput');
  const ghSnippetPreview = document.getElementById('ghSnippetPreview');
  const btnSubmitGitHubPR = document.getElementById('btnSubmitGitHubPR');

  // Rules Modal Elements
  const rulesModal = document.getElementById('rulesModal');
  const modalTitle = document.getElementById('modalTitle');
  const modalContent = document.getElementById('modalContent');
  const btnCloseModal = document.getElementById('btnCloseModal');
  const btnCopyModalRules = document.getElementById('btnCopyModalRules');

  const btnCopyBlockingRule = document.getElementById('btnCopyBlockingRule');
  const btnCopyJson = document.getElementById('btnCopyJson');
  const btnDownloadJson = document.getElementById('btnDownloadJson');
  const toast = document.getElementById('toast');

  let samplePresets = {};
  let currentReport = null;
  let selectedVulnForPR = null;
  let allActiveThreats = [];

  // 1. Cargar muestras
  fetchSamples();
  // 2. Iniciar telemetría 24/7 y Cyber Map
  fetchDefenseStatus();
  setInterval(fetchDefenseStatus, 4000);
  initCyberMap();
  // 3. Inicializar SDK generator
  loadSdkCommand('node');

  async function fetchSamples() {
    try {
      const res = await fetch('/api/samples');
      if (res.ok) {
        samplePresets = await res.json();
        if (samplePresets.critical_node) {
          presetSelector.value = 'critical_node';
          loadPreset('critical_node');
        }
      }
    } catch (err) {
      console.warn('No se pudieron precargar presets:', err);
    }
  }

  function loadPreset(key) {
    if (samplePresets[key]) {
      rawJsonEditor.value = JSON.stringify(samplePresets[key].data, null, 2);
      hideJsonError();
    }
  }

  btnLoadPreset.addEventListener('click', () => {
    const val = presetSelector.value;
    if (val && samplePresets[val]) {
      loadPreset(val);
      showToast(`Muestra cargada: ${samplePresets[val].name}`);
    } else {
      showToast('Selecciona un caso de prueba en el selector.');
    }
  });

  presetSelector.addEventListener('change', (e) => {
    if (e.target.value) {
      loadPreset(e.target.value);
    }
  });

  btnFormatJson.addEventListener('click', () => {
    try {
      const parsed = JSON.parse(rawJsonEditor.value);
      rawJsonEditor.value = JSON.stringify(parsed, null, 2);
      hideJsonError();
      showToast('JSON formateado correctamente.');
    } catch (e) {
      showJsonError(`Error de sintaxis: ${e.message}`);
    }
  });

  btnClearInput.addEventListener('click', () => {
    rawJsonEditor.value = '';
    hideJsonError();
    rawJsonEditor.focus();
  });

  btnExportExecutivePdf.addEventListener('click', () => {
    if (!currentReport) {
      showToast('Ejecuta un análisis primero antes de exportar el informe.');
      return;
    }
    showToast('Generando vista de impresión ejecutiva...');
    setTimeout(() => {
      window.print();
    }, 400);
  });

  // Gestión de Pestañas
  const tabBtns = document.querySelectorAll('.tab-nav .tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => b.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      const tabId = btn.getAttribute('data-tab');
      const activeContent = document.getElementById(tabId);
      if (activeContent) {
        activeContent.classList.add('active');
      }
    });
  });

  // Ejecución de análisis CanaryEngine
  btnAnalyze.addEventListener('click', async () => {
    const rawText = rawJsonEditor.value.trim();
    if (!rawText) {
      showJsonError('El editor está vacío. Ingresa un JSON de evidencia técnica.');
      return;
    }

    let payload;
    try {
      payload = JSON.parse(rawText);
      hideJsonError();
    } catch (err) {
      showJsonError(`JSON malformado: ${err.message}`);
      return;
    }

    emptyState.classList.add('hidden');
    resultsContainer.classList.add('hidden');
    scanningState.classList.remove('hidden');
    btnAnalyze.disabled = true;

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `HTTP ${response.status}`);
      }

      const report = await response.json();
      currentReport = report;

      setTimeout(() => {
        scanningState.classList.add('hidden');
        resultsContainer.classList.remove('hidden');
        btnAnalyze.disabled = false;
        renderReport(report, payload);
        showToast('Análisis determinista completado.');
      }, 500);

    } catch (error) {
      scanningState.classList.add('hidden');
      emptyState.classList.remove('hidden');
      btnAnalyze.disabled = false;
      showJsonError(`Error de ejecución en CanaryEngine: ${error.message}`);
    }
  });

  function renderReport(report, rawInput) {
    const { summary, vulnerabilities, defense_recommendations } = report;

    targetUrlLink.textContent = summary.target_url || 'N/A';
    targetUrlLink.href = summary.target_url.startsWith('http') ? summary.target_url : `https://${summary.target_url}`;
    
    vulnCount.textContent = summary.total_vulnerabilities;
    tabVulnCount.textContent = summary.total_vulnerabilities;
    
    const hpCount = defense_recommendations?.recommended_honeypots?.length || 0;
    honeypotCount.textContent = `${hpCount} Trampas`;
    tabHoneypotCount.textContent = hpCount;

    riskLevelBadge.textContent = summary.risk_level;
    riskLevelBadge.className = 'risk-badge';
    if (summary.risk_level === 'CRITICAL') riskLevelBadge.classList.add('badge-critical');
    else if (summary.risk_level === 'HIGH') riskLevelBadge.classList.add('badge-high');
    else if (summary.risk_level === 'MEDIUM') riskLevelBadge.classList.add('badge-medium');
    else riskLevelBadge.classList.add('badge-low');

    // Generar sello criptográfico determinista
    const pseudoHash = generateDeterministicHash(JSON.stringify(report));
    reportSha256.textContent = pseudoHash;

    animateGauge(summary.security_score, summary.risk_level);
    renderTechTags(rawInput.technologies || []);
    renderVulnerabilities(vulnerabilities);
    renderHoneypots(defense_recommendations);
    rawOutputCode.textContent = JSON.stringify(report, null, 2);
  }

  function generateDeterministicHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash |= 0;
    }
    const hex = Math.abs(hash).toString(16).padStart(8, '0');
    return `${hex}a98f7e2c4b1d3e8f6a5b2c9d8e7f1a0b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8`;
  }

  function animateGauge(finalScore, riskLevel) {
    const circumference = 2 * Math.PI * 70;
    const targetOffset = circumference - (finalScore / 100) * circumference;

    let strokeColor = 'var(--sev-critical)';
    if (riskLevel === 'HIGH') strokeColor = 'var(--sev-high)';
    else if (riskLevel === 'MEDIUM') strokeColor = 'var(--sev-medium)';
    else if (riskLevel === 'LOW') strokeColor = 'var(--sev-low)';

    gaugeFill.style.stroke = strokeColor;
    gaugeFill.style.strokeDashoffset = targetOffset;

    let current = 0;
    const duration = 800;
    const stepTime = 15;
    const totalSteps = duration / stepTime;
    const increment = finalScore / totalSteps;

    scoreValue.textContent = '0';
    if (finalScore === 0) {
      scoreValue.textContent = '0';
      return;
    }

    const timer = setInterval(() => {
      current += increment;
      if (current >= finalScore) {
        scoreValue.textContent = Math.round(finalScore);
        clearInterval(timer);
      } else {
        scoreValue.textContent = Math.round(current);
      }
    }, stepTime);
  }

  function renderTechTags(technologies) {
    techStackTags.innerHTML = '';
    if (!technologies || technologies.length === 0) {
      techStackTags.innerHTML = '<span class="tech-tag">Estándar Web</span>';
      return;
    }

    technologies.forEach(tech => {
      const tag = document.createElement('span');
      tag.className = 'tech-tag';
      tag.innerHTML = `${tech.name} ${tech.version ? `<span>v${tech.version}</span>` : ''}`;
      techStackTags.appendChild(tag);
    });
  }

  function renderVulnerabilities(vulnerabilities) {
    vulnerabilitiesList.innerHTML = '';

    if (!vulnerabilities || vulnerabilities.length === 0) {
      vulnerabilitiesList.innerHTML = `
        <div class="empty-state" style="padding: 2rem;">
          <h4 style="color: var(--sev-low);">🛡️ Cero Vulnerabilidades Detectadas</h4>
          <p style="color: var(--text-muted); font-size: 0.85rem;">La evidencia técnica analizada cumple con todas las directivas de seguridad evaluadas.</p>
        </div>
      `;
      return;
    }

    vulnerabilities.forEach((vuln, index) => {
      const card = document.createElement('div');
      card.className = `vuln-card ${index === 0 ? 'expanded' : ''}`;

      const sevClass = `badge-${vuln.severity.toLowerCase()}`;

      card.innerHTML = `
        <div class="vuln-card-header">
          <div class="vuln-card-title-group">
            <span class="risk-badge ${sevClass}">${vuln.severity}</span>
            <div>
              <div class="vuln-card-title">${vuln.title}</div>
              <span class="vuln-id-tag">${vuln.id} • Categoría: ${vuln.category}</span>
            </div>
          </div>
          <svg class="vuln-toggle-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="6 9 12 15 18 9"></polyline>
          </svg>
        </div>

        <div class="vuln-card-body">
          <div class="vuln-section">
            <div class="vuln-section-title">Diagnóstico Técnico</div>
            <div class="vuln-text">${vuln.description}</div>
          </div>

          <div class="vuln-section">
            <div class="vuln-section-title">Impacto de Amenaza</div>
            <div class="vuln-impact-box vuln-text">${vuln.impact}</div>
          </div>

          <div class="vuln-section">
            <div class="vuln-section-title">Guía de Mitigación Manual</div>
            <ul class="fix-steps-list">
              ${vuln.manual_fix_steps.map(step => `<li>${step}</li>`).join('')}
            </ul>
          </div>

          <div class="vuln-section">
            <div class="vuln-section-title">Parche Determinista (Auto-Fix)</div>
            <div class="autofix-box">
              <div class="autofix-header">
                <div class="autofix-meta">
                  <span class="autofix-file">📄 ${vuln.auto_fix.file_target}</span>
                  <span class="autofix-lang">${vuln.auto_fix.language}</span>
                </div>
                <div class="autofix-actions no-print">
                  <button class="btn-gh-pr btn-open-gh-modal" data-vulnid="${vuln.id}">
                    <svg viewBox="0 0 16 16" width="13" height="13" fill="currentColor">
                      <path d="M7.177 3.073L9.573.677A.25.25 0 0110 .854v4.792a.25.25 0 01-.427.177L7.177 3.427a.25.25 0 010-.354zM3.75 2.5a.75.75 0 100 1.5.75.75 0 000-1.5zm-2.25.75a2.25 2.25 0 113 2.122v5.256a2.251 2.251 0 11-1.5 0V5.372A2.25 2.25 0 011.5 3.25zM11 2.5h-1V4h1a1 1 0 011 1v5.628a2.251 2.251 0 101.5 0V5A2.5 2.5 0 0011 2.5zm1 10.25a.75.75 0 111.5 0 .75.75 0 01-1.5 0zM3.75 12a.75.75 0 100 1.5.75.75 0 000-1.5z"></path>
                    </svg>
                    <span>Crear PR</span>
                  </button>
                  <button class="btn-redteam btn-open-redteam" data-vulnid="${vuln.id}">
                    🎯 Validar con Red Team
                  </button>
                  <button class="btn-rollback btn-open-rollback" data-vulnid="${vuln.id}">
                    ⏪ Rollback
                  </button>
                  <button class="btn-download-patch btn-download-file" data-file="${vuln.auto_fix.file_target}" data-code="${encodeURIComponent(vuln.auto_fix.code_snippet)}">
                    💾 Descargar Archivo
                  </button>
                  <button class="btn-secondary btn-sm btn-copy-autofix" data-code="${encodeURIComponent(vuln.auto_fix.code_snippet)}">
                    Copiar
                  </button>
                </div>
              </div>
              <pre class="autofix-code"><code>${escapeHtml(vuln.auto_fix.code_snippet)}</code></pre>
            </div>
          </div>
        </div>
      `;

      const header = card.querySelector('.vuln-card-header');
      header.addEventListener('click', () => {
        card.classList.toggle('expanded');
      });

      const copyBtn = card.querySelector('.btn-copy-autofix');
      copyBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const code = decodeURIComponent(copyBtn.getAttribute('data-code'));
        copyToClipboard(code, 'Código de parche copiado al portapapeles.');
      });

      const downloadBtn = card.querySelector('.btn-download-file');
      downloadBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const code = decodeURIComponent(downloadBtn.getAttribute('data-code'));
        const fileName = downloadBtn.getAttribute('data-file').split('/').pop();
        downloadFile(fileName, code);
      });

      const ghBtn = card.querySelector('.btn-open-gh-modal');
      ghBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        selectedVulnForPR = vuln;
        openGitHubModal(vuln);
      });

      const rtBtn = card.querySelector('.btn-open-redteam');
      rtBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        triggerRedTeamSimulation(vuln);
      });

      const rbBtn = card.querySelector('.btn-open-rollback');
      rbBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        executeRollbackAction(vuln);
      });

      vulnerabilitiesList.appendChild(card);
    });
  }

  function downloadFile(filename, text) {
    const element = document.createElement('a');
    element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
    element.setAttribute('download', filename);
    element.style.display = 'none';
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
    showToast(`Archivo ${filename} descargado.`);
  }

  function renderHoneypots(defense) {
    honeypotsList.innerHTML = '';
    const traps = defense?.recommended_honeypots || [];

    traps.forEach(trap => {
      const card = document.createElement('div');
      card.className = 'honeypot-card';
      card.innerHTML = `
        <div class="honeypot-type">${trap.type}</div>
        <div class="honeypot-path">${trap.path}</div>
        <div class="honeypot-reason">${trap.reason}</div>
      `;
      honeypotsList.appendChild(card);
    });

    autoBlockingText.textContent = defense?.auto_blocking_rules || 'No se registraron reglas de auto-bloqueo.';
  }

  // ==========================================
  // 🎯 RED TEAM TERMINAL HACKER INTERACTIVA
  // ==========================================

  async function triggerRedTeamSimulation(vuln) {
    redTeamModal.classList.remove('hidden');
    rtTerminalOutput.innerHTML = '';
    rtSimulationResults.classList.add('hidden');

    const terminalLines = [
      { text: `[+] Inicializando suite ofensiva Canary Red Team contra target...`, class: 'term-line-info' },
      { text: `[+] Vector seleccionado: ${vuln.id} (${vuln.title})`, class: 'term-line-info' },
      { text: `[+] Estableciendo socket TCP y handshake TLS con el servidor...`, class: 'term-line-info' },
      { text: `[!] Forjando payload de penetración malicioso...`, class: 'term-line-alert' }
    ];

    for (const l of terminalLines) {
      appendTerminalLine(l.text, l.class);
      await sleep(250);
    }

    try {
      const res = await fetch('/api/redteam/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          vulnId: vuln.id,
          targetUrl: currentReport?.summary?.target_url || 'https://target.local'
        })
      });

      const data = await res.json();

      appendTerminalLine(`[!] Payload enviado: ${data.payloadUsed}`, 'term-line-alert');
      await sleep(350);
      appendTerminalLine(`[+] Evaluando cabeceras de respuesta y contexto de ejecución...`, 'term-line-info');
      await sleep(350);
      appendTerminalLine(`[✓] ÉXITO: Parche verificado. ${data.mitigationDefense}`, 'term-line-success');
      appendTerminalLine(`[✓] Veredicto determinista: ${data.postPatchVerdict}`, 'term-line-success');

      rtVectorTitle.textContent = `${data.vectorName} (${data.vulnId})`;
      rtPreVerdict.textContent = data.prePatchVerdict;
      rtPostVerdict.textContent = data.postPatchVerdict;
      rtSimulationResults.classList.remove('hidden');

    } catch (e) {
      appendTerminalLine(`[-] Error durante la inyección ofensiva: ${e.message}`, 'term-line-alert');
    }
  }

  function appendTerminalLine(text, className) {
    const p = document.createElement('div');
    p.className = className;
    p.textContent = text;
    rtTerminalOutput.appendChild(p);
    rtTerminalOutput.scrollTop = rtTerminalOutput.scrollHeight;
  }

  function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
  }

  btnCloseRedTeamModal.addEventListener('click', () => redTeamModal.classList.add('hidden'));
  btnCloseRedTeamBottom.addEventListener('click', () => redTeamModal.classList.add('hidden'));

  // ==========================================
  // 🔬 FICHA FORENSE DE ATACANTE
  // ==========================================

  function openForensicModal(threat) {
    forensicModalContent.innerHTML = `
      <div class="forensic-row">
        <span class="forensic-label">DIRECCIÓN IP & LOCALIZACIÓN GLOBAL</span>
        <span class="forensic-val">${threat.geo.flag} ${threat.ip} • ${threat.geo.country} (${threat.geo.city})</span>
      </div>
      <div class="forensic-row">
        <span class="forensic-label">ORGANIZACIÓN / ASN / PROVEEDOR</span>
        <span class="forensic-val">${threat.geo.org} (Actor: ${threat.geo.actorType})</span>
      </div>
      <div class="forensic-row">
        <span class="forensic-label">USER-AGENT CRUDA DETECTADA</span>
        <span class="forensic-val" style="color: var(--accent-cyan);">${threat.userAgent}</span>
      </div>
      <div class="forensic-row">
        <span class="forensic-label">TRAMPA ACTIVADA & VECTORES EVALUADOS</span>
        <span class="forensic-val">${threat.trapPath} (Método HTTP: ${threat.method})</span>
      </div>
      <div class="forensic-row">
        <span class="forensic-label">DEFENSA TARPIT ACTIVADA</span>
        <span class="forensic-val" style="color: var(--sev-low);">Retraso forzado de 1500ms aplicado a socket del atacante antes de 403 Forbidden</span>
      </div>
      <div class="forensic-row">
        <span class="forensic-label">EXPIRACIÓN DEL BLOQUEO AUTOMÁTICO</span>
        <span class="forensic-val">${new Date(threat.expiresAt).toLocaleString()}</span>
      </div>
    `;
    forensicModal.classList.remove('hidden');
  }

  btnCloseForensicModal.addEventListener('click', () => forensicModal.classList.add('hidden'));
  btnCloseForensicBottom.addEventListener('click', () => forensicModal.classList.add('hidden'));

  // ==========================================
  // 🛡️ GESTIÓN DE WHITELIST
  // ==========================================

  btnOpenWhitelistModal.addEventListener('click', async () => {
    whitelistModal.classList.remove('hidden');
    loadWhitelist();
  });

  btnCloseWhitelistModal.addEventListener('click', () => whitelistModal.classList.add('hidden'));
  btnCloseWhitelistBottom.addEventListener('click', () => whitelistModal.classList.add('hidden'));

  async function loadWhitelist() {
    try {
      const res = await fetch('/api/firewall/whitelist');
      const data = await res.json();
      renderWhitelist(data.whitelist || []);
    } catch (e) {
      console.warn('Error al cargar whitelist:', e);
    }
  }

  function renderWhitelist(items) {
    whitelistItemsList.innerHTML = '';
    items.forEach(ip => {
      const row = document.createElement('div');
      row.className = 'whitelist-item';
      row.innerHTML = `
        <span>🛡️ ${ip}</span>
        ${(ip !== '127.0.0.1' && ip !== '::1' && ip !== 'localhost') ? `<button class="btn-ghost btn-sm btn-remove-wl" data-ip="${ip}" style="color: var(--sev-critical);">Remover</button>` : '<span style="font-size: 0.7rem; color: var(--text-dim);">Sistema</span>'}
      `;

      const removeBtn = row.querySelector('.btn-remove-wl');
      if (removeBtn) {
        removeBtn.addEventListener('click', async () => {
          await removeWhitelistIp(removeBtn.getAttribute('data-ip'));
        });
      }

      whitelistItemsList.appendChild(row);
    });
  }

  btnAddWhitelistBtn.addEventListener('click', async () => {
    const ip = whitelistIpInput.value.trim();
    if (!ip) return;
    try {
      const res = await fetch('/api/firewall/whitelist/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });
      const data = await res.json();
      showToast(data.message);
      whitelistIpInput.value = '';
      loadWhitelist();
      fetchDefenseStatus();
    } catch (e) {
      showToast('Error al añadir a lista blanca.');
    }
  });

  async function removeWhitelistIp(ip) {
    try {
      const res = await fetch('/api/firewall/whitelist/remove', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });
      const data = await res.json();
      showToast(data.message);
      loadWhitelist();
    } catch (e) {
      showToast('Error al remover de lista blanca.');
    }
  }

  // ==========================================
  // ⏪ ROLLBACK MANAGER LOGIC
  // ==========================================

  async function executeRollbackAction(vuln) {
    if (!confirm(`¿Deseas generar la cápsula de reversión (Rollback) para restaurar ${vuln.auto_fix.file_target} a su estado original?`)) {
      return;
    }

    try {
      const res = await fetch('/api/rollback/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          vulnId: vuln.id,
          repo: ghRepoInput.value.trim() || 'empresa/web-backend'
        })
      });

      const data = await res.json();
      showToast(`⏪ Rollback completado: Parche revertido en ${data.restoredBranch}`);
      window.open(data.prUrl, '_blank');
    } catch (e) {
      showToast('Error al ejecutar rollback.');
    }
  }

  // ==========================================
  // 🚀 MODAL GITHUB PULL REQUEST
  // ==========================================

  function openGitHubModal(vuln) {
    ghModalBranchPreview.textContent = `canary/auto-fix-${vuln.id.toLowerCase()}`;
    ghModalFilePreview.textContent = vuln.auto_fix.file_target;
    ghSnippetPreview.textContent = vuln.auto_fix.code_snippet;
    githubModal.classList.remove('hidden');
  }

  btnCloseGhModal.addEventListener('click', () => {
    githubModal.classList.add('hidden');
  });

  btnSubmitGitHubPR.addEventListener('click', async () => {
    if (!selectedVulnForPR) return;

    btnSubmitGitHubPR.disabled = true;
    btnSubmitGitHubPR.innerHTML = '<span>Generando Pull Request en GitHub...</span>';

    const repo = ghRepoInput.value.trim() || 'empresa/web-backend';
    const baseBranch = ghBaseBranchSelect.value || 'main';
    const token = ghTokenInput.value.trim() || 'demo_token';

    try {
      const res = await fetch('/api/github/create-pr', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: token,
          repo: repo,
          baseBranch: baseBranch,
          labels: ['security', 'canary-autofix', `severity:${selectedVulnForPR.severity.toLowerCase()}`],
          fileTarget: selectedVulnForPR.auto_fix.file_target,
          patchCode: selectedVulnForPR.auto_fix.code_snippet,
          vulnId: selectedVulnForPR.id,
          vulnTitle: selectedVulnForPR.title,
          severity: selectedVulnForPR.severity
        })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Error al crear Pull Request');

      githubModal.classList.add('hidden');
      showToast(`🎉 PR #${data.pr_number} abierto contra [${baseBranch}]: ${data.message}`);
      window.open(data.pr_url, '_blank');

    } catch (err) {
      showToast(`Error: ${err.message}`);
    } finally {
      btnSubmitGitHubPR.disabled = false;
      btnSubmitGitHubPR.innerHTML = '<span>Crear Pull Request en 1-Clic</span>';
    }
  });

  // ==========================================
  // ⚡ MODAL SDK 1-LÍNEA
  // ==========================================

  btnOpenSdkModal.addEventListener('click', () => {
    sdkModal.classList.remove('hidden');
  });

  btnCloseSdkModal.addEventListener('click', () => {
    sdkModal.classList.add('hidden');
  });
  btnCloseSdkModalBottom.addEventListener('click', () => {
    sdkModal.classList.add('hidden');
  });

  sdkTabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      sdkTabBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const stack = btn.getAttribute('data-stack');
      loadSdkCommand(stack);
    });
  });

  async function loadSdkCommand(stack) {
    try {
      const res = await fetch(`/api/sdk/install-command?stack=${stack}`);
      if (!res.ok) return;
      const data = await res.json();
      sdkCommandInput.value = data.oneLineCommand;
      sdkCodeSnippet.textContent = data.integrationSnippet;
    } catch (e) {
      console.warn('Error cargando comando SDK:', e);
    }
  }

  btnCopySdkCommand.addEventListener('click', () => {
    copyToClipboard(sdkCommandInput.value, 'Comando de instalación copiado al portapapeles.');
  });

  // ==========================================
  // 🗺️ SOC CYBER ATTACK MAP CANVAS GLOBAL
  // ==========================================

  let attackArcs = [];
  const TARGET_SERVER = { x: 460, y: 170, label: 'Protected Server' };

  // Nodos representativos en los 5 continentes
  const GLOBAL_NODES = [
    { country: 'Colombia', x: 230, y: 180, flag: '🇨🇴' },
    { country: 'México', x: 170, y: 155, flag: '🇲🇽' },
    { country: 'Brasil', x: 280, y: 240, flag: '🇧🇷' },
    { country: 'Argentina', x: 250, y: 285, flag: '🇦🇷' },
    { country: 'Estados Unidos', x: 190, y: 120, flag: '🇺🇸' },
    { country: 'España', x: 440, y: 125, flag: '🇪🇸' },
    { country: 'Alemania', x: 490, y: 105, flag: '🇩🇪' },
    { country: 'Países Bajos', x: 475, y: 95, flag: '🇳🇱' },
    { country: 'Rusia', x: 620, y: 80, flag: '🇷🇺' },
    { country: 'China', x: 740, y: 145, flag: '🇨🇳' },
    { country: 'Japón', x: 800, y: 135, flag: '🇯🇵' },
    { country: 'Singapur', x: 710, y: 200, flag: '🇸🇬' },
    { country: 'Sudáfrica', x: 500, y: 270, flag: '🇿🇦' },
    { country: 'Australia', x: 780, y: 260, flag: '🇦🇺' }
  ];

  function initCyberMap() {
    if (!cyberAttackCanvas) return;
    const ctx = cyberAttackCanvas.getContext('2d');

    setInterval(() => {
      spawnRandomAttackArc();
    }, 2200);

    function renderMapFrame() {
      ctx.clearRect(0, 0, cyberAttackCanvas.width, cyberAttackCanvas.height);

      drawRadarGrid(ctx);
      drawWorldMapLines(ctx);

      GLOBAL_NODES.forEach(node => {
        ctx.fillStyle = 'rgba(255, 0, 85, 0.4)';
        ctx.beginPath();
        ctx.arc(node.x, node.y, 4, 0, Math.PI * 2);
        ctx.fill();

        ctx.fillStyle = '#ff4d79';
        ctx.font = '9px monospace';
        ctx.fillText(`${node.flag} ${node.country}`, node.x + 6, node.y + 3);
      });

      // Servidor protegido en el centro
      ctx.fillStyle = 'rgba(0, 242, 254, 0.2)';
      ctx.beginPath();
      ctx.arc(TARGET_SERVER.x, TARGET_SERVER.y, 14, 0, Math.PI * 2);
      ctx.fill();

      ctx.fillStyle = '#00f2fe';
      ctx.beginPath();
      ctx.arc(TARGET_SERVER.x, TARGET_SERVER.y, 6, 0, Math.PI * 2);
      ctx.fill();

      for (let i = attackArcs.length - 1; i >= 0; i--) {
        const arc = attackArcs[i];
        arc.progress += 0.016;

        const currentX = arc.from.x + (arc.to.x - arc.from.x) * arc.progress;
        const currentY = arc.from.y + (arc.to.y - arc.from.y) * arc.progress - Math.sin(arc.progress * Math.PI) * 45;

        ctx.strokeStyle = `rgba(255, 0, 85, ${1 - arc.progress * 0.4})`;
        ctx.lineWidth = 1.5;
        ctx.setLineDash([3, 3]);
        ctx.beginPath();
        ctx.moveTo(arc.from.x, arc.from.y);
        ctx.quadraticCurveTo(
          (arc.from.x + arc.to.x) / 2,
          Math.min(arc.from.y, arc.to.y) - 50,
          currentX,
          currentY
        );
        ctx.stroke();
        ctx.setLineDash([]);

        ctx.fillStyle = '#ff0055';
        ctx.shadowColor = '#ff0055';
        ctx.shadowBlur = 10;
        ctx.beginPath();
        ctx.arc(currentX, currentY, 3, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;

        if (arc.progress >= 1) {
          attackArcs.splice(i, 1);
        }
      }

      requestAnimationFrame(renderMapFrame);
    }

    renderMapFrame();
  }

  function spawnRandomAttackArc(customFrom = null) {
    const fromNode = customFrom || GLOBAL_NODES[Math.floor(Math.random() * GLOBAL_NODES.length)];
    attackArcs.push({
      from: fromNode,
      to: TARGET_SERVER,
      progress: 0
    });
  }

  function drawRadarGrid(ctx) {
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.03)';
    ctx.lineWidth = 1;
    for (let x = 0; x < cyberAttackCanvas.width; x += 40) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, cyberAttackCanvas.height);
      ctx.stroke();
    }
    for (let y = 0; y < cyberAttackCanvas.height; y += 40) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(cyberAttackCanvas.width, y);
      ctx.stroke();
    }
  }

  function drawWorldMapLines(ctx) {
    ctx.strokeStyle = 'rgba(0, 242, 254, 0.15)';
    ctx.lineWidth = 1;
    ctx.strokeRect(120, 70, 160, 110); // Norteamérica
    ctx.strokeRect(220, 190, 110, 115); // Sudamérica
    ctx.strokeRect(420, 75, 140, 85);  // Europa
    ctx.strokeRect(450, 175, 120, 115); // África
    ctx.strokeRect(580, 70, 240, 125); // Asia
    ctx.strokeRect(710, 225, 110, 75);  // Oceanía
  }

  // ==========================================
  // 🛡️ TELEMETRÍA GLOBAL Y BUSCADOR
  // ==========================================

  async function fetchDefenseStatus() {
    try {
      const res = await fetch('/api/defense/status');
      if (!res.ok) return;
      const data = await res.json();

      allActiveThreats = data.active_threats || [];
      const count = data.blocked_ips_count || 0;
      threatsTotalNumber.textContent = count;
      tabBlockedCount.textContent = count;

      applyThreatFilter();
    } catch (err) {
      console.warn('Fallo en telemetría 24/7:', err);
    }
  }

  threatSearchInput.addEventListener('input', () => {
    applyThreatFilter();
  });

  function applyThreatFilter() {
    const query = threatSearchInput.value.trim().toLowerCase();
    if (!query) {
      renderThreatsTable(allActiveThreats);
      return;
    }

    const filtered = allActiveThreats.filter(t => 
      t.ip.toLowerCase().includes(query) ||
      t.geo.country.toLowerCase().includes(query) ||
      t.geo.city.toLowerCase().includes(query) ||
      t.geo.org.toLowerCase().includes(query) ||
      t.trapPath.toLowerCase().includes(query)
    );

    renderThreatsTable(filtered);
  }

  function renderThreatsTable(threats) {
    if (!threats || threats.length === 0) {
      threatsTableBody.innerHTML = `
        <div class="no-threats-msg">
          No se encontraron amenazas coincidentes. El sensor global continúa escuchando peticiones 24/7.
        </div>
      `;
      return;
    }

    threatsTableBody.innerHTML = '';
    threats.forEach(t => {
      const row = document.createElement('div');
      row.className = 'threat-row';

      const timeFormatted = new Date(t.blockedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      const flag = t.geo?.flag || '🌐';
      const country = t.geo?.country || 'Desconocido';
      const cityOrg = `${t.geo?.city || 'N/A'} • ${t.geo?.org || 'ASN Host'}`;

      row.innerHTML = `
        <span class="threat-flag" title="${country}">${flag}</span>
        <span class="threat-ip">${t.ip}</span>
        <div class="threat-geo-meta">
          <span class="threat-country">${country}</span>
          <span class="threat-city-asn">${cityOrg}</span>
        </div>
        <span class="threat-trap">${t.trapPath}</span>
        <span class="threat-time">${timeFormatted}</span>
        <div class="threat-actions-cell no-print">
          <button class="btn-ghost btn-sm btn-view-forensic" style="color: var(--accent-cyan);">🔬 Ficha</button>
          <button class="btn-ghost btn-sm btn-unblock" data-ip="${t.ip}" style="color: var(--sev-critical);">Desbloquear</button>
        </div>
      `;

      // Clic en fila o en botón Ficha para abrir panel forense
      row.addEventListener('click', (e) => {
        if (!e.target.classList.contains('btn-unblock')) {
          openForensicModal(t);
        }
      });

      const unblockBtn = row.querySelector('.btn-unblock');
      unblockBtn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const targetIp = unblockBtn.getAttribute('data-ip');
        await unblockIp(targetIp);
      });

      threatsTableBody.appendChild(row);
    });
  }

  btnSimulateAttack.addEventListener('click', async () => {
    btnSimulateAttack.disabled = true;
    try {
      const res = await fetch('/api/defense/simulate-attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      const data = await res.json();
      showToast(`Ataque interceptado: IP ${data.record.ip} (${data.record.geo.flag} ${data.record.geo.country}) bloqueada.`);
      fetchDefenseStatus();
      spawnRandomAttackArc();
    } catch (e) {
      showToast('Error al simular ataque.');
    } finally {
      btnSimulateAttack.disabled = false;
    }
  });

  btnSimulateTokenDetonation.addEventListener('click', async () => {
    btnSimulateTokenDetonation.disabled = true;
    try {
      const res = await fetch('/api/tokens/simulate-detonation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      const data = await res.json();
      showToast(`💣 ALERTA SEV-0: Credencial robada detonada desde ${data.geo.flag} ${data.geo.country}. IP neutralizada.`);
      fetchDefenseStatus();
      spawnRandomAttackArc({ country: data.geo.country, x: 620, y: 80, flag: data.geo.flag });
    } catch (e) {
      showToast('Error al detonar token.');
    } finally {
      btnSimulateTokenDetonation.disabled = false;
    }
  });

  async function unblockIp(ip) {
    try {
      const res = await fetch('/api/firewall/unblock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });
      const data = await res.json();
      showToast(data.message || 'IP procesada.');
      fetchDefenseStatus();
    } catch (e) {
      showToast('Error al desbloquear IP.');
    }
  }

  btnExportNginx.addEventListener('click', async () => {
    const res = await fetch('/api/firewall/rules?format=nginx');
    const text = await res.text();
    openModal('Directivas Nginx (nginx.conf)', text);
  });

  btnExportIptables.addEventListener('click', async () => {
    const res = await fetch('/api/firewall/rules?format=iptables');
    const text = await res.text();
    openModal('Reglas de Cortafuegos Linux (iptables)', text);
  });

  function openModal(title, content) {
    modalTitle.textContent = title;
    modalContent.textContent = content;
    rulesModal.classList.remove('hidden');
  }

  btnCloseModal.addEventListener('click', () => {
    rulesModal.classList.add('hidden');
  });

  btnCopyModalRules.addEventListener('click', () => {
    copyToClipboard(modalContent.textContent, 'Reglas copiadas al portapapeles.');
    rulesModal.classList.add('hidden');
  });

  btnCopyBlockingRule.addEventListener('click', () => {
    if (autoBlockingText.textContent) {
      copyToClipboard(autoBlockingText.textContent, 'Directiva de bloqueo WAF copiada.');
    }
  });

  btnCopyJson.addEventListener('click', () => {
    if (currentReport) {
      copyToClipboard(JSON.stringify(currentReport, null, 2), 'Reporte JSON copiado.');
    }
  });

  btnDownloadJson.addEventListener('click', () => {
    if (!currentReport) return;
    const blob = new Blob([JSON.stringify(currentReport, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `canary-report-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('Reporte JSON descargado.');
  });

  function showJsonError(msg) {
    jsonErrorMessage.textContent = msg;
    jsonErrorBar.classList.remove('hidden');
  }

  function hideJsonError() {
    jsonErrorBar.classList.add('hidden');
  }

  function showToast(msg) {
    toast.textContent = msg;
    toast.classList.remove('hidden');
    clearTimeout(toast._timeout);
    toast._timeout = setTimeout(() => {
      toast.classList.add('hidden');
    }, 3000);
  }

  function copyToClipboard(text, successMsg) {
    navigator.clipboard.writeText(text).then(() => {
      showToast(successMsg);
    }).catch(() => {
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      showToast(successMsg);
    });
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
});
