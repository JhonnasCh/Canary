/**
 * Canary Sentinel - Controlador del Escáner SAST y Auto-Parchador de IA
 */

let currentScanResult = null;
let activePendingPatch = null;

// Inicialización de escuchadores del escáner
document.addEventListener('DOMContentLoaded', () => {
  const codeInput = document.getElementById('source-code-input');
  const btnStartScan = document.getElementById('btn-start-scan');
  const btnClear = document.getElementById('btn-clear-code');
  const btnTriggerUpload = document.getElementById('btn-trigger-upload');
  const fileUploadInput = document.getElementById('file-upload-input');
  const sampleButtons = document.querySelectorAll('.btn-sample');

  // Actualizar contador de líneas al escribir
  codeInput.addEventListener('input', () => {
    updateLinesCounter(codeInput.value);
  });

  // Botones de muestras precargadas
  sampleButtons.forEach(btn => {
    btn.addEventListener('click', async () => {
      const sampleName = btn.getAttribute('data-sample');
      await loadSampleCode(sampleName);
    });
  });

  // Subida de archivos
  btnTriggerUpload.addEventListener('click', () => fileUploadInput.click());
  fileUploadInput.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('sourceFile', file);

    window.showToast?.(`Subiendo ${file.name} para análisis...`, 'info');
    document.getElementById('editor-active-filename').textContent = file.name;

    try {
      const res = await fetch('/api/scan/upload', {
        method: 'POST',
        body: formData
      });
      const data = await res.json();
      if (data.success) {
        // Cargar el archivo también en el editor
        const reader = new FileReader();
        reader.onload = (ev) => {
          codeInput.value = ev.target.result;
          updateLinesCounter(ev.target.result);
        };
        reader.readAsText(file);

        renderScanResults(data);
        window.showToast?.(`Auditoría completada: ${data.vulnerabilities.length} hallazgos`, 'success');
      } else {
        window.showToast?.('Error al escanear archivo: ' + data.error, 'error');
      }
    } catch (err) {
      window.showToast?.('Error en la comunicación con el servidor', 'error');
    }
  });

  // Botón Limpiar
  btnClear.addEventListener('click', () => {
    codeInput.value = '';
    updateLinesCounter('');
    document.getElementById('scan-results-container').classList.remove('visible');
    document.getElementById('editor-active-filename').textContent = 'app.js';
    window.showToast?.('Editor restablecido', 'info');
  });

  // Botón Iniciar Auditoría
  btnStartScan.addEventListener('click', async () => {
    const code = codeInput.value.trim();
    if (!code) {
      window.showToast?.('Por favor ingresa o sube código fuente para analizar.', 'warning');
      return;
    }

    const filename = document.getElementById('editor-active-filename').textContent || 'app.js';
    btnStartScan.disabled = true;
    btnStartScan.innerHTML = `${Icons.spinner()} <span>Analizando con IA...</span>`;

    try {
      const res = await fetch('/api/scan/code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, filename })
      });
      const data = await res.json();

      if (data.success) {
        renderScanResults(data);
        window.showToast?.(`Análisis finalizado: ${data.vulnerabilities.length} vulnerabilidades detectadas`, 'success');
      } else {
        window.showToast?.(data.error || 'Error al procesar el código', 'error');
      }
    } catch (err) {
      window.showToast?.('Error de red al ejecutar el escaneo', 'error');
    } finally {
      btnStartScan.disabled = false;
      btnStartScan.innerHTML = `${Icons.bolt()} <span>Iniciar Auditoría de Seguridad con IA</span>`;
    }
  });

  // Botón Aplicar Parche al Editor
  const btnApplyPatch = document.getElementById('btn-apply-patch');
  if (btnApplyPatch) {
    btnApplyPatch.addEventListener('click', () => {
      if (activePendingPatch && activePendingPatch.fullPatchedCode) {
        codeInput.value = activePendingPatch.fullPatchedCode;
        updateLinesCounter(activePendingPatch.fullPatchedCode);
        window.closeModal?.('modal-patch');
        window.showToast?.('Parche seguro aplicado al código en el editor.', 'success');

        // Re-escanear automáticamente para mostrar la mejora en el Health Score
        setTimeout(() => {
          btnStartScan.click();
        }, 500);
      }
    });
  }

  // Botón Copiar Parche
  const btnCopyPatch = document.getElementById('btn-copy-patch');
  if (btnCopyPatch) {
    btnCopyPatch.addEventListener('click', () => {
      if (activePendingPatch && activePendingPatch.patchedCode) {
        navigator.clipboard.writeText(activePendingPatch.patchedCode).then(() => {
          window.showToast?.('Código de parche copiado al portapapeles', 'info');
        });
      }
    });
  }
});

function updateLinesCounter(text) {
  const lines = text ? text.split(/\r?\n/).length : 0;
  const el = document.getElementById('editor-lines-count');
  if (el) el.textContent = `${lines} línea${lines === 1 ? '' : 's'}`;
}

async function loadSampleCode(sampleName) {
  try {
    const res = await fetch(`/api/samples/${sampleName}`);
    const data = await res.json();
    if (data.success) {
      const codeInput = document.getElementById('source-code-input');
      codeInput.value = data.code;
      document.getElementById('editor-active-filename').textContent = data.filename;
      updateLinesCounter(data.code);
      window.showToast?.(`Muestra "${data.filename}" cargada. Haz clic en "Iniciar Auditoría".`, 'info');
    }
  } catch (err) {
    window.showToast?.('Error cargando muestra vulnerable', 'error');
  }
}

/**
 * Renderiza los resultados del análisis SAST
 */
function renderScanResults(results) {
  currentScanResult = results;
  const container = document.getElementById('scan-results-container');
  container.classList.add('visible');

  // Actualizar Dial de Salud
  const scoreCircle = document.getElementById('summary-score-circle');
  const scoreTitle = document.getElementById('summary-score-title');
  const scoreDesc = document.getElementById('summary-score-desc');
  const score = results.stats.healthScore;

  scoreCircle.textContent = score;
  scoreCircle.className = 'score-circle ' + (score >= 80 ? 'score-good' : score >= 50 ? 'score-warn' : 'score-danger');

  if (score >= 80) {
    scoreTitle.textContent = 'Nivel de Seguridad Bueno';
    scoreDesc.textContent = 'Bajo índice de vulnerabilidades detectadas.';
  } else if (score >= 50) {
    scoreTitle.textContent = 'Riesgo Moderado Detectado';
    scoreDesc.textContent = 'Se identificaron puntos críticos que requieren atención inmediata.';
  } else {
    scoreTitle.textContent = 'Condición Crítica / Alto Peligro';
    scoreDesc.textContent = 'Múltiples fallos críticos de seguridad comprometen la aplicación.';
  }

  // Contadores
  document.getElementById('count-critical').textContent = results.stats.critical;
  document.getElementById('count-high').textContent = results.stats.high;
  document.getElementById('count-medium').textContent = results.stats.medium;
  document.getElementById('count-low').textContent = results.stats.low;
  document.getElementById('total-vulns-count').textContent = results.vulnerabilities.length;

  // Lista de Tarjetas de Vulnerabilidad
  const listEl = document.getElementById('vuln-cards-list');
  listEl.innerHTML = '';

  if (results.vulnerabilities.length === 0) {
    listEl.innerHTML = `
      <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 8px; padding: 24px; text-align: center;">
        <span style="display: block; color: #34d399; margin-bottom: 8px;">${Icons.checkCircle('icon-lg')}</span>
        <h4 style="color: #34d399; margin-top: 8px;">Excelente: No se detectaron vulnerabilidades conocidas</h4>
        <p style="color: var(--text-muted); font-size: 0.88rem;">El código fuente analizado cumple con los estándares defensivos configurados.</p>
      </div>
    `;
    return;
  }

  results.vulnerabilities.forEach(vuln => {
    const card = document.createElement('div');
    const sevClass = vuln.severity.toLowerCase();
    card.className = `vuln-card ${sevClass}`;

    // Renderizar snippet con resaltado
    const snippetHtml = escapeHtml(vuln.codeSnippet).replace(
      />>> \| (.*)/g,
      `<span class="highlight-line">>>> | $1</span>`
    );

    card.innerHTML = `
      <div class="vuln-header-row">
        <div class="vuln-title-group">
          <h3>${escapeHtml(vuln.title)}</h3>
          <div class="vuln-tags">
            <span class="sev-pill sev-${sevClass}">${vuln.severity}</span>
            <span class="tag-cwe">${vuln.cwe}</span>
            <span class="tag-cwe">${vuln.owasp}</span>
          </div>
        </div>
        <div class="vuln-location-badge">
          ${Icons.file()} ${vuln.filename} : Línea ${vuln.line}
        </div>
      </div>

      <p class="vuln-desc-text">${escapeHtml(vuln.description)}</p>

      <div class="code-context-box">${snippetHtml}</div>

      <div class="vuln-actions-row">
        <div style="font-size: 0.8rem; color: var(--text-muted);">
          <strong>Impacto:</strong> ${escapeHtml(vuln.impact)}
        </div>
        <div style="display: flex; gap: 8px; align-items: center;">
          <button class="btn-ai-explain" data-id="${vuln.id}">
            ${Icons.info()} <span>Explicación Pedagógica IA</span>
          </button>
          ${
            vuln.canAutoPatch
              ? `<button class="btn-ai-patch" data-id="${vuln.id}">
                   ${Icons.wrench()} <span>Parchar con IA (Diff)</span>
                 </button>`
              : `<button class="badge-manual-guide" data-id="${vuln.id}">
                   ${Icons.shield()} <span>Protocolo de Honestidad IA</span>
                 </button>`
          }
        </div>
      </div>
    `;

    listEl.appendChild(card);
  });

  // Vincular eventos a los botones de cada tarjeta
  document.querySelectorAll('.btn-ai-explain').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = btn.getAttribute('data-id');
      const vuln = results.vulnerabilities.find(v => v.id === id);
      if (vuln) openAiExplainModal(vuln);
    });
  });

  document.querySelectorAll('.btn-ai-patch').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = btn.getAttribute('data-id');
      const vuln = results.vulnerabilities.find(v => v.id === id);
      if (vuln) openAiPatchModal(vuln);
    });
  });

  document.querySelectorAll('.badge-manual-guide').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = btn.getAttribute('data-id');
      const vuln = results.vulnerabilities.find(v => v.id === id);
      if (vuln) openAiHonestyModal(vuln);
    });
  });
}

/**
 * Abre el modal de Explicación de la IA
 */
async function openAiExplainModal(vuln) {
  const modalBody = document.getElementById('modal-explain-body');
  document.getElementById('modal-explain-title').innerHTML = `${Icons.info()} <span>Explicación de ${escapeHtml(vuln.title)}</span>`;

  modalBody.innerHTML = `
    <div style="text-align: center; padding: 30px;">
      <div class="pulse-dot" style="margin: 0 auto 12px; width: 14px; height: 14px;"></div>
      <p style="color: var(--text-muted);">Consultando al motor de Inteligencia Artificial...</p>
    </div>
  `;
  window.openModal?.('modal-explain');

  try {
    const res = await fetch('/api/ai/explain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ vulnerability: vuln, contextCode: vuln.codeSnippet })
    });
    const data = await res.json();

    if (data.success && data.explanation) {
      const exp = data.explanation;
      modalBody.innerHTML = `
        <div style="display: flex; flex-direction: column; gap: 18px;">
          <div style="background: rgba(0, 240, 255, 0.08); border: 1px solid rgba(0, 240, 255, 0.2); border-radius: 8px; padding: 16px;">
            <h4 style="color: var(--neon-cyan); margin-bottom: 6px; font-size: 1rem; display: flex; align-items: center; gap: 8px;">
              ${Icons.info()} <span>Concepto Fundamental</span>
            </h4>
            <p style="color: #e2e8f0; font-size: 0.92rem;">${escapeHtml(exp.overview)}</p>
          </div>

          <div style="background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 8px; padding: 16px;">
            <h4 style="color: #f87171; margin-bottom: 6px; font-size: 1rem; display: flex; align-items: center; gap: 8px;">
              ${Icons.crosshair()} <span>Mecánica del Vector de Ataque</span>
            </h4>
            <p style="color: #cbd5e1; font-size: 0.92rem;">${escapeHtml(exp.attackMechanics)}</p>
          </div>

          <div style="background: rgba(245, 158, 11, 0.08); border: 1px solid rgba(245, 158, 11, 0.2); border-radius: 8px; padding: 16px;">
            <h4 style="color: #fbbf24; margin-bottom: 6px; font-size: 1rem; display: flex; align-items: center; gap: 8px;">
              ${Icons.bolt()} <span>Impacto en Datos y Clientes</span>
            </h4>
            <p style="color: #cbd5e1; font-size: 0.92rem;">${escapeHtml(exp.businessImpact)}</p>
          </div>

          <div style="background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.2); border-radius: 8px; padding: 16px;">
            <h4 style="color: #34d399; margin-bottom: 6px; font-size: 1rem; display: flex; align-items: center; gap: 8px;">
              ${Icons.shield()} <span>Principio de Remediación y Defensa en Profundidad</span>
            </h4>
            <p style="color: #cbd5e1; font-size: 0.92rem;">${escapeHtml(exp.remediationConcept)}</p>
          </div>

          <div style="font-size: 0.78rem; font-family: var(--font-mono); color: var(--text-dim); text-align: right;">
            ${escapeHtml(exp.standardsReference)}
          </div>
        </div>
      `;
    } else {
      modalBody.innerHTML = `<p style="color: var(--neon-crimson);">Error al obtener la explicación.</p>`;
    }
  } catch (err) {
    modalBody.innerHTML = `<p style="color: var(--neon-crimson);">Error de conexión con el motor de IA.</p>`;
  }
}

/**
 * Abre el modal de Parche Seguro con Diff interactivo
 */
async function openAiPatchModal(vuln) {
  const modalBody = document.getElementById('modal-patch-body');
  const codeInput = document.getElementById('source-code-input');
  document.getElementById('modal-patch-title').innerHTML = `${Icons.wrench()} <span>Parche Seguro con IA: ${escapeHtml(vuln.title)}</span>`;

  modalBody.innerHTML = `
    <div style="text-align: center; padding: 30px;">
      <div class="pulse-dot" style="margin: 0 auto 12px; width: 14px; height: 14px;"></div>
      <p style="color: var(--text-muted);">Generando parche de código seguro y validando sintaxis...</p>
    </div>
  `;
  window.openModal?.('modal-patch');

  try {
    const res = await fetch('/api/ai/fix', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        vulnerability: vuln,
        fullCode: codeInput.value
      })
    });
    const patch = await res.json();
    activePendingPatch = patch;

    if (patch.success) {
      // Dar formato al Diff con colores rojo y verde
      const diffHtml = escapeHtml(patch.diff)
        .split('\n')
        .map(line => {
          if (line.startsWith('-')) return `<span class="diff-line-del">${line}</span>`;
          if (line.startsWith('+')) return `<span class="diff-line-add">${line}</span>`;
          return line;
        })
        .join('\n');

      modalBody.innerHTML = `
        <div style="display: flex; flex-direction: column; gap: 16px;">
          <div style="background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 8px; padding: 14px;">
            <h4 style="color: #34d399; margin-bottom: 6px; font-size: 0.95rem; display: flex; align-items: center; gap: 8px;">
              ${Icons.info()} <span>Justificación de Seguridad del Parche</span>
            </h4>
            <p style="color: #cbd5e1; font-size: 0.88rem;">${escapeHtml(patch.explanation)}</p>
          </div>

          <div>
            <h4 style="font-size: 0.95rem; margin-bottom: 6px;">Visualizador de Cambios (Diff Unificado):</h4>
            <div class="diff-viewer">${diffHtml}</div>
          </div>

          <div>
            <h4 style="font-size: 0.95rem; margin-bottom: 6px; display: flex; align-items: center; gap: 8px;">
              ${Icons.checkCircle()} <span>Pasos de Verificación Recomendados:</span>
            </h4>
            <ul style="padding-left: 20px; font-size: 0.85rem; color: var(--text-muted); display: flex; flex-direction: column; gap: 4px;">
              ${patch.verificationChecklist.map(step => `<li>${escapeHtml(step)}</li>`).join('')}
            </ul>
          </div>
        </div>
      `;
    } else if (patch.isTransparentFallback) {
      // La IA honestamente no puede auto-parchar a ciegas
      window.closeModal?.('modal-patch');
      openAiHonestyModal(vuln, patch);
    }
  } catch (err) {
    modalBody.innerHTML = `<p style="color: var(--neon-crimson);">Error al generar el parche con IA.</p>`;
  }
}

/**
 * Abre el modal de Protocolo de Honestidad y Transparencia
 */
async function openAiHonestyModal(vuln, preloadedData = null) {
  const modalBody = document.getElementById('modal-fallback-body');
  window.openModal?.('modal-fallback');

  let data = preloadedData;
  if (!data) {
    modalBody.innerHTML = `
      <div style="text-align: center; padding: 30px;">
        <div class="pulse-dot" style="margin: 0 auto 12px; width: 14px; height: 14px; background: var(--canary-gold);"></div>
        <p style="color: var(--text-muted);">Consultando protocolo de honestidad de la IA...</p>
      </div>
    `;

    try {
      const res = await fetch('/api/ai/fix', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vulnerability: vuln })
      });
      data = await res.json();
    } catch (err) {
      modalBody.innerHTML = `<p style="color: var(--neon-crimson);">Error al consultar el protocolo.</p>`;
      return;
    }
  }

  modalBody.innerHTML = `
    <div style="display: flex; flex-direction: column; gap: 16px;">
      <div style="background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.3); border-radius: 8px; padding: 16px;">
        <h4 style="color: #fbbf24; margin-bottom: 6px; font-size: 1rem; display: flex; align-items: center; gap: 8px;">
          ${Icons.alertTriangle()} <span>¿Por qué la IA no aplica un parche automático a ciegas?</span>
        </h4>
        <p style="color: #e2e8f0; font-size: 0.9rem; line-height: 1.5; white-space: pre-wrap;">${escapeHtml(data.whyAutomatedPatchIsUnsafe)}</p>
      </div>

      <div>
        <h4 style="font-size: 0.95rem; margin-bottom: 8px; color: var(--canary-gold); display: flex; align-items: center; gap: 8px;">
          ${Icons.file()} <span>Guía de Remediación Manual Paso a Paso:</span>
        </h4>
        <div style="display: flex; flex-direction: column; gap: 8px;">
          ${data.manualRemediationGuide.map((step, idx) => `
            <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 6px; padding: 10px 14px; font-size: 0.86rem; display: flex; gap: 10px; align-items: flex-start;">
              <span style="background: rgba(255, 199, 0, 0.15); color: var(--canary-gold); border-radius: 50%; width: 20px; height: 20px; display: flex; align-items: center; justify-content: center; font-size: 0.75rem; font-weight: 700; flex-shrink: 0;">${idx + 1}</span>
              <span style="color: #cbd5e1;">${escapeHtml(step)}</span>
            </div>
          `).join('')}
        </div>
      </div>
    </div>
  `;
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
