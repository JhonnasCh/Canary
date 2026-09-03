/**
 * Canary Sentinel - Controlador del Módulo de Repositorios Git (GitHub Connect)
 */

let activeConnectedRepo = null;
let currentRepoTree = [];
let currentFilterText = '';

document.addEventListener('DOMContentLoaded', () => {
  const formConnect = document.getElementById('form-connect-repo');
  const inputRepoUrl = document.getElementById('input-repo-url');
  const inputRepoToken = document.getElementById('input-repo-token');
  const btnConnect = document.getElementById('btn-connect-repo');
  const btnAuditAll = document.getElementById('btn-audit-entire-repo');
  const treeFilterInput = document.getElementById('repo-tree-filter');

  // Conectar al repositorio
  formConnect.addEventListener('submit', async (e) => {
    e.preventDefault();
    const repoUrl = inputRepoUrl.value.trim();
    const token = inputRepoToken.value.trim();

    if (!repoUrl) {
      window.showToast?.('Por favor ingresa la URL o identificador del repositorio', 'warning');
      return;
    }

    btnConnect.disabled = true;
    btnConnect.innerHTML = `${Icons.spinner()} <span>Conectando...</span>`;
    window.showToast?.('Conectando a GitHub e inspeccionando árbol de archivos...', 'info');

    try {
      const res = await fetch('/api/repo/connect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repoUrl, token })
      });
      const data = await res.json();

      if (data.success) {
        activeConnectedRepo = {
          url: repoUrl,
          token: token,
          metadata: data.metadata,
          branch: data.metadata.defaultBranch
        };
        currentRepoTree = data.tree;

        renderRepoOverview(data.metadata, data.tree);
        renderFileTree(data.tree);

        document.getElementById('repo-explorer-container').style.display = 'block';
        window.showToast?.(`Repositorio ${data.metadata.fullName} conectado exitosamente.`, 'success');
      } else {
        window.showToast?.(data.error || 'Error al conectar con el repositorio', 'error');
      }
    } catch (err) {
      window.showToast?.('Error de comunicación con el servidor', 'error');
    } finally {
      btnConnect.disabled = false;
      btnConnect.innerHTML = `${Icons.search()} <span>Conectar e Inspeccionar</span>`;
    }
  });

  // Filtrado de archivos en tiempo real
  if (treeFilterInput) {
    treeFilterInput.addEventListener('input', (e) => {
      currentFilterText = e.target.value.toLowerCase().trim();
      renderFileTree(currentRepoTree, currentFilterText);
    });
  }

  // Auditar todo el repositorio
  if (btnAuditAll) {
    btnAuditAll.addEventListener('click', async () => {
      if (!activeConnectedRepo) return;

      btnAuditAll.disabled = true;
      btnAuditAll.innerHTML = `${Icons.spinner()} <span>Auditando Repositorio Completo...</span>`;
      window.showToast?.('Ejecutando análisis SAST sobre los archivos de código del repositorio...', 'info');

      try {
        const res = await fetch('/api/repo/scan-all', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            repoUrl: activeConnectedRepo.url,
            branch: activeConnectedRepo.branch,
            token: activeConnectedRepo.token
          })
        });
        const data = await res.json();

        if (data.success && data.report) {
          renderRepoAuditReport(data.report);
          window.showToast?.(`Auditoría global completada: ${data.report.totalVulnerabilities} vulnerabilidades en ${data.report.vulnerableFilesCount} archivos.`, 'success');
        } else {
          window.showToast?.(data.error || 'Error durante la auditoría global', 'error');
        }
      } catch (err) {
        window.showToast?.('Error al auditar el repositorio', 'error');
      } finally {
        btnAuditAll.disabled = false;
        btnAuditAll.innerHTML = `${Icons.bolt()} <span>Auditar Repositorio Completo</span>`;
      }
    });
  }
});

/**
 * Renderiza la tarjeta de metadatos del repositorio conectado
 */
function renderRepoOverview(meta, tree) {
  const metaContainer = document.getElementById('repo-meta-summary');
  if (!metaContainer) return;

  const scannableCount = tree.filter(t => t.isScannable).length;

  metaContainer.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px;">
      <div>
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 6px;">
          <h3 style="font-size: 1.3rem; color: #ffffff;">
            <a href="${meta.htmlUrl}" target="_blank" rel="noopener" style="color: var(--neon-cyan); text-decoration: none;">
              ${escapeHtml(meta.fullName)}
            </a>
          </h3>
          <span style="font-size: 0.72rem; padding: 2px 8px; border-radius: 4px; ${meta.isPrivate ? 'background: rgba(245,158,11,0.2); color:#fbbf24;' : 'background: rgba(16,185,129,0.2); color:#34d399;'}">
            ${meta.isPrivate ? Icons.lock() + ' Privado' : Icons.globe() + ' Público'}
          </span>
          <span style="font-size: 0.75rem; background: rgba(255,255,255,0.06); padding: 2px 8px; border-radius: 4px; color: var(--text-muted); font-family: var(--font-mono);">
            Rama: ${escapeHtml(meta.defaultBranch)}
          </span>
        </div>
        <p style="color: var(--text-muted); font-size: 0.88rem;">${escapeHtml(meta.description || 'Sin descripción en GitHub.')}</p>
      </div>

      <div style="display: flex; gap: 16px; align-items: center;">
        <div style="text-align: right;">
          <div style="font-size: 1.2rem; font-weight: 700; color: #ffffff;">${scannableCount} / ${tree.length}</div>
          <div style="font-size: 0.75rem; color: var(--text-muted);">Archivos Auditables</div>
        </div>
      </div>
    </div>
  `;
}

/**
 * Renderiza el árbol de archivos en el explorador
 */
function renderFileTree(tree, filter = '') {
  const container = document.getElementById('repo-files-list');
  if (!container) return;

  container.innerHTML = '';

  const filteredTree = filter
    ? tree.filter(f => f.path.toLowerCase().includes(filter))
    : tree;

  if (filteredTree.length === 0) {
    container.innerHTML = `
      <div style="padding: 24px; text-align: center; color: var(--text-muted); font-size: 0.85rem;">
        No se encontraron archivos que coincidan con "${escapeHtml(filter)}".
      </div>
    `;
    return;
  }

  // Ordenar: primero los auditables, luego por nombre
  const sorted = [...filteredTree].sort((a, b) => {
    if (a.isScannable && !b.isScannable) return -1;
    if (!a.isScannable && b.isScannable) return 1;
    return a.path.localeCompare(b.path);
  });

  sorted.forEach(item => {
    const row = document.createElement('div');
    row.className = 'repo-file-row' + (item.isScannable ? ' scannable' : '');

    const icon = getFileIcon(item.path, item.type);
    const sizeStr = formatBytes(item.size);

    row.innerHTML = `
      <div class="repo-file-info">
        <span class="file-icon">${icon}</span>
        <span class="file-path">${escapeHtml(item.path)}</span>
        ${item.isScannable ? '<span class="badge-auditable">Auditable</span>' : ''}
      </div>
      <div class="repo-file-actions">
        <span class="file-size">${sizeStr}</span>
        ${
          item.isScannable
            ? `<button class="btn-inspect-file" data-path="${escapeHtml(item.path)}" title="Cargar y Auditar en el Editor">
                 ${Icons.search()} <span>Examinar</span>
               </button>`
            : ''
        }
      </div>
    `;

    container.appendChild(row);
  });

  // Asignar eventos de inspección individual de archivos
  container.querySelectorAll('.btn-inspect-file').forEach(btn => {
    btn.addEventListener('click', async () => {
      const path = btn.getAttribute('data-path');
      await loadRepoFileIntoEditor(path);
    });
  });
}

/**
 * Descarga un archivo específico del repositorio y lo carga en el editor SAST
 */
async function loadRepoFileIntoEditor(filePath) {
  if (!activeConnectedRepo) return;

  window.showToast?.(`Cargando ${filePath} desde el repositorio...`, 'info');

  try {
    const res = await fetch('/api/repo/file', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        repoUrl: activeConnectedRepo.url,
        filePath: filePath,
        branch: activeConnectedRepo.branch,
        token: activeConnectedRepo.token
      })
    });
    const data = await res.json();

    if (data.success && data.content) {
      // Cambiar a la pestaña del escáner SAST
      const tabScannerBtn = document.getElementById('tab-btn-scanner');
      if (tabScannerBtn) tabScannerBtn.click();

      // Cargar en el editor
      const editor = document.getElementById('source-code-input');
      const filenameEl = document.getElementById('editor-active-filename');
      editor.value = data.content;
      filenameEl.textContent = filePath;

      // Disparar evento de líneas
      editor.dispatchEvent(new Event('input'));

      window.showToast?.(`Archivo ${filePath} cargado en el editor. Iniciando escaneo...`, 'success');

      // Iniciar el escaneo automáticamente
      setTimeout(() => {
        const btnStartScan = document.getElementById('btn-start-scan');
        if (btnStartScan) btnStartScan.click();
      }, 300);
    } else {
      window.showToast?.(data.error || 'Error al leer el archivo del repositorio', 'error');
    }
  } catch (err) {
    window.showToast?.('Error al descargar el archivo', 'error');
  }
}

/**
 * Renderiza el Reporte Ejecutivo tras la auditoría de todo el repositorio
 */
function renderRepoAuditReport(report) {
  const reportContainer = document.getElementById('repo-audit-report-container');
  if (!reportContainer) return;

  reportContainer.style.display = 'block';

  const scoreCircleClass = report.stats.healthScore >= 80 ? 'score-good' : report.stats.healthScore >= 50 ? 'score-warn' : 'score-danger';

  let filesHtml = '';
  if (report.findingsByFile.length === 0) {
    filesHtml = `
      <div style="padding: 20px; text-align: center; background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.3); border-radius: 8px;">
        <span style="display: block; color: #34d399;">${Icons.checkCircle('icon-lg')}</span>
        <h4 style="color: #34d399; margin-top: 6px;">Repositorio Limpio</h4>
        <p style="color: var(--text-muted); font-size: 0.85rem;">No se detectaron vulnerabilidades en los ${report.scannedFilesCount} archivos de código analizados.</p>
      </div>
    `;
  } else {
    filesHtml = report.findingsByFile.map(f => `
      <div class="repo-audit-file-card">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <div style="font-family: var(--font-mono); font-weight: 700; color: var(--neon-cyan); font-size: 0.95rem; display: flex; align-items: center; gap: 6px;">
            ${Icons.file()} ${escapeHtml(f.path)}
          </div>
          <button class="btn-inspect-file" data-path="${escapeHtml(f.path)}" style="padding: 4px 12px; font-size: 0.78rem;">
            ${Icons.wrench()} <span>Cargar en Patcher de IA</span>
          </button>
        </div>
        <div style="display: flex; gap: 8px; flex-wrap: wrap;">
          ${f.stats.critical > 0 ? `<span class="sev-pill sev-critical">${f.stats.critical} Crítica${f.stats.critical > 1 ? 's' : ''}</span>` : ''}
          ${f.stats.high > 0 ? `<span class="sev-pill sev-high">${f.stats.high} Alta${f.stats.high > 1 ? 's' : ''}</span>` : ''}
          ${f.stats.medium > 0 ? `<span class="sev-pill sev-medium">${f.stats.medium} Media${f.stats.medium > 1 ? 's' : ''}</span>` : ''}
          ${f.stats.low > 0 ? `<span class="sev-pill sev-low">${f.stats.low} Baja${f.stats.low > 1 ? 's' : ''}</span>` : ''}
        </div>
        <ul style="margin-top: 10px; padding-left: 20px; font-size: 0.82rem; color: #cbd5e1; display: flex; flex-direction: column; gap: 4px;">
          ${f.vulnerabilities.map(v => `<li>[Línea ${v.line}] <strong>${escapeHtml(v.title)}</strong> (${v.cwe})</li>`).join('')}
        </ul>
      </div>
    `).join('');
  }

  reportContainer.innerHTML = `
    <div class="results-summary-box" style="margin-bottom: 20px;">
      <div class="health-score-dial">
        <div class="score-circle ${scoreCircleClass}">${report.stats.healthScore}</div>
        <div>
          <div class="score-title">Salud Global del Repositorio</div>
          <div class="score-subtitle">Analizados ${report.scannedFilesCount} archivos de código en ${report.repository}</div>
        </div>
      </div>
      <div class="severity-breakdown">
        <div class="sev-pill sev-critical">${report.stats.critical} Críticas</div>
        <div class="sev-pill sev-high">${report.stats.high} Altas</div>
        <div class="sev-pill sev-medium">${report.stats.medium} Medias</div>
        <div class="sev-pill sev-low">${report.stats.low} Bajas</div>
      </div>
    </div>

    <h4 style="margin-bottom: 12px; font-size: 1.1rem; color: #ffffff;">
      Archivos con Vulnerabilidades Detectadas (${report.vulnerableFilesCount}):
    </h4>
    <div style="display: flex; flex-direction: column; gap: 12px;">
      ${filesHtml}
    </div>
  `;

  // Re-asignar eventos de carga en el reporte
  reportContainer.querySelectorAll('.btn-inspect-file').forEach(btn => {
    btn.addEventListener('click', async () => {
      const path = btn.getAttribute('data-path');
      await loadRepoFileIntoEditor(path);
    });
  });

  // Scroll suave hacia el reporte
  reportContainer.scrollIntoView({ behavior: 'smooth' });
}

function getFileIcon(path, type) {
  const folderIcon = Icons.folder();
  const fileIcon = Icons.file();
  const codeIcon = Icons.code();
  const globeIcon = Icons.globe();
  const lockIcon = Icons.lock();
  const keyIcon = Icons.key();

  if (type === 'directory') return folderIcon;
  if (path.endsWith('.js') || path.endsWith('.jsx') || path.endsWith('.ts') || path.endsWith('.tsx')) return codeIcon;
  if (path.endsWith('.php') || path.endsWith('.py')) return codeIcon;
  if (path.endsWith('.html') || path.endsWith('.htm')) return globeIcon;
  if (path.endsWith('.json')) return fileIcon;
  if (path.includes('.env')) return keyIcon;
  return fileIcon;
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
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
