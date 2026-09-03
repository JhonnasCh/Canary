/**
 * Canary Sentinel - Aplicación Principal y Control de Interfaz
 */

document.addEventListener('DOMContentLoaded', () => {
  setupTabs();
  setupModals();
  console.log('🛡️ Canary Sentinel UI inicializada.');
});

/**
 * Navegación de pestañas
 */
function setupTabs() {
  const tabButtons = document.querySelectorAll('.tab-btn');
  const tabPanes = document.querySelectorAll('.tab-pane');
  const viewTitle = document.getElementById('active-view-title');

  const titles = {
    'tab-scanner': 'Auditor SAST & Auto-Parchador IA',
    'tab-repo': 'Inspección de Repositorios GitHub',
    'tab-guardian': 'Centro Guardián 24/7 (WAF SOC)',
    'tab-simulator': 'Simulador de Ciberataques',
    'tab-connect': 'Conexión de Sitios Web & Ajustes'
  };

  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-tab');

      tabButtons.forEach(b => b.classList.remove('active'));
      tabPanes.forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const targetPane = document.getElementById(targetId);
      if (targetPane) {
        targetPane.classList.add('active');
      }

      if (viewTitle && titles[targetId]) {
        viewTitle.textContent = titles[targetId];
      }
    });
  });

  // Botón de refrescar telemetría en el dashboard
  const btnRefresh = document.getElementById('btn-refresh-telemetry');
  if (btnRefresh) {
    btnRefresh.addEventListener('click', () => {
      window.showToast?.('Actualizando telemetría en tiempo real...', 'info');
      // Disparar actualizaciones
      if (window.fetchGuardianStats) window.fetchGuardianStats();
      if (window.fetchConnectedSites) window.fetchConnectedSites();
    });
  }
}

/**
 * Control global de modales (abrir, cerrar, cerrar con Escape o clic fuera)
 */
function setupModals() {
  // Botones de cierre [data-close]
  document.querySelectorAll('[data-close]').forEach(btn => {
    btn.addEventListener('click', () => {
      const modalId = btn.getAttribute('data-close');
      closeModal(modalId);
    });
  });

  // Cerrar al hacer clic en el fondo oscuro
  document.querySelectorAll('.modal-backdrop').forEach(backdrop => {
    backdrop.addEventListener('click', (e) => {
      if (e.target === backdrop) {
        closeModal(backdrop.id);
      }
    });
  });

  // Cerrar con la tecla ESC
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      document.querySelectorAll('.modal-backdrop.open').forEach(backdrop => {
        closeModal(backdrop.id);
      });
    }
  });
}

function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.add('open');
    document.body.style.overflow = 'hidden';
  }
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.remove('open');
    document.body.style.overflow = '';
  }
}

/**
 * Sistema de Notificaciones Toast
 */
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = 'toast';

  const icons = {
    info: window.Icons ? window.Icons.info() : '',
    success: window.Icons ? window.Icons.checkCircle() : '',
    warning: window.Icons ? window.Icons.alertTriangle() : '',
    error: window.Icons ? window.Icons.xCircle() : ''
  };

  const borders = {
    info: 'var(--neon-cyan)',
    success: 'var(--neon-emerald)',
    warning: 'var(--canary-gold)',
    error: 'var(--neon-crimson)'
  };

  toast.style.borderColor = borders[type] || borders.info;
  toast.innerHTML = `
    <span class="toast-icon">${icons[type] || ''}</span>
    <span>${escapeHtml(message)}</span>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
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

// Exponer funciones globales en window
window.openModal = openModal;
window.closeModal = closeModal;
window.showToast = showToast;
