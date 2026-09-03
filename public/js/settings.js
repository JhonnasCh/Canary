/**
 * Canary Sentinel - Controlador de Configuración de IA y Enlace Web
 */

document.addEventListener('DOMContentLoaded', () => {
  const selectProvider = document.getElementById('select-ai-provider');
  const groupApiKey = document.getElementById('group-api-key');
  const groupModelName = document.getElementById('group-model-name');
  const groupCustomEndpoint = document.getElementById('group-custom-endpoint');
  const formAiSettings = document.getElementById('form-ai-settings');
  const inputApiKey = document.getElementById('input-api-key');
  const inputModelName = document.getElementById('input-model-name');
  const inputCustomEndpoint = document.getElementById('input-custom-endpoint');
  const metricAiProvider = document.getElementById('metric-ai-provider');

  // Cargar configuración existente desde la API
  loadAiConfig();

  // Cambio dinámico de proveedor
  selectProvider.addEventListener('change', () => {
    updateFieldVisibility(selectProvider.value);
  });

  // Envío del formulario de configuración de IA
  formAiSettings.addEventListener('submit', async (e) => {
    e.preventDefault();

    const provider = selectProvider.value;
    const apiKey = inputApiKey.value.trim();
    const modelName = inputModelName.value.trim();
    const customEndpoint = inputCustomEndpoint.value.trim();

    try {
      const res = await fetch('/api/settings/ai', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider,
          apiKey,
          modelName,
          customEndpoint
        })
      });
      const data = await res.json();

      if (data.success) {
        window.showToast?.('Configuración de IA guardada exitosamente.', 'success');
        updateHeaderMetric(data.config);
      } else {
        window.showToast?.('Error al guardar configuración', 'error');
      }
    } catch (err) {
      window.showToast?.('Error al conectar con el servidor', 'error');
    }
  });

  // Copiar fragmentos de código al portapapeles
  document.querySelectorAll('.btn-copy-code').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-clipboard');
      const targetEl = document.getElementById(targetId);
      if (targetEl) {
        navigator.clipboard.writeText(targetEl.textContent).then(() => {
          btn.textContent = '¡Copiado!';
          setTimeout(() => (btn.textContent = 'Copiar'), 2000);
          window.showToast?.('Código de integración copiado al portapapeles', 'info');
        });
      }
    });
  });

  // Botón directo en el header para ir a configuración
  const btnSettings = document.getElementById('btn-open-settings');
  if (btnSettings) {
    btnSettings.addEventListener('click', () => {
      const tabConnect = document.getElementById('tab-btn-connect');
      if (tabConnect) tabConnect.click();
    });
  }

  function updateFieldVisibility(provider) {
    if (provider === 'local') {
      groupApiKey.style.display = 'none';
      groupModelName.style.display = 'none';
      groupCustomEndpoint.style.display = 'none';
    } else if (provider === 'openai') {
      groupApiKey.style.display = 'block';
      groupModelName.style.display = 'block';
      groupCustomEndpoint.style.display = 'none';
      if (!inputModelName.value) inputModelName.value = 'gpt-4o-mini';
    } else if (provider === 'gemini') {
      groupApiKey.style.display = 'block';
      groupModelName.style.display = 'block';
      groupCustomEndpoint.style.display = 'none';
      if (!inputModelName.value) inputModelName.value = 'gemini-1.5-pro';
    } else if (provider === 'custom') {
      groupApiKey.style.display = 'block';
      groupModelName.style.display = 'block';
      groupCustomEndpoint.style.display = 'block';
    }
  }

  async function loadAiConfig() {
    try {
      const res = await fetch('/api/settings/ai');
      const data = await res.json();

      selectProvider.value = data.provider || 'local';
      if (data.modelName) inputModelName.value = data.modelName;
      if (data.customEndpoint) inputCustomEndpoint.value = data.customEndpoint;
      if (data.hasApiKey) inputApiKey.placeholder = '•••••••••••••••• (API Key Activa)';

      updateFieldVisibility(data.provider || 'local');
      updateHeaderMetric(data);
    } catch (err) {
      console.warn('Error al cargar configuración de IA:', err.message);
    }
  }

  function updateHeaderMetric(config) {
    if (!metricAiProvider) return;
    if (config.provider === 'local') {
      metricAiProvider.textContent = 'Local (Activo)';
    } else if (config.provider === 'gemini') {
      metricAiProvider.textContent = 'Gemini (' + (config.modelName || '1.5-Pro') + ')';
    } else if (config.provider === 'openai') {
      metricAiProvider.textContent = 'OpenAI (' + (config.modelName || 'GPT-4o') + ')';
    } else {
      metricAiProvider.textContent = 'API Custom';
    }
  }
});
