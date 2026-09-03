require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');

const { getAiConfig, updateAiConfig } = require('./config/aiConfig');
const { analyzeCode } = require('./services/scannerService');
const { explainVulnerability, generatePatch } = require('./services/aiService');
const {
  initializeFileIntegrityMonitor,
  inspectRequest,
  recordEvent,
  registerSseClient,
  getGuardianStats,
  simulateAttack
} = require('./services/guardianService');
const { canaryGuardian } = require('./guardian-agent/sentinel-agent');
const {
  parseRepoIdentifier,
  fetchRepoMetadata,
  fetchRepoFileTree,
  fetchFileContent,
  auditEntireRepo
} = require('./services/repoService');
const {
  registerSite,
  getConnectedSites,
  getSiteById,
  removeSite,
  handleProxyRequest
} = require('./services/siteProxyService');

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';

// Configuración de Multer para análisis de archivos subidos
const upload = multer({
  limits: { fileSize: 5 * 1024 * 1024 }, // Máximo 5MB
  storage: multer.memoryStorage()
});

// Middleware esencial
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Inicializar el Monitor de Integridad de Archivos (FIM)
initializeFileIntegrityMonitor(path.resolve(__dirname, '..'));

// Proteger activamente este servidor con el Guardián 24/7
// (excluyendo rutas de análisis de código, IA, repositorios, pasarela shield y simulador)
app.use((req, res, next) => {
  if (
    req.path.startsWith('/api/guardian/simulate') ||
    req.path.startsWith('/api/scan') ||
    req.path.startsWith('/api/ai') ||
    req.path.startsWith('/api/repo') ||
    req.path.startsWith('/api/sites') ||
    req.path.startsWith('/shield')
  ) {
    return next();
  }
  return canaryGuardian({
    hubUrl: `http://localhost:${PORT}`,
    blockMode: true
  })(req, res, next);
});

// Servir archivos estáticos del frontend
app.use(express.static(path.join(__dirname, '../public')));

// ----------------------------------------------------
// RUTAS DE LA API REST
// ----------------------------------------------------

// 1. Estado y Salud del Sistema
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ONLINE',
    service: 'Canary Sentinel Security Engine',
    version: '1.0.0',
    shield: 'SHIELD_ACTIVE_24_7',
    timestamp: new Date().toISOString()
  });
});

// 2. Escaneo SAST de Código (Texto directo)
app.post('/api/scan/code', (req, res) => {
  const { code, filename = 'source_code.js' } = req.body;

  if (!code || typeof code !== 'string') {
    return res.status(400).json({ error: 'Debes proporcionar el código fuente a analizar.' });
  }

  const results = analyzeCode(code, filename);
  res.json({ success: true, ...results });
});

// 3. Escaneo SAST de Archivo Subido
app.post('/api/scan/upload', upload.single('sourceFile'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No se subió ningún archivo para escanear.' });
  }

  const code = req.file.buffer.toString('utf-8');
  const filename = req.file.originalname || 'uploaded_file.js';
  const results = analyzeCode(code, filename);

  res.json({
    success: true,
    fileSize: req.file.size,
    ...results
  });
});

// 4. Muestras de Código Vulnerable Precargadas
app.get('/api/samples/:name', (req, res) => {
  const sampleMap = {
    auth: 'vulnerable-auth.js',
    upload: 'vulnerable-upload.js',
    frontend: 'vulnerable-frontend.js'
  };

  const sampleFile = sampleMap[req.params.name];
  if (!sampleFile) {
    return res.status(404).json({ error: 'Muestra no encontrada' });
  }

  const samplePath = path.join(__dirname, 'samples', sampleFile);
  try {
    const code = fs.readFileSync(samplePath, 'utf-8');
    res.json({ success: true, name: req.params.name, filename: sampleFile, code });
  } catch (err) {
    res.status(500).json({ error: 'Error leyendo archivo de muestra' });
  }
});

// 5. Explicación de Vulnerabilidad con IA
app.post('/api/ai/explain', async (req, res) => {
  const { vulnerability, contextCode } = req.body;

  if (!vulnerability) {
    return res.status(400).json({ error: 'Datos de vulnerabilidad requeridos.' });
  }

  try {
    const explanation = await explainVulnerability(vulnerability, contextCode);
    res.json(explanation);
  } catch (err) {
    res.status(500).json({ error: 'Error al generar explicación: ' + err.message });
  }
});

// 6. Generación de Parche Seguro con IA (Diff y Auto-fix)
app.post('/api/ai/fix', async (req, res) => {
  const { vulnerability, fullCode } = req.body;

  if (!vulnerability) {
    return res.status(400).json({ error: 'Datos de vulnerabilidad requeridos.' });
  }

  try {
    const patchResult = await generatePatch(vulnerability, fullCode);
    res.json(patchResult);
  } catch (err) {
    res.status(500).json({ error: 'Error al generar parche: ' + err.message });
  }
});

// 7. Estadísticas y Telemetría del Guardián 24/7
app.get('/api/guardian/stats', (req, res) => {
  const stats = getGuardianStats();
  res.json(stats);
});

// 8. Stream en Tiempo Real de Ataques Bloqueados (Server-Sent Events)
app.get('/api/guardian/events', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();

  registerSseClient(res);

  // Enviar mensaje de bienvenida en el stream
  res.write(`data: ${JSON.stringify({ type: 'CONNECTED', message: 'Conectado al canal de telemetría de Canary Sentinel 24/7', timestamp: new Date().toISOString() })}\n\n`);
});

// 9. Simulador de Ciberataques para Comprobación del Guardián
app.post('/api/guardian/simulate', (req, res) => {
  const { type = 'sqli' } = req.body;
  const simulation = simulateAttack(type);
  res.json(simulation);
});

// 10. Receptor de Telemetría desde Sitios Web de Clientes Conectados
app.post('/api/guardian/telemetry', (req, res) => {
  const eventData = req.body;
  
  if (eventData && eventData.threatType) {
    recordEvent({
      id: 'ext_' + Math.random().toString(36).substring(2, 9),
      timestamp: eventData.timestamp || new Date().toISOString(),
      threatType: eventData.threatType,
      threatName: eventData.threatName,
      severity: eventData.severity || 'HIGH',
      action: eventData.action || 'BLOCKED_403',
      attackerIp: eventData.attackerIp || '127.0.0.1',
      method: eventData.method || 'POST',
      targetPath: eventData.targetPath || '/',
      payloadSnippet: eventData.payloadSnippet || 'Payload bloqueado por agente remoto'
    });
    return res.json({ success: true, message: 'Telemetría de incidente registrada.' });
  }

  res.status(400).json({ error: 'Payload de telemetría inválido' });
});

// 11. Conexión y Exploración de Repositorio Git (GitHub)
app.post('/api/repo/connect', async (req, res) => {
  const { repoUrl, token = '' } = req.body;

  const parsed = parseRepoIdentifier(repoUrl);
  if (!parsed) {
    return res.status(400).json({
      error: 'Formato de repositorio inválido. Usa "usuario/repositorio" o "https://github.com/usuario/repositorio".'
    });
  }

  try {
    const metadata = await fetchRepoMetadata(parsed.owner, parsed.repo, token);
    const tree = await fetchRepoFileTree(parsed.owner, parsed.repo, metadata.defaultBranch, token);

    res.json({
      success: true,
      metadata,
      filesCount: tree.length,
      scannableCount: tree.filter(f => f.isScannable).length,
      tree
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 12. Obtener Contenido de un Archivo de Repositorio
app.post('/api/repo/file', async (req, res) => {
  const { repoUrl, filePath, branch = 'main', token = '' } = req.body;

  const parsed = parseRepoIdentifier(repoUrl);
  if (!parsed || !filePath) {
    return res.status(400).json({ error: 'Datos de archivo o repositorio incompletos.' });
  }

  try {
    const content = await fetchFileContent(parsed.owner, parsed.repo, filePath, branch, token);
    res.json({
      success: true,
      filePath,
      content
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 13. Auditoría Completa de Todo el Repositorio
app.post('/api/repo/scan-all', async (req, res) => {
  const { repoUrl, branch = 'main', token = '', maxFiles = 30 } = req.body;

  const parsed = parseRepoIdentifier(repoUrl);
  if (!parsed) {
    return res.status(400).json({ error: 'Repositorio no válido.' });
  }

  try {
    const auditReport = await auditEntireRepo(parsed.owner, parsed.repo, branch, token, maxFiles);
    res.json({
      success: true,
      report: auditReport
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 14. Gestión de Sitios Web Conectados al Guardián 24/7
app.get('/api/sites', (req, res) => {
  res.json({
    success: true,
    sites: getConnectedSites()
  });
});

app.post('/api/sites/connect', async (req, res) => {
  const { name, targetUrl } = req.body;
  try {
    const site = await registerSite({ name, targetUrl });
    res.json({
      success: true,
      site,
      message: `Sitio "${site.name}" blindado y conectado a la pasarela 24/7 exitosamente.`
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/sites/:siteId', (req, res) => {
  const removed = removeSite(req.params.siteId);
  if (removed) {
    res.json({ success: true, message: 'Sitio desconectado del escudo.' });
  } else {
    res.status(404).json({ error: 'Sitio no encontrado.' });
  }
});

// 15. Pasarela WAF Reverse Proxy Activa (Inspección y Reenvío en Tiempo Real)
app.all('/shield/:siteId', (req, res) => {
  handleProxyRequest(req, res, req.params.siteId, '');
});

app.all('/shield/:siteId/*', (req, res) => {
  const subPath = req.params[0] || '';
  handleProxyRequest(req, res, req.params.siteId, subPath);
});

// 16. Configuración de API de IA
app.get('/api/settings/ai', (req, res) => {
  res.json(getAiConfig());
});

app.post('/api/settings/ai', (req, res) => {
  const updated = updateAiConfig(req.body);
  res.json({ success: true, config: updated, message: 'Configuración de IA actualizada exitosamente.' });
});

// Ruta por defecto para SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Iniciar servidor
app.listen(PORT, HOST, () => {
  console.log(`====================================================`);
  console.log(` 🛡️  CANARY SENTINEL - CYBERSHIELD AI READY`);
  console.log(` 🚀 Servidor corriendo en: http://${HOST}:${PORT}`);
  console.log(` 📡 Escudo Guardián 24/7: ACTIVO Y VIGILANDO`);
  console.log(`====================================================`);
});
