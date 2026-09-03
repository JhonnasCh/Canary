/**
 * Canary — API Server
 * Express server that exposes the security scanner via REST API.
 * Also serves the static frontend files.
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const { SecurityScanner } = require('./scanner');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Serve static frontend files
app.use(express.static(path.join(__dirname, '..')));

// ==========================================
// API ROUTES
// ==========================================

/**
 * POST /api/scan
 * Body: { "url": "https://example.com" }
 * Returns: Full scan results
 */
app.post('/api/scan', async (req, res) => {
  const { url } = req.body;

  // Validate URL
  if (!url) {
    return res.status(400).json({
      error: true,
      message_en: 'URL is required.',
      message_es: 'La URL es requerida.',
    });
  }

  // Validate URL format
  let parsedUrl;
  try {
    parsedUrl = new URL(url);
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      throw new Error('Invalid protocol');
    }
  } catch {
    return res.status(400).json({
      error: true,
      message_en: 'Invalid URL. Please provide a valid HTTP or HTTPS URL.',
      message_es: 'URL inválida. Proporciona una URL HTTP o HTTPS válida.',
    });
  }

  // Block scanning localhost / private IPs (basic SSRF protection)
  const hostname = parsedUrl.hostname;
  const blocked = [
    'localhost', '127.0.0.1', '0.0.0.0', '::1',
    '10.', '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
    '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
    '172.30.', '172.31.', '192.168.',
  ];

  if (blocked.some(b => hostname.startsWith(b) || hostname === b)) {
    return res.status(403).json({
      error: true,
      message_en: 'Scanning internal/private addresses is not allowed.',
      message_es: 'No se permite escanear direcciones internas/privadas.',
    });
  }

  try {
    console.log(`[SCAN] Starting scan for: ${url}`);
    const startTime = Date.now();

    const scanner = new SecurityScanner(url);
    const results = await scanner.scan();

    const duration = Date.now() - startTime;
    results.scanDuration = duration;

    console.log(`[SCAN] Completed in ${duration}ms — Score: ${results.score}/100 — ${results.findings.length} findings`);

    res.json({
      error: false,
      data: results,
    });
  } catch (err) {
    console.error(`[SCAN] Error scanning ${url}:`, err.message);
    res.status(500).json({
      error: true,
      message_en: `Scan failed: ${err.message}`,
      message_es: `Error en el escaneo: ${err.message}`,
    });
  }
});

/**
 * GET /api/health
 * Health check endpoint
 */
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', service: 'canary-scanner', timestamp: new Date().toISOString() });
});

// Fallback: serve index.html for any non-API route
app.get('*', (req, res) => {
  if (!req.path.startsWith('/api')) {
    res.sendFile(path.join(__dirname, '..', 'index.html'));
  }
});

// Start server
app.listen(PORT, () => {
  console.log('');
  console.log('  🐦 Canary Security Scanner');
  console.log('  ─────────────────────────');
  console.log(`  ✓ Server running on http://localhost:${PORT}`);
  console.log(`  ✓ API endpoint: POST http://localhost:${PORT}/api/scan`);
  console.log('');
});

module.exports = app;
