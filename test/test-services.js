const assert = require('assert');
const { analyzeCode, SECURITY_RULES } = require('../src/services/scannerService');
const { explainVulnerability, generatePatch } = require('../src/services/aiService');
const { inspectRequest, simulateAttack, getGuardianStats } = require('../src/services/guardianService');

console.log('--- INICIANDO SUITE DE PRUEBAS DE CANARY SENTINEL ---');

// 1. Prueba de Escáner SAST sobre SQL Injection y Secretos
const sampleVulnerableCode = `
const secretKey = "super-insecure-secret-token-1234";
const userQuery = "SELECT * FROM accounts WHERE id = " + req.query.id;
db.query(userQuery);
`;

const scanResult = analyzeCode(sampleVulnerableCode, 'test-file.js');
console.log(`[SAST] Vulnerabilidades detectadas: ${scanResult.vulnerabilities.length}`);
assert(scanResult.vulnerabilities.length >= 2, 'Debe detectar al menos SQLi y Secreto Hardcodeado');

const sqli = scanResult.vulnerabilities.find(v => v.ruleId === 'SQL_INJECTION');
const secret = scanResult.vulnerabilities.find(v => v.ruleId === 'HARDCODED_SECRET');

assert(sqli, 'Debe detectar SQL Injection');
assert(secret, 'Debe detectar Hardcoded Secret');
console.log('✓ Detección SAST validada.');

// 2. Prueba de Explicación con IA
(async () => {
  const explanation = await explainVulnerability(sqli);
  assert(explanation.success, 'La explicación debe ser exitosa');
  assert(explanation.explanation.overview, 'Debe contener visión general didáctica');
  console.log('✓ Explicación de vulnerabilidad con IA validada.');

  // 3. Prueba de Auto-Parchado con IA (Diff y código seguro)
  const patch = await generatePatch(sqli, sampleVulnerableCode);
  assert(patch.success, 'El parche para SQLi debe ser exitoso');
  assert(patch.diff.includes('+'), 'El Diff debe contener líneas añadidas seguras');
  console.log('✓ Generación de Parche con Diff interactivo validada.');

  // 4. Prueba del Protocolo de Honestidad y Transparencia
  // El secreto hardcodeado tiene canAutoPatch: false
  const honestFallback = await generatePatch(secret, sampleVulnerableCode);
  assert(honestFallback.isTransparentFallback === true, 'Debe activar el protocolo de honestidad');
  assert(honestFallback.manualRemediationGuide.length > 0, 'Debe proveer guía manual paso a paso');
  console.log('✓ Protocolo de Honestidad y Transparencia validado (La IA no adivina secretos).');

  // 5. Prueba del Guardián 24/7 y Mitigación de Ataques
  const safeReq = { path: '/home', query: 'page=1', body: '', userAgent: 'Mozilla' };
  const safeResult = inspectRequest(safeReq);
  assert(safeResult.blocked === false, 'Petición normal no debe ser bloqueada');

  const attackReq = { path: '/login', query: "user=admin' OR '1'='1'--", body: '', userAgent: 'Mozilla' };
  const blockedResult = inspectRequest(attackReq);
  assert(blockedResult.blocked === true, 'Ataque SQLi debe ser bloqueado');
  console.log('✓ Inspección y Bloqueo en tiempo real del Guardián validado.');

  // 6. Prueba del Simulador de Ataques
  const sim = simulateAttack('xss');
  assert(sim.result.blocked === true, 'Simulación de ataque XSS debe ser bloqueada y registrada');
  console.log('✓ Simulador de Ataques validado.');

  const stats = getGuardianStats();
  assert(stats.shieldStatus === 'SHIELD_ACTIVE_24_7', 'El escudo debe reportar estado activo');
  console.log('✓ Estadísticas globales del Guardián validadas.');

  // 7. Prueba del Módulo de Repositorios Git
  const { parseRepoIdentifier } = require('../src/services/repoService');
  const parsed1 = parseRepoIdentifier('https://github.com/facebook/react.git');
  assert(parsed1.owner === 'facebook' && parsed1.repo === 'react', 'Debe parsear URL completa de GitHub');
  const parsed2 = parseRepoIdentifier('expressjs/express');
  assert(parsed2.owner === 'expressjs' && parsed2.repo === 'express', 'Debe parsear slug corto owner/repo');
  console.log('✓ Parser de identificadores de Repositorio Git validado.');

  console.log('--- TODAS LAS PRUEBAS UNITARIAS PASARON EXITOSAMENTE ---');
})();
