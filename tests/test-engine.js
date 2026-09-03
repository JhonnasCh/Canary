const { analyzeEvidence } = require('../engine/analyzer');

console.log('=== INICIANDO PRUEBAS DETERMINISTAS DE CANARY ENGINE ===\n');

// CASO 1: Sitio altamente vulnerable con Express
const case1 = {
  target_url: 'https://vulnerable-shop.io',
  technologies: [
    { name: 'Express', version: '4.17.1' },
    { name: 'Node.js', version: '16.14.0' }
  ],
  security_headers: {
    'X-Frame-Options': true,
    'Content-Security-Policy': false,
    'Strict-Transport-Security': false,
    'X-Content-Type-Options': false
  },
  cookies: [
    { name: 'session_token', http_only: false, secure: false, same_site: 'None' }
  ],
  ssl_tls: {
    valid: false,
    issuer: 'Self-Signed Untrusted CA'
  },
  detected_cves: [
    { cve_id: 'CVE-2022-29244', severity: 'CRITICAL', component: 'npm-package-qs' }
  ]
};

const result1 = analyzeEvidence(case1);
console.log('--- RESULTADO CASO 1 (Express vulnerable) ---');
console.log('Target URL:', result1.summary.target_url);
console.log('Security Score:', result1.summary.security_score, '(Esperado: 20)');
console.log('Risk Level:', result1.summary.risk_level, '(Esperado: CRITICAL)');
console.log('Total Vulnerabilidades:', result1.summary.total_vulnerabilities);
console.log('Honeypots Recomendados:', result1.defense_recommendations.recommended_honeypots.map(h => h.path));

if (result1.summary.security_score !== 20) {
  console.error('❌ FALLO: El score calculado no coincide con la fórmula determinista.');
  process.exit(1);
}

// CASO 2: Sitio Django con fallas menores
const case2 = {
  target_url: 'https://secure-portal.org',
  technologies: [
    { name: 'Django', version: '4.2.0' },
    { name: 'Python', version: '3.11' }
  ],
  security_headers: {
    'Content-Security-Policy': true,
    'Strict-Transport-Security': true,
    'X-Frame-Options': true,
    'X-Content-Type-Options': true
  },
  cookies: [
    { name: 'sessionid', http_only: true, secure: true, same_site: 'Lax' }
  ],
  ssl_tls: {
    valid: true,
    issuer: "Let's Encrypt Authority X3"
  },
  detected_cves: []
};

const result2 = analyzeEvidence(case2);
console.log('\n--- RESULTADO CASO 2 (Django Seguro) ---');
console.log('Security Score:', result2.summary.security_score, '(Esperado: 100)');
console.log('Risk Level:', result2.summary.risk_level, '(Esperado: LOW)');
console.log('Total Vulnerabilidades:', result2.summary.total_vulnerabilities, '(Esperado: 0)');

if (result2.summary.security_score !== 100) {
  console.error('❌ FALLO: Sitio limpio no obtuvo 100 puntos.');
  process.exit(1);
}

console.log('\n✅ TODAS LAS PRUEBAS DETERMINISTAS PASARON SATISFACTORIAMENTE.');
