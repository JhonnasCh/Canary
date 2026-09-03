/**
 * CanaryEngine - Scorer & Risk Assessor
 * Implementación determinista del algoritmo de evaluación cuantitativa de riesgo.
 */

const KEY_SECURITY_HEADERS = [
  'Content-Security-Policy',
  'Strict-Transport-Security',
  'X-Frame-Options',
  'X-Content-Type-Options'
];

function calculateSecurityScore(evidence) {
  let score = 100;
  const deductions = [];

  // 1. Deducción por CVEs CRITICAL o HIGH (-25 pts c/u)
  const highOrCriticalCVEs = (evidence.detected_cves || []).filter(cve => {
    const sev = (cve.severity || '').toUpperCase();
    return sev === 'CRITICAL' || sev === 'HIGH';
  });

  if (highOrCriticalCVEs.length > 0) {
    const cvePenalty = highOrCriticalCVEs.length * 25;
    score -= cvePenalty;
    deductions.push({
      reason: `${highOrCriticalCVEs.length} CVE(s) de severidad CRITICAL/HIGH detectados`,
      points: -cvePenalty
    });
  }

  // 2. Deducción por cabeceras de seguridad clave ausentes (-10 pts c/u)
  const missingHeaders = [];
  for (const header of KEY_SECURITY_HEADERS) {
    if (!evidence.security_headers || !evidence.security_headers[header]) {
      missingHeaders.push(header);
      score -= 10;
    }
  }
  if (missingHeaders.length > 0) {
    deductions.push({
      reason: `${missingHeaders.length} cabecera(s) de seguridad clave ausente(s): ${missingHeaders.join(', ')}`,
      points: -(missingHeaders.length * 10)
    });
  }

  // 3. Deducción por cookies sin HttpOnly o Secure (-10 pts)
  const cookies = evidence.cookies || [];
  const insecureCookies = cookies.filter(cookie => !cookie.http_only || !cookie.secure);
  if (insecureCookies.length > 0) {
    score -= 10;
    deductions.push({
      reason: `${insecureCookies.length} cookie(s) sin banderas HttpOnly o Secure`,
      points: -10
    });
  }

  // 4. Deducción por SSL/TLS inválido o ausente (-15 pts)
  if (!evidence.ssl_tls || !evidence.ssl_tls.valid) {
    score -= 15;
    deductions.push({
      reason: 'Certificado SSL/TLS no válido, revocado o ausente',
      points: -15
    });
  }

  // Límite inferior: 0 puntos
  const finalScore = Math.max(0, score);

  // Clasificación de Risk Level
  const hasCriticalCVE = (evidence.detected_cves || []).some(
    cve => (cve.severity || '').toUpperCase() === 'CRITICAL'
  );
  const hasHighCVE = (evidence.detected_cves || []).some(
    cve => (cve.severity || '').toUpperCase() === 'HIGH'
  );

  let riskLevel = 'LOW';
  if (finalScore <= 39 || hasCriticalCVE) {
    riskLevel = 'CRITICAL';
  } else if (finalScore <= 69 || hasHighCVE) {
    riskLevel = 'HIGH';
  } else if (finalScore <= 89) {
    riskLevel = 'MEDIUM';
  } else {
    riskLevel = 'LOW';
  }

  return {
    score: finalScore,
    risk_level: riskLevel,
    deductions,
    missing_key_headers: missingHeaders,
    insecure_cookies: insecureCookies
  };
}

module.exports = { calculateSecurityScore, KEY_SECURITY_HEADERS };
