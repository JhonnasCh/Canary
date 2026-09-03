/**
 * CanaryEngine - Core Analysis Engine
 * Orquestador central de Canary AI: procesa evidencia cruda determinista y
 * produce el objeto JSON estricto sin alucinaciones.
 */

const { validateAndSanitizeInput } = require('./validator');
const { calculateSecurityScore } = require('./scorer');
const { detectDominantStack } = require('./autofix');
const { buildVulnerabilities } = require('./classifier');
const { generateHoneypots } = require('./honeypots');

function analyzeEvidence(rawEvidence) {
  // 1. Validar y normalizar entrada
  const evidence = validateAndSanitizeInput(rawEvidence);

  // 2. Identificar el stack tecnológico dominante
  const dominantStack = detectDominantStack(evidence.technologies);

  // 3. Ejecutar algoritmo matemático determinista de puntuación
  const scoring = calculateSecurityScore(evidence);

  // 4. Construir diagnósticos, impacto y parches Auto-Fix
  const vulnerabilities = buildVulnerabilities(evidence, scoring, dominantStack);

  // 5. Generar recomendaciones de defensa activa (Honeypots adaptativos)
  const defenseRecommendations = generateHoneypots(evidence.technologies, dominantStack);

  // 6. Retornar estructura JSON estricta requerida por la especificación
  return {
    summary: {
      target_url: evidence.target_url,
      security_score: scoring.score,
      risk_level: scoring.risk_level,
      total_vulnerabilities: vulnerabilities.length
    },
    vulnerabilities: vulnerabilities,
    defense_recommendations: defenseRecommendations
  };
}

module.exports = { analyzeEvidence };
