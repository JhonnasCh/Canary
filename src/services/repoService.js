/**
 * Canary Sentinel - Servicio de Auditoría de Repositorios Git (GitHub Connect)
 * Permite explorar y analizar repositorios públicos y privados con permisos de lectura (read-only).
 */

const { analyzeCode } = require('./scannerService');

// Extensiones de código relevantes para auditoría de seguridad
const SCANNABLE_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.jsx',
  '.ts', '.tsx',
  '.php',
  '.py',
  '.html', '.htm',
  '.json',
  '.env', '.env.example', '.env.local',
  '.yml', '.yaml'
]);

/**
 * Normaliza y extrae { owner, repo } a partir de URLs o slugs
 * Ejemplos aceptados:
 * - "https://github.com/owner/repo"
 * - "github.com/owner/repo"
 * - "owner/repo"
 */
function parseRepoIdentifier(input) {
  if (!input || typeof input !== 'string') return null;

  let cleaned = input.trim().replace(/\.git$/i, '');
  cleaned = cleaned.replace(/^https?:\/\//i, '');
  cleaned = cleaned.replace(/^github\.com\//i, '');

  const parts = cleaned.split('/').filter(Boolean);
  if (parts.length >= 2) {
    return {
      owner: parts[0],
      repo: parts[1]
    };
  }

  return null;
}

/**
 * Encabezados para la API de GitHub (incluye token si fue suministrado)
 */
function getGitHubHeaders(token) {
  const headers = {
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'Canary-Sentinel-Security-Scanner/1.0'
  };

  if (token && typeof token === 'string' && token.trim().length > 0) {
    headers['Authorization'] = `token ${token.trim()}`;
  }

  return headers;
}

/**
 * Conecta y obtiene metadatos del repositorio
 */
async function fetchRepoMetadata(owner, repo, token = '') {
  const url = `https://api.github.com/repos/${owner}/${repo}`;
  const res = await fetch(url, { headers: getGitHubHeaders(token) });

  if (!res.ok) {
    if (res.status === 404) {
      throw new Error(`Repositorio "${owner}/${repo}" no encontrado. Si es privado, asegúrate de ingresar un Personal Access Token (PAT) con permiso "repo" o "contents:read".`);
    }
    if (res.status === 401) {
      throw new Error('Token de acceso no válido o expirado.');
    }
    if (res.status === 403) {
      throw new Error('Límite de tasa de GitHub API excedido. Por favor proporciona un token de GitHub personal para aumentar el límite.');
    }
    throw new Error(`Error de GitHub API (${res.status}): ${res.statusText}`);
  }

  const data = await res.json();
  return {
    name: data.name,
    fullName: data.full_name,
    owner: data.owner?.login,
    description: data.description || 'Sin descripción',
    defaultBranch: data.default_branch || 'main',
    isPrivate: data.private,
    htmlUrl: data.html_url,
    language: data.language || 'Desconocido',
    stars: data.stargazers_count,
    openIssues: data.open_issues_count
  };
}

/**
 * Obtiene el árbol completo de archivos del repositorio de forma recursiva en una sola llamada
 */
async function fetchRepoFileTree(owner, repo, branch = 'main', token = '') {
  const url = `https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`;
  const res = await fetch(url, { headers: getGitHubHeaders(token) });

  if (!res.ok) {
    throw new Error(`Error al obtener árbol de archivos (${res.status}): ${res.statusText}`);
  }

  const data = await res.json();
  if (!data.tree || !Array.isArray(data.tree)) {
    return [];
  }

  // Filtrar y catalogar archivos
  return data.tree.map(item => {
    const ext = extractExtension(item.path);
    return {
      path: item.path,
      type: item.type === 'blob' ? 'file' : 'directory',
      size: item.size || 0,
      sha: item.sha,
      isScannable: item.type === 'blob' && SCANNABLE_EXTENSIONS.has(ext),
      extension: ext
    };
  });
}

/**
 * Descarga el contenido de un archivo del repositorio
 */
async function fetchFileContent(owner, repo, filePath, branch = 'main', token = '') {
  const url = `https://api.github.com/repos/${owner}/${repo}/contents/${filePath}?ref=${branch}`;
  const res = await fetch(url, { headers: getGitHubHeaders(token) });

  if (!res.ok) {
    throw new Error(`Error al leer archivo "${filePath}" (${res.status})`);
  }

  const data = await res.json();
  if (data.encoding === 'base64' && data.content) {
    const buffer = Buffer.from(data.content, 'base64');
    return buffer.toString('utf-8');
  }

  if (data.download_url) {
    const rawRes = await fetch(data.download_url, { headers: getGitHubHeaders(token) });
    return await rawRes.text();
  }

  throw new Error('No se pudo decodificar el contenido del archivo.');
}

/**
 * Escanea masivamente todos los archivos de código del repositorio
 */
async function auditEntireRepo(owner, repo, branch = 'main', token = '', maxFiles = 30) {
  const tree = await fetchRepoFileTree(owner, repo, branch, token);
  const scannableFiles = tree.filter(f => f.isScannable && f.size < 500 * 1024).slice(0, maxFiles);

  const fileResults = [];
  let totalVulns = 0;
  let totalCritical = 0;
  let totalHigh = 0;
  let totalMedium = 0;
  let totalLow = 0;

  for (const file of scannableFiles) {
    try {
      const code = await fetchFileContent(owner, repo, file.path, branch, token);
      const scan = analyzeCode(code, file.path);

      if (scan.vulnerabilities.length > 0) {
        fileResults.push({
          path: file.path,
          lines: scan.linesCount,
          vulnerabilities: scan.vulnerabilities,
          stats: scan.stats
        });

        totalVulns += scan.vulnerabilities.length;
        totalCritical += scan.stats.critical;
        totalHigh += scan.stats.high;
        totalMedium += scan.stats.medium;
        totalLow += scan.stats.low;
      }
    } catch (err) {
      console.warn(`[Repo Audit] Error analizando ${file.path}:`, err.message);
    }
  }

  // Cálculo de salud global del repositorio
  const repoPenalty = (totalCritical * 35) + (totalHigh * 20) + (totalMedium * 10) + (totalLow * 5);
  const repoHealthScore = Math.max(0, 100 - repoPenalty);

  return {
    repository: `${owner}/${repo}`,
    branch,
    scannedFilesCount: scannableFiles.length,
    vulnerableFilesCount: fileResults.length,
    totalVulnerabilities: totalVulns,
    stats: {
      healthScore: repoHealthScore,
      critical: totalCritical,
      high: totalHigh,
      medium: totalMedium,
      low: totalLow
    },
    findingsByFile: fileResults,
    auditedAt: new Date().toISOString()
  };
}

function extractExtension(filePath) {
  if (!filePath) return '';
  const lastDot = filePath.lastIndexOf('.');
  if (lastDot === -1) return '';
  return filePath.substring(lastDot).toLowerCase();
}

module.exports = {
  parseRepoIdentifier,
  fetchRepoMetadata,
  fetchRepoFileTree,
  fetchFileContent,
  auditEntireRepo
};
