/**
 * CanaryEngine - GitHub Auto-Remediation Integrator
 * Automatiza la creación de ramas y Pull Requests de seguridad en GitHub
 * mediante la API REST oficial (sin alucinaciones ni pushes destructivos).
 */

const https = require('https');

class GitHubIntegrator {
  /**
   * Realiza una petición HTTPS genérica a la API de GitHub v3
   */
  async requestGitHub(token, endpoint, method = 'GET', data = null) {
    return new Promise((resolve, reject) => {
      const url = new URL(`https://api.github.com${endpoint}`);
      const payload = data ? JSON.stringify(data) : null;

      const options = {
        hostname: url.hostname,
        path: url.pathname + url.search,
        method: method,
        headers: {
          'User-Agent': 'Canary-AI-Security-Engine',
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/vnd.github.v3+json',
          ...(payload ? {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload)
          } : {})
        }
      };

      const req = https.request(options, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
          try {
            const parsed = body ? JSON.parse(body) : {};
            if (res.statusCode >= 200 && res.statusCode < 300) {
              resolve(parsed);
            } else {
              reject(new Error(parsed.message || `GitHub API Error HTTP ${res.statusCode}`));
            }
          } catch (e) {
            reject(new Error(`Error al parsear respuesta de GitHub: ${body}`));
          }
        });
      });

      req.on('error', reject);
      if (payload) req.write(payload);
      req.end();
    });
  }

  /**
   * Crea un Pull Request de seguridad completo en el repositorio del cliente
   */
  async createSecurityPullRequest({ token, repo, fileTarget, patchCode, vulnId, vulnTitle, severity }) {
    // Si es modo Demo/Simulación (token de prueba o no provisto)
    if (!token || token === 'demo_token' || token.startsWith('demo_')) {
      const branchName = `canary/auto-fix-${(vulnId || 'patch').toLowerCase()}-${Date.now().toString().slice(-4)}`;
      return {
        success: true,
        mode: 'SIMULATION_SANDBOX',
        repo: repo || 'empresa/web-backend',
        branch: branchName,
        pr_number: Math.floor(Math.random() * 80) + 10,
        pr_url: `https://github.com/${repo || 'empresa/web-backend'}/pull/${Math.floor(Math.random() * 80) + 10}`,
        title: `[Canary AI Auto-Fix] Mitigación de seguridad: ${vulnTitle}`,
        file_modified: fileTarget,
        message: 'Pull Request generado en sandbox con éxito. Listo para merge seguro.'
      };
    }

    try {
      const [owner, repoName] = repo.split('/');
      if (!owner || !repoName) {
        throw new Error("El formato del repositorio debe ser 'propietario/repositorio' (ej. usuario/mi-web).");
      }

      // 1. Obtener la rama por defecto (main o master)
      const repoInfo = await this.requestGitHub(token, `/repos/${owner}/${repoName}`);
      const defaultBranch = repoInfo.default_branch || 'main';

      // 2. Obtener el commit SHA de la rama por defecto
      const branchInfo = await this.requestGitHub(token, `/repos/${owner}/${repoName}/git/ref/heads/${defaultBranch}`);
      const latestCommitSha = branchInfo.object.sha;

      // 3. Crear una nueva rama dedicada al parche de Canary
      const newBranchName = `canary/security-patch-${(vulnId || 'fix').toLowerCase()}-${Date.now().toString().slice(-4)}`;
      await this.requestGitHub(token, `/repos/${owner}/${repoName}/git/refs`, 'POST', {
        ref: `refs/heads/${newBranchName}`,
        sha: latestCommitSha
      });

      // 4. Obtener el SHA actual del archivo si existe (para actualizarlo)
      let fileSha = null;
      try {
        const existingFile = await this.requestGitHub(token, `/repos/${owner}/${repoName}/contents/${fileTarget}?ref=${newBranchName}`);
        fileSha = existingFile.sha;
      } catch (e) {
        // El archivo no existe aún, se creará nuevo
      }

      // 5. Commit del código del parche en la nueva rama
      const commitMessage = `fix(security): aplicar parche de mitigación para ${vulnId}\n\nGenerado por Canary AI Engine.\nSeveridad: ${severity}`;
      const contentEncoded = Buffer.from(patchCode).toString('base64');

      await this.requestGitHub(token, `/repos/${owner}/${repoName}/contents/${fileTarget}`, 'PUT', {
        message: commitMessage,
        content: contentEncoded,
        branch: newBranchName,
        ...(fileSha ? { sha: fileSha } : {})
      });

      // 6. Abrir el Pull Request oficial
      const prBody = `## 🛡️ Canary AI - Auto-Fix Security Patch\n\n` +
        `**Vulnerabilidad Mitigada**: \`${vulnId}\` - ${vulnTitle}\n` +
        `**Nivel de Severidad**: \`${severity}\`\n` +
        `**Archivo Objetivo Modificado**: \`${fileTarget}\`\n\n` +
        `### Descripción del Cambio:\n` +
        `Este parche fue sintetizado de manera determinista por el motor **CanaryEngine** tras evaluar la evidencia técnica cruda del escáner.\n\n` +
        `### Pasos de Validación:\n` +
        `1. Revise los diffs en la pestaña *Files changed*.\n` +
        `2. Verifique la ejecución del pipeline CI/CD.\n` +
        `3. Realice merge de este PR para desplegar la protección.\n\n` +
        `*Generado automáticamente por Canary AI Defense Core.*`;

      const prResponse = await this.requestGitHub(token, `/repos/${owner}/${repoName}/pulls`, 'POST', {
        title: `[Canary AI Auto-Fix] Mitigación para ${vulnId}: ${vulnTitle}`,
        head: newBranchName,
        base: defaultBranch,
        body: prBody
      });

      return {
        success: true,
        mode: 'LIVE_GITHUB',
        repo: repo,
        branch: newBranchName,
        pr_number: prResponse.number,
        pr_url: prResponse.html_url,
        title: prResponse.title,
        file_modified: fileTarget,
        message: 'Pull Request creado exitosamente en GitHub.'
      };
    } catch (error) {
      throw new Error(`Fallo en automatización GitHub: ${error.message}`);
    }
  }
}

const gitHubIntegrator = new GitHubIntegrator();

module.exports = { gitHubIntegrator };
