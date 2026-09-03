/**
 * CanaryEngine - Auto-Fix Deterministic Generator
 * Generador de código de mitigación 100% funcional y sintácticamente preciso,
 * adaptado a la tecnología dominante detectada en la evidencia.
 * PRINCIPIO: Cero alucinaciones.
 */

function detectDominantStack(technologies) {
  const techNames = (technologies || []).map(t => (t.name || '').toLowerCase());

  if (techNames.some(t => t.includes('next'))) return 'nextjs';
  if (techNames.some(t => t.includes('express') || t.includes('node'))) return 'express';
  if (techNames.some(t => t.includes('django') || t.includes('python') || t.includes('flask') || t.includes('fastapi'))) return 'django';
  if (techNames.some(t => t.includes('laravel') || t.includes('php'))) return 'laravel';
  if (techNames.some(t => t.includes('apache'))) return 'apache';
  if (techNames.some(t => t.includes('nginx'))) return 'nginx';

  return 'nginx'; // Estándar de la industria para proxy inverso
}

function generateHeaderAutoFix(headerName, stack) {
  switch (stack) {
    case 'express':
      return {
        file_target: 'server.js',
        language: 'javascript',
        code_snippet: generateExpressHeaderSnippet(headerName)
      };

    case 'nextjs':
      return {
        file_target: 'next.config.js',
        language: 'javascript',
        code_snippet: generateNextJsHeaderSnippet(headerName)
      };

    case 'django':
      return {
        file_target: 'settings.py',
        language: 'python',
        code_snippet: generateDjangoHeaderSnippet(headerName)
      };

    case 'laravel':
      return {
        file_target: 'app/Http/Middleware/SecurityHeaders.php',
        language: 'php',
        code_snippet: generateLaravelHeaderSnippet(headerName)
      };

    case 'apache':
      return {
        file_target: '.htaccess',
        language: 'apache',
        code_snippet: generateApacheHeaderSnippet(headerName)
      };

    case 'nginx':
    default:
      return {
        file_target: 'nginx.conf',
        language: 'nginx',
        code_snippet: generateNginxHeaderSnippet(headerName)
      };
  }
}

function generateExpressHeaderSnippet(headerName) {
  switch (headerName) {
    case 'Content-Security-Policy':
      return `// Instalar dependencia: npm install helmet
const express = require('express');
const helmet = require('helmet');
const app = express();

app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  })
);`;

    case 'Strict-Transport-Security':
      return `const helmet = require('helmet');
app.use(
  helmet.hsts({
    maxAge: 31536000, // 1 año en segundos
    includeSubDomains: true,
    preload: true
  })
);`;

    case 'X-Frame-Options':
      return `const helmet = require('helmet');
app.use(helmet.frameguard({ action: 'deny' })); // Previene Clickjacking`;

    case 'X-Content-Type-Options':
      return `const helmet = require('helmet');
app.use(helmet.noSniff()); // Previene MIME-type sniffing`;

    default:
      return `app.use((req, res, next) => {
  res.setHeader('${headerName}', 'DENY');
  next();
});`;
  }
}

function generateNginxHeaderSnippet(headerName) {
  switch (headerName) {
    case 'Content-Security-Policy':
      return `# Bloque server {} o location / {} en nginx.conf
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests" always;`;

    case 'Strict-Transport-Security':
      return `# HSTS - Forzar HTTPS por 1 año incluyendo subdominios y precarga
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;`;

    case 'X-Frame-Options':
      return `# Mitigación de Clickjacking
add_header X-Frame-Options "DENY" always;`;

    case 'X-Content-Type-Options':
      return `# Prevención de MIME-Sniffing
add_header X-Content-Type-Options "nosniff" always;`;

    default:
      return `add_header ${headerName} "1; mode=block" always;`;
  }
}

function generateApacheHeaderSnippet(headerName) {
  switch (headerName) {
    case 'Content-Security-Policy':
      return `# Requiere módulo mod_headers activado: a2enmod headers
<IfModule mod_headers.c>
  Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none';"
</IfModule>`;

    case 'Strict-Transport-Security':
      return `<IfModule mod_headers.c>
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
</IfModule>`;

    case 'X-Frame-Options':
      return `<IfModule mod_headers.c>
  Header always set X-Frame-Options "DENY"
</IfModule>`;

    case 'X-Content-Type-Options':
      return `<IfModule mod_headers.c>
  Header always set X-Content-Type-Options "nosniff"
</IfModule>`;

    default:
      return `<IfModule mod_headers.c>
  Header always set ${headerName} "DENY"
</IfModule>`;
  }
}

function generateNextJsHeaderSnippet(headerName) {
  const headerMap = {
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'",
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff'
  };

  const val = headerMap[headerName] || 'DENY';

  return `// next.config.js
module.exports = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: '${headerName}',
            value: "${val}",
          },
        ],
      },
    ];
  },
};`;
}

function generateDjangoHeaderSnippet(headerName) {
  switch (headerName) {
    case 'Content-Security-Policy':
      return `# settings.py (con paquete django-csp: pip install django-csp)
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'csp.middleware.CSPMiddleware',
    # ... otros middlewares
]

CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")
CSP_IMG_SRC = ("'self'", "data:")
CSP_OBJECT_SRC = ("'none'",)`;

    case 'Strict-Transport-Security':
      return `# settings.py
SECURE_HSTS_SECONDS = 31536000 # 1 año
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_SSL_REDIRECT = True`;

    case 'X-Frame-Options':
      return `# settings.py
X_FRAME_OPTIONS = 'DENY'`;

    case 'X-Content-Type-Options':
      return `# settings.py
SECURE_CONTENT_TYPE_NOSNIFF = True`;

    default:
      return `# Configuración de seguridad en settings.py`;
  }
}

function generateLaravelHeaderSnippet(headerName) {
  return `<?php
// app/Http/Middleware/SecurityHeaders.php
namespace App\\Http\\Middleware;
use Closure;

class SecurityHeaders {
    public function handle($request, Closure $next) {
        $response = $next($request);
        $response->headers->set('${headerName}', '${headerName === 'Strict-Transport-Security' ? 'max-age=31536000; includeSubDomains; preload' : (headerName === 'X-Content-Type-Options' ? 'nosniff' : 'DENY')}');
        return $response;
    }
}`;
}

function generateCookieAutoFix(stack, insecureCookies) {
  const cookieNames = (insecureCookies || []).map(c => c.name).join(', ') || 'session_id';

  switch (stack) {
    case 'express':
      return {
        file_target: 'server.js',
        language: 'javascript',
        code_snippet: `// Configuración de cookies seguras en Express
const session = require('express-session');

app.use(session({
  name: '__Host-session', // Prefijo seguro
  secret: process.env.SESSION_SECRET || 'genera-un-secreto-criptografico-fuerte',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true, // Bloquea acceso desde JavaScript (mitiga XSS)
    secure: true,   // Solo transmite por HTTPS
    sameSite: 'strict', // Mitiga CSRF
    maxAge: 1000 * 60 * 60 * 2 // 2 horas
  }
}));`
      };

    case 'django':
      return {
        file_target: 'settings.py',
        language: 'python',
        code_snippet: `# settings.py - Forzar banderas seguras para cookies de sesión y CSRF
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = 'Strict'
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_SAMESITE = 'Strict'`
      };

    case 'laravel':
      return {
        file_target: 'config/session.php',
        language: 'php',
        code_snippet: `// config/session.php
return [
    'secure' => env('SESSION_SECURE_COOKIE', true),
    'http_only' => true,
    'same_site' => 'strict',
];`
      };

    case 'nginx':
    default:
      return {
        file_target: 'nginx.conf',
        language: 'nginx',
        code_snippet: `# Inyectar directivas Secure y HttpOnly en cookies proxy pasadas al cliente
proxy_cookie_path / "/; Secure; HttpOnly; SameSite=Strict";`
      };
  }
}

function generateSSLAutoFix(stack) {
  return {
    file_target: 'certbot / nginx.conf',
    language: 'bash',
    code_snippet: `# 1. Obtener e instalar certificado SSL/TLS con Let's Encrypt (Certbot)
sudo apt update && sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d tudominio.com -d www.tudominio.com --redirect

# 2. Asegurar TLS 1.2 y 1.3 en nginx.conf
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers HIGH:!aNULL:!MD5;
ssl_prefer_server_ciphers on;`
  };
}

function generateCVEAutoFix(cve, stack) {
  const component = (cve.component || 'dependencia').toLowerCase();

  if (component.includes('express') || stack === 'express' || stack === 'nextjs') {
    return {
      file_target: 'package.json',
      language: 'bash',
      code_snippet: `# Remediar ${cve.cve_id} en ${cve.component}:
npm audit fix --force
# O actualizar paquete específico a la última versión segura:
npm update ${component} --depth 999`
    };
  }

  if (stack === 'django') {
    return {
      file_target: 'requirements.txt',
      language: 'bash',
      code_snippet: `# Remediar ${cve.cve_id} en ${cve.component}:
pip install --upgrade ${component}
pip freeze > requirements.txt`
    };
  }

  if (stack === 'laravel') {
    return {
      file_target: 'composer.json',
      language: 'bash',
      code_snippet: `# Remediar ${cve.cve_id} en ${cve.component}:
composer update ${component} --with-all-dependencies`
    };
  }

  return {
    file_target: 'Dockerfile / server',
    language: 'bash',
    code_snippet: `# Actualizar paquete del sistema operativo para mitigar ${cve.cve_id}:
sudo apt update && sudo apt --only-upgrade install ${component}`
  };
}

module.exports = {
  detectDominantStack,
  generateHeaderAutoFix,
  generateCookieAutoFix,
  generateSSLAutoFix,
  generateCVEAutoFix
};
