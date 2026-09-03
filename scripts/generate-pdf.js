const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// 1. Cargar imagen del logo en base64
const logoPath = path.join(__dirname, '../public/images/canary-logo.jpeg');
const logoB64 = fs.existsSync(logoPath) ? fs.readFileSync(logoPath).toString('base64') : '';
const logoDataUri = `data:image/jpeg;base64,${logoB64}`;

const htmlContent = `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>CANARY — Manual Técnico y Documentación Completa</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    @page {
      size: A4;
      margin: 14mm 14mm 14mm 14mm;
      @bottom-right {
        content: counter(page);
        font-family: 'Plus Jakarta Sans', sans-serif;
        font-size: 8pt;
        color: #71717a;
      }
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
      color: #18181b;
      background-color: #ffffff;
      line-height: 1.5;
      font-size: 9.4pt;
      -webkit-font-smoothing: antialiased;
    }

    .page-break {
      page-break-before: always;
    }

    .no-break {
      page-break-inside: avoid;
    }

    /* PORTADA EJECUTIVA */
    .cover {
      height: 94vh;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      padding: 24px 10px;
      page-break-after: always;
    }

    .cover-top {
      display: flex;
      align-items: center;
      gap: 16px;
    }

    .cover-logo {
      width: 68px;
      height: 68px;
      border-radius: 14px;
      border: 2px solid #f5c21b;
      box-shadow: 0 4px 14px rgba(245, 194, 27, 0.3);
      object-fit: cover;
    }

    .cover-brand-title {
      font-size: 24pt;
      font-weight: 800;
      letter-spacing: 0.08em;
      color: #09090b;
      line-height: 1;
    }

    .cover-brand-sub {
      font-size: 8.8pt;
      font-family: 'JetBrains Mono', monospace;
      color: #d97706;
      font-weight: 600;
      letter-spacing: 0.08em;
      margin-top: 4px;
    }

    .cover-hero {
      margin: auto 0;
    }

    .cover-badge {
      display: inline-block;
      background: #fef3c7;
      color: #b45309;
      border: 1px solid #fde68a;
      font-size: 7.8pt;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      padding: 3px 10px;
      border-radius: 9999px;
      margin-bottom: 14px;
    }

    .cover-h1 {
      font-size: 26pt;
      font-weight: 800;
      line-height: 1.15;
      color: #09090b;
      letter-spacing: -0.02em;
      margin-bottom: 12px;
    }

    .cover-desc {
      font-size: 11pt;
      color: #52525b;
      max-width: 90%;
      line-height: 1.5;
    }

    .cover-features-pill-row {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-top: 20px;
    }

    .feature-pill {
      background: #f4f4f5;
      border: 1px solid #e4e4e7;
      color: #27272a;
      padding: 5px 10px;
      border-radius: 6px;
      font-size: 8.2pt;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 5px;
    }

    .feature-pill span.dot {
      width: 5px;
      height: 5px;
      border-radius: 50%;
      background: #f5c21b;
    }

    .cover-footer {
      border-top: 1px solid #e4e4e7;
      padding-top: 16px;
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
      font-size: 8.2pt;
      color: #71717a;
    }

    .cover-footer strong {
      color: #09090b;
    }

    /* ENCABEZADOS Y SECCIONES */
    h2 {
      font-size: 13.5pt;
      font-weight: 700;
      color: #09090b;
      margin: 16pt 0 6pt;
      padding-bottom: 4pt;
      border-bottom: 1.5px solid #f4f4f5;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    h2::before {
      content: '';
      display: inline-block;
      width: 3.5px;
      height: 13pt;
      background: #f5c21b;
      border-radius: 2px;
    }

    h3 {
      font-size: 10.5pt;
      font-weight: 600;
      color: #18181b;
      margin: 10pt 0 4pt;
    }

    p {
      margin-bottom: 6pt;
      color: #3f3f46;
      text-align: justify;
    }

    strong {
      color: #09090b;
      font-weight: 600;
    }

    ul, ol {
      margin: 4pt 0 8pt 14pt;
      color: #3f3f46;
    }

    li {
      margin-bottom: 3pt;
    }

    /* CAJAS Y TARJETAS */
    .card {
      background: #fafafa;
      border: 1px solid #e4e4e7;
      border-radius: 8px;
      padding: 10pt;
      margin: 8pt 0;
    }

    .card-gold {
      background: #fffbeb;
      border: 1px solid #fef3c7;
      border-left: 4px solid #f5c21b;
      border-radius: 6px;
      padding: 8pt 10pt;
      margin: 8pt 0;
    }

    .card-gold h4 {
      color: #92400e;
      font-size: 9.5pt;
      font-weight: 700;
      margin-bottom: 3pt;
    }

    .card-dark {
      background: #09090b;
      color: #f4f4f5;
      border-radius: 8px;
      padding: 10pt 12pt;
      margin: 8pt 0;
    }

    .card-dark h4 {
      color: #f5c21b;
      font-size: 9.5pt;
      margin-bottom: 4pt;
    }

    .card-dark p {
      color: #a1a1aa;
      font-size: 8.5pt;
      margin-bottom: 3pt;
    }

    /* DIAGRAMAS VISUALES EN CSS */
    .diagram-flow {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8pt;
      margin: 14pt 0;
      padding: 12pt;
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
    }

    .diagram-box {
      flex: 1;
      background: #ffffff;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      padding: 8pt 10pt;
      text-align: center;
      font-size: 8.5pt;
    }

    .diagram-box.primary {
      border-color: #f5c21b;
      background: #fffbeb;
    }

    .diagram-box.danger {
      border-color: #ef4444;
      background: #fef2f2;
      color: #991b1b;
    }

    .diagram-box.success {
      border-color: #10b981;
      background: #ecfdf5;
      color: #065f46;
    }

    .diagram-arrow {
      font-size: 14pt;
      color: #94a3b8;
      font-weight: bold;
    }

    /* TABLAS */
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 10pt 0;
      font-size: 8.8pt;
    }

    th, td {
      padding: 7pt 10pt;
      text-align: left;
      border-bottom: 1px solid #e4e4e7;
    }

    th {
      background: #f4f4f5;
      color: #18181b;
      font-weight: 600;
      font-size: 8.5pt;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }

    tr:nth-child(even) td {
      background: #fafafa;
    }

    /* BADGES */
    .badge {
      display: inline-block;
      font-size: 7.5pt;
      font-family: 'JetBrains Mono', monospace;
      font-weight: 600;
      padding: 2px 6px;
      border-radius: 4px;
    }

    .badge-critical { background: #fee2e2; color: #b91c1c; border: 1px solid #fca5a5; }
    .badge-high { background: #fef3c7; color: #b45309; border: 1px solid #fde68a; }
    .badge-medium { background: #e0f2fe; color: #0369a1; border: 1px solid #bae6fd; }
    .badge-clean { background: #dcfce7; color: #15803d; border: 1px solid #86efac; }

    /* CÓDIGO */
    code {
      font-family: 'JetBrains Mono', monospace;
      font-size: 8.5pt;
      background: #f4f4f5;
      color: #b45309;
      padding: 1px 4px;
      border-radius: 4px;
      border: 1px solid #e4e4e7;
    }

    pre {
      background: #09090b;
      color: #f4f4f5;
      font-family: 'JetBrains Mono', monospace;
      font-size: 8pt;
      padding: 10pt 12pt;
      border-radius: 6px;
      margin: 8pt 0;
      overflow-x: auto;
      line-height: 1.45;
    }

    .code-comment { color: #71717a; }
    .code-keyword { color: #f5c21b; font-weight: 600; }
    .code-string { color: #34d399; }
    .code-danger { color: #f87171; font-weight: 600; }

    /* COMPARADOR DIFF */
    .diff-box {
      background: #09090b;
      border-radius: 6px;
      padding: 8pt 10pt;
      font-family: 'JetBrains Mono', monospace;
      font-size: 8pt;
      margin: 8pt 0;
    }

    .diff-del {
      background: rgba(239, 68, 68, 0.18);
      color: #fca5a5;
      padding: 2px 4px;
      display: block;
      border-left: 2px solid #ef4444;
    }

    .diff-add {
      background: rgba(16, 185, 129, 0.18);
      color: #86efac;
      padding: 2px 4px;
      display: block;
      border-left: 2px solid #10b981;
    }

    /* PIE DE PÁGINA IMPRESIÓN */
    .header-doc {
      display: flex;
      justify-content: space-between;
      border-bottom: 1px solid #e4e4e7;
      padding-bottom: 6pt;
      margin-bottom: 14pt;
      font-size: 8pt;
      color: #a1a1aa;
    }
  </style>
</head>
<body>

  <!-- =========================================================================
       PORTADA
       ========================================================================= -->
  <div class="cover">
    <div class="cover-top">
      <img src="${logoDataUri}" alt="Logo Canary" class="cover-logo">
      <div>
        <div class="cover-brand-title">CANARY</div>
        <div class="cover-brand-sub">DEFENSIVE CYBERSECURITY PLATFORM</div>
      </div>
    </div>

    <div class="cover-hero">
      <span class="cover-badge">Documento Técnico Oficial</span>
      <h1 class="cover-h1">Manual Completo del Sistema & Arquitectura Defensiva</h1>
      <p class="cover-desc">
        Guía explicativa integral sobre el funcionamiento del <strong>Auditor SAST Asistido por Inteligencia Artificial</strong> y el <strong>Escudo Guardián 24/7 (WAF Reverse Proxy)</strong> para la protección perimetral de sitios web y APIs.
      </p>

      <div class="cover-features-pill-row">
        <div class="feature-pill"><span class="dot"></span> Auditoría Estática de Código (SAST)</div>
        <div class="feature-pill"><span class="dot"></span> Auto-Parchado con Diff Interactivo</div>
        <div class="feature-pill"><span class="dot"></span> Conexión e Inspección GitHub</div>
        <div class="feature-pill"><span class="dot"></span> WAF Reverse Proxy 24/7 en Vivo</div>
        <div class="feature-pill"><span class="dot"></span> Monitor de Integridad (FIM SHA-256)</div>
        <div class="feature-pill"><span class="dot"></span> Protocolo de Honestidad IA</div>
      </div>
    </div>

    <div class="cover-footer">
      <div>
        <div><strong>Plataforma:</strong> CANARY Sentinel Core</div>
        <div><strong>Autoría:</strong> Equipo de Ciberseguridad Defensiva</div>
      </div>
      <div style="text-align: right;">
        <div><strong>Versión:</strong> 1.0.0 (Producción)</div>
        <div><strong>Fecha:</strong> Septiembre 2026</div>
      </div>
    </div>
  </div>

  <!-- =========================================================================
       PÁGINA 2: RESUMEN EJECUTIVO Y ARQUITECTURA GENERAL
       ========================================================================= -->
  <div class="header-doc">
    <span>CANARY — Plataforma de Ciberseguridad Defensiva</span>
    <span>Sección 1: Arquitectura General</span>
  </div>

  <h2>1. ¿Qué es CANARY y cuál es su propósito?</h2>
  <p>
    <strong>CANARY</strong> es un ecosistema defensivo de ciberseguridad diseñado para proteger aplicaciones y sitios web en dos momentos críticos: <strong>antes de salir a producción</strong> (auditando el código fuente en busca de vulnerabilidades) y <strong>después de salir a producción</strong> (vigilando e interceptando ciberataques en tiempo real las 24 horas del día).
  </p>

  <div class="card-gold">
    <h4>¿Por qué el nombre CANARY?</h4>
    <p style="margin:0; font-size:9pt; color:#78350f;">
      Históricamente, los mineros de carbón bajaban con un canario en una jaula. Debido a su sensibilidad biológica, el canario alertaba ante la presencia del más mínimo gas letal antes de que fuera percibido por los humanos. Del mismo modo, <strong>CANARY detecta amenazas ocultas en el código y en el tráfico web</strong> antes de que puedan comprometer los datos de tus clientes.
    </p>
  </div>

  <h2>2. Arquitectura General en Dos Fases</h2>
  <p>
    El sistema opera mediante dos anillos de protección desacoplados y complementarios:
  </p>

  <div class="diagram-flow no-break">
    <div class="diagram-box">
      <strong>FASE 1: PREVENTIVA</strong><br>
      <span style="color:#64748b; font-size:7.8pt;">Código Fuente / GitHub</span>
      <div style="margin-top:4pt; font-size:7.5pt; color:#0f172a;">Motor SAST + IA Generativa</div>
    </div>
    <div class="diagram-arrow">➔</div>
    <div class="diagram-box primary">
      <strong>NÚCLEO CANARY</strong><br>
      <span style="color:#d97706; font-size:7.8pt;">Análisis + Auto-Parchado</span>
      <div style="margin-top:4pt; font-size:7.5pt; color:#0f172a;">Reglas OWASP / CWE</div>
    </div>
    <div class="diagram-arrow">➔</div>
    <div class="diagram-box success">
      <strong>FASE 2: DEFENSIVA 24/7</strong><br>
      <span style="color:#059669; font-size:7.8pt;">WAF Reverse Proxy Activo</span>
      <div style="margin-top:4pt; font-size:7.5pt; color:#0f172a;">Bloqueo HTTP 403 en Milisegundos</div>
    </div>
  </div>

  <table>
    <thead>
      <tr>
        <th>Capa</th>
        <th>Tecnología / Módulo</th>
        <th>Función Principal</th>
        <th>Beneficio Inmediato</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>Auditoría Estática</strong></td>
        <td>Motor SAST Regex + Parser AST</td>
        <td>Escaneo sintáctico y semántico del código fuente</td>
        <td>Encuentra fallos antes del despliegue</td>
      </tr>
      <tr>
        <td><strong>Remediación IA</strong></td>
        <td>Motor Semántico + Orquestador LLM</td>
        <td>Generación de diagnóstico pedagógico y parches</td>
        <td>El usuario repara el fallo con un clic</td>
      </tr>
      <tr>
        <td><strong>Inspección Git</strong></td>
        <td>GitHub REST API Client</td>
        <td>Exploración y escaneo global de repositorios</td>
        <td>Auditoría masiva sin clonar proyectos</td>
      </tr>
      <tr>
        <td><strong>Perímetro 24/7</strong></td>
        <td>WAF Reverse Proxy (HTTP/SSE)</td>
        <td>Pasarela de filtrado bidireccional en tiempo real</td>
        <td>Cero cambios de código para el cliente</td>
      </tr>
      <tr>
        <td><strong>Integridad (FIM)</strong></td>
        <td>SHA-256 File Cryptographic Watcher</td>
        <td>Monitoreo continuo de cambios no autorizados</td>
        <td>Detecta inserción de webshells al instante</td>
      </tr>
    </tbody>
  </table>

  <!-- =========================================================================
       PÁGINA 3: AUDITOR SAST Y AUTO-PARCHADOR IA
       ========================================================================= -->
  <div class="page-break"></div>
  <div class="header-doc">
    <span>CANARY — Plataforma de Ciberseguridad Defensiva</span>
    <span>Sección 2: Auditor SAST & Auto-Parchador IA</span>
  </div>

  <h2>3. Módulo 1: Auditor SAST & Auto-Parchador con IA</h2>
  <p>
    El módulo de <strong>Análisis Estático de Seguridad (SAST)</strong> permite pegar cualquier fragmento de código fuente o cargar archivos desde el ordenador para someterlos a una inspección minuciosa.
  </p>

  <h3>Vulnerabilidades Detectadas de Acuerdo con OWASP y CWE</h3>
  <ul>
    <li><strong style="color:#b91c1c;">Inyección SQL (SQLi - CWE-89):</strong> Localiza concatenaciones directas de cadenas de texto dentro de consultas de bases de datos que permitirían a un atacante alterar la lógica del sistema o vaciar tablas.</li>
    <li><strong style="color:#b45309;">Cross-Site Scripting (XSS - CWE-79):</strong> Detecta inyecciones en el DOM mediante <code>innerHTML</code>, <code>document.write()</code> o variables no saneadas que facultan el robo de cookies y sesiones.</li>
    <li><strong style="color:#b45309;">Salto de Directorio (Path Traversal / LFI - CWE-22):</strong> Identifica lecturas de archivos en el servidor (ej. <code>fs.readFile</code>) donde la ruta se concatena directamente con parámetros de entrada del usuario sin normalizar ni validar contra rutas permitidas.</li>
    <li><strong style="color:#b91c1c;">Ejecución Remota de Código (RCE - CWE-78 / CWE-94):</strong> Alerta sobre el uso peligroso de funciones de consola como <code>child_process.exec()</code> o intérpretes dinámicos como <code>eval()</code>.</li>
    <li><strong style="color:#b45309;">Secretos y Credenciales en Texto Plano (Hardcoded Secrets - CWE-798):</strong> Identifica contraseñas de bases de datos, tokens JWT y claves privadas quemadas directamente en el código.</li>
  </ul>

  <h3>El Ciclo de Asistencia con IA: Diagnóstico, Parche y Honestidad</h3>
  
  <div class="card no-break">
    <strong style="font-size:10pt; color:#09090b;">1. Explicación Didáctica (Diagnóstico Pedagógico)</strong>
    <p style="font-size:9pt; margin-top:4pt;">
      Al presionar <em>"Explicar con IA"</em>, la inteligencia artificial genera un reporte estructurado explicando con claridad humana qué es la vulnerabilidad, cuál es el impacto en el negocio y la recomendación técnica estándar para solucionarla.
    </p>

    <strong style="font-size:10pt; color:#09090b;">2. Auto-Parchado con Diff Interactivo</strong>
    <p style="font-size:9pt; margin-top:4pt;">
      Al presionar <em>"Parche con IA"</em>, el sistema presenta un comparador visual que contrasta exactamente qué líneas se eliminan (rojo) y qué líneas seguras se agregan (verde):
    </p>
    
    <div class="diff-box">
      <span class="diff-del">- const query = "SELECT * FROM users WHERE user = '" + req.body.user + "';";</span>
      <span class="diff-add">+ const query = "SELECT * FROM users WHERE user = $1;";</span>
      <span class="diff-add">+ const result = await db.query(query, [req.body.user]);</span>
    </div>
    <p style="font-size:8.5pt; color:#52525b; margin-top:4pt;">
      El botón <strong>"Aplicar Parche al Editor"</strong> reemplaza automáticamente el código vulnerable por el código saneado sin que el usuario tenga que escribirlo manualmente.
    </p>

    <strong style="font-size:10pt; color:#09090b;">3. Protocolo de Honestidad y Transparencia</strong>
    <p style="font-size:9pt; margin-top:4pt;">
      Cuando el código contiene una contraseña quemada, la IA <strong>nunca inventa claves falsas</strong>. En su lugar, despliega un aviso pedagógico indicando que las credenciales no deben adivinarse ni guardarse en el código, instruyendo al desarrollador sobre cómo moverlas a un archivo <code>.env</code> seguro con <code>process.env</code>.
    </p>
  </div>

  <!-- =========================================================================
       PÁGINA 4: REPOSITORIOS GITHUB Y GUARDIÁN WAF
       ========================================================================= -->
  <div class="page-break"></div>
  <div class="header-doc">
    <span>CANARY — Plataforma de Ciberseguridad Defensiva</span>
    <span>Sección 3: Repositorios GitHub & Guardián 24/7</span>
  </div>

  <h2>4. Módulo 2: Inspección de Repositorios Git (GitHub Connect)</h2>
  <p>
    Este módulo permite analizar proyectos alojados en GitHub con total fluidez:
  </p>
  <ul>
    <li><strong>Conexión Ágil:</strong> Basta ingresar la URL del repositorio (ej. <code>https://github.com/usuario/mi-web</code>) o su identificador (<code>usuario/repo</code>). Para repositorios privados, se puede suministrar un Personal Access Token con permisos de sólo lectura (<code>contents:read</code>).</li>
    <li><strong>Explorador Inteligente:</strong> Clasifica de inmediato cuáles archivos son auditables (código fuente) y cuáles son recursos estáticos o documentación.</li>
    <li><strong>Auditoría Global (Batch Scan):</strong> El botón <em>"Auditar Todo el Repositorio"</em> ejecuta el motor SAST en paralelo sobre todos los archivos del proyecto, produciendo un <strong>Índice de Salud Global (de 0 a 100)</strong> y una lista priorizada de archivos afectados.</li>
  </ul>

  <h2>5. Módulo 3: Guardián 24/7 (WAF Reverse Proxy Activo)</h2>
  <p>
    El Guardián 24/7 es el núcleo de defensa perimetral en tiempo real. Funciona como un <strong>WAF Pasarela (Reverse Proxy)</strong> que se sitúa entre Internet y el servidor real de tu cliente.
  </p>

  <div class="diagram-flow no-break">
    <div class="diagram-box">
      <strong>Internet / Clientes</strong><br>
      <span style="font-size:7.5pt; color:#64748b;">Peticiones HTTP/HTTPS</span>
    </div>
    <div class="diagram-arrow">➔</div>
    <div class="diagram-box primary">
      <strong>PASARELA CANARY</strong><br>
      <code>/shield/:siteId/*</code><br>
      <span style="font-size:7.2pt; color:#d97706;">Filtro de Cargas Hostiles</span>
    </div>
    <div class="diagram-arrow">➔</div>
    <div class="diagram-box success">
      <strong>Servidor Real</strong><br>
      <code>localhost:8080</code><br>
      <span style="font-size:7.2pt; color:#059669;">Tráfico Limpio Aprobado</span>
    </div>
  </div>

  <div class="card no-break">
    <h4 style="font-size:10pt; color:#09090b; margin-bottom:6pt;">¿Cómo se protege una web real sin modificar su código?</h4>
    <ol style="margin-left:14pt; font-size:9pt;">
      <li>El usuario registra el nombre de la web y la URL de su servidor (ej. <code>http://localhost:8080</code> o <code>https://mi-tienda.com</code>).</li>
      <li>CANARY genera al instante una <strong>URL Pasarela Protegida</strong> (ej. <code>http://localhost:3000/shield/site_123/</code>).</li>
      <li>El cliente apunta su tráfico hacia esta URL pasarela.</li>
      <li><strong>Si la petición es limpia:</strong> El proxy la reenvía intacta al servidor del cliente y le devuelve la respuesta original (HTTP 200).</li>
      <li><strong>Si la petición contiene un ataque (SQLi, XSS, Path Traversal, RCE):</strong> La pasarela la intercepta en menos de 5 milisegundos, devuelve un <strong>HTTP 403 Forbidden</strong> y registra el incidente en el SOC en vivo sin que el servidor del cliente sufra daño alguno.</li>
    </ol>
  </div>

  <h3>File Integrity Monitoring (FIM con SHA-256)</h3>
  <p>
    El sistema calcula periódicamente el hash criptográfico SHA-256 de los archivos esenciales. Si un atacante lograse acceder al disco e inyectar un script o webshell, el hash cambia y el panel emite una alerta inmediata de compromiso de integridad.
  </p>

  <!-- =========================================================================
       PÁGINA 5: SIMULADOR, IA Y GUÍA DE USO
       ========================================================================= -->
  <div class="page-break"></div>
  <div class="header-doc">
    <span>CANARY — Plataforma de Ciberseguridad Defensiva</span>
    <span>Sección 4: Simulación, Configuración & Despliegue</span>
  </div>

  <h2>6. Módulo 4: Simulador de Ciberataques</h2>
  <p>
    Permite comprobar la efectividad del Guardián 24/7 disparando sondas controladas en tiempo real:
  </p>

  <table>
    <thead>
      <tr>
        <th>Simulación</th>
        <th>Carga Enviada (*Payload*)</th>
        <th>Comportamiento Esperado</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>Inyección SQL (SQLi)</strong></td>
        <td><code>' OR '1'='1'--</code></td>
        <td><span class="badge badge-critical">HTTP 403 Bloqueado</span> Interceptado por filtro SQLi</td>
      </tr>
      <tr>
        <td><strong>Inyección XSS</strong></td>
        <td><code>&lt;script&gt;document.location=...&lt;/script&gt;</code></td>
        <td><span class="badge badge-critical">HTTP 403 Bloqueado</span> Interceptado por filtro XSS</td>
      </tr>
      <tr>
        <td><strong>Salto de Directorio (LFI)</strong></td>
        <td><code>../../../../etc/passwd</code></td>
        <td><span class="badge badge-critical">HTTP 403 Bloqueado</span> Interceptado por filtro Traversal</td>
      </tr>
      <tr>
        <td><strong>Comandos de Consola (RCE)</strong></td>
        <td><code>127.0.0.1; cat /etc/shadow</code></td>
        <td><span class="badge badge-critical">HTTP 403 Bloqueado</span> Interceptado por filtro Shell RCE</td>
      </tr>
      <tr>
        <td><strong>Escáner Hostil (Bot)</strong></td>
        <td><code>User-Agent: sqlmap/1.7.2#stable</code></td>
        <td><span class="badge badge-critical">HTTP 403 Bloqueado</span> Neutralizado por filtro de reputación</td>
      </tr>
    </tbody>
  </table>

  <h2>7. Módulo 5: Configuración Modular de Inteligencia Artificial</h2>
  <p>
    El sistema cuenta con un conector multimodelo desacoplado:
  </p>
  <ul>
    <li><strong>Modo Local (Listo de Fábrica):</strong> No requiere claves de API ni costo alguno. Realiza el diagnóstico semántico y genera parches de seguridad de forma instantánea.</li>
    <li><strong>Conexión a OpenAI:</strong> Permite ingresar tu clave <code>sk-...</code> para conectar modelos como <code>gpt-4o</code> o <code>gpt-4o-mini</code>.</li>
    <li><strong>Conexión a Google Gemini:</strong> Permite utilizar modelos de última generación como <code>gemini-1.5-pro</code> y <code>gemini-1.5-flash</code>.</li>
    <li><strong>API Personalizada:</strong> Soporta endpoints locales compatibles con OpenAI (como Ollama, LocalAI o vLLM) para entornos con privacidad estricta.</li>
  </ul>

  <h2>8. Guía Rápida de Ejecución y Comandos</h2>

  <div class="card-dark no-break">
    <h4>Comandos de Terminal para Operar CANARY</h4>
    <pre><span class="code-comment"># 1. Iniciar el servidor principal de CANARY (Puerto 3000)</span>
<span class="code-keyword">npm</span> start

<span class="code-comment"># 2. Iniciar el servidor de demostración de tienda web de cliente (Puerto 8080)</span>
<span class="code-keyword">node</span> src/samples/customer-live-web.js

<span class="code-comment"># 3. Ejecutar la suite completa de pruebas unitarias automatizadas</span>
<span class="code-keyword">npm</span> test</pre>
  </div>

  <div class="card-gold" style="margin-top:16pt;">
    <h4>Resumen de Acceso a la Interfaz Gráfica</h4>
    <p style="margin:0; font-size:9pt; color:#78350f;">
      Una vez iniciado el servidor, ingresa en cualquier navegador moderno a:<br>
      👉 <strong>http://localhost:3000</strong>
    </p>
  </div>

</body>
</html>
`;

// Escribir archivo temporal HTML
const tempHtmlPath = path.join(__dirname, 'temp-doc-for-pdf.html');
fs.writeFileSync(tempHtmlPath, htmlContent, 'utf-8');

// Ruta final del PDF
const outputPdfPath = path.join(__dirname, '../CANARY_DOCUMENTACION_OFICIAL.pdf');

console.log('Generando PDF con Google Chrome Headless...');

const chromePath = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const command = `"${chromePath}" --headless --disable-gpu --no-pdf-header-footer --print-to-pdf="${outputPdfPath}" "file://${tempHtmlPath}"`;

try {
  execSync(command);
  console.log('✅ PDF generado exitosamente en:', outputPdfPath);
  // Limpiar HTML temporal
  if (fs.existsSync(tempHtmlPath)) fs.unlinkSync(tempHtmlPath);
} catch (err) {
  console.error('Error al generar PDF:', err.message);
  process.exit(1);
}
