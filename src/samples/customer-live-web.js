/**
 * Canary Sentinel - Servidor Web de Demostración del Cliente
 * 
 * Este es un servidor web real e independiente (puerto 8080) que simula
 * la aplicación web o tienda de un cliente.
 * 
 * Al pasar por el Escudo Reverse Proxy de Canary Sentinel:
 * - El tráfico legítimo llega a este servidor intacto.
 * - Los ataques hostiles son bloqueados en la pasarela y NUNCA tocan este servidor.
 */

const express = require('express');
const app = express();
const PORT = process.env.CUSTOMER_PORT || 8080;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Registro en consola de peticiones que efectivamente alcanzan este servidor
app.use((req, res, next) => {
  const isProtected = req.headers['x-canary-shield'] === 'Verified-Clean';
  console.log(`[Customer Web :8080] ${new Date().toLocaleTimeString()} → ${req.method} ${req.url} | Escudo: ${isProtected ? '🛡️ PROTEGIDO POR CANARY SENTINEL' : '⚠️ Directo (Sin Escudo)'}`);
  next();
});

// 1. Página de inicio de la web del cliente
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="es">
    <head>
      <meta charset="UTF-8">
      <title>TechNova Store - Web Real del Cliente</title>
      <style>
        body { font-family: -apple-system, sans-serif; background: #f1f5f9; color: #1e293b; padding: 40px; margin: 0; }
        .card { max-width: 700px; margin: 0 auto; background: white; border-radius: 12px; padding: 30px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); }
        h1 { color: #0284c7; }
        .badge { background: #dcfce7; color: #166534; padding: 6px 12px; border-radius: 20px; font-size: 14px; font-weight: bold; }
        .endpoint { background: #f8fafc; border: 1px solid #e2e8f0; padding: 12px; border-radius: 8px; margin-top: 10px; font-family: monospace; }
      </style>
    </head>
    <body>
      <div class="card">
        <span class="badge">● SERVIDOR DEL CLIENTE ACTIVO (Puerto 8080)</span>
        <h1>TechNova Solutions</h1>
        <p>Esta es la aplicación web real del cliente. Contiene base de datos de usuarios y catálogo de productos.</p>
        <hr style="border: 0; border-top: 1px solid #e2e8f0; margin: 20px 0;">
        <h3>Endpoints Disponibles:</h3>
        <div class="endpoint">GET /api/products → Catálogo de productos</div>
        <div class="endpoint">GET /api/search?q=término → Búsqueda en catálogo</div>
        <div class="endpoint">POST /api/login → Autenticación de usuarios</div>
      </div>
    </body>
    </html>
  `);
});

// 2. Catálogo de productos
app.get('/api/products', (req, res) => {
  res.json({
    store: 'TechNova Store',
    status: 'ACTIVE',
    products: [
      { id: 101, name: 'Servidor Cloud Pro Ultra', price: 499.00, stock: 15 },
      { id: 102, name: 'Base de Datos PostgreSQL Enterprise', price: 299.00, stock: 24 },
      { id: 103, name: 'Certificado SSL Wildcard', price: 89.00, stock: 999 }
    ],
    timestamp: new Date().toISOString()
  });
});

// 3. Endpoint de búsqueda
app.get('/api/search', (req, res) => {
  const query = req.query.q || '';
  res.json({
    message: `Resultados de búsqueda para: "${query}"`,
    matchesFound: 3,
    queryProcessedSafely: true,
    data: ['Servidor Cloud', 'Base de Datos', 'Certificado SSL']
  });
});

// 4. Endpoint de login
app.post('/api/login', (req, res) => {
  const { username } = req.body;
  res.json({
    success: true,
    user: username || 'invitado',
    message: 'Sesión procesada en el servidor del cliente.'
  });
});

app.listen(PORT, () => {
  console.log(`[Customer Web] 🌐 Servidor real del cliente corriendo en http://localhost:${PORT}`);
});
