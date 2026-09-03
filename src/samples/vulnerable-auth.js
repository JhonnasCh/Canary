const express = require('express');
const router = express.Router();
const db = require('./fake-db');

// VULNERABILIDAD 1: Secreto sensible hardcodeado directamente en el código fuente (CWE-798)
const JWT_SECRET = 'super-secret-key-12345-production-token-do-not-share';

router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // VULNERABILIDAD 2: Inyección SQL crítica mediante concatenación directa (CWE-89)
  const query = "SELECT * FROM users WHERE username = '" + username + "' AND active = 1";
  
  try {
    const user = await db.query(query);

    if (!user) {
      return res.status(401).json({ error: 'Usuario no encontrado' });
    }

    // VULNERABILIDAD 3: Comparación de contraseñas en texto plano sin función hash (CWE-256)
    if (user.password === password) {
      const token = jwt.sign({ userId: user.id }, JWT_SECRET);
      return res.json({ success: true, token });
    } else {
      return res.status(401).json({ error: 'Contraseña inválida' });
    }
  } catch (err) {
    return res.status(500).json({ error: 'Error en el servidor' });
  }
});

module.exports = router;
