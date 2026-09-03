const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

// VULNERABILIDAD 1: Salto de Directorio Arbitrario (Path Traversal / LFI) (CWE-22)
router.get('/download', (req, res) => {
  const filename = req.query.file;
  // Peligro: path.join con req.query sin validación permite secuencias ../../../../etc/passwd
  const filePath = path.join(__dirname, 'public', req.query.file);

  fs.readFile(filePath, (err, data) => {
    if (err) return res.status(404).send('Archivo no encontrado');
    res.send(data);
  });
});

// VULNERABILIDAD 2: Inyección de Comandos del Sistema Operativo (CWE-78)
router.post('/convert', (req, res) => {
  const userFile = req.body.fileName;
  // Peligro: exec invoca directamente /bin/sh concatenando la entrada del usuario
  exec(`convert-image ${userFile} output.png`, (error, stdout, stderr) => {
    if (error) return res.status(500).json({ error: 'Error en la conversión' });
    res.json({ success: true, message: 'Conversión finalizada' });
  });
});

module.exports = router;
