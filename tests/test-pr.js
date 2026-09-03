const http = require('http');

const payload = JSON.stringify({
  repo: 'cliente/ecommerce-api',
  fileTarget: 'server.js',
  patchCode: 'const helmet = require("helmet"); app.use(helmet());',
  vulnId: 'VULN-HDR-CSP',
  vulnTitle: 'Ausencia de CSP',
  severity: 'HIGH'
});

const req = http.request('http://localhost:3000/api/github/create-pr', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(payload)
  }
}, res => {
  let body = '';
  res.on('data', d => body += d);
  res.on('end', () => console.log('PR Sandbox Output:\n', JSON.stringify(JSON.parse(body), null, 2)));
});

req.write(payload);
req.end();
