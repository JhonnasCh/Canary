// Muestra de código Frontend con vulnerabilidades comunes en clientes web

function renderUserProfile(userData) {
  const profileContainer = document.getElementById('profile-box');
  
  // VULNERABILIDAD 1: DOM-XSS por inserción directa en innerHTML sin sanitizar (CWE-79)
  profileContainer.innerHTML = '<h2>Bienvenido, ' + userData.username + '</h2><p>' + userData.bio + '</p>';
}

function processDynamicCalculation(userFormula) {
  // VULNERABILIDAD 2: Uso peligroso de eval() para computar expresiones del usuario (CWE-95)
  // La IA activará su Protocolo de Honestidad aquí indicando que no puede auto-parcharlo a ciegas
  const result = eval(userFormula);
  return result;
}

// VULNERABILIDAD 3: Configuración insegura de CORS
function setupApiHeaders(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
}
