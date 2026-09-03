/**
 * Canary — Security Scanner Module
 * Deterministic scanning: NO AI, NO hallucinations.
 * Performs real HTTP requests and analyzes responses.
 */

const https = require('https');
const http = require('http');
const { URL } = require('url');
const tls = require('tls');
const dns = require('dns').promises;

// ==========================================
// TECHNOLOGY SIGNATURES DATABASE (80+ Technologies)
// ==========================================
const TECH_SIGNATURES = {
  // Detected from response headers
  headers: {
    'x-powered-by': {
      'Express': { name: 'Express', category: 'Backend Framework', icon: '⚡' },
      'PHP': { name: 'PHP', category: 'Language', icon: '🐘' },
      'ASP.NET': { name: 'ASP.NET', category: 'Backend Framework', icon: '🔷' },
      'Next.js': { name: 'Next.js', category: 'Fullstack Framework', icon: '▲' },
      'Nuxt': { name: 'Nuxt.js', category: 'Fullstack Framework', icon: '💚' },
      'Koa': { name: 'Koa', category: 'Backend Framework', icon: '🌿' },
      'Fastify': { name: 'Fastify', category: 'Backend Framework', icon: '🐎' },
      'NestJS': { name: 'NestJS', category: 'Backend Framework', icon: '🦁' },
      'W3 Total Cache': { name: 'WordPress W3 Total Cache', category: 'Plugin', icon: '📝' },
      'WP Engine': { name: 'WP Engine', category: 'Hosting Platform', icon: '⚙️' },
    },
    'server': {
      'nginx': { name: 'Nginx', category: 'Web Server', icon: '🟢' },
      'Apache': { name: 'Apache', category: 'Web Server', icon: '🪶' },
      'cloudflare': { name: 'Cloudflare', category: 'CDN/WAF', icon: '☁️' },
      'Vercel': { name: 'Vercel', category: 'Platform', icon: '▲' },
      'Netlify': { name: 'Netlify', category: 'Platform', icon: '🔷' },
      'Microsoft-IIS': { name: 'Microsoft IIS', category: 'Web Server', icon: '🪟' },
      'gunicorn': { name: 'Gunicorn', category: 'WSGI Server', icon: '🐍' },
      'uvicorn': { name: 'Uvicorn', category: 'ASGI Server', icon: '🐍' },
      'caddy': { name: 'Caddy', category: 'Web Server', icon: '🔒' },
      'litespeed': { name: 'LiteSpeed', category: 'Web Server', icon: '⚡' },
      'openresty': { name: 'OpenResty', category: 'Web Server', icon: '🟢' },
      'envoy': { name: 'Envoy Proxy', category: 'Proxy', icon: '🛰️' },
      'Cowboy': { name: 'Erlang Cowboy (Heroku)', category: 'Web Server', icon: '🤠' },
      'Kestrel': { name: 'ASP.NET Kestrel', category: 'Web Server', icon: '🔷' },
      'Google Frontend': { name: 'Google Cloud Platform', category: 'Platform', icon: '🌐' },
    },
    'x-aspnet-version': {
      '': { name: 'ASP.NET', category: 'Backend Framework', icon: '🔷' },
    },
    'x-generator': {
      'Drupal': { name: 'Drupal', category: 'CMS', icon: '💧' },
      'WordPress': { name: 'WordPress', category: 'CMS', icon: '📝' },
      'Joomla': { name: 'Joomla', category: 'CMS', icon: '📋' },
    },
  },
  // Detected from HTML body content
  body: [
    { pattern: /__next|next-head-count|__NEXT_DATA__/i, name: 'Next.js', category: 'Fullstack Framework', icon: '▲' },
    { pattern: /__nuxt|data-n-head|__NUXT__/i, name: 'Nuxt.js', category: 'Fullstack Framework', icon: '💚' },
    { pattern: /_app\.js|react-dom|reactDOM|data-reactroot|__REACT|_reactRootContainer/i, name: 'React', category: 'Frontend Library', icon: '⚛️' },
    { pattern: /vue\.?js|v-app|data-v-|__vue|Vue\.config|data-server-rendered/i, name: 'Vue.js', category: 'Frontend Framework', icon: '💚' },
    { pattern: /ng-version|angular\.min|ng-app|angular\.io|_ngcontent/i, name: 'Angular', category: 'Frontend Framework', icon: '🔴' },
    { pattern: /svelte|__svelte|svelte-announcer/i, name: 'Svelte', category: 'Frontend Framework', icon: '🟠' },
    { pattern: /wp-content|wp-includes|wordpress|wp-json|xmlrpc\.php/i, name: 'WordPress', category: 'CMS', icon: '📝' },
    { pattern: /woocommerce|wc-cart-fragments/i, name: 'WooCommerce', category: 'E-commerce', icon: '🛒' },
    { pattern: /jquery[\.\-]?\d|jquery\.min\.js|jquery\.js|jQuery\s*v/i, name: 'jQuery', category: 'Frontend Library', icon: '📜' },
    { pattern: /jquery-ui|ui-widget|ui-dialog/i, name: 'jQuery UI', category: 'Frontend Library', icon: '📜' },
    { pattern: /bootstrap\.min|bootstrap\.css|bootstrap\.js|data-bs-toggle/i, name: 'Bootstrap', category: 'CSS Framework', icon: '🅱️' },
    { pattern: /tailwindcss|tailwind\.min|tailwind/i, name: 'Tailwind CSS', category: 'CSS Framework', icon: '🌊' },
    { pattern: /gatsby|___gatsby/i, name: 'Gatsby', category: 'Frontend Framework', icon: '💜' },
    { pattern: /remix|__remix/i, name: 'Remix', category: 'Fullstack Framework', icon: '💿' },
    { pattern: /astro-island|data-astro|astro\.build/i, name: 'Astro', category: 'Fullstack Framework', icon: '🚀' },
    { pattern: /laravel|csrf-token.*content|livewire/i, name: 'Laravel', category: 'Backend Framework', icon: '🔴' },
    { pattern: /django|csrfmiddlewaretoken/i, name: 'Django', category: 'Backend Framework', icon: '🐍' },
    { pattern: /flask/i, name: 'Flask', category: 'Backend Framework', icon: '🐍' },
    { pattern: /fastapi/i, name: 'FastAPI', category: 'Backend Framework', icon: '⚡' },
    { pattern: /ruby on rails|rails|turbolinks|stimulus/i, name: 'Ruby on Rails', category: 'Fullstack Framework', icon: '💎' },
    { pattern: /ember|ember-application/i, name: 'Ember.js', category: 'Frontend Framework', icon: '🐹' },
    { pattern: /backbone/i, name: 'Backbone.js', category: 'Frontend Library', icon: '📜' },
    { pattern: /lodash/i, name: 'Lodash', category: 'Utility Library', icon: '📦' },
    { pattern: /moment\.js|moment\.min/i, name: 'Moment.js', category: 'Utility Library', icon: '🕐' },
    { pattern: /dayjs|day\.js/i, name: 'Day.js', category: 'Utility Library', icon: '📅' },
    { pattern: /axios/i, name: 'Axios', category: 'HTTP Client', icon: '📡' },
    { pattern: /socket\.io/i, name: 'Socket.io', category: 'Realtime Library', icon: '🔌' },
    { pattern: /three\.js|three\.min/i, name: 'Three.js', category: '3D Graphics', icon: '🎮' },
    { pattern: /d3\.js|d3\.min|d3\.v\d/i, name: 'D3.js', category: 'Data Visualization', icon: '📊' },
    { pattern: /chart\.js|chartjs/i, name: 'Chart.js', category: 'Data Visualization', icon: '📈' },
    { pattern: /highcharts/i, name: 'Highcharts', category: 'Data Visualization', icon: '📊' },
    { pattern: /apexcharts/i, name: 'ApexCharts', category: 'Data Visualization', icon: '📈' },
    { pattern: /gsap|greensock|TweenMax/i, name: 'GSAP', category: 'Animation Library', icon: '🎬' },
    { pattern: /swiper|swiper-container|swiper-slide/i, name: 'Swiper Slider', category: 'UI Component', icon: '🖼️' },
    { pattern: /slick-slider|slick\.min/i, name: 'Slick Carousel', category: 'UI Component', icon: '🖼️' },
    { pattern: /handlebars/i, name: 'Handlebars', category: 'Template Engine', icon: '📝' },
    { pattern: /mustache/i, name: 'Mustache', category: 'Template Engine', icon: '📝' },
    { pattern: /underscore/i, name: 'Underscore.js', category: 'Utility Library', icon: '📦' },
    { pattern: /alpine\.?js|x-data|x-bind|x-show/i, name: 'Alpine.js', category: 'Frontend Framework', icon: '🏔️' },
    { pattern: /htmx|hx-get|hx-post/i, name: 'HTMX', category: 'Frontend Library', icon: '📡' },
    { pattern: /preact/i, name: 'Preact', category: 'Frontend Framework', icon: '⚛️' },
    { pattern: /solid-js|solidjs/i, name: 'Solid.js', category: 'Frontend Framework', icon: '💙' },
    { pattern: /lit-html|lit-element/i, name: 'Lit', category: 'Web Components', icon: '🔥' },
    { pattern: /webflow|w-nav|w-slider/i, name: 'Webflow', category: 'Website Builder', icon: '🌐' },
    { pattern: /framer\.com|framer-motion|framerUser/i, name: 'Framer', category: 'Website Builder', icon: '🖼️' },
    { pattern: /fontawesome|fa-solid|fa-regular|fa-brands/i, name: 'Font Awesome', category: 'Icons', icon: '🎨' },
    { pattern: /google-analytics|gtag|ga\.js|analytics\.js|googletagmanager/i, name: 'Google Analytics & GTM', category: 'Analytics', icon: '📊' },
    { pattern: /hotjar\.com|hjid/i, name: 'Hotjar', category: 'User Analytics', icon: '🔥' },
    { pattern: /clarity\.ms/i, name: 'Microsoft Clarity', category: 'User Analytics', icon: '👁️' },
    { pattern: /mixpanel/i, name: 'Mixpanel', category: 'Product Analytics', icon: '📊' },
    { pattern: /segment\.com|analytics\.track/i, name: 'Segment', category: 'Data Platform', icon: '🔄' },
    { pattern: /sentry\.io|Sentry\.init|raven\.js/i, name: 'Sentry', category: 'Monitoring', icon: '🛡️' },
    { pattern: /datadoghq|datadog/i, name: 'Datadog', category: 'Monitoring', icon: '🐶' },
    { pattern: /newrelic|NREUM/i, name: 'New Relic', category: 'Monitoring', icon: '📉' },
    { pattern: /stripe\.com|Stripe\(|stripe-js/i, name: 'Stripe', category: 'Payment Processing', icon: '💳' },
    { pattern: /paypal\.com|paypal-sdk/i, name: 'PayPal', category: 'Payment Processing', icon: '💳' },
    { pattern: /recaptcha\/api\.js|grecaptcha/i, name: 'Google reCAPTCHA', category: 'Security / Bot Defense', icon: '🤖' },
    { pattern: /hcaptcha\.com|hcaptcha/i, name: 'hCaptcha', category: 'Security / Bot Defense', icon: '🤖' },
    { pattern: /challenges\.cloudflare\.com\/turnstile/i, name: 'Cloudflare Turnstile', category: 'Security / Bot Defense', icon: '🛡️' },
    { pattern: /intercom\.io|Intercom\(/i, name: 'Intercom', category: 'Customer Support', icon: '💬' },
    { pattern: /zendesk\.com|zE\(/i, name: 'Zendesk', category: 'Customer Support', icon: '💬' },
    { pattern: /crisp\.chat|\$crisp/i, name: 'Crisp Chat', category: 'Customer Support', icon: '💬' },
    { pattern: /auth0\.com|auth0-js/i, name: 'Auth0', category: 'Authentication', icon: '🔐' },
    { pattern: /clerk\.com|clerk-js/i, name: 'Clerk Auth', category: 'Authentication', icon: '🔐' },
    { pattern: /firebase\.google\.com|firebaseio\.com|firebase/i, name: 'Firebase', category: 'BaaS / Database', icon: '🔥' },
    { pattern: /supabase\.co|supabase/i, name: 'Supabase', category: 'BaaS / Database', icon: '⚡' },
    { pattern: /chakra-ui|@chakra-ui/i, name: 'Chakra UI', category: 'UI Framework', icon: '⚡' },
    { pattern: /material-ui|mui|@mui/i, name: 'Material UI (MUI)', category: 'UI Framework', icon: '🎨' },
    { pattern: /ant-design|antd/i, name: 'Ant Design', category: 'UI Framework', icon: '🐜' },
    { pattern: /styled-components/i, name: 'Styled Components', category: 'CSS-in-JS', icon: '💅' },
    { pattern: /emotion\/react|@emotion/i, name: 'Emotion', category: 'CSS-in-JS', icon: '👩‍🎤' },
    { pattern: /bulma\.min\.css|bulma\.css/i, name: 'Bulma', category: 'CSS Framework', icon: '🥦' },
  ],
  // Detected from meta tags
  meta: [
    { name: 'generator', pattern: /wordpress\s*([\d.]*)/i, tech: { name: 'WordPress', category: 'CMS', icon: '📝' } },
    { name: 'generator', pattern: /drupal\s*([\d.]*)/i, tech: { name: 'Drupal', category: 'CMS', icon: '💧' } },
    { name: 'generator', pattern: /joomla[!]?\s*([\d.]*)/i, tech: { name: 'Joomla', category: 'CMS', icon: '📋' } },
    { name: 'generator', pattern: /shopify/i, tech: { name: 'Shopify', category: 'E-commerce', icon: '🛒' } },
    { name: 'generator', pattern: /wix\.com/i, tech: { name: 'Wix', category: 'Website Builder', icon: '🌐' } },
    { name: 'generator', pattern: /squarespace/i, tech: { name: 'Squarespace', category: 'Website Builder', icon: '⬛' } },
    { name: 'generator', pattern: /hugo\s*([\d.]*)/i, tech: { name: 'Hugo', category: 'Static Site Generator', icon: '📄' } },
    { name: 'generator', pattern: /ghost\s*([\d.]*)/i, tech: { name: 'Ghost', category: 'CMS', icon: '👻' } },
    { name: 'generator', pattern: /hexo/i, tech: { name: 'Hexo', category: 'Static Site Generator', icon: '📄' } },
    { name: 'generator', pattern: /jekyll\s*v?([\d.]*)/i, tech: { name: 'Jekyll', category: 'Static Site Generator', icon: '📄' } },
    { name: 'generator', pattern: /docusaurus\s*v?([\d.]*)/i, tech: { name: 'Docusaurus', category: 'Documentation Framework', icon: '🦖' } },
    { name: 'generator', pattern: /magento\s*([\d.]*)/i, tech: { name: 'Magento', category: 'E-commerce', icon: '🛍️' } },
    { name: 'generator', pattern: /prestashop\s*([\d.]*)/i, tech: { name: 'PrestaShop', category: 'E-commerce', icon: '🐧' } },
    { name: 'generator', pattern: /hubspot/i, tech: { name: 'HubSpot CMS', category: 'CMS', icon: '🟠' } },
  ],
  // Detected from script/link tag URLs — pattern extracts version from URL
  scripts: [
    { pattern: /jquery[.-]([\d.]+)/i, name: 'jQuery' },
    { pattern: /jquery-ui[.-]([\d.]+)/i, name: 'jQuery UI' },
    { pattern: /bootstrap[.-]([\d.]+)/i, name: 'Bootstrap' },
    { pattern: /vue[.-]([\d.]+)/i, name: 'Vue.js' },
    { pattern: /react[.-]dom[.-]([\d.]+)/i, name: 'React' },
    { pattern: /react[.-]([\d.]+)/i, name: 'React' },
    { pattern: /angular[.-]([\d.]+)/i, name: 'Angular' },
    { pattern: /d3[.-]v?([\d.]+)/i, name: 'D3.js' },
    { pattern: /moment[.-]([\d.]+)/i, name: 'Moment.js' },
    { pattern: /dayjs@([\d.]+)|dayjs[.-]([\d.]+)/i, name: 'Day.js' },
    { pattern: /lodash[.-]([\d.]+)/i, name: 'Lodash' },
    { pattern: /axios[.-]([\d.]+)|axios@([\d.]+)/i, name: 'Axios' },
    { pattern: /three[.-]([\d.]+)|three@([\d.]+)/i, name: 'Three.js' },
    { pattern: /socket\.io[.-]([\d.]+)|socket\.io@([\d.]+)/i, name: 'Socket.io' },
    { pattern: /chart[.-]js[.-]?([\d.]+)|chart\.js@([\d.]+)/i, name: 'Chart.js' },
    { pattern: /highcharts[.-]([\d.]+)/i, name: 'Highcharts' },
    { pattern: /apexcharts[.-]([\d.]+)/i, name: 'ApexCharts' },
    { pattern: /swiper[.-]([\d.]+)|swiper@([\d.]+)/i, name: 'Swiper Slider' },
    { pattern: /slick[.-]([\d.]+)/i, name: 'Slick Carousel' },
    { pattern: /backbone[.-]([\d.]+)/i, name: 'Backbone.js' },
    { pattern: /ember[.-]([\d.]+)/i, name: 'Ember.js' },
    { pattern: /handlebars[.-]([\d.]+)/i, name: 'Handlebars' },
    { pattern: /underscore[.-]([\d.]+)/i, name: 'Underscore.js' },
    { pattern: /alpine[.-]?js[.-]?([\d.]+)|alpinejs@([\d.]+)/i, name: 'Alpine.js' },
    { pattern: /htmx\.org@([\d.]+)|htmx[.-]([\d.]+)/i, name: 'HTMX' },
    { pattern: /gsap[.-]([\d.]+)|gsap@([\d.]+)/i, name: 'GSAP' },
    { pattern: /fontawesome[.-]([\d.]+)|fa[.-]([\d.]+)|@fortawesome.*?([\d.]+)/i, name: 'Font Awesome' },
    { pattern: /tailwindcss@([\d.]+)/i, name: 'Tailwind CSS' },
    { pattern: /sweetalert2@([\d.]+)|sweetalert2[.-]([\d.]+)/i, name: 'SweetAlert2' },
  ],
  // Detected from cookie names
  cookies: {
    'PHPSESSID': { name: 'PHP', category: 'Language', icon: '🐘' },
    'JSESSIONID': { name: 'Java / Spring', category: 'Backend Platform', icon: '☕' },
    'ASP.NET_SessionId': { name: 'ASP.NET', category: 'Backend Framework', icon: '🔷' },
    'csrftoken': { name: 'Django', category: 'Backend Framework', icon: '🐍' },
    'laravel_session': { name: 'Laravel', category: 'Backend Framework', icon: '🔴' },
    '_rails_session': { name: 'Ruby on Rails', category: 'Fullstack Framework', icon: '💎' },
    'connect.sid': { name: 'Express', category: 'Backend Framework', icon: '⚡' },
    'wp-settings': { name: 'WordPress', category: 'CMS', icon: '📝' },
    'woocommerce_cart_hash': { name: 'WooCommerce', category: 'E-commerce', icon: '🛒' },
    '_shopify_s': { name: 'Shopify', category: 'E-commerce', icon: '🛒' },
    '_ga': { name: 'Google Analytics', category: 'Analytics', icon: '📊' },
    '_gid': { name: 'Google Analytics', category: 'Analytics', icon: '📊' },
    '_fbp': { name: 'Facebook Pixel', category: 'Marketing', icon: '📘' },
    'hubspotutk': { name: 'HubSpot', category: 'Marketing & CRM', icon: '🟠' },
    'mp_': { name: 'Mixpanel', category: 'Analytics', icon: '📊' },
    'ajs_user_id': { name: 'Segment', category: 'Data Platform', icon: '🔄' },
    '_gh_sess': { name: 'GitHub Enterprise', category: 'Platform', icon: '🐙' },
    'cf_clearance': { name: 'Cloudflare Bot Management', category: 'Security', icon: '☁️' },
    '__cf_bm': { name: 'Cloudflare Bot Management', category: 'Security', icon: '☁️' },
  },
};

// ==========================================
// KNOWN VULNERABILITIES DATABASE
// Curated list of critical CVEs for popular libraries.
// 'below' means all versions BELOW this are vulnerable.
// ==========================================
const KNOWN_VULNERABILITIES = {
  'jQuery': [
    { below: '3.5.0', severity: 'HIGH', cve: 'CVE-2020-11022', title: 'XSS in htmlPrefilter', title_es: 'XSS en htmlPrefilter', desc_en: 'Passing HTML from untrusted sources to jQuery DOM manipulation methods may execute untrusted code.', desc_es: 'Pasar HTML de fuentes no confiables a métodos de manipulación DOM de jQuery puede ejecutar código no confiable.' },
    { below: '3.4.0', severity: 'MEDIUM', cve: 'CVE-2019-11358', title: 'Prototype pollution in jQuery.extend', title_es: 'Contaminación de prototipo en jQuery.extend', desc_en: 'Object.prototype pollution via crafted objects passed to jQuery.extend(true, ...).', desc_es: 'Contaminación de Object.prototype mediante objetos manipulados en jQuery.extend(true, ...).' },
    { below: '3.0.0', severity: 'HIGH', cve: 'CVE-2015-9251', title: 'XSS in cross-domain Ajax requests', title_es: 'XSS en peticiones Ajax cross-domain', desc_en: 'jQuery before 3.0.0 is vulnerable to XSS via cross-domain Ajax text/javascript responses.', desc_es: 'jQuery anterior a 3.0.0 es vulnerable a XSS mediante respuestas Ajax cross-domain text/javascript.' },
    { below: '1.12.0', severity: 'MEDIUM', cve: 'CVE-2015-9251', title: 'Multiple XSS vectors', title_es: 'Múltiples vectores XSS', desc_en: 'jQuery versions before 1.12.0 have multiple cross-site scripting vulnerabilities.', desc_es: 'Las versiones de jQuery anteriores a 1.12.0 tienen múltiples vulnerabilidades de cross-site scripting.' },
  ],
  'Angular': [
    { below: '1.8.0', severity: 'CRITICAL', cve: 'CVE-2022-25869', title: 'XSS via SVG xlink:href', title_es: 'XSS mediante SVG xlink:href', desc_en: 'AngularJS before 1.8.0 allows XSS via xlink:href attributes in SVG elements.', desc_es: 'AngularJS anterior a 1.8.0 permite XSS mediante atributos xlink:href en elementos SVG.' },
    { below: '1.6.9', severity: 'HIGH', cve: 'CVE-2019-10768', title: 'Prototype pollution', title_es: 'Contaminación de prototipo', desc_en: 'AngularJS is vulnerable to prototype pollution via merge/extend functions.', desc_es: 'AngularJS es vulnerable a contaminación de prototipo mediante funciones merge/extend.' },
  ],
  'React': [
    { below: '16.4.2', severity: 'HIGH', cve: 'CVE-2018-6341', title: 'XSS via server-side rendering', title_es: 'XSS mediante renderizado del lado del servidor', desc_en: 'React before 16.4.2 is vulnerable to XSS via attribute names in SSR.', desc_es: 'React anterior a 16.4.2 es vulnerable a XSS mediante nombres de atributos en SSR.' },
    { below: '0.14.0', severity: 'HIGH', cve: 'CVE-2015-1164', title: 'XSS via dangerouslySetInnerHTML', title_es: 'XSS mediante dangerouslySetInnerHTML', desc_en: 'Older React versions have insufficient sanitization in dangerouslySetInnerHTML.', desc_es: 'Versiones antiguas de React tienen sanitización insuficiente en dangerouslySetInnerHTML.' },
  ],
  'Vue.js': [
    { below: '2.5.17', severity: 'MEDIUM', cve: 'CVE-2018-11235', title: 'XSS via template compilation', title_es: 'XSS mediante compilación de plantillas', desc_en: 'Vue.js before 2.5.17 has potential XSS in SSR template compilation.', desc_es: 'Vue.js anterior a 2.5.17 tiene potencial XSS en la compilación de plantillas SSR.' },
  ],
  'Bootstrap': [
    { below: '4.3.1', severity: 'MEDIUM', cve: 'CVE-2019-8331', title: 'XSS in data-template tooltip/popover', title_es: 'XSS en tooltip/popover data-template', desc_en: 'Bootstrap before 4.3.1 allows XSS via data-template attribute in tooltips and popovers.', desc_es: 'Bootstrap anterior a 4.3.1 permite XSS mediante el atributo data-template en tooltips y popovers.' },
    { below: '3.4.0', severity: 'HIGH', cve: 'CVE-2018-14040', title: 'XSS in collapse data-parent', title_es: 'XSS en collapse data-parent', desc_en: 'Bootstrap 3 before 3.4.0 has XSS via data-parent attribute in collapse plugin.', desc_es: 'Bootstrap 3 anterior a 3.4.0 tiene XSS mediante atributo data-parent en plugin collapse.' },
  ],
  'WordPress': [
    { below: '6.4.0', severity: 'HIGH', cve: 'CVE-2023-39999', title: 'Information disclosure via REST API', title_es: 'Divulgación de información via REST API', desc_en: 'WordPress before 6.4 allows unauthorized access to sensitive data via REST API.', desc_es: 'WordPress anterior a 6.4 permite acceso no autorizado a datos sensibles mediante REST API.' },
    { below: '6.0.0', severity: 'HIGH', cve: 'CVE-2022-21661', title: 'SQL injection via WP_Query', title_es: 'Inyección SQL via WP_Query', desc_en: 'WordPress before 6.0 is vulnerable to SQL injection via WP_Query.', desc_es: 'WordPress anterior a 6.0 es vulnerable a inyección SQL mediante WP_Query.' },
    { below: '5.8.0', severity: 'CRITICAL', cve: 'CVE-2021-29447', title: 'XXE in media upload', title_es: 'XXE en subida de archivos', desc_en: 'WordPress before 5.8 allows XML External Entity injection during media file upload.', desc_es: 'WordPress anterior a 5.8 permite inyección de Entidades Externas XML durante la subida de archivos.' },
  ],
  'Lodash': [
    { below: '4.17.21', severity: 'HIGH', cve: 'CVE-2021-23337', title: 'Command injection via template', title_es: 'Inyección de comandos via template', desc_en: 'Lodash before 4.17.21 is vulnerable to command injection via template function.', desc_es: 'Lodash anterior a 4.17.21 es vulnerable a inyección de comandos mediante la función template.' },
    { below: '4.17.12', severity: 'HIGH', cve: 'CVE-2019-10744', title: 'Prototype pollution', title_es: 'Contaminación de prototipo', desc_en: 'Lodash before 4.17.12 is vulnerable to prototype pollution via defaultsDeep.', desc_es: 'Lodash anterior a 4.17.12 es vulnerable a contaminación de prototipo mediante defaultsDeep.' },
  ],
  'Moment.js': [
    { below: '2.29.4', severity: 'HIGH', cve: 'CVE-2022-31129', title: 'ReDoS in date parsing', title_es: 'ReDoS en parseo de fechas', desc_en: 'Moment.js before 2.29.4 is vulnerable to Regular Expression Denial of Service (ReDoS).', desc_es: 'Moment.js anterior a 2.29.4 es vulnerable a Denegación de Servicio por Expresión Regular (ReDoS).' },
    { below: '2.19.3', severity: 'MEDIUM', cve: 'CVE-2017-18214', title: 'ReDoS vulnerability', title_es: 'Vulnerabilidad ReDoS', desc_en: 'Moment.js before 2.19.3 has a ReDoS vulnerability in date parsing.', desc_es: 'Moment.js anterior a 2.19.3 tiene una vulnerabilidad ReDoS en parseo de fechas.' },
  ],
  'Express': [
    { below: '4.19.2', severity: 'MEDIUM', cve: 'CVE-2024-29041', title: 'Open redirect vulnerability', title_es: 'Vulnerabilidad de redirección abierta', desc_en: 'Express before 4.19.2 allows open redirects via crafted URL in res.redirect().', desc_es: 'Express anterior a 4.19.2 permite redirecciones abiertas mediante URL manipulada en res.redirect().' },
    { below: '4.17.3', severity: 'HIGH', cve: 'CVE-2022-24999', title: 'Prototype pollution via qs', title_es: 'Contaminación de prototipo via qs', desc_en: 'Express before 4.17.3 is affected by prototype pollution via the qs dependency.', desc_es: 'Express anterior a 4.17.3 está afectado por contaminación de prototipo mediante la dependencia qs.' },
  ],
  'Next.js': [
    { below: '14.1.1', severity: 'HIGH', cve: 'CVE-2024-24758', title: 'SSRF via host header', title_es: 'SSRF mediante header host', desc_en: 'Next.js before 14.1.1 allows Server-Side Request Forgery via host header manipulation.', desc_es: 'Next.js anterior a 14.1.1 permite falsificación de peticiones del lado del servidor mediante manipulación del header host.' },
    { below: '13.4.20', severity: 'MEDIUM', cve: 'CVE-2023-46298', title: 'Path traversal in Server Actions', title_es: 'Path traversal en Server Actions', desc_en: 'Next.js before 13.4.20 allows path traversal in Server Actions.', desc_es: 'Next.js anterior a 13.4.20 permite path traversal en Server Actions.' },
  ],
  'Drupal': [
    { below: '10.1.0', severity: 'CRITICAL', cve: 'CVE-2023-4290', title: 'Access bypass vulnerability', title_es: 'Bypass de acceso', desc_en: 'Drupal before 10.1.0 has an access bypass vulnerability in certain configurations.', desc_es: 'Drupal anterior a 10.1.0 tiene una vulnerabilidad de bypass de acceso en ciertas configuraciones.' },
  ],
  'Nginx': [
    { below: '1.25.3', severity: 'MEDIUM', cve: 'CVE-2023-44487', title: 'HTTP/2 Rapid Reset DDoS', title_es: 'DDoS HTTP/2 Rapid Reset', desc_en: 'Nginx before 1.25.3 is vulnerable to HTTP/2 rapid reset attack (DDoS).', desc_es: 'Nginx anterior a 1.25.3 es vulnerable al ataque HTTP/2 rapid reset (DDoS).' },
  ],
  'Apache': [
    { below: '2.4.58', severity: 'HIGH', cve: 'CVE-2023-44487', title: 'HTTP/2 Rapid Reset DDoS', title_es: 'DDoS HTTP/2 Rapid Reset', desc_en: 'Apache before 2.4.58 is vulnerable to the HTTP/2 rapid reset attack.', desc_es: 'Apache anterior a 2.4.58 es vulnerable al ataque HTTP/2 rapid reset.' },
    { below: '2.4.52', severity: 'CRITICAL', cve: 'CVE-2021-44790', title: 'Buffer overflow in mod_lua', title_es: 'Desbordamiento de buffer en mod_lua', desc_en: 'Apache before 2.4.52 has a buffer overflow vulnerability in mod_lua.', desc_es: 'Apache anterior a 2.4.52 tiene una vulnerabilidad de desbordamiento de buffer en mod_lua.' },
  ],
  'D3.js': [
    { below: '6.0.0', severity: 'MEDIUM', cve: 'N/A', title: 'XSS via HTML injection in older versions', title_es: 'XSS mediante inyección HTML en versiones antiguas', desc_en: 'D3.js versions before 6.0 do not sanitize HTML in .html() method, allowing XSS.', desc_es: 'Las versiones de D3.js anteriores a 6.0 no sanitizan HTML en el método .html(), permitiendo XSS.' },
  ],
  'Socket.io': [
    { below: '4.6.2', severity: 'MEDIUM', cve: 'CVE-2023-32695', title: 'Denial of Service', title_es: 'Denegación de Servicio', desc_en: 'Socket.io before 4.6.2 allows denial of service via malformed packets.', desc_es: 'Socket.io anterior a 4.6.2 permite denegación de servicio mediante paquetes malformados.' },
  ],
};

// ==========================================
// VERSION COMPARISON UTILITY
// ==========================================
/**
 * Compare two semver-like version strings.
 * Returns: -1 if a < b, 0 if a == b, 1 if a > b
 */
function compareVersions(a, b) {
  if (!a || !b) return 0;
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const na = pa[i] || 0;
    const nb = pb[i] || 0;
    if (na < nb) return -1;
    if (na > nb) return 1;
  }
  return 0;
}

/**
 * Check if version is below a threshold.
 */
function isVersionBelow(version, threshold) {
  return compareVersions(version, threshold) < 0;
}

// ==========================================
// REQUIRED SECURITY HEADERS
// ==========================================
const SECURITY_HEADERS = {
  'content-security-policy': {
    name: 'Content-Security-Policy',
    severity: 'HIGH',
    description_en: 'Controls which resources the browser is allowed to load. Prevents XSS, clickjacking, and data injection attacks.',
    description_es: 'Controla qué recursos puede cargar el navegador. Previene ataques XSS, clickjacking e inyección de datos.',
    fix_en: 'Add a Content-Security-Policy header to your server response.',
    fix_es: 'Añade un header Content-Security-Policy a la respuesta de tu servidor.',
  },
  'x-content-type-options': {
    name: 'X-Content-Type-Options',
    severity: 'MEDIUM',
    description_en: 'Prevents MIME type sniffing. Should be set to "nosniff".',
    description_es: 'Previene el MIME type sniffing. Debe establecerse como "nosniff".',
    fix_en: 'Add header: X-Content-Type-Options: nosniff',
    fix_es: 'Añade el header: X-Content-Type-Options: nosniff',
  },
  'x-frame-options': {
    name: 'X-Frame-Options',
    severity: 'MEDIUM',
    description_en: 'Prevents your page from being embedded in iframes. Protects against clickjacking attacks.',
    description_es: 'Previene que tu página sea embebida en iframes. Protege contra ataques de clickjacking.',
    fix_en: 'Add header: X-Frame-Options: DENY or SAMEORIGIN',
    fix_es: 'Añade el header: X-Frame-Options: DENY o SAMEORIGIN',
  },
  'strict-transport-security': {
    name: 'Strict-Transport-Security (HSTS)',
    severity: 'HIGH',
    description_en: 'Forces browsers to use HTTPS. Without it, users can be downgraded to insecure HTTP connections.',
    description_es: 'Fuerza a los navegadores a usar HTTPS. Sin él, los usuarios pueden ser degradados a conexiones HTTP inseguras.',
    fix_en: 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains',
    fix_es: 'Añade el header: Strict-Transport-Security: max-age=31536000; includeSubDomains',
  },
  'x-xss-protection': {
    name: 'X-XSS-Protection',
    severity: 'LOW',
    description_en: 'Legacy XSS filter. Modern browsers use CSP instead, but this provides defense-in-depth.',
    description_es: 'Filtro XSS legado. Los navegadores modernos usan CSP, pero este proporciona defensa en profundidad.',
    fix_en: 'Add header: X-XSS-Protection: 1; mode=block',
    fix_es: 'Añade el header: X-XSS-Protection: 1; mode=block',
  },
  'referrer-policy': {
    name: 'Referrer-Policy',
    severity: 'LOW',
    description_en: 'Controls how much referrer information is included with requests. Protects user privacy.',
    description_es: 'Controla cuánta información de referencia se incluye en las peticiones. Protege la privacidad del usuario.',
    fix_en: 'Add header: Referrer-Policy: strict-origin-when-cross-origin',
    fix_es: 'Añade el header: Referrer-Policy: strict-origin-when-cross-origin',
  },
  'permissions-policy': {
    name: 'Permissions-Policy',
    severity: 'MEDIUM',
    description_en: 'Controls which browser features and APIs can be used. Limits access to camera, microphone, geolocation, etc.',
    description_es: 'Controla qué funciones y APIs del navegador pueden usarse. Limita acceso a cámara, micrófono, geolocalización, etc.',
    fix_en: 'Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()',
    fix_es: 'Añade el header: Permissions-Policy: camera=(), microphone=(), geolocation=()',
  },
};

// ==========================================
// MAIN SCANNER CLASS
// ==========================================
class SecurityScanner {
  constructor(targetUrl) {
    this.targetUrl = targetUrl;
    this.parsedUrl = new URL(targetUrl);
    this.results = {
      url: targetUrl,
      timestamp: new Date().toISOString(),
      technologies: [],
      structure: null,
      headers: {
        raw: {},
        security: [],
        missing: [],
        info: [],
      },
      cookies: [],
      tls: null,
      dns: null,
      waf: null,
      performance: null,
      exposedInfo: [],
      vulnerabilities: [],
      subdomains: [],
      securityTxt: null,
      corsAnalysis: null,
      reputation: null,
      secrets: [],
      sourceLeaks: [],
      deepTLS: null,
      clickjacking: null,
      paymentSecurity: null,
      adminSurface: [],
      malwareThreats: [],
      phishingScamAnalysis: null,
      findings: [],
      executiveSummary: null,
      score: 0,
    };
  }

  /**
   * Run the full scan pipeline.
   */
  async scan() {
    try {
      // Step 1: Make HTTP request and get response
      const response = await this._fetchTarget();

      // Step 2: Analyze security headers
      this._analyzeHeaders(response.headers);

      // Step 3: Detect technologies
      this._detectTechnologies(response.headers, response.body);

      // Step 4: Analyze cookies
      this._analyzeCookies(response.headers);

      // Step 5: Check TLS/SSL certificate
      if (this.parsedUrl.protocol === 'https:') {
        await this._checkTLS();
      } else {
        this.results.findings.push({
          id: 'no-https',
          title: 'No HTTPS',
          title_es: 'Sin HTTPS',
          severity: 'CRITICAL',
          description_en: 'The application is served over HTTP without encryption. All data including passwords and session tokens are transmitted in plain text.',
          description_es: 'La aplicación se sirve sobre HTTP sin cifrado. Todos los datos incluyendo contraseñas y tokens de sesión se transmiten en texto plano.',
          category: 'tls',
        });
      }

      // Step 5b: Check detected versions against known vulnerabilities & set status badges
      this._checkVersionVulnerabilities();

      // Step 5c: Analyze application structure
      this._analyzeStructure(response.body);

      // Step 6: Deep CSP analysis
      this._deepCSPAnalysis(response.headers);

      // Step 7: Subresource Integrity (SRI) check
      this._checkSRI(response.body);

      // Step 8: Mixed content detection
      this._checkMixedContent(response.body);

      // Step 9: Check for exposed information
      this._checkExposedInfo(response.headers, response.body);

      // Step 10: Check dangerous HTTP methods
      await this._checkHTTPMethods();

      // Step 11: DNS Security (SPF/DMARC)
      await this._checkDNSSecurity();

      // Step 12: Form security analysis
      this._analyzeFormSecurity(response.body);

      // Step 13: Dangerous JS patterns
      this._checkDangerousJS(response.body);

      // Step 14: WAF detection
      this._detectWAF(response.headers);

      // Step 15: robots.txt analysis
      await this._analyzeRobotsTxt();

      // Step 16: Compression & performance
      this._checkPerformance(response.headers, response.body);

      // Step 17: Error page leak check
      await this._checkErrorPageLeaks();

      // Step 18: Directory listing check
      await this._checkDirectoryListing();

      // Step 19: Open redirect check
      await this._checkOpenRedirects();

      // Step 20: Common insecure configurations
      await this._checkInsecureConfigs();

      // Step 21: Subdomain discovery (dev, staging, api, admin)
      await this._discoverSubdomains();

      // Step 22: security.txt (RFC 9116)
      await this._checkSecurityTxt();

      // Step 23: Active CORS testing (Origin reflection & credentials)
      await this._testCORSConfiguration();

      // Step 24: Domain reputation & blocklist verification
      await this._checkDomainReputation();

      // Step 25: API Keys & Secrets Harvester in JS
      this._harvestSecrets(response.body);

      // Step 26: Source code & Backup file leaks (.git, .js.map, .sql, .bak)
      await this._checkSourceAndBackupLeaks(response.body);

      // Step 27: Deep Cryptographic & Cipher Suite TLS Audit
      await this._deepTLSAudit();

      // Step 28: Active Clickjacking & Frame Defense Analysis
      this._analyzeClickjacking(response.headers);

      // Step 29: Payment Security & Data Exfiltration / Skimming Analysis
      this._analyzePaymentAndExfiltration(response.body, response.headers);

      // Step 30: Exposed Admin Panels & API Documentation surface
      await this._checkAdminAndApiSurface();

      // Step 31: Webshells & Backdoor Malware Check
      await this._checkWebshellsAndMalware();

      // Step 32: Phishing, Scam & Malicious Intent Analysis
      this._analyzePhishingAndScam(response.body, response.headers);

      // Step 33: Calculate security score
      this._calculateScore();

      // Step 34: Generate contextual, dynamic executive summary
      this._generateExecutiveSummary();

      return this.results;
    } catch (error) {
      throw new Error(`Scan failed: ${error.message}`);
    }
  }

  /**
   * Fetch the target URL and return response data.
   */
  _fetchTarget() {
    return new Promise((resolve, reject) => {
      const protocol = this.parsedUrl.protocol === 'https:' ? https : http;
      const options = {
        hostname: this.parsedUrl.hostname,
        port: this.parsedUrl.port || (this.parsedUrl.protocol === 'https:' ? 443 : 80),
        path: this.parsedUrl.pathname + this.parsedUrl.search,
        method: 'GET',
        headers: {
          'User-Agent': 'Canary-SecurityScanner/1.0',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5',
        },
        timeout: 15000,
        // Follow redirects manually handled below
        maxRedirects: 5,
      };

      const req = protocol.request(options, (res) => {
        // Handle redirects
        if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
          const redirectUrl = new URL(res.headers.location, this.targetUrl);
          this.results.redirects = this.results.redirects || [];
          this.results.redirects.push({
            from: this.targetUrl,
            to: redirectUrl.href,
            status: res.statusCode,
          });

          // Check if HTTP redirects to HTTPS (good practice)
          if (this.parsedUrl.protocol === 'http:' && redirectUrl.protocol === 'https:') {
            this.results.findings.push({
              id: 'http-to-https-redirect',
              title: 'HTTP to HTTPS redirect',
              title_es: 'Redirección de HTTP a HTTPS',
              severity: 'INFO',
              description_en: 'The application correctly redirects HTTP to HTTPS.',
              description_es: 'La aplicación redirige correctamente de HTTP a HTTPS.',
            });
          }
        }

        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            body: body,
          });
        });
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timed out'));
      });
      req.end();
    });
  }

  /**
   * Analyze response headers for security issues.
   */
  _analyzeHeaders(headers) {
    this.results.headers.raw = { ...headers };

    // Check each required security header
    for (const [headerKey, headerInfo] of Object.entries(SECURITY_HEADERS)) {
      if (headers[headerKey]) {
        this.results.headers.security.push({
          name: headerInfo.name,
          value: headers[headerKey],
          status: 'present',
          severity: 'INFO',
        });
      } else {
        this.results.headers.missing.push({
          name: headerInfo.name,
          header: headerKey,
          severity: headerInfo.severity,
        });

        this.results.findings.push({
          id: `missing-header-${headerKey}`,
          title: `Missing ${headerInfo.name}`,
          title_es: `Falta ${headerInfo.name}`,
          severity: headerInfo.severity,
          description_en: headerInfo.description_en,
          description_es: headerInfo.description_es,
          fix_en: headerInfo.fix_en,
          fix_es: headerInfo.fix_es,
          category: 'headers',
        });
      }
    }

    // Check CORS headers
    if (headers['access-control-allow-origin'] === '*') {
      this.results.findings.push({
        id: 'cors-wildcard',
        title: 'Permissive CORS configuration',
        title_es: 'Configuración CORS permisiva',
        severity: 'MEDIUM',
        description_en: 'Access-Control-Allow-Origin is set to "*", allowing any website to make requests to your API. This can lead to data theft.',
        description_es: 'Access-Control-Allow-Origin está configurado como "*", permitiendo que cualquier sitio web haga peticiones a tu API. Esto puede llevar a robo de datos.',
        category: 'headers',
      });
    }
  }

  /**
   * Detect technologies from headers, body, scripts, CDNs, and inline metadata.
   */
  _detectTechnologies(headers, body) {
    const detected = new Map();

    // 1. From headers
    for (const [headerName, signatures] of Object.entries(TECH_SIGNATURES.headers)) {
      const headerValue = headers[headerName];
      if (headerValue) {
        for (const [keyword, tech] of Object.entries(signatures)) {
          if (keyword === '' || headerValue.toLowerCase().includes(keyword.toLowerCase())) {
            const version = this._extractVersion(headerValue, keyword);
            detected.set(tech.name, { ...tech, version, source: `header:${headerName}` });
          }
        }
      }
    }

    // 2. From body patterns
    for (const sig of TECH_SIGNATURES.body) {
      if (sig.pattern.test(body)) {
        if (!detected.has(sig.name)) {
          detected.set(sig.name, { ...sig, version: null, source: 'body' });
        }
      }
    }

    // 3. From <script src="..."> and <link href="..."> tags — extract tech + version from URLs & CDNs
    const scriptRegex = /<script[^>]*src=["']([^"']+)["'][^>]*>/gi;
    const linkRegex = /<link[^>]*href=["']([^"']+)["'][^>]*>/gi;
    const allUrls = [];

    let urlMatch;
    while ((urlMatch = scriptRegex.exec(body)) !== null) allUrls.push(urlMatch[1]);
    while ((urlMatch = linkRegex.exec(body)) !== null) allUrls.push(urlMatch[1]);

    for (const url of allUrls) {
      // Direct regex from script patterns
      for (const sig of (TECH_SIGNATURES.scripts || [])) {
        const m = url.match(sig.pattern);
        if (m) {
          const version = m[1] || m[2] || null;
          const existing = detected.get(sig.name);
          if (!existing || (!existing.version && version) || (version && existing.version && version.split('.').length > existing.version.split('.').length)) {
            const bodyMatch = TECH_SIGNATURES.body.find(b => b.name === sig.name);
            detected.set(sig.name, {
              name: sig.name,
              category: bodyMatch ? bodyMatch.category : 'Library',
              icon: bodyMatch ? bodyMatch.icon : '📦',
              version: version ? version.replace(/\.+$/, '') : (existing ? existing.version : null),
              source: 'script-url',
            });
          }
        }
      }

      // CDN Pattern: cdnjs.cloudflare.com/ajax/libs/<name>/<version>/
      const cdnjsMatch = url.match(/cdnjs\.cloudflare\.com\/ajax\/libs\/([^/]+)\/([\d.]+)/i);
      if (cdnjsMatch) {
        const pkg = cdnjsMatch[1].toLowerCase();
        const ver = cdnjsMatch[2];
        const match = TECH_SIGNATURES.body.find(b => b.name.toLowerCase() === pkg || pkg.includes(b.name.toLowerCase()));
        if (match) {
          detected.set(match.name, { ...match, version: ver, source: 'cdn:cdnjs' });
        }
      }

      // CDN Pattern: unpkg.com/<name>@<version>/
      const unpkgMatch = url.match(/unpkg\.com\/(@?[^/@]+)(?:@([\d.]+))?/i);
      if (unpkgMatch) {
        const pkg = unpkgMatch[1].toLowerCase();
        const ver = unpkgMatch[2] || null;
        const match = TECH_SIGNATURES.body.find(b => b.name.toLowerCase() === pkg || pkg.includes(b.name.toLowerCase()));
        if (match) {
          detected.set(match.name, { ...match, version: ver || (detected.get(match.name)?.version || null), source: 'cdn:unpkg' });
        }
      }

      // CDN Pattern: cdn.jsdelivr.net/npm/<name>@<version>/
      const jsdelivrMatch = url.match(/cdn\.jsdelivr\.net\/(?:npm|gh)\/(@?[^/@]+)(?:@([\d.]+))?/i);
      if (jsdelivrMatch) {
        const pkg = jsdelivrMatch[1].toLowerCase();
        const ver = jsdelivrMatch[2] || null;
        const match = TECH_SIGNATURES.body.find(b => b.name.toLowerCase() === pkg || pkg.includes(b.name.toLowerCase()));
        if (match) {
          detected.set(match.name, { ...match, version: ver || (detected.get(match.name)?.version || null), source: 'cdn:jsdelivr' });
        }
      }
    }

    // 4. From inline comments: e.g. /*! jQuery v3.6.0 | ... */
    const commentMatches = body.match(/\/\*!?\s*([a-zA-Z0-9_.-]+)\s+(?:v|version)?\s*([\d.]+)/gi);
    if (commentMatches) {
      for (const c of commentMatches) {
        const m = c.match(/\/\*!?\s*([a-zA-Z0-9_.-]+)\s+(?:v|version)?\s*([\d.]+)/i);
        if (m) {
          const name = m[1];
          const ver = m[2];
          for (const sig of TECH_SIGNATURES.body) {
            if (sig.name.toLowerCase() === name.toLowerCase()) {
              const existing = detected.get(sig.name);
              if (!existing || !existing.version) {
                detected.set(sig.name, { ...sig, version: ver, source: 'inline-comment' });
              }
            }
          }
        }
      }
    }

    // 5. From meta tags (with version extraction from generator content)
    const metaRegex = /<meta[^>]*name=["']([^"']*)["'][^>]*content=["']([^"']*)["'][^>]*>/gi;
    let match;
    while ((match = metaRegex.exec(body)) !== null) {
      const metaName = match[1].toLowerCase();
      const metaContent = match[2];
      for (const sig of TECH_SIGNATURES.meta) {
        if (metaName === sig.name) {
          const vMatch = metaContent.match(sig.pattern);
          if (vMatch) {
            const version = vMatch[1] || this._extractVersion(metaContent, '');
            detected.set(sig.tech.name, { ...sig.tech, version: version || null, source: 'meta' });
          }
        }
      }
    }

    // 6. Angular ng-version attribute
    const ngVersion = body.match(/ng-version=["']([\d.]+)["']/i);
    if (ngVersion) {
      detected.set('Angular', { name: 'Angular', category: 'Frontend Framework', icon: '🔴', version: ngVersion[1], source: 'html-attr' });
    }

    // 7. From cookie names
    const setCookies = headers['set-cookie'];
    if (setCookies) {
      const cookieArray = Array.isArray(setCookies) ? setCookies : [setCookies];
      for (const cookieStr of cookieArray) {
        const cookieName = cookieStr.split('=')[0].trim();
        for (const [cnName, tech] of Object.entries(TECH_SIGNATURES.cookies || {})) {
          if (cookieName.toLowerCase().includes(cnName.toLowerCase())) {
            if (!detected.has(tech.name)) {
              detected.set(tech.name, { ...tech, version: null, source: 'cookie' });
            }
          }
        }
      }
    }

    this.results.technologies = Array.from(detected.values());
  }

  /**
   * Try to extract a version number from a string.
   */
  _extractVersion(str, keyword) {
    const versionPatterns = [
      /(\d+\.\d+\.\d+)/,
      /(\d+\.\d+)/,
      /\/(\d+\.\d+[\.\d]*)/,
    ];
    for (const pattern of versionPatterns) {
      const match = str.match(pattern);
      if (match) return match[1];
    }
    return null;
  }

  /**
   * Check detected technology versions against known vulnerability database
   * and assign clear status badges (vulnerable / outdated / secure / detected).
   */
  _checkVersionVulnerabilities() {
    const majorVersionThresholds = {
      'jQuery': '3.5.0',
      'React': '18.0.0',
      'Vue.js': '3.0.0',
      'Angular': '15.0.0',
      'Bootstrap': '5.0.0',
      'Next.js': '14.0.0',
      'Nuxt.js': '3.0.0',
      'Express': '4.19.0',
      'D3.js': '7.0.0',
      'Lodash': '4.17.21',
      'Moment.js': '2.29.4',
      'WordPress': '6.4.0',
      'Drupal': '10.1.0',
      'Nginx': '1.25.0',
      'Apache': '2.4.58',
      'PHP': '8.2.0',
      'Socket.io': '4.6.0',
    };

    for (const tech of this.results.technologies) {
      // Default: detected / active
      tech.status = 'detected';
      tech.statusLabel = 'Activo';
      tech.statusLabel_en = 'Active';
      tech.statusIcon = 'ℹ️';

      const vulns = KNOWN_VULNERABILITIES[tech.name];
      let isVulnerable = false;

      if (vulns && tech.version) {
        for (const vuln of vulns) {
          if (isVersionBelow(tech.version, vuln.below)) {
            isVulnerable = true;
            tech.status = 'vulnerable';
            tech.statusLabel = `Vulnerable (${vuln.cve})`;
            tech.statusLabel_en = `Vulnerable (${vuln.cve})`;
            tech.statusIcon = '🚨';
            tech.cve = vuln.cve;
            tech.fixedIn = vuln.below;

            const vulnEntry = {
              technology: tech.name,
              detectedVersion: tech.version,
              fixedIn: vuln.below,
              cve: vuln.cve,
              severity: vuln.severity,
              title: vuln.title,
              title_es: vuln.title_es,
            };
            this.results.vulnerabilities.push(vulnEntry);

            this.results.findings.push({
              id: `vuln-${tech.name}-${vuln.cve}`.toLowerCase().replace(/[^a-z0-9-]/g, '-'),
              title: `${tech.name} ${tech.version}: ${vuln.title} (${vuln.cve})`,
              title_es: `${tech.name} ${tech.version}: ${vuln.title_es} (${vuln.cve})`,
              severity: vuln.severity,
              description_en: `${vuln.desc_en} Detected version: ${tech.version}. Fixed in version ${vuln.below} or later.`,
              description_es: `${vuln.desc_es} Versión detectada: ${tech.version}. Corregido en versión ${vuln.below} o posterior.`,
              fix_en: `Update ${tech.name} to version ${vuln.below} or later.`,
              fix_es: `Actualiza ${tech.name} a la versión ${vuln.below} o posterior.`,
              category: 'vulnerability',
            });
            break;
          }
        }
      }

      if (!isVulnerable && tech.version) {
        const threshold = majorVersionThresholds[tech.name];
        if (threshold && isVersionBelow(tech.version, threshold)) {
          tech.status = 'outdated';
          tech.statusLabel = 'Desactualizado';
          tech.statusLabel_en = 'Outdated';
          tech.statusIcon = '⚠️';
          tech.recommendedMin = threshold;

          this.results.findings.push({
            id: `outdated-${tech.name}`.toLowerCase().replace(/[^a-z0-9-]/g, '-'),
            title: `${tech.name} ${tech.version} is outdated`,
            title_es: `${tech.name} ${tech.version} está desactualizado`,
            severity: 'MEDIUM',
            description_en: `${tech.name} version ${tech.version} is outdated. Recommended minimum is ${threshold}+.`,
            description_es: `${tech.name} versión ${tech.version} está desactualizada. Se recomienda actualizar a ${threshold}+.`,
            fix_en: `Update ${tech.name} to version ${threshold} or later.`,
            fix_es: `Actualiza ${tech.name} a la versión ${threshold} o posterior.`,
            category: 'outdated',
          });
        } else {
          // Version is modern & secure
          tech.status = 'secure';
          tech.statusLabel = 'Actualizado / Seguro';
          tech.statusLabel_en = 'Up to date / Secure';
          tech.statusIcon = '✅';
        }
      }
    }
  }

  /**
   * Generate a comprehensive, contextual, non-generic Executive Security Summary.
   */
  _generateExecutiveSummary() {
    const findings = this.results.findings || [];
    const vulns = this.results.vulnerabilities || [];
    const techs = this.results.technologies || [];
    const score = this.results.score;
    const rating = this.results.rating;
    const domain = this.parsedUrl.hostname;

    const criticalFindings = findings.filter(f => f.severity === 'CRITICAL');
    const highFindings = findings.filter(f => f.severity === 'HIGH');
    const mediumFindings = findings.filter(f => f.severity === 'MEDIUM');

    const paragraphs_es = [];
    const paragraphs_en = [];

    // 1. Overall posture statement
    if (score >= 80) {
      paragraphs_es.push(`La aplicación en **${domain}** presenta una postura de seguridad sólida (**Puntuación ${score}/100, Calificación ${rating}**), con cifrado TLS activo y una arquitectura base bien protegida frente a ataques comunes.`);
      paragraphs_en.push(`The application at **${domain}** demonstrates a solid security posture (**Score ${score}/100, Rating ${rating}**), with active TLS encryption and well-defended baseline architecture.`);
    } else if (score >= 60) {
      paragraphs_es.push(`La aplicación en **${domain}** cuenta con una base funcional aceptable (**Puntuación ${score}/100, Calificación ${rating}**), pero expone varias brechas de configuración y cabeceras que incrementan la superficie de ataque frente a amenazas automatizadas.`);
      paragraphs_en.push(`The application at **${domain}** maintains acceptable baseline defenses (**Score ${score}/100, Rating ${rating}**), but exposes multiple configuration and header gaps that increase exposure to automated attack vectors.`);
    } else {
      paragraphs_es.push(`La aplicación en **${domain}** presenta un nivel de riesgo elevado (**Puntuación ${score}/100, Calificación ${rating}**), requiriendo atención prioritaria en sus capas de transporte, dependencias y protección de sesiones.`);
      paragraphs_en.push(`The application at **${domain}** exhibits an elevated risk profile (**Score ${score}/100, Rating ${rating}**), requiring urgent remediation across transport security, software dependencies, and session management.`);
    }

    // 2. Vulnerabilities and Technology specific details
    const techNames = techs.map(t => t.name + (t.version ? ` v${t.version}` : '')).join(', ');
    if (techs.length > 0) {
      paragraphs_es.push(`Se identificaron **${techs.length} tecnologías y librerías clave** en ejecución (${techNames}).`);
      paragraphs_en.push(`Detected **${techs.length} key technologies and libraries** in use (${techNames}).`);
    }

    if (vulns.length > 0) {
      const vulnDetails = vulns.map(v => `${v.technology} v${v.detectedVersion} (${v.cve} - ${v.title_es || v.title})`).join('; ');
      paragraphs_es.push(`🚨 **Vulnerabilidades Críticas Detectadas:** Se identificaron versiones con fallos de seguridad conocidos en: ${vulnDetails}. Esto expone vectores de ataque documentados (como Cross-Site Scripting o inyección remota).`);
      paragraphs_en.push(`🚨 **Known Critical Vulnerabilities:** Outdated components with active CVEs were identified: ${vulns.map(v => `${v.technology} v${v.detectedVersion} (${v.cve} - ${v.title})`).join('; ')}.`);
    }

    // 3. Header & Cookie Specifics
    const missingCritHeaders = findings.filter(f => f.category === 'headers' || f.category === 'csp');
    if (missingCritHeaders.length > 0) {
      const headerNames = missingCritHeaders.map(f => f.title_es || f.title).slice(0, 4).join(', ');
      paragraphs_es.push(`🛡️ **Defensas del Navegador:** Se detectaron deficiencias en cabeceras de protección (${headerNames}), lo que deja expuesta la aplicación a clickjacking, MIME-sniffing o ataques XSS.`);
      paragraphs_en.push(`🛡️ **Browser Defense Gaps:** Security header deficiencies were identified (${missingCritHeaders.map(f => f.title).slice(0, 4).join(', ')}), exposing users to clickjacking, MIME-sniffing, or cross-site scripting.`);
    }

    // 4. DNS / Email Security
    if (this.results.dns && (!this.results.dns.hasDMARC || !this.results.dns.hasSPF)) {
      paragraphs_es.push(`📨 **Riesgo de Suplantación (Email Spoofing):** El dominio carece de políticas ${!this.results.dns.hasSPF ? 'SPF ' : ''}${!this.results.dns.hasDMARC ? 'DMARC ' : ''}estrictas, lo que facilita que terceros envíen correos fraudulentos en nombre de tu dominio.`);
      paragraphs_en.push(`📨 **Email Spoofing Exposure:** The domain lacks strict ${!this.results.dns.hasSPF ? 'SPF ' : ''}${!this.results.dns.hasDMARC ? 'DMARC ' : ''}policies, facilitating domain impersonation in phishing campaigns.`);
    }

    // Strengths
    const strengths_es = [];
    const strengths_en = [];
    if (this.results.tls && this.results.tls.valid) {
      strengths_es.push(`Cifrado HTTPS / TLS válido (${this.results.tls.protocol || 'TLS 1.3'}) con certificado activo.`);
      strengths_en.push(`Valid HTTPS / TLS certificate (${this.results.tls.protocol || 'TLS 1.3'}) actively protecting transport data.`);
    }
    if (this.results.waf && this.results.waf.length > 0) {
      strengths_es.push(`Protección perimetral activa con WAF / CDN (${this.results.waf.map(w => w.name).join(', ')}).`);
      strengths_en.push(`Active perimeter firewall & CDN (${this.results.waf.map(w => w.name).join(', ')}).`);
    }
    if (this.results.headers?.security?.length > 0) {
      strengths_es.push(`${this.results.headers.security.length} cabeceras de seguridad correctamente configuradas.`);
      strengths_en.push(`${this.results.headers.security.length} security headers properly implemented.`);
    }
    if (this.results.dns?.hasSPF && this.results.dns?.hasDMARC) {
      strengths_es.push(`Autenticación DNS completa (SPF y DMARC activos).`);
      strengths_en.push(`Full email DNS authentication (SPF & DMARC active).`);
    }

    // Prioritized Action Plan
    const actionPlan = [];
    if (criticalFindings.length > 0 || vulns.length > 0) {
      actionPlan.push({
        priority: 'P0 - Urgente',
        priority_en: 'P0 - Urgent',
        title_es: 'Parchear dependencias vulnerables y corregir fallos críticos',
        title_en: 'Patch vulnerable dependencies and resolve critical flaws',
        action_es: vulns.length > 0 ? `Actualizar ${vulns.map(v => `${v.technology} a v${v.fixedIn}+`).join(', ')}.` : 'Resolver vulnerabilidades críticas inmediatamente.',
        action_en: vulns.length > 0 ? `Update ${vulns.map(v => `${v.technology} to v${v.fixedIn}+`).join(', ')}.` : 'Resolve critical vulnerabilities immediately.',
      });
    }

    if (highFindings.length > 0) {
      actionPlan.push({
        priority: 'P1 - Alta Prioridad',
        priority_en: 'P1 - High Priority',
        title_es: 'Implementar Content-Security-Policy (CSP) y cabeceras estrictas',
        title_en: 'Deploy strict Content-Security-Policy (CSP) and transport headers',
        action_es: 'Añadir cabeceras HSTS y una política CSP restrictiva que bloquee scripts no autorizados.',
        action_en: 'Add HSTS and a restrictive CSP policy blocking unauthorized inline script execution.',
      });
    }

    if (mediumFindings.length > 0 || (this.results.dns && !this.results.dns.hasDMARC)) {
      actionPlan.push({
        priority: 'P2 - Recomendado',
        priority_en: 'P2 - Recommended',
        title_es: 'Blindar cookies y configurar autenticación DMARC en DNS',
        title_en: 'Harden cookie flags and establish DMARC DNS policies',
        action_es: 'Añadir banderas HttpOnly y SameSite a cookies de sesión; configurar registro _dmarc con política de rechazo.',
        action_en: 'Set HttpOnly and SameSite flags on session cookies; add a _dmarc TXT record with quarantine/reject policy.',
      });
    }

    this.results.executiveSummary = {
      score,
      rating,
      domain,
      narrative_es: paragraphs_es.join('\n\n'),
      narrative_en: paragraphs_en.join('\n\n'),
      strengths_es,
      strengths_en,
      actionPlan,
      totalFindings: findings.length,
    };
  }

  /**
   * Analyze the application structure (SPA, SSR, static, CMS, API).
   */
  _analyzeStructure(body) {
    const structure = {
      type: 'unknown',
      type_es: 'desconocido',
      indicators: [],
      hasSPA: false,
      hasSSR: false,
      hasAPI: false,
      hasCMS: false,
    };

    // Check for SPA indicators
    const spaIndicators = [
      { pattern: /<div\s+id=["'](root|app|__next|__nuxt)["']/i, label: 'SPA mount point detected' },
      { pattern: /\bbundle\.js|main\.[a-f0-9]+\.js|app\.[a-f0-9]+\.js/i, label: 'Hashed JS bundle detected' },
      { pattern: /data-reactroot|data-react-helmet/i, label: 'React root element' },
      { pattern: /data-v-[a-f0-9]|data-server-rendered/i, label: 'Vue.js scoped styles' },
      { pattern: /ng-version|ng-app/i, label: 'Angular application' },
    ];

    for (const ind of spaIndicators) {
      if (ind.pattern.test(body)) {
        structure.hasSPA = true;
        structure.indicators.push(ind.label);
      }
    }

    // Check for SSR indicators
    const ssrIndicators = [
      { pattern: /__NEXT_DATA__|__next/i, label: 'Next.js SSR data' },
      { pattern: /__NUXT__|nuxt/i, label: 'Nuxt.js SSR data' },
      { pattern: /data-server-rendered="true"/i, label: 'Vue SSR rendered' },
    ];

    for (const ind of ssrIndicators) {
      if (ind.pattern.test(body)) {
        structure.hasSSR = true;
        structure.indicators.push(ind.label);
      }
    }

    // Check for CMS indicators
    const cmsIndicators = [
      { pattern: /wp-content|wp-includes/i, label: 'WordPress CMS' },
      { pattern: /sites\/default\/files|drupal/i, label: 'Drupal CMS' },
      { pattern: /joomla/i, label: 'Joomla CMS' },
    ];

    for (const ind of cmsIndicators) {
      if (ind.pattern.test(body)) {
        structure.hasCMS = true;
        structure.indicators.push(ind.label);
      }
    }

    // Check for API endpoints referenced in HTML
    const apiPatterns = /[\/](api|graphql|rest|v1|v2|v3)[\/]/gi;
    if (apiPatterns.test(body)) {
      structure.hasAPI = true;
      structure.indicators.push('API endpoints referenced');
    }

    // Determine primary type
    if (structure.hasCMS) {
      structure.type = 'CMS (Content Management System)';
      structure.type_es = 'CMS (Sistema de Gestión de Contenidos)';
    } else if (structure.hasSSR) {
      structure.type = 'SSR (Server-Side Rendered)';
      structure.type_es = 'SSR (Renderizado del Lado del Servidor)';
    } else if (structure.hasSPA) {
      structure.type = 'SPA (Single Page Application)';
      structure.type_es = 'SPA (Aplicación de Página Única)';
    } else {
      // Check if it's mostly static
      const hasMinimalJS = (body.match(/<script/gi) || []).length <= 2;
      if (hasMinimalJS) {
        structure.type = 'Static Website';
        structure.type_es = 'Sitio Web Estático';
      } else {
        structure.type = 'Dynamic Website';
        structure.type_es = 'Sitio Web Dinámico';
      }
    }

    this.results.structure = structure;
  }

  /**
   * Analyze Set-Cookie headers for security issues.
   */
  _analyzeCookies(headers) {
    const setCookies = headers['set-cookie'];
    if (!setCookies) return;

    const cookieArray = Array.isArray(setCookies) ? setCookies : [setCookies];

    cookieArray.forEach((cookieStr, index) => {
      const parts = cookieStr.split(';').map(p => p.trim());
      const nameValue = parts[0].split('=');
      const cookieName = nameValue[0];
      const flags = parts.slice(1).map(f => f.toLowerCase());

      const cookie = {
        name: cookieName,
        httpOnly: flags.some(f => f === 'httponly'),
        secure: flags.some(f => f === 'secure'),
        sameSite: null,
        path: null,
        issues: [],
      };

      // Check SameSite
      const sameSiteFlag = flags.find(f => f.startsWith('samesite'));
      if (sameSiteFlag) {
        cookie.sameSite = sameSiteFlag.split('=')[1] || 'unset';
      }

      // Check for security issues
      if (!cookie.httpOnly) {
        cookie.issues.push('missing-httponly');
        this.results.findings.push({
          id: `cookie-no-httponly-${cookieName}`,
          title: `Cookie "${cookieName}" without HttpOnly flag`,
          title_es: `Cookie "${cookieName}" sin flag HttpOnly`,
          severity: 'HIGH',
          description_en: `The cookie "${cookieName}" is accessible via JavaScript. An XSS attack could steal this cookie and hijack user sessions.`,
          description_es: `La cookie "${cookieName}" es accesible via JavaScript. Un ataque XSS podría robar esta cookie y secuestrar sesiones de usuario.`,
          category: 'cookies',
        });
      }

      if (!cookie.secure) {
        cookie.issues.push('missing-secure');
        this.results.findings.push({
          id: `cookie-no-secure-${cookieName}`,
          title: `Cookie "${cookieName}" without Secure flag`,
          title_es: `Cookie "${cookieName}" sin flag Secure`,
          severity: 'MEDIUM',
          description_en: `The cookie "${cookieName}" can be transmitted over insecure HTTP connections, exposing it to interception.`,
          description_es: `La cookie "${cookieName}" puede ser transmitida sobre conexiones HTTP inseguras, exponiéndola a interceptación.`,
          category: 'cookies',
        });
      }

      if (!cookie.sameSite || cookie.sameSite === 'none') {
        cookie.issues.push('missing-samesite');
        this.results.findings.push({
          id: `cookie-no-samesite-${cookieName}`,
          title: `Cookie "${cookieName}" without SameSite flag`,
          title_es: `Cookie "${cookieName}" sin flag SameSite`,
          severity: 'MEDIUM',
          description_en: `The cookie "${cookieName}" lacks SameSite attribute, making it vulnerable to CSRF (Cross-Site Request Forgery) attacks.`,
          description_es: `La cookie "${cookieName}" no tiene atributo SameSite, haciéndola vulnerable a ataques CSRF (Cross-Site Request Forgery).`,
          category: 'cookies',
        });
      }

      this.results.cookies.push(cookie);
    });
  }

  /**
   * Check TLS/SSL certificate details.
   */
  _checkTLS() {
    return new Promise((resolve) => {
      const options = {
        host: this.parsedUrl.hostname,
        port: this.parsedUrl.port || 443,
        servername: this.parsedUrl.hostname,
        rejectUnauthorized: false, // We want to inspect even invalid certs
      };

      const socket = tls.connect(options, () => {
        const cert = socket.getPeerCertificate();
        const authorized = socket.authorized;
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();

        this.results.tls = {
          valid: authorized,
          protocol: protocol,
          cipher: cipher ? cipher.name : null,
          issuer: cert.issuer ? cert.issuer.O : null,
          subject: cert.subject ? cert.subject.CN : null,
          validFrom: cert.valid_from,
          validTo: cert.valid_to,
          daysUntilExpiry: null,
          selfSigned: false,
        };

        // Check expiry
        if (cert.valid_to) {
          const expiry = new Date(cert.valid_to);
          const now = new Date();
          const daysLeft = Math.floor((expiry - now) / (1000 * 60 * 60 * 24));
          this.results.tls.daysUntilExpiry = daysLeft;

          if (daysLeft < 0) {
            this.results.findings.push({
              id: 'tls-expired',
              title: 'SSL/TLS certificate has expired',
              title_es: 'El certificado SSL/TLS ha expirado',
              severity: 'CRITICAL',
              description_en: `The SSL certificate expired ${Math.abs(daysLeft)} days ago. Users will see security warnings.`,
              description_es: `El certificado SSL expiró hace ${Math.abs(daysLeft)} días. Los usuarios verán advertencias de seguridad.`,
              category: 'tls',
            });
          } else if (daysLeft < 30) {
            this.results.findings.push({
              id: 'tls-expiring-soon',
              title: 'SSL/TLS certificate expiring soon',
              title_es: 'El certificado SSL/TLS expira pronto',
              severity: 'MEDIUM',
              description_en: `The SSL certificate expires in ${daysLeft} days. Renew it before it expires.`,
              description_es: `El certificado SSL expira en ${daysLeft} días. Renuévalo antes de que expire.`,
              category: 'tls',
            });
          }
        }

        // Check self-signed
        if (cert.issuer && cert.subject && cert.issuer.CN === cert.subject.CN) {
          this.results.tls.selfSigned = true;
          this.results.findings.push({
            id: 'tls-self-signed',
            title: 'Self-signed SSL certificate',
            title_es: 'Certificado SSL auto-firmado',
            severity: 'HIGH',
            description_en: 'The SSL certificate is self-signed and will not be trusted by browsers.',
            description_es: 'El certificado SSL es auto-firmado y no será confiable para los navegadores.',
            category: 'tls',
          });
        }

        // Check old TLS versions
        if (protocol && (protocol === 'TLSv1' || protocol === 'TLSv1.1')) {
          this.results.findings.push({
            id: 'tls-old-version',
            title: `Outdated TLS version: ${protocol}`,
            title_es: `Versión TLS desactualizada: ${protocol}`,
            severity: 'HIGH',
            description_en: `The server supports ${protocol} which has known vulnerabilities. Use TLSv1.2 or TLSv1.3.`,
            description_es: `El servidor soporta ${protocol} que tiene vulnerabilidades conocidas. Usa TLSv1.2 o TLSv1.3.`,
            category: 'tls',
          });
        }

        if (!authorized) {
          this.results.findings.push({
            id: 'tls-invalid',
            title: 'Invalid SSL/TLS certificate',
            title_es: 'Certificado SSL/TLS inválido',
            severity: 'CRITICAL',
            description_en: 'The SSL certificate is not valid. This could be due to expiration, domain mismatch, or untrusted issuer.',
            description_es: 'El certificado SSL no es válido. Puede deberse a expiración, discordancia de dominio o emisor no confiable.',
            category: 'tls',
          });
        }

        socket.end();
        resolve();
      });

      socket.on('error', (err) => {
        this.results.tls = { valid: false, error: err.message };
        this.results.findings.push({
          id: 'tls-connection-error',
          title: 'TLS connection failed',
          title_es: 'Error de conexión TLS',
          severity: 'CRITICAL',
          description_en: `Could not establish a secure TLS connection: ${err.message}`,
          description_es: `No se pudo establecer una conexión TLS segura: ${err.message}`,
          category: 'tls',
        });
        resolve();
      });

      socket.setTimeout(10000, () => {
        socket.destroy();
        resolve();
      });
    });
  }

  /**
   * Check for exposed information in headers and body.
   */
  _checkExposedInfo(headers, body) {
    // Server version exposure
    if (headers['server'] && /[\d.]+/.test(headers['server'])) {
      const serverHeader = headers['server'];
      this.results.findings.push({
        id: 'server-version-exposed',
        title: `Server version exposed: ${serverHeader}`,
        title_es: `Versión del servidor expuesta: ${serverHeader}`,
        severity: 'LOW',
        description_en: 'The server header reveals its version number, which helps attackers find known vulnerabilities for that specific version.',
        description_es: 'El header del servidor revela su número de versión, lo que ayuda a atacantes a encontrar vulnerabilidades conocidas para esa versión específica.',
        category: 'info-exposure',
      });
    }

    // X-Powered-By exposure
    if (headers['x-powered-by']) {
      this.results.findings.push({
        id: 'x-powered-by-exposed',
        title: `Technology exposed: ${headers['x-powered-by']}`,
        title_es: `Tecnología expuesta: ${headers['x-powered-by']}`,
        severity: 'LOW',
        description_en: 'The X-Powered-By header reveals the server technology. Remove it to reduce attack surface.',
        description_es: 'El header X-Powered-By revela la tecnología del servidor. Elimínalo para reducir la superficie de ataque.',
        category: 'info-exposure',
      });
    }

    // Check for common exposed paths in HTML
    const exposedPaths = [
      { pattern: /\/\.env/i, name: '.env file reference' },
      { pattern: /\/debug|\/debugger/i, name: 'Debug endpoint' },
      { pattern: /\/phpinfo/i, name: 'phpinfo() exposed' },
      { pattern: /\/adminer|\/phpmyadmin/i, name: 'Database admin panel' },
      { pattern: /\/\.git/i, name: '.git directory' },
      { pattern: /\/api\/docs|\/swagger/i, name: 'API documentation' },
      { pattern: /source[Mm]apping[Uu][Rr][Ll]/i, name: 'Source maps' },
    ];

    exposedPaths.forEach(({ pattern, name }) => {
      if (pattern.test(body)) {
        this.results.exposedInfo.push(name);
      }
    });

    // Check for source maps
    if (headers['sourcemap'] || headers['x-sourcemap']) {
      this.results.findings.push({
        id: 'sourcemaps-exposed',
        title: 'Source maps are publicly accessible',
        title_es: 'Los source maps son accesibles públicamente',
        severity: 'LOW',
        description_en: 'Source maps expose your original source code to anyone. Disable them in production.',
        description_es: 'Los source maps exponen tu código fuente original a cualquiera. Desactívalos en producción.',
        category: 'info-exposure',
      });
    }
  }

  /**
   * Check for common insecure configurations by probing specific paths.
   */
  async _checkInsecureConfigs() {
    const probePaths = [
      { path: '/.env', name: 'Environment file exposed', name_es: 'Archivo de entorno expuesto' },
      { path: '/.git/HEAD', name: 'Git repository exposed', name_es: 'Repositorio Git expuesto' },
      { path: '/robots.txt', name: 'Robots.txt', name_es: 'Robots.txt', isInfo: true },
      { path: '/.well-known/security.txt', name: 'security.txt', name_es: 'security.txt', isInfo: true },
    ];

    const probePromises = probePaths.map(probe => this._probeEndpoint(probe));
    await Promise.allSettled(probePromises);
  }

  /**
   * Probe a specific endpoint to check if it's accessible.
   */
  _probeEndpoint(probe) {
    return new Promise((resolve) => {
      const protocol = this.parsedUrl.protocol === 'https:' ? https : http;
      const options = {
        hostname: this.parsedUrl.hostname,
        port: this.parsedUrl.port || (this.parsedUrl.protocol === 'https:' ? 443 : 80),
        path: probe.path,
        method: 'HEAD',
        headers: { 'User-Agent': 'Canary-SecurityScanner/1.0' },
        timeout: 5000,
      };

      const req = protocol.request(options, (res) => {
        if (res.statusCode === 200 && !probe.isInfo) {
          this.results.findings.push({
            id: `exposed-${probe.path.replace(/[^a-z]/g, '')}`,
            title: probe.name,
            title_es: probe.name_es,
            severity: 'CRITICAL',
            description_en: `The path ${probe.path} is publicly accessible. This could expose sensitive configuration data.`,
            description_es: `La ruta ${probe.path} es accesible públicamente. Esto podría exponer datos de configuración sensibles.`,
            category: 'config',
          });
        } else if (res.statusCode === 200 && probe.isInfo) {
          this.results.findings.push({
            id: `info-${probe.path.replace(/[^a-z]/g, '')}`,
            title: `${probe.name} found`,
            title_es: `${probe.name_es} encontrado`,
            severity: 'INFO',
            description_en: `${probe.name} is accessible at ${probe.path}.`,
            description_es: `${probe.name_es} es accesible en ${probe.path}.`,
            category: 'info',
          });
        }
        resolve();
      });

      req.on('error', () => resolve());
      req.on('timeout', () => { req.destroy(); resolve(); });
      req.end();
    });
  }

  /**
   * Deep analysis of Content-Security-Policy directives.
   */
  _deepCSPAnalysis(headers) {
    const csp = headers['content-security-policy'];
    if (!csp) return; // Already flagged as missing

    const directives = csp.split(';').map(d => d.trim().toLowerCase());
    const parsed = {};
    directives.forEach(d => {
      const parts = d.split(/\s+/);
      if (parts.length > 0) parsed[parts[0]] = parts.slice(1);
    });

    // Check for unsafe-inline in script-src
    const scriptSrc = parsed['script-src'] || parsed['default-src'] || [];
    if (scriptSrc.includes("'unsafe-inline'")) {
      this.results.findings.push({
        id: 'csp-unsafe-inline',
        title: 'CSP allows unsafe-inline scripts',
        title_es: 'CSP permite scripts unsafe-inline',
        severity: 'HIGH',
        description_en: 'The Content-Security-Policy allows inline scripts via unsafe-inline, which significantly weakens XSS protection.',
        description_es: 'El Content-Security-Policy permite scripts inline mediante unsafe-inline, lo que debilita significativamente la protección contra XSS.',
        fix_en: 'Remove unsafe-inline from script-src and use nonces or hashes instead.',
        fix_es: 'Elimina unsafe-inline de script-src y usa nonces o hashes en su lugar.',
        category: 'csp',
      });
    }

    // Check for unsafe-eval in script-src
    if (scriptSrc.includes("'unsafe-eval'")) {
      this.results.findings.push({
        id: 'csp-unsafe-eval',
        title: 'CSP allows unsafe-eval',
        title_es: 'CSP permite unsafe-eval',
        severity: 'HIGH',
        description_en: 'The CSP allows eval() and similar dynamic code execution, enabling code injection attacks.',
        description_es: 'El CSP permite eval() y ejecución dinámica de código similar, habilitando ataques de inyección de código.',
        fix_en: 'Remove unsafe-eval from script-src directive.',
        fix_es: 'Elimina unsafe-eval de la directiva script-src.',
        category: 'csp',
      });
    }

    // Check for wildcard sources
    if (scriptSrc.includes('*') || (parsed['default-src'] || []).includes('*')) {
      this.results.findings.push({
        id: 'csp-wildcard',
        title: 'CSP uses wildcard source',
        title_es: 'CSP usa origen wildcard',
        severity: 'MEDIUM',
        description_en: 'The CSP uses a wildcard (*) which allows loading resources from any origin, defeating the purpose of CSP.',
        description_es: 'El CSP usa un wildcard (*) que permite cargar recursos de cualquier origen, anulando el propósito del CSP.',
        fix_en: 'Replace wildcard with specific trusted domains.',
        fix_es: 'Reemplaza el wildcard con dominios de confianza específicos.',
        category: 'csp',
      });
    }

    // Check for missing frame-ancestors (clickjacking)
    if (!parsed['frame-ancestors']) {
      this.results.findings.push({
        id: 'csp-no-frame-ancestors',
        title: 'CSP missing frame-ancestors directive',
        title_es: 'CSP sin directiva frame-ancestors',
        severity: 'LOW',
        description_en: 'The CSP does not include frame-ancestors. Consider adding it for clickjacking protection.',
        description_es: 'El CSP no incluye frame-ancestors. Considera añadirlo para protección contra clickjacking.',
        category: 'csp',
      });
    }
  }

  /**
   * Check if external scripts use Subresource Integrity (SRI).
   */
  _checkSRI(body) {
    const externalScripts = [];
    const scriptRegex = /<script[^>]*src=["']([^"']+)["'][^>]*>/gi;
    let match;

    while ((match = scriptRegex.exec(body)) !== null) {
      const fullTag = match[0];
      const src = match[1];
      // Only check external scripts (CDN, different domain)
      if (src.startsWith('http') || src.startsWith('//')) {
        const hasIntegrity = /integrity=/i.test(fullTag);
        externalScripts.push({ src, hasIntegrity });
      }
    }

    const withoutSRI = externalScripts.filter(s => !s.hasIntegrity);
    if (withoutSRI.length > 0) {
      this.results.findings.push({
        id: 'missing-sri',
        title: `${withoutSRI.length} external script(s) without Subresource Integrity`,
        title_es: `${withoutSRI.length} script(s) externo(s) sin Subresource Integrity`,
        severity: 'MEDIUM',
        description_en: `${withoutSRI.length} external scripts are loaded without integrity hashes. If the CDN is compromised, malicious code could be injected. Scripts: ${withoutSRI.slice(0, 3).map(s => s.src.split('/').pop()).join(', ')}${withoutSRI.length > 3 ? '...' : ''}`,
        description_es: `${withoutSRI.length} scripts externos se cargan sin hashes de integridad. Si el CDN es comprometido, se podría inyectar código malicioso. Scripts: ${withoutSRI.slice(0, 3).map(s => s.src.split('/').pop()).join(', ')}${withoutSRI.length > 3 ? '...' : ''}`,
        fix_en: 'Add integrity="sha384-..." and crossorigin="anonymous" to external script tags.',
        fix_es: 'Añade integrity="sha384-..." y crossorigin="anonymous" a las etiquetas de scripts externos.',
        category: 'sri',
      });
    }
  }

  /**
   * Detect mixed content (HTTP resources on HTTPS page).
   */
  _checkMixedContent(body) {
    if (this.parsedUrl.protocol !== 'https:') return;

    const httpResources = [];
    const patterns = [
      { regex: /src=["']http:\/\/[^"']+["']/gi, type: 'src' },
      { regex: /href=["']http:\/\/[^"']+["']/gi, type: 'href' },
      { regex: /url\(["']?http:\/\/[^"')]+["']?\)/gi, type: 'css-url' },
    ];

    for (const { regex, type } of patterns) {
      let match;
      while ((match = regex.exec(body)) !== null) {
        httpResources.push({ url: match[0], type });
      }
    }

    if (httpResources.length > 0) {
      this.results.findings.push({
        id: 'mixed-content',
        title: `${httpResources.length} mixed content resource(s) detected`,
        title_es: `${httpResources.length} recurso(s) de contenido mixto detectado(s)`,
        severity: 'MEDIUM',
        description_en: `${httpResources.length} resources are loaded over insecure HTTP on this HTTPS page. This can be blocked by browsers and compromises the security of the entire page.`,
        description_es: `${httpResources.length} recursos se cargan por HTTP inseguro en esta página HTTPS. Esto puede ser bloqueado por los navegadores y compromete la seguridad de toda la página.`,
        fix_en: 'Change all resource URLs to use HTTPS or protocol-relative URLs (//).',
        fix_es: 'Cambia todas las URLs de recursos a HTTPS o URLs relativas al protocolo (//).',
        category: 'mixed-content',
      });
    }
  }

  /**
   * Check if dangerous HTTP methods are enabled.
   */
  async _checkHTTPMethods() {
    const dangerousMethods = ['TRACE', 'PUT', 'DELETE'];
    const results = [];

    const checkPromises = dangerousMethods.map(method => {
      return new Promise((resolve) => {
        const protocol = this.parsedUrl.protocol === 'https:' ? https : http;
        const options = {
          hostname: this.parsedUrl.hostname,
          port: this.parsedUrl.port || (this.parsedUrl.protocol === 'https:' ? 443 : 80),
          path: '/',
          method: method,
          headers: { 'User-Agent': 'Canary-SecurityScanner/1.0' },
          timeout: 5000,
        };

        const req = protocol.request(options, (res) => {
          // If not 405 Method Not Allowed, the method might be enabled
          if (res.statusCode !== 405 && res.statusCode !== 501 && res.statusCode !== 404) {
            results.push({ method, status: res.statusCode });
          }
          res.resume();
          resolve();
        });

        req.on('error', () => resolve());
        req.on('timeout', () => { req.destroy(); resolve(); });
        req.end();
      });
    });

    await Promise.allSettled(checkPromises);

    // TRACE is always dangerous (enables XST attacks)
    const trace = results.find(r => r.method === 'TRACE');
    if (trace) {
      this.results.findings.push({
        id: 'http-trace-enabled',
        title: 'HTTP TRACE method enabled',
        title_es: 'Método HTTP TRACE habilitado',
        severity: 'MEDIUM',
        description_en: 'The TRACE method is enabled, which can be used for Cross-Site Tracing (XST) attacks to steal credentials.',
        description_es: 'El método TRACE está habilitado, lo que puede usarse para ataques Cross-Site Tracing (XST) para robar credenciales.',
        fix_en: 'Disable the TRACE method in your web server configuration.',
        fix_es: 'Desactiva el método TRACE en la configuración de tu servidor web.',
        category: 'http-methods',
      });
    }

    const otherDangerous = results.filter(r => r.method !== 'TRACE');
    if (otherDangerous.length > 0) {
      this.results.findings.push({
        id: 'http-dangerous-methods',
        title: `Potentially dangerous HTTP methods enabled: ${otherDangerous.map(r => r.method).join(', ')}`,
        title_es: `Métodos HTTP potencialmente peligrosos habilitados: ${otherDangerous.map(r => r.method).join(', ')}`,
        severity: 'LOW',
        description_en: `The methods ${otherDangerous.map(r => r.method).join(', ')} appear to be enabled. If not intentionally configured, disable them.`,
        description_es: `Los métodos ${otherDangerous.map(r => r.method).join(', ')} parecen estar habilitados. Si no están configurados intencionalmente, desactívalos.`,
        category: 'http-methods',
      });
    }
  }

  /**
   * Check DNS security records (SPF, DMARC).
   */
  async _checkDNSSecurity() {
    const domain = this.parsedUrl.hostname;
    const dnsResults = { spf: null, dmarc: null, hasSPF: false, hasDMARC: false };

    try {
      // Check SPF record
      try {
        const txtRecords = await dns.resolveTxt(domain);
        const spfRecord = txtRecords.flat().find(r => r.startsWith('v=spf1'));
        if (spfRecord) {
          dnsResults.spf = spfRecord;
          dnsResults.hasSPF = true;

          // Check for overly permissive SPF
          if (spfRecord.includes('+all')) {
            this.results.findings.push({
              id: 'spf-permissive',
              title: 'SPF record is overly permissive (+all)',
              title_es: 'Registro SPF demasiado permisivo (+all)',
              severity: 'HIGH',
              description_en: 'The SPF record ends with +all, which means any server can send emails on behalf of this domain. This allows email spoofing.',
              description_es: 'El registro SPF termina con +all, lo que significa que cualquier servidor puede enviar correos en nombre de este dominio. Esto permite spoofing de correo.',
              fix_en: 'Change +all to ~all (softfail) or -all (hardfail) in your SPF record.',
              fix_es: 'Cambia +all por ~all (softfail) o -all (hardfail) en tu registro SPF.',
              category: 'dns',
            });
          }
        } else {
          this.results.findings.push({
            id: 'missing-spf',
            title: 'No SPF record found',
            title_es: 'No se encontró registro SPF',
            severity: 'MEDIUM',
            description_en: 'No SPF record was found for this domain. Without SPF, attackers can send emails impersonating your domain (email spoofing).',
            description_es: 'No se encontró registro SPF para este dominio. Sin SPF, los atacantes pueden enviar correos suplantando tu dominio (spoofing de correo).',
            fix_en: 'Add a TXT record: v=spf1 include:_spf.google.com ~all (adjust for your email provider).',
            fix_es: 'Añade un registro TXT: v=spf1 include:_spf.google.com ~all (ajusta según tu proveedor de correo).',
            category: 'dns',
          });
        }
      } catch { /* DNS lookup failed */ }

      // Check DMARC record
      try {
        const dmarcRecords = await dns.resolveTxt(`_dmarc.${domain}`);
        const dmarcRecord = dmarcRecords.flat().find(r => r.startsWith('v=DMARC1'));
        if (dmarcRecord) {
          dnsResults.dmarc = dmarcRecord;
          dnsResults.hasDMARC = true;

          // Check for p=none (monitoring only, no enforcement)
          if (dmarcRecord.includes('p=none')) {
            this.results.findings.push({
              id: 'dmarc-none',
              title: 'DMARC policy is set to none (no enforcement)',
              title_es: 'Política DMARC establecida en none (sin enforcement)',
              severity: 'LOW',
              description_en: 'DMARC is configured with p=none, which only monitors but does not reject spoofed emails.',
              description_es: 'DMARC está configurado con p=none, que solo monitorea pero no rechaza correos falsificados.',
              fix_en: 'Change DMARC policy to p=quarantine or p=reject for active protection.',
              fix_es: 'Cambia la política DMARC a p=quarantine o p=reject para protección activa.',
              category: 'dns',
            });
          }
        } else {
          this.results.findings.push({
            id: 'missing-dmarc',
            title: 'No DMARC record found',
            title_es: 'No se encontró registro DMARC',
            severity: 'MEDIUM',
            description_en: 'No DMARC record was found. DMARC prevents email spoofing by specifying how to handle unauthorized emails.',
            description_es: 'No se encontró registro DMARC. DMARC previene spoofing de correo especificando cómo manejar correos no autorizados.',
            fix_en: 'Add a TXT record for _dmarc.yourdomain.com: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com',
            fix_es: 'Añade un registro TXT para _dmarc.tudominio.com: v=DMARC1; p=quarantine; rua=mailto:dmarc@tudominio.com',
            category: 'dns',
          });
        }
      } catch { /* DNS lookup failed */ }
    } catch { /* Outer catch */ }

    this.results.dns = dnsResults;
  }

  /**
   * Analyze form security (CSRF tokens, autocomplete).
   */
  _analyzeFormSecurity(body) {
    const formRegex = /<form[^>]*>([\s\S]*?)<\/form>/gi;
    let match;
    let formIndex = 0;

    while ((match = formRegex.exec(body)) !== null) {
      formIndex++;
      const formTag = match[0];
      const formContent = match[1];

      // Check for POST forms without CSRF tokens
      const isPost = /method=["']post["']/i.test(formTag);
      const hasCSRF = /csrf|_token|authenticity_token|__RequestVerificationToken/i.test(formContent);

      if (isPost && !hasCSRF) {
        this.results.findings.push({
          id: `form-no-csrf-${formIndex}`,
          title: `Form #${formIndex} (POST) missing CSRF token`,
          title_es: `Formulario #${formIndex} (POST) sin token CSRF`,
          severity: 'HIGH',
          description_en: 'A POST form was found without a CSRF token. This makes it vulnerable to Cross-Site Request Forgery attacks.',
          description_es: 'Se encontró un formulario POST sin token CSRF. Esto lo hace vulnerable a ataques Cross-Site Request Forgery.',
          fix_en: 'Add a hidden CSRF token field to all POST forms.',
          fix_es: 'Añade un campo oculto con token CSRF a todos los formularios POST.',
          category: 'forms',
        });
      }

      // Check for password fields with autocomplete enabled
      const hasPasswordNoAutocomplete = /type=["']password["']/i.test(formContent) &&
        !/autocomplete=["']off["']|autocomplete=["']new-password["']/i.test(formContent);

      if (hasPasswordNoAutocomplete) {
        this.results.findings.push({
          id: `form-password-autocomplete-${formIndex}`,
          title: `Password field in form #${formIndex} allows autocomplete`,
          title_es: `Campo de contraseña en formulario #${formIndex} permite autocompletado`,
          severity: 'LOW',
          description_en: 'A password field does not disable autocomplete. Stored passwords could be accessed by other users on shared devices.',
          description_es: 'Un campo de contraseña no desactiva el autocompletado. Las contraseñas guardadas podrían ser accedidas por otros usuarios en dispositivos compartidos.',
          fix_en: 'Add autocomplete="new-password" or autocomplete="off" to sensitive fields.',
          fix_es: 'Añade autocomplete="new-password" o autocomplete="off" a los campos sensibles.',
          category: 'forms',
        });
      }

      // Check for forms without action (submits to same page)
      const hasAction = /action=["'][^"']+["']/i.test(formTag);
      const formMethod = isPost ? 'POST' : 'GET';
      if (!hasAction && isPost) {
        this.results.findings.push({
          id: `form-no-action-${formIndex}`,
          title: `Form #${formIndex} (${formMethod}) has no explicit action`,
          title_es: `Formulario #${formIndex} (${formMethod}) sin action explícito`,
          severity: 'INFO',
          description_en: 'A POST form has no action attribute and will submit to the current URL.',
          description_es: 'Un formulario POST no tiene atributo action y enviará datos a la URL actual.',
          category: 'forms',
        });
      }
    }
  }

  /**
   * Detect dangerous JavaScript patterns in the HTML.
   */
  _checkDangerousJS(body) {
    const patterns = [
      {
        regex: /\beval\s*\(/gi,
        id: 'js-eval',
        title: 'eval() usage detected',
        title_es: 'Uso de eval() detectado',
        severity: 'MEDIUM',
        desc_en: 'eval() executes arbitrary code and is a common vector for code injection attacks. Avoid using eval() in production.',
        desc_es: 'eval() ejecuta código arbitrario y es un vector común para ataques de inyección de código. Evita usar eval() en producción.',
      },
      {
        regex: /document\.write\s*\(/gi,
        id: 'js-document-write',
        title: 'document.write() usage detected',
        title_es: 'Uso de document.write() detectado',
        severity: 'LOW',
        desc_en: 'document.write() can be exploited for DOM-based XSS attacks. Use safer DOM manipulation methods instead.',
        desc_es: 'document.write() puede ser explotado para ataques XSS basados en DOM. Usa métodos de manipulación DOM más seguros.',
      },
      {
        regex: /\.innerHTML\s*=/gi,
        id: 'js-innerhtml',
        title: 'innerHTML assignment detected',
        title_es: 'Asignación innerHTML detectada',
        severity: 'LOW',
        desc_en: 'Direct innerHTML assignment with user input can lead to XSS. Use textContent or sanitize input before using innerHTML.',
        desc_es: 'La asignación directa de innerHTML con entrada de usuario puede llevar a XSS. Usa textContent o sanitiza la entrada antes de usar innerHTML.',
      },
    ];

    // Only check inline scripts (not external files)
    const inlineScripts = [];
    const scriptContentRegex = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
    let scriptMatch;
    while ((scriptMatch = scriptContentRegex.exec(body)) !== null) {
      inlineScripts.push(scriptMatch[1]);
    }
    const inlineJS = inlineScripts.join('\n');

    for (const pattern of patterns) {
      const matches = inlineJS.match(pattern.regex);
      if (matches && matches.length > 0) {
        this.results.findings.push({
          id: pattern.id,
          title: `${pattern.title} (${matches.length} occurrence${matches.length > 1 ? 's' : ''})`,
          title_es: `${pattern.title_es} (${matches.length} ocurrencia${matches.length > 1 ? 's' : ''})`,
          severity: pattern.severity,
          description_en: pattern.desc_en,
          description_es: pattern.desc_es,
          category: 'js-security',
        });
      }
    }
  }

  /**
   * Detect Web Application Firewalls (WAF).
   */
  _detectWAF(headers) {
    const wafSignatures = [
      { header: 'server', pattern: /cloudflare/i, name: 'Cloudflare', icon: '☁️' },
      { header: 'x-cdn', pattern: /cloudflare/i, name: 'Cloudflare', icon: '☁️' },
      { header: 'cf-ray', pattern: /./, name: 'Cloudflare', icon: '☁️' },
      { header: 'x-sucuri-id', pattern: /./, name: 'Sucuri', icon: '🛡️' },
      { header: 'x-sucuri-cache', pattern: /./, name: 'Sucuri', icon: '🛡️' },
      { header: 'server', pattern: /akamai/i, name: 'Akamai', icon: '🔒' },
      { header: 'x-akamai-transformed', pattern: /./, name: 'Akamai', icon: '🔒' },
      { header: 'server', pattern: /awselb|amazons3|cloudfront/i, name: 'AWS (CloudFront/ELB)', icon: '🔶' },
      { header: 'x-amz-cf-id', pattern: /./, name: 'AWS CloudFront', icon: '🔶' },
      { header: 'x-azure-ref', pattern: /./, name: 'Azure CDN', icon: '🔷' },
      { header: 'server', pattern: /imperva|incapsula/i, name: 'Imperva/Incapsula', icon: '🛡️' },
      { header: 'x-iinfo', pattern: /./, name: 'Imperva/Incapsula', icon: '🛡️' },
      { header: 'x-fw-protection', pattern: /./, name: 'Fortinet FortiWeb', icon: '🔒' },
      { header: 'server', pattern: /barracuda/i, name: 'Barracuda WAF', icon: '🛡️' },
    ];

    const detected = new Set();
    for (const sig of wafSignatures) {
      const value = headers[sig.header];
      if (value && sig.pattern.test(value)) {
        detected.add(JSON.stringify({ name: sig.name, icon: sig.icon }));
      }
    }

    if (detected.size > 0) {
      const wafs = Array.from(detected).map(w => JSON.parse(w));
      this.results.waf = wafs;
      this.results.findings.push({
        id: 'waf-detected',
        title: `WAF/CDN detected: ${wafs.map(w => w.name).join(', ')}`,
        title_es: `WAF/CDN detectado: ${wafs.map(w => w.name).join(', ')}`,
        severity: 'INFO',
        description_en: `Web Application Firewall detected: ${wafs.map(w => w.name).join(', ')}. This provides an additional layer of security.`,
        description_es: `Firewall de Aplicación Web detectado: ${wafs.map(w => w.name).join(', ')}. Esto proporciona una capa adicional de seguridad.`,
        category: 'waf',
      });
    } else {
      this.results.findings.push({
        id: 'no-waf',
        title: 'No WAF/CDN detected',
        title_es: 'No se detectó WAF/CDN',
        severity: 'LOW',
        description_en: 'No Web Application Firewall was detected. A WAF can help protect against common attacks like SQL injection and XSS.',
        description_es: 'No se detectó Firewall de Aplicación Web. Un WAF puede ayudar a proteger contra ataques comunes como inyección SQL y XSS.',
        fix_en: 'Consider using a WAF service like Cloudflare, AWS WAF, or Sucuri.',
        fix_es: 'Considera usar un servicio WAF como Cloudflare, AWS WAF o Sucuri.',
        category: 'waf',
      });
    }
  }

  /**
   * Analyze robots.txt for sensitive paths.
   */
  async _analyzeRobotsTxt() {
    try {
      const robotsContent = await this._fetchPath('/robots.txt');
      if (!robotsContent) return;

      const lines = robotsContent.split('\n');
      const disallowed = lines
        .filter(l => l.trim().toLowerCase().startsWith('disallow:'))
        .map(l => l.split(':').slice(1).join(':').trim())
        .filter(p => p.length > 0);

      const sensitivePatterns = [
        { pattern: /admin/i, label: 'Admin panel' },
        { pattern: /login|signin|auth/i, label: 'Authentication endpoint' },
        { pattern: /api/i, label: 'API endpoint' },
        { pattern: /backup/i, label: 'Backup files' },
        { pattern: /config/i, label: 'Configuration' },
        { pattern: /database|db|sql/i, label: 'Database' },
        { pattern: /debug|test|staging/i, label: 'Debug/Test environment' },
        { pattern: /upload|files/i, label: 'File uploads' },
        { pattern: /private|secret|internal/i, label: 'Private/Internal' },
        { pattern: /\.env|\.git|\.svn/i, label: 'Config/VCS files' },
      ];

      const sensitiveDisallowed = [];
      for (const path of disallowed) {
        for (const { pattern, label } of sensitivePatterns) {
          if (pattern.test(path)) {
            sensitiveDisallowed.push({ path, label });
            break;
          }
        }
      }

      if (sensitiveDisallowed.length > 0) {
        this.results.findings.push({
          id: 'robots-sensitive-paths',
          title: `robots.txt reveals ${sensitiveDisallowed.length} sensitive path(s)`,
          title_es: `robots.txt revela ${sensitiveDisallowed.length} ruta(s) sensible(s)`,
          severity: 'LOW',
          description_en: `The robots.txt file disallows paths that reveal internal structure: ${sensitiveDisallowed.slice(0, 5).map(s => s.path).join(', ')}${sensitiveDisallowed.length > 5 ? '...' : ''}. Attackers use robots.txt to discover hidden endpoints.`,
          description_es: `El archivo robots.txt bloquea rutas que revelan estructura interna: ${sensitiveDisallowed.slice(0, 5).map(s => s.path).join(', ')}${sensitiveDisallowed.length > 5 ? '...' : ''}. Los atacantes usan robots.txt para descubrir endpoints ocultos.`,
          category: 'robots',
        });
      }
    } catch { /* robots.txt not found or error */ }
  }

  /**
   * Check compression and performance headers.
   */
  _checkPerformance(headers, body) {
    const perf = {
      compression: null,
      caching: null,
      pageSize: body.length,
      pageSizeKB: Math.round(body.length / 1024),
    };

    // Check compression
    const encoding = headers['content-encoding'];
    if (encoding) {
      perf.compression = encoding;
    } else {
      this.results.findings.push({
        id: 'no-compression',
        title: 'No response compression (gzip/brotli)',
        title_es: 'Sin compresión de respuesta (gzip/brotli)',
        severity: 'INFO',
        description_en: 'The response is not compressed. Enable gzip or brotli compression to improve page load times.',
        description_es: 'La respuesta no está comprimida. Habilita compresión gzip o brotli para mejorar los tiempos de carga.',
        fix_en: 'Enable gzip or brotli compression in your web server configuration.',
        fix_es: 'Habilita compresión gzip o brotli en la configuración de tu servidor web.',
        category: 'performance',
      });
    }

    // Check caching
    const cacheControl = headers['cache-control'];
    if (cacheControl) {
      perf.caching = cacheControl;
    }

    // Large page size warning
    if (perf.pageSizeKB > 500) {
      this.results.findings.push({
        id: 'large-page',
        title: `Large page size: ${perf.pageSizeKB}KB`,
        title_es: `Tamaño de página grande: ${perf.pageSizeKB}KB`,
        severity: 'INFO',
        description_en: `The page is ${perf.pageSizeKB}KB which may cause slow load times on mobile devices.`,
        description_es: `La página tiene ${perf.pageSizeKB}KB lo que puede causar tiempos de carga lentos en dispositivos móviles.`,
        category: 'performance',
      });
    }

    this.results.performance = perf;
  }

  /**
   * Check error pages for information leaks.
   */
  async _checkErrorPageLeaks() {
    try {
      const errorBody = await this._fetchPath('/canary-test-404-' + Date.now());
      if (!errorBody) return;

      const leakPatterns = [
        { pattern: /stack\s*trace|traceback|at\s+\w+\.\w+\s*\(/i, label: 'Stack trace' },
        { pattern: /exception|error.*line\s+\d+/i, label: 'Error details with line numbers' },
        { pattern: /mysql|postgresql|sqlite|mongodb|redis/i, label: 'Database name' },
        { pattern: /\/home\/|\/var\/|\/usr\/|C:\\\\|\/app\//i, label: 'File system paths' },
        { pattern: /django|laravel|rails|express|flask/i, label: 'Framework name' },
        { pattern: /debug\s*=\s*true|debug\s*mode/i, label: 'Debug mode enabled' },
      ];

      const leaks = [];
      for (const { pattern, label } of leakPatterns) {
        if (pattern.test(errorBody)) {
          leaks.push(label);
        }
      }

      if (leaks.length > 0) {
        this.results.findings.push({
          id: 'error-page-leaks',
          title: `Error page reveals sensitive information`,
          title_es: `Página de error revela información sensible`,
          severity: 'MEDIUM',
          description_en: `The 404 error page exposes: ${leaks.join(', ')}. This information helps attackers understand your application's internals.`,
          description_es: `La página de error 404 expone: ${leaks.join(', ')}. Esta información ayuda a los atacantes a entender los internos de tu aplicación.`,
          fix_en: 'Use custom error pages that do not reveal server details. Disable debug mode in production.',
          fix_es: 'Usa páginas de error personalizadas que no revelen detalles del servidor. Desactiva el modo debug en producción.',
          category: 'error-pages',
        });
      }
    } catch { /* Error page check failed */ }
  }

  /**
   * Check for directory listing on common paths.
   */
  async _checkDirectoryListing() {
    const dirsToCheck = ['/images/', '/uploads/', '/assets/', '/static/', '/media/', '/css/', '/js/'];

    const checkPromises = dirsToCheck.map(dir => {
      return new Promise(async (resolve) => {
        try {
          const body = await this._fetchPath(dir);
          if (body && /<title>Index of|<h1>Index of|Directory listing|Parent Directory/i.test(body)) {
            this.results.findings.push({
              id: `dir-listing-${dir.replace(/\//g, '')}`,
              title: `Directory listing enabled on ${dir}`,
              title_es: `Listado de directorio habilitado en ${dir}`,
              severity: 'MEDIUM',
              description_en: `Directory browsing is enabled on ${dir}. This exposes file names and structure to attackers.`,
              description_es: `La navegación de directorio está habilitada en ${dir}. Esto expone nombres de archivos y estructura a atacantes.`,
              fix_en: 'Disable directory listing in your web server configuration (e.g., Options -Indexes in Apache).',
              fix_es: 'Desactiva el listado de directorio en la configuración de tu servidor (ej: Options -Indexes en Apache).',
              category: 'directory-listing',
            });
          }
        } catch { /* Ignore errors */ }
        resolve();
      });
    });

    await Promise.allSettled(checkPromises);
  }

  /**
   * Check for open redirect vulnerabilities.
   */
  async _checkOpenRedirects() {
    const redirectParams = ['redirect', 'url', 'next', 'return', 'returnTo', 'goto', 'redirect_uri', 'continue'];
    const testUrl = 'https://evil.example.com';

    const checkPromises = redirectParams.slice(0, 4).map(param => {
      return new Promise((resolve) => {
        const path = `/?${param}=${encodeURIComponent(testUrl)}`;
        const protocol = this.parsedUrl.protocol === 'https:' ? https : http;
        const options = {
          hostname: this.parsedUrl.hostname,
          port: this.parsedUrl.port || (this.parsedUrl.protocol === 'https:' ? 443 : 80),
          path: path,
          method: 'GET',
          headers: { 'User-Agent': 'Canary-SecurityScanner/1.0' },
          timeout: 5000,
        };

        const req = protocol.request(options, (res) => {
          // Check if it redirects to our evil URL
          if ([301, 302, 303, 307, 308].includes(res.statusCode)) {
            const location = res.headers.location || '';
            if (location.includes('evil.example.com')) {
              this.results.findings.push({
                id: `open-redirect-${param}`,
                title: `Open redirect via ?${param}= parameter`,
                title_es: `Redirección abierta via parámetro ?${param}=`,
                severity: 'MEDIUM',
                description_en: `The application redirects to external URLs via the "${param}" parameter without validation. Attackers can use this for phishing.`,
                description_es: `La aplicación redirige a URLs externas mediante el parámetro "${param}" sin validación. Los atacantes pueden usar esto para phishing.`,
                fix_en: 'Validate redirect URLs against a whitelist of allowed domains.',
                fix_es: 'Valida las URLs de redirección contra una lista blanca de dominios permitidos.',
                category: 'open-redirect',
              });
            }
          }
          res.resume();
          resolve();
        });

        req.on('error', () => resolve());
        req.on('timeout', () => { req.destroy(); resolve(); });
        req.end();
      });
    });

    await Promise.allSettled(checkPromises);
  }

  /**
   * Helper: Fetch a specific path and return body text.
   */
  _fetchPath(path) {
    return new Promise((resolve) => {
      const protocol = this.parsedUrl.protocol === 'https:' ? https : http;
      const options = {
        hostname: this.parsedUrl.hostname,
        port: this.parsedUrl.port || (this.parsedUrl.protocol === 'https:' ? 443 : 80),
        path: path,
        method: 'GET',
        headers: { 'User-Agent': 'Canary-SecurityScanner/1.0' },
        timeout: 5000,
      };

      const req = protocol.request(options, (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          resolve(null);
          return;
        }
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => resolve(body));
      });

      req.on('error', () => resolve(null));
      req.on('timeout', () => { req.destroy(); resolve(null); });
      req.end();
    });
  }

  /**
   * Step 21: Subdomain Discovery
   * Probes common subdomains (api, dev, staging, admin, test, vpn, mail, auth, portal, etc.)
   */
  async _discoverSubdomains() {
    try {
      const hostname = this.parsedUrl.hostname;
      const parts = hostname.split('.');
      const baseDomain = parts.length > 2 ? parts.slice(-2).join('.') : hostname;

      const candidates = [
        'api', 'dev', 'staging', 'admin', 'test', 'vpn', 'mail', 
        'portal', 'beta', 'demo', 'auth', 'app', 'dashboard', 'status', 'cdn'
      ];

      const discovered = [];
      const devExposed = [];

      const lookupPromises = candidates.map(async (sub) => {
        const fqdn = `${sub}.${baseDomain}`;
        if (fqdn === hostname) return;

        try {
          const ips = await Promise.race([
            dns.resolve4(fqdn),
            new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 1500))
          ]);

          if (ips && ips.length > 0) {
            const isDev = ['dev', 'staging', 'test', 'beta', 'admin'].includes(sub);
            discovered.push({
              subdomain: sub,
              fqdn,
              ips: ips.slice(0, 2),
              isDev,
            });

            if (isDev) {
              devExposed.push(fqdn);
            }
          }
        } catch {
          // Not resolved or timed out
        }
      });

      await Promise.all(lookupPromises);
      this.results.subdomains = discovered;

      if (devExposed.length > 0) {
        this.results.findings.push({
          id: 'exposed-dev-subdomains',
          title: `Exposed development/internal subdomains: ${devExposed.slice(0, 3).join(', ')}`,
          title_es: `Subdominios de desarrollo/pruebas expuestos: ${devExposed.slice(0, 3).join(', ')}`,
          severity: 'MEDIUM',
          description_en: `Discovered active pre-production or administrative subdomains (${devExposed.join(', ')}). Dev environments frequently lack authentication or contain sensitive debug endpoints.`,
          description_es: `Se descubrieron subdominios activos de pruebas o administración (${devExposed.join(', ')}). Los entornos de desarrollo suelen carecer de autenticación robusta o contienen endpoints con información sensible.`,
          fix_en: 'Protect dev/staging subdomains behind VPN, IP whitelisting, or HTTP Basic Auth.',
          fix_es: 'Protege los subdominios de pruebas detrás de una VPN, lista blanca de IPs o autenticación básica.',
          category: 'subdomains',
        });
      }
    } catch {
      this.results.subdomains = [];
    }
  }

  /**
   * Step 22: Security.txt RFC 9116 verification
   */
  async _checkSecurityTxt() {
    try {
      let content = await this._fetchPath('/.well-known/security.txt');
      let pathUsed = '/.well-known/security.txt';

      if (!content || !content.includes('Contact:')) {
        content = await this._fetchPath('/security.txt');
        pathUsed = '/security.txt';
      }

      if (content && content.includes('Contact:')) {
        const contactMatch = content.match(/Contact:\s*([^\r\n]+)/i);
        const expiresMatch = content.match(/Expires:\s*([^\r\n]+)/i);
        const policyMatch = content.match(/Policy:\s*([^\r\n]+)/i);
        const encryptionMatch = content.match(/Encryption:\s*([^\r\n]+)/i);

        let isExpired = false;
        if (expiresMatch) {
          try {
            const expDate = new Date(expiresMatch[1].trim());
            if (expDate < new Date()) isExpired = true;
          } catch {}
        }

        this.results.securityTxt = {
          present: true,
          path: pathUsed,
          contact: contactMatch ? contactMatch[1].trim() : null,
          expires: expiresMatch ? expiresMatch[1].trim() : null,
          policy: policyMatch ? policyMatch[1].trim() : null,
          encryption: encryptionMatch ? encryptionMatch[1].trim() : null,
          isExpired,
        };

        if (isExpired) {
          this.results.findings.push({
            id: 'expired-security-txt',
            title: 'security.txt policy is expired',
            title_es: 'El archivo security.txt está vencido',
            severity: 'LOW',
            description_en: `The security.txt file at ${pathUsed} has an expiration date in the past (${this.results.securityTxt.expires}).`,
            description_es: `El archivo security.txt en ${pathUsed} tiene una fecha de expiración en el pasado (${this.results.securityTxt.expires}).`,
            fix_en: 'Update the Expires directive in your security.txt to a future date.',
            fix_es: 'Actualiza la directiva Expires en tu security.txt con una fecha futura.',
            category: 'config',
          });
        }
      } else {
        this.results.securityTxt = { present: false };
        this.results.findings.push({
          id: 'missing-security-txt',
          title: 'Missing security.txt (RFC 9116)',
          title_es: 'Falta archivo security.txt (RFC 9116)',
          severity: 'INFO',
          description_en: 'The website lacks a security.txt file at /.well-known/security.txt. Security researchers need an official channel to report vulnerabilities.',
          description_es: 'El sitio no cuenta con un archivo security.txt en /.well-known/security.txt. Los investigadores de seguridad necesitan un canal oficial para reportar vulnerabilidades.',
          fix_en: 'Create a /.well-known/security.txt file with your security contact email.',
          fix_es: 'Crea un archivo /.well-known/security.txt con el correo de contacto de seguridad.',
          category: 'config',
        });
      }
    } catch {
      this.results.securityTxt = { present: false };
    }
  }

  /**
   * Step 23: Active CORS Misconfiguration Test
   */
  async _testCORSConfiguration() {
    try {
      const testOrigin = 'https://canary-audit-attacker.com';
      const protocol = this.parsedUrl.protocol === 'https:' ? https : http;

      const options = {
        hostname: this.parsedUrl.hostname,
        port: this.parsedUrl.port || (this.parsedUrl.protocol === 'https:' ? 443 : 80),
        path: this.parsedUrl.pathname || '/',
        method: 'OPTIONS',
        headers: {
          'User-Agent': 'Canary-SecurityScanner/1.0',
          'Origin': testOrigin,
          'Access-Control-Request-Method': 'POST',
        },
        timeout: 4000,
      };

      const res = await new Promise((resolve) => {
        const req = protocol.request(options, (response) => {
          response.resume();
          resolve(response);
        });
        req.on('error', () => resolve(null));
        req.on('timeout', () => { req.destroy(); resolve(null); });
        req.end();
      });

      if (!res) {
        this.results.corsAnalysis = { tested: false };
        return;
      }

      const allowOrigin = (res.headers['access-control-allow-origin'] || '').toLowerCase().trim();
      const allowCreds = (res.headers['access-control-allow-credentials'] || '').toLowerCase().trim() === 'true';

      const originReflected = allowOrigin === testOrigin.toLowerCase();
      const isWildcard = allowOrigin === '*';

      this.results.corsAnalysis = {
        tested: true,
        allowOrigin: allowOrigin || null,
        allowCredentials: allowCreds,
        originReflected,
        isWildcard,
        status: (originReflected && allowCreds) ? 'CRITICAL' : isWildcard ? 'PERMISSIVE' : 'SECURE',
      };

      if (originReflected && allowCreds) {
        this.results.findings.push({
          id: 'cors-arbitrary-origin-reflection',
          title: 'Critical CORS Vulnerability: Arbitrary Origin Reflection with Credentials',
          title_es: 'Vulnerabilidad Crítica de CORS: Reflejo Arbitrario de Origen con Credenciales',
          severity: 'CRITICAL',
          description_en: 'The server reflects untrusted request Origin and allows credentials (Access-Control-Allow-Credentials: true). Any malicious website can steal private user data and perform authenticated actions.',
          description_es: 'El servidor refleja orígenes no confiables y permite credenciales (Access-Control-Allow-Credentials: true). Cualquier sitio malicioso puede robar datos privados de usuarios autenticados.',
          fix_en: 'Validate origins against an explicit whitelist before returning Access-Control-Allow-Origin.',
          fix_es: 'Valida los orígenes contra una lista blanca explícita antes de responder Access-Control-Allow-Origin.',
          category: 'headers',
        });
      }
    } catch {
      this.results.corsAnalysis = { tested: false };
    }
  }

  /**
   * Step 24: Domain Reputation & Blocklist Check
   */
  async _checkDomainReputation() {
    try {
      const domain = this.parsedUrl.hostname;
      const providers = [
        { name: 'Spamhaus DBL', zone: 'dbl.spamhaus.org' },
        { name: 'SURBL Multi', zone: 'multi.surbl.org' },
      ];

      const results = [];
      let isBlacklisted = false;

      const checks = providers.map(async (provider) => {
        const query = `${domain}.${provider.zone}`;
        try {
          const ips = await Promise.race([
            dns.resolve4(query),
            new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 1500))
          ]);
          if (ips && ips.length > 0) {
            isBlacklisted = true;
            results.push({ provider: provider.name, listed: true, code: ips[0] });
          } else {
            results.push({ provider: provider.name, listed: false });
          }
        } catch {
          results.push({ provider: provider.name, listed: false });
        }
      });

      await Promise.all(checks);

      this.results.reputation = {
        clean: !isBlacklisted,
        blacklisted: isBlacklisted,
        providers: results,
      };

      if (isBlacklisted) {
        this.results.findings.push({
          id: 'domain-blacklisted',
          title: 'Domain is listed on threat blocklists (Spamhaus / SURBL)',
          title_es: 'El dominio está en listas negras de amenazas (Spamhaus / SURBL)',
          severity: 'HIGH',
          description_en: `The domain ${domain} is currently flagged on threat intelligence blocklists for malware, spam or phishing activity.`,
          description_es: `El dominio ${domain} está listado en bases de datos de amenazas por actividad sospechosa de malware, spam o phishing.`,
          fix_en: 'Review your server for malware/compromise and request delisting at Spamhaus/SURBL.',
          fix_es: 'Revisa tu servidor en busca de malware y solicita la deslistación en Spamhaus/SURBL.',
          category: 'dns',
        });
      }
    } catch {
      this.results.reputation = { clean: true, blacklisted: false, providers: [] };
    }
  }

  /**
   * Step 25: Harvest Exposed API Keys, Tokens & Private Credentials in Client JS
   */
  _harvestSecrets(body) {
    const secretSignatures = [
      {
        name: 'AWS Access Key ID',
        pattern: /\b(AKIA[0-9A-Z]{16})\b/g,
        severity: 'CRITICAL',
        category: 'secrets',
        desc_en: 'AWS Access Key ID exposed in client-side HTML/JavaScript. Attackers can use this to enumerate and compromise cloud infrastructure.',
        desc_es: 'AWS Access Key ID expuesta en el código HTML/JavaScript del cliente. Un atacante puede usarla para comprometer infraestructura en la nube.',
        fix_en: 'Revoke this AWS key immediately and use server-side environment variables.',
        fix_es: 'Revoca esta clave de AWS inmediatamente y usa variables de entorno en el servidor.',
      },
      {
        name: 'Stripe Secret / Live Key',
        pattern: /\b((?:sk|rk)_live_[0-9a-zA-Z]{24,34})\b/g,
        severity: 'CRITICAL',
        category: 'secrets',
        desc_en: 'Live Stripe Secret Key exposed. Allows unauthorized refunds, customer data extraction, or fraudulent charges.',
        desc_es: 'Clave Secreta de Stripe en producción expuesta. Permite reembolsos no autorizados, extracción de clientes o cobros fraudulentos.',
        fix_en: 'Roll the key in Stripe Dashboard and only use publishable keys (pk_live_...) on the frontend.',
        fix_es: 'Cambia la clave en el panel de Stripe y usa exclusivamente claves públicas (pk_live_...) en el frontend.',
      },
      {
        name: 'GitHub Personal Access Token',
        pattern: /\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b/g,
        severity: 'CRITICAL',
        category: 'secrets',
        desc_en: 'GitHub Personal Access Token exposed in client-side assets, granting repository access.',
        desc_es: 'Token de acceso personal de GitHub expuesto en assets públicos, permitiendo acceso al repositorio.',
        fix_en: 'Revoke the token immediately in GitHub Settings > Developer Settings.',
        fix_es: 'Revoca el token de inmediato en Configuración de GitHub.',
      },
      {
        name: 'SendGrid API Key',
        pattern: /\b(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})\b/g,
        severity: 'CRITICAL',
        category: 'secrets',
        desc_en: 'SendGrid API Key exposed, allowing attackers to hijack your domain for phishing campaigns.',
        desc_es: 'Clave de API de SendGrid expuesta, permitiendo a atacantes enviar correos de phishing usando tu dominio.',
        fix_en: 'Revoke the SendGrid key and move mailing logic to the backend.',
        fix_es: 'Revoca la clave en SendGrid y traslada el envío de correos al backend.',
      },
      {
        name: 'Slack Webhook URL',
        pattern: /(https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+)/g,
        severity: 'HIGH',
        category: 'secrets',
        desc_en: 'Incoming Slack Webhook URL exposed. Attackers can spam internal channels or impersonate bots.',
        desc_es: 'Webhook entrante de Slack expuesto. Permite a atacantes enviar mensajes no autorizados a tus canales internos.',
        fix_en: 'Deactivate the webhook URL and proxy Slack notifications through a backend endpoint.',
        fix_es: 'Desactiva el webhook en Slack y procesa las notificaciones a través de tu backend.',
      },
      {
        name: 'RSA / Private Key Block',
        pattern: /(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)/g,
        severity: 'CRITICAL',
        category: 'secrets',
        desc_en: 'Private cryptographic key header detected in client code. Catastrophic confidentiality risk.',
        desc_es: 'Cabecera de clave privada criptográfica detectada en el cliente. Riesgo crítico de confidencialidad.',
        fix_en: 'Remove private keys from public web root and rotate affected certificates.',
        fix_es: 'Elimina las claves privadas del directorio web público y renueva los certificados afectados.',
      },
      {
        name: 'Exposed Internal IP / Host',
        pattern: /\b(?:https?:\/\/)?(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|localhost|127\.0\.0\.1)(?::\d+)?(?:\/[^\s"']*)?\b/g,
        severity: 'MEDIUM',
        category: 'info-exposure',
        desc_en: 'Internal IP address or localhost reference leaked in client-side code, revealing internal network architecture.',
        desc_es: 'Dirección IP interna o referencia a localhost filtrada en el cliente, revelando la topología de red interna.',
        fix_en: 'Remove internal debugging endpoints before deploying to production.',
        fix_es: 'Elimina endpoints de debug y pruebas internas antes de desplegar a producción.',
      },
    ];

    const harvested = [];

    for (const sig of secretSignatures) {
      let match;
      while ((match = sig.pattern.exec(body)) !== null) {
        const rawSecret = match[1];
        if (!rawSecret) continue;

        const masked = rawSecret.length > 8 
          ? rawSecret.substring(0, 4) + '•'.repeat(Math.min(12, rawSecret.length - 8)) + rawSecret.substring(rawSecret.length - 4)
          : '••••••••';

        harvested.push({
          type: sig.name,
          masked,
          severity: sig.severity,
        });

        this.results.findings.push({
          id: `secret-${sig.name.toLowerCase().replace(/[^a-z0-9-]/g, '-')}`,
          title: `Secret Leak: ${sig.name} detected (${masked})`,
          title_es: `Fuga de Secreto: ${sig.name} detectada (${masked})`,
          severity: sig.severity,
          description_en: sig.desc_en,
          description_es: sig.desc_es,
          fix_en: sig.fix_en,
          fix_es: sig.fix_es,
          category: sig.category,
        });
        break;
      }
    }

    this.results.secrets = harvested;
  }

  /**
   * Step 26: Source Code & Backup File Leaks (.git, .js.map, .sql, .bak, Dockerfile)
   */
  async _checkSourceAndBackupLeaks(body) {
    const leakPaths = [
      { path: '/.git/HEAD', check: (c) => c.startsWith('ref: refs/') || c.includes('refs/heads/'), name: 'Exposed Git Repository (/.git/HEAD)', name_es: 'Repositorio Git Expuesto (/.git/HEAD)', sev: 'CRITICAL', desc_es: 'El directorio .git está expuesto públicamente. Permite reconstruir y descargar todo el código fuente del sitio.' },
      { path: '/.git/config', check: (c) => c.includes('[core]') || c.includes('[remote "origin"]'), name: 'Git Configuration (/.git/config)', name_es: 'Configuración de Git (/.git/config)', sev: 'CRITICAL', desc_es: 'El archivo de configuración de Git es accesible, exponiendo repositorios remotos y ramas privadas.' },
      { path: '/.env.backup', check: (c) => c.includes('DB_') || c.includes('APP_') || c.includes('SECRET'), name: 'Backup Environment File (/.env.backup)', name_es: 'Archivo .env de respaldo (/.env.backup)', sev: 'CRITICAL', desc_es: 'Copia de seguridad del archivo de variables de entorno expuesta con contraseñas de BD y claves maestras.' },
      { path: '/wp-config.php.bak', check: (c) => c.includes('DB_PASSWORD') || c.includes('DB_NAME'), name: 'WordPress Config Backup (/wp-config.php.bak)', name_es: 'Respaldo de wp-config.php (.bak)', sev: 'CRITICAL', desc_es: 'Respaldo de configuración de WordPress accesible con credenciales de base de datos.' },
      { path: '/database.sql', check: (c) => c.includes('CREATE TABLE') || c.includes('INSERT INTO'), name: 'Public Database Dump (/database.sql)', name_es: 'Volcado de Base de Datos Público (/database.sql)', sev: 'CRITICAL', desc_es: 'Volcado SQL de la base de datos descargable directamente sin autenticación.' },
      { path: '/backup.sql', check: (c) => c.includes('CREATE TABLE') || c.includes('INSERT INTO'), name: 'Public SQL Backup (/backup.sql)', name_es: 'Copia de Seguridad SQL Pública (/backup.sql)', sev: 'CRITICAL', desc_es: 'Archivo de backup SQL accesible en la raíz del servidor.' },
      { path: '/Dockerfile', check: (c) => c.includes('FROM ') || c.includes('RUN '), name: 'Exposed Dockerfile (/Dockerfile)', name_es: 'Dockerfile Expuesto (/Dockerfile)', sev: 'HIGH', desc_es: 'El Dockerfile está expuesto, revelando la imagen base, dependencias y comandos de construcción.' },
      { path: '/docker-compose.yml', check: (c) => c.includes('services:') || c.includes('version:'), name: 'Exposed docker-compose.yml', name_es: 'docker-compose.yml Expuesto', sev: 'HIGH', desc_es: 'Configuración de orquestación Docker expuesta con nombres de contenedores y puertos internos.' },
      { path: '/package.json', check: (c) => c.includes('"dependencies"') || c.includes('"scripts"'), name: 'Exposed package.json', name_es: 'package.json Expuesto', sev: 'LOW', desc_es: 'El archivo package.json revela versiones exactas de librerías y scripts internos del proyecto.' },
    ];

    const leaksFound = [];

    const leakPromises = leakPaths.map(async (item) => {
      try {
        const content = await this._fetchPath(item.path);
        if (content && item.check(content)) {
          leaksFound.push({
            path: item.path,
            name: item.name,
            name_es: item.name_es,
            severity: item.sev,
          });

          this.results.findings.push({
            id: `leak-${item.path.replace(/[^a-z0-9]/gi, '-')}`,
            title: `Source/Backup Leak: ${item.name}`,
            title_es: `Fuga de Código/Respaldo: ${item.name_es}`,
            severity: item.sev,
            description_en: `Sensitive source control or backup file is publicly accessible at ${item.path}. Attackers can extract application source code and credentials.`,
            description_es: item.desc_es,
            fix_en: `Block access to ${item.path} in your web server configuration (Nginx/Apache) or delete backup files from the web root.`,
            fix_es: `Bloquea el acceso a ${item.path} en tu servidor web (Nginx/Apache) o elimina los archivos de respaldo del directorio público.`,
            category: 'config',
          });
        }
      } catch {}
    });

    await Promise.all(leakPromises);

    // Also check for Source Maps (.js.map)
    const scriptSrcRegex = /<script[^>]*src=["']([^"']+\.js)["'][^>]*>/gi;
    let sMatch;
    const jsUrls = [];
    while ((sMatch = scriptSrcRegex.exec(body)) !== null) jsUrls.push(sMatch[1]);

    for (const jsUrl of jsUrls.slice(0, 3)) {
      try {
        const mapUrl = jsUrl + '.map';
        const parsedMap = new URL(mapUrl, this.targetUrl);
        if (parsedMap.hostname === this.parsedUrl.hostname) {
          const mapContent = await this._fetchPath(parsedMap.pathname);
          if (mapContent && mapContent.includes('"sources":') && mapContent.includes('"version":')) {
            leaksFound.push({
              path: parsedMap.pathname,
              name: `Public Source Map (${parsedMap.pathname})`,
              name_es: `Source Map Público (${parsedMap.pathname})`,
              severity: 'MEDIUM',
            });

            this.results.findings.push({
              id: 'source-map-exposed',
              title: `Source Map Exposed: ${parsedMap.pathname}`,
              title_es: `Source Map Expuesto: ${parsedMap.pathname}`,
              severity: 'MEDIUM',
              description_en: 'JavaScript Source Map (.js.map) is publicly downloadable, exposing original unminified TypeScript/JavaScript source code and internal file paths.',
              description_es: 'El mapa de código fuente (.js.map) es público, permitiendo a cualquier persona ver el código fuente original sin minificar con nombres de variables y rutas.',
              fix_en: 'Disable source maps generation in production builds or configure web server to deny access to .map files.',
              fix_es: 'Desactiva la generación de source maps en producción o bloquea el acceso a archivos .map en el servidor.',
              category: 'config',
            });
            break;
          }
        }
      } catch {}
    }

    this.results.sourceLeaks = leaksFound;
  }

  /**
   * Step 27: Deep TLS Cryptographic & Cipher Suite Audit
   */
  async _deepTLSAudit() {
    if (this.parsedUrl.protocol !== 'https:') {
      this.results.deepTLS = { isHttps: false };
      return;
    }

    try {
      const port = this.parsedUrl.port || 443;
      const host = this.parsedUrl.hostname;

      const tlsDetails = await new Promise((resolve) => {
        const socket = tls.connect({
          host,
          port,
          servername: host,
          rejectUnauthorized: false,
          timeout: 4000,
        }, () => {
          const cipher = socket.getCipher();
          const protocol = socket.getProtocol();
          const cert = socket.getPeerCertificate(true);
          const alpn = socket.alpnProtocol;

          socket.end();

          resolve({
            protocol,
            cipherName: cipher ? cipher.name : 'Unknown',
            cipherStandardName: cipher ? cipher.standardName : null,
            cipherVersion: cipher ? cipher.version : null,
            alpnProtocol: alpn || 'http/1.1',
            keyBits: cert && cert.bits ? cert.bits : null,
            sigAlg: cert ? cert.sigalg : null,
            sctSupported: cert && cert.raw && cert.raw.length > 0,
          });
        });

        socket.on('error', () => resolve(null));
        socket.on('timeout', () => { socket.destroy(); resolve(null); });
      });

      if (!tlsDetails) {
        this.results.deepTLS = { tested: false };
        return;
      }

      const isLegacyProtocol = ['TLSv1', 'TLSv1.1'].includes(tlsDetails.protocol);
      const isWeakCipher = tlsDetails.cipherName && (
        tlsDetails.cipherName.includes('CBC') ||
        tlsDetails.cipherName.includes('RC4') ||
        tlsDetails.cipherName.includes('3DES') ||
        tlsDetails.cipherName.includes('NULL')
      );

      this.results.deepTLS = {
        tested: true,
        ...tlsDetails,
        isLegacyProtocol,
        isWeakCipher,
        grade: (isLegacyProtocol || isWeakCipher) ? 'WEAK' : 'STRONG',
      };

      if (isLegacyProtocol) {
        this.results.findings.push({
          id: 'deprecated-tls-protocol',
          title: `Deprecated TLS protocol in use (${tlsDetails.protocol})`,
          title_es: `Protocolo TLS obsoleto en uso (${tlsDetails.protocol})`,
          severity: 'HIGH',
          description_en: `Server negotiates ${tlsDetails.protocol}, which is deprecated and contains known cryptographic weaknesses (POODLE, BEAST).`,
          description_es: `El servidor negocia ${tlsDetails.protocol}, protocolo deprecado con debilidades criptográficas documentadas.`,
          fix_en: 'Configure web server to only support TLSv1.2 and TLSv1.3.',
          fix_es: 'Configura el servidor web para soportar únicamente TLSv1.2 y TLSv1.3.',
          category: 'tls',
        });
      }

      if (isWeakCipher) {
        this.results.findings.push({
          id: 'weak-cipher-suite',
          title: `Weak cipher suite negotiated: ${tlsDetails.cipherName}`,
          title_es: `Suite de cifrado débil negociada: ${tlsDetails.cipherName}`,
          severity: 'MEDIUM',
          description_en: `The negotiated cipher suite (${tlsDetails.cipherName}) uses legacy CBC mode or weak ciphers susceptible to padding oracle attacks.`,
          description_es: `La suite de cifrado negociada (${tlsDetails.cipherName}) usa modo CBC o cifradores antiguos vulnerables a ataques de padding oracle.`,
          fix_en: 'Enable modern AEAD ciphers (AES-GCM, CHACHA20-POLY1305) in TLS configuration.',
          fix_es: 'Habilita cifrados modernos AEAD (AES-GCM, CHACHA20-POLY1305) en la configuración TLS.',
          category: 'tls',
        });
      }
    } catch {
      this.results.deepTLS = { tested: false };
    }
  }

  /**
   * Step 28: Active Clickjacking & Frame Defense Analysis
   */
  _analyzeClickjacking(headers) {
    const xfo = (headers['x-frame-options'] || '').toUpperCase().trim();
    const csp = (headers['content-security-policy'] || '').toLowerCase();

    let frameAncestors = null;
    const faMatch = csp.match(/frame-ancestors\s+([^;]+)/i);
    if (faMatch) {
      frameAncestors = faMatch[1].trim();
    }

    let status = 'VULNERABLE';
    let status_es = 'Vulnerable';
    let canBeFramed = true;
    let detail_en = 'The page can be embedded inside third-party iframes, enabling UI redressing and Clickjacking attacks.';
    let detail_es = 'La página puede ser incrustada en iframes de terceros, permitiendo ataques de secuestro de clics (Clickjacking).';

    if (frameAncestors === "'none'" || xfo === 'DENY') {
      status = 'PROTECTED';
      status_es = 'Completamente Protegida';
      canBeFramed = false;
      detail_en = 'Framing is completely denied across all domains via X-Frame-Options: DENY or frame-ancestors: \'none\'.';
      detail_es = 'La incrustación está completamente bloqueada en todos los dominios mediante X-Frame-Options: DENY o frame-ancestors: \'none\'.';
    } else if (frameAncestors === "'self'" || xfo === 'SAMEORIGIN') {
      status = 'PROTECTED_SAMEORIGIN';
      status_es = 'Protegida (Mismo Origen)';
      canBeFramed = false;
      detail_en = 'Only the same origin is permitted to embed this page. Third-party framing is blocked.';
      detail_es = 'Solo el mismo origen puede incrustar la página. La incrustación de terceros está bloqueada.';
    } else if (frameAncestors) {
      status = 'CUSTOM_ALLOWLIST';
      status_es = 'Lista Blanca Personalizada';
      canBeFramed = false;
      detail_en = `Framing restricted to authorized origins: ${frameAncestors}`;
      detail_es = `Incrustación restringida a orígenes autorizados: ${frameAncestors}`;
    }

    this.results.clickjacking = {
      status,
      status_es,
      canBeFramed,
      xfo: xfo || null,
      frameAncestors: frameAncestors || null,
      detail_en,
      detail_es,
    };
  }

  /**
   * Step 29: Payment Security & Data Exfiltration / Skimming Analysis
   */
  _analyzePaymentAndExfiltration(body, headers) {
    const cardInputRegex = /<(?:input|select)[^>]*(?:name|id|placeholder|autocomplete)=["']([^"']*(?:card|cc-num|cardnumber|cvv|cvc|exp-date|tarjeta|caducidad|titular)[^"']*)["'][^>]*>/gi;
    const personalDataRegex = /<(?:input|select)[^>]*(?:name|id|placeholder|autocomplete)=["']([^"']*(?:ssn|dni|cedula|curp|passport|pasaporte|rut|account_number|cuenta_bancaria)[^"']*)["'][^>]*>/gi;

    let hasCardInputs = false;
    let hasPersonalInputs = false;
    const inputMatches = [];

    let m;
    while ((m = cardInputRegex.exec(body)) !== null) {
      hasCardInputs = true;
      inputMatches.push(m[1]);
    }
    while ((m = personalDataRegex.exec(body)) !== null) {
      hasPersonalInputs = true;
      inputMatches.push(m[1]);
    }

    // Check form submission endpoints for external exfiltration
    const formRegex = /<form[^>]*action=["']([^"']*)["'][^>]*>/gi;
    let fMatch;
    const exfiltrationTargets = [];
    const currentHost = this.parsedUrl.hostname;

    while ((fMatch = formRegex.exec(body)) !== null) {
      const actionUrl = fMatch[1].trim();
      if (!actionUrl || actionUrl.startsWith('#') || actionUrl.startsWith('javascript:')) continue;

      try {
        const parsedAction = new URL(actionUrl, this.targetUrl);
        if (parsedAction.hostname && parsedAction.hostname !== currentHost && !parsedAction.hostname.endsWith('.' + currentHost)) {
          exfiltrationTargets.push({
            action: actionUrl,
            targetHost: parsedAction.hostname,
            isInsecureHttp: parsedAction.protocol === 'http:',
          });
        }
      } catch {}
    }

    // Check for Magecart skimming signatures in inline JS
    const skimmingSignatures = [
      /addEventListener\s*\(\s*["'](?:keypress|keydown|keyup|input)["']\s*,\s*function[^{]*\{[^}]*(?:btoa|fromCharCode|sendBeacon|fetch|XMLHttpRequest)[^}]*\.php/gi,
      /(?:document|window)\.location\s*=\s*["']https?:\/\/[^"']*\?[^"']*(?:card|cc|cvv|pass|pwd)=/gi,
      /eval\s*\(\s*atob\s*\([^)]*\)\s*\)/gi,
    ];

    let skimmingDetected = false;
    for (const sig of skimmingSignatures) {
      if (sig.test(body)) {
        skimmingDetected = true;
        break;
      }
    }

    const isExfiltrationRisk = exfiltrationTargets.length > 0 && (hasCardInputs || hasPersonalInputs);

    this.results.paymentSecurity = {
      hasCardInputs,
      hasPersonalInputs,
      exfiltrationTargets,
      skimmingDetected,
      status: (isExfiltrationRisk || skimmingDetected) ? 'CRITICAL' : hasCardInputs ? 'SENSITIVE_FORM' : 'SAFE',
    };

    if (isExfiltrationRisk) {
      this.results.findings.push({
        id: 'data-exfiltration-external-domain',
        title: 'CRITICAL: Personal/Payment Data Form Submits to External Domain',
        title_es: 'CRÍTICO: Formulario con Datos Personales/Bancarios Envía Información a un Dominio Externo',
        severity: 'CRITICAL',
        description_en: `Sensitive form fields (cards/passwords/identity) submit directly to a foreign external domain (${exfiltrationTargets.map(e => e.targetHost).join(', ')}). This is a hallmark indicator of Magecart skimming, phishing, or unauthorized data harvesting.`,
        description_es: `Formularios con datos sensibles (tarjetas/identidad/contraseñas) envían los datos directamente a un dominio externo (${exfiltrationTargets.map(e => e.targetHost).join(', ')}). Este es un indicador crítico de robo de datos, phishing o skimming tipo Magecart.`,
        fix_en: 'Ensure all forms submit exclusively to your authorized backend endpoints over HTTPS.',
        fix_es: 'Asegúrate de que todos los formularios procesen la información exclusivamente en tus propios servidores seguros bajo HTTPS.',
        category: 'forms',
      });
    }

    if (skimmingDetected) {
      this.results.findings.push({
        id: 'magecart-skimming-pattern',
        title: 'Magecart / Keylogger Skimming Pattern Detected in Client Code',
        title_es: 'Patrón de Keylogger / Skimming Magecart Detectado en el Código Cliente',
        severity: 'CRITICAL',
        description_en: 'Detected client-side JavaScript listening on input keystrokes and exfiltrating encoded data to external endpoints.',
        description_es: 'Se detectó JavaScript en el cliente capturando pulsaciones de teclado en inputs y exfiltrando datos codificados hacia el exterior.',
        fix_en: 'Audit all third-party scripts and remove unauthorized or obfuscated JavaScript trackers.',
        fix_es: 'Audita los scripts de terceros y elimina cualquier código JavaScript ofuscado o no autorizado.',
        category: 'js-security',
      });
    }
  }

  /**
   * Step 30: Exposed Admin Panels & API Documentation surface
   */
  async _checkAdminAndApiSurface() {
    const adminEndpoints = [
      { path: '/admin', name: 'Admin Panel (/admin)', type: 'Admin' },
      { path: '/administrator', name: 'Joomla/Custom Admin (/administrator)', type: 'Admin' },
      { path: '/wp-login.php', name: 'WordPress Login (/wp-login.php)', type: 'Auth' },
      { path: '/phpmyadmin/', name: 'phpMyAdmin Database Manager', type: 'Database' },
      { path: '/swagger-ui.html', name: 'Swagger UI API Documentation', type: 'API Docs' },
      { path: '/api-docs', name: 'REST API Docs (/api-docs)', type: 'API Docs' },
      { path: '/openapi.json', name: 'OpenAPI Specification (/openapi.json)', type: 'API Docs' },
      { path: '/graphql', name: 'GraphQL Endpoint (/graphql)', type: 'API' },
      { path: '/actuator/health', name: 'Spring Boot Actuator Health', type: 'Monitoring' },
    ];

    const exposed = [];

    const checks = adminEndpoints.map(async (ep) => {
      try {
        const content = await this._fetchPath(ep.path);
        if (content && content.length > 50) {
          const lower = content.toLowerCase();
          const isRealHit = (
            lower.includes('login') ||
            lower.includes('password') ||
            lower.includes('swagger') ||
            lower.includes('graphql') ||
            lower.includes('phpmyadmin') ||
            lower.includes('"status":"up"') ||
            lower.includes('openapi')
          );

          if (isRealHit) {
            exposed.push({
              path: ep.path,
              name: ep.name,
              type: ep.type,
            });

            this.results.findings.push({
              id: `exposed-${ep.path.replace(/[^a-z0-9]/gi, '-')}`,
              title: `Exposed Administrative / API Surface: ${ep.name}`,
              title_es: `Superficie de Administración / API Expuesta: ${ep.name}`,
              severity: ep.type === 'Database' || ep.type === 'API Docs' ? 'MEDIUM' : 'LOW',
              description_en: `Administrative interface or API documentation is publicly reachable at ${ep.path}. Attackers can brute-force credentials or map private endpoints.`,
              description_es: `Interfaz administrativa o documentación de APIs accesible públicamente en ${ep.path}. Permite a atacantes intentar ataques de fuerza bruta o mapear endpoints privados.`,
              fix_en: 'Restrict admin and API documentation panels behind VPN, IP allowlist, or strong MFA.',
              fix_es: 'Restringe el acceso a paneles y documentación de APIs detrás de una VPN, lista blanca de IPs o MFA.',
              category: 'config',
            });
          }
        }
      } catch {}
    });

    await Promise.all(checks);
    this.results.adminSurface = exposed;
  }

  /**
   * Step 31: Webshells & Backdoor Malware Check
   */
  async _checkWebshellsAndMalware() {
    const webshellPaths = [
      { path: '/wso.php', sig: 'WSO ' },
      { path: '/c99.php', sig: 'c99shell' },
      { path: '/r57.php', sig: 'r57shell' },
      { path: '/shell.php', sig: 'name="cmd"' },
      { path: '/alfa.php', sig: 'Alfa Team' },
      { path: '/uploader.php', sig: 'type="file"' },
    ];

    const detectedThreats = [];

    const checks = webshellPaths.map(async (ws) => {
      try {
        const content = await this._fetchPath(ws.path);
        if (content && content.includes(ws.sig)) {
          detectedThreats.push({
            path: ws.path,
            signature: ws.sig,
          });

          this.results.findings.push({
            id: `webshell-${ws.path.replace(/[^a-z0-9]/gi, '-')}`,
            title: `CRITICAL MALWARE: Webshell Detected at ${ws.path}`,
            title_es: `MALWARE CRÍTICO: Webshell / Puerta Trasera Detectada en ${ws.path}`,
            severity: 'CRITICAL',
            description_en: `Active webshell or backdoor interface identified at ${ws.path}. The server is compromised and under unauthorized control.`,
            description_es: `Se identificó una webshell o puerta trasera activa en ${ws.path}. El servidor ha sido comprometido y puede ser controlado remotamente.`,
            fix_en: 'Isolate the server immediately, purge malicious files, and conduct a full forensic incident response.',
            fix_es: 'Aísla el servidor de inmediato, elimina los archivos maliciosos y realiza un análisis forense de intrusión.',
            category: 'config',
          });
        }
      } catch {}
    });

    await Promise.all(checks);
    this.results.malwareThreats = detectedThreats;
  }

  /**
   * Step 32: Phishing, Scam & Malicious Intent Analysis
   */
  _analyzePhishingAndScam(body, headers) {
    const lowerBody = body.toLowerCase();
    const domain = this.parsedUrl.hostname.toLowerCase();

    const reasons = [];
    let scamScore = 0;

    // 1. Lookalike brand impersonation
    const brandPatterns = [
      { name: 'PayPal', match: /paypal\s*(?:login|iniciar sesión|verify|cuenta)/i, legit: /paypal\.com$/ },
      { name: 'Netflix', match: /netflix\s*(?:reactivaci[oó]n|actualizar pago|suspensi[oó]n|login)/i, legit: /netflix\.com$/ },
      { name: 'Apple / iCloud', match: /(?:apple\s*id|icloud)\s*(?:bloqueado|login|verify)/i, legit: /apple\.com$/ },
      { name: 'WhatsApp', match: /whatsapp\s*(?:web|c[oó]digo|activaci[oó]n)/i, legit: /(?:whatsapp\.com|wa\.me)$/ },
      { name: 'Banco / Entidad Financiera', match: /(?:banco|bancolombia|santander|bbva|bcp|interbank)\s*(?:en l[ií]nea|ingreso|clave din[aá]mica|token)/i, legit: /(?:bancolombia\.com|santander\.|bbva\.|viabcp\.com|interbank\.pe)$/ },
      { name: 'Meta / Facebook', match: /(?:meta|facebook|instagram)\s*(?:copyright|infringement|security center|verificaci[oó]n)/i, legit: /(?:facebook\.com|instagram\.com|meta\.com)$/ },
    ];

    for (const b of brandPatterns) {
      if (b.match.test(lowerBody) && !b.legit.test(domain)) {
        reasons.push(`Usa logotipos/textos alusivos a ${b.name}, pero el dominio (${domain}) no pertenece a la entidad legítima.`);
        scamScore += 45;
      }
    }

    // 2. Urgent scam psychological triggers
    const urgencyPatterns = [
      { pattern: /(?:cuenta|tarjeta|servicio)\s*(?:ser[aá]\s*suspendid[ao]|bloquead[ao]|cancelad[ao])\s*en\s*\d+\s*(?:horas|minutos)/i, text: 'Uso de tácticas de miedo y urgencia ("Su cuenta será bloqueada en X horas")' },
      { pattern: /(?:ganador|felicidades|premio|ha sido seleccionado|sorteo)\s*(?:reclamar|obtener|gratis)/i, text: 'Promesa de premios falsos o dinero no solicitado' },
      { pattern: /(?:inicie sesi[oó]n|verifique su identidad)\s*para\s*evitar\s*(?:multas|cargos|suspensi[oó]n)/i, text: 'Presión coercitiva para forzar el ingreso de credenciales' },
    ];

    for (const u of urgencyPatterns) {
      if (u.pattern.test(lowerBody)) {
        reasons.push(u.text);
        scamScore += 25;
      }
    }

    // 3. Hidden credential harvesting fields
    if (/<input[^>]*style=["'][^"']*(?:opacity:\s*0|display:\s*none|visibility:\s*hidden)[^"']*(?:password|token|pin|card)[^>]*>/i.test(body)) {
      reasons.push('Campos de captura de contraseñas o PIN ocultos de forma maliciosa en el HTML.');
      scamScore += 35;
    }

    // 4. External Data Exfiltration already detected
    if (this.results.paymentSecurity && this.results.paymentSecurity.exfiltrationTargets.length > 0) {
      reasons.push(`Exfiltración activa: el formulario envía datos personales a ${this.results.paymentSecurity.exfiltrationTargets.map(e => e.targetHost).join(', ')}.`);
      scamScore += 50;
    }

    const isSuspicious = scamScore >= 40;

    this.results.phishingScamAnalysis = {
      isSuspicious,
      scamScore: Math.min(100, scamScore),
      riskLevel: scamScore >= 70 ? 'CRITICAL' : scamScore >= 40 ? 'HIGH' : 'LOW',
      reasons,
    };

    if (isSuspicious) {
      this.results.findings.push({
        id: 'phishing-scam-indicators-detected',
        title: 'HIGH MALICIOUS RISK: Phishing, Scam or Data Harvesting Indicators Detected',
        title_es: 'ALTO RIESGO DE FRAUDE: Indicadores de Phishing, Estafa o Robo de Información Detectados',
        severity: scamScore >= 70 ? 'CRITICAL' : 'HIGH',
        description_en: `This website exhibits characteristics typical of fraudulent sites or phishing kits: ${reasons.join('; ')}`,
        description_es: `Este sitio web presenta características típicas de páginas de phishing o estafas: ${reasons.join('; ')}`,
        fix_en: 'If this is your site, remove unauthorized lookalike assets and ensure forms submit to valid internal endpoints.',
        fix_es: 'Si eres el administrador, retira activos o textos que imiten a terceros y valida que los formularios no envíen datos al exterior.',
        category: 'forms',
      });
    }
  }

  /**
   * Calculate the overall security score (0-100) using a balanced, industry-standard model.
   * Categorizes risks with maximum deduction caps per category so minor issues don't cascade to 0.
   */
  _calculateScore() {
    let score = 100;

    // Category deduction trackers
    const categoryDeductions = {
      'tls': 0,          // Max -30
      'vulnerability': 0,// Max -35
      'config': 0,       // Max -30 (exposed .env, .git)
      'headers': 0,      // Max -20
      'csp': 0,          // Max -15
      'cookies': 0,      // Max -15
      'dns': 0,          // Max -10
      'forms': 0,        // Max -10
      'js-security': 0,  // Max -10
      'mixed-content': 0,// Max -10
      'open-redirect': 0,// Max -10
      'directory-listing': 0, // Max -10
      'error-pages': 0,  // Max -5
      'sri': 0,          // Max -5
      'robots': 0,       // Max -3
      'performance': 0,  // Max -3
      'info-exposure': 0,// Max -3
      'other': 0,
    };

    const categoryCaps = {
      'tls': 30,
      'vulnerability': 35,
      'config': 30,
      'headers': 20,
      'csp': 15,
      'cookies': 15,
      'dns': 10,
      'forms': 10,
      'js-security': 10,
      'mixed-content': 10,
      'open-redirect': 10,
      'directory-listing': 10,
      'error-pages': 5,
      'sri': 5,
      'robots': 3,
      'performance': 3,
      'info-exposure': 3,
      'other': 10,
    };

    const severityPoints = {
      'CRITICAL': 18,
      'HIGH': 8,
      'MEDIUM': 4,
      'LOW': 1.5,
      'INFO': 0,
    };

    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };

    this.results.findings.forEach(finding => {
      const sev = finding.severity || 'INFO';
      if (counts[sev] !== undefined) counts[sev]++;

      const cat = finding.category || 'other';
      const points = severityPoints[sev] || 0;

      if (categoryDeductions[cat] !== undefined) {
        categoryDeductions[cat] += points;
      } else {
        categoryDeductions['other'] += points;
      }
    });

    // Apply capped category deductions
    for (const [cat, totalDeduction] of Object.entries(categoryDeductions)) {
      const cap = categoryCaps[cat] || 15;
      const effectiveDeduction = Math.min(totalDeduction, cap);
      score -= effectiveDeduction;
    }

    // Bonuses for positive security signals (up to +10 pts)
    if (this.results.waf && this.results.waf.length > 0) {
      score += 4; // WAF/CDN in place
    }
    if (this.results.tls && this.results.tls.valid) {
      score += 2; // Valid TLS
    }
    if (this.results.dns && this.results.dns.hasSPF && this.results.dns.hasDMARC) {
      score += 3; // Comprehensive email authentication
    }

    // Clamp score to 0-100 and round
    score = Math.round(Math.max(5, Math.min(100, score)));

    this.results.score = score;
    this.results.summary = {
      total: this.results.findings.length,
      critical: counts.CRITICAL,
      high: counts.HIGH,
      medium: counts.MEDIUM,
      low: counts.LOW,
      info: counts.INFO,
    };

    // Assign realistic rating
    if (score >= 90) this.results.rating = 'A';
    else if (score >= 78) this.results.rating = 'B';
    else if (score >= 65) this.results.rating = 'C';
    else if (score >= 50) this.results.rating = 'D';
    else this.results.rating = 'F';
  }
}

module.exports = { SecurityScanner };


