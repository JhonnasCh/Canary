/**
 * Canary — Internationalization (i18n) Module
 * Detects browser language, loads translations, and swaps text dynamically.
 */

const SUPPORTED_LANGS = ['es', 'en'];
const DEFAULT_LANG = 'en';
const STORAGE_KEY = 'canary-lang';

let currentLang = DEFAULT_LANG;
let translations = {};

/**
 * Detect the preferred language.
 * Priority: localStorage > navigator.language > default
 */
function detectLanguage() {
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored && SUPPORTED_LANGS.includes(stored)) {
    return stored;
  }

  const browserLang = navigator.language || navigator.userLanguage || '';
  if (browserLang.startsWith('es')) {
    return 'es';
  }

  return DEFAULT_LANG;
}

/**
 * Load translation JSON file for a given language.
 */
async function loadTranslations(lang) {
  try {
    const response = await fetch(`/lang/${lang}.json`);
    if (!response.ok) throw new Error(`Failed to load ${lang}.json`);
    return await response.json();
  } catch (err) {
    console.error(`[i18n] Error loading translations for "${lang}":`, err);
    return {};
  }
}

/**
 * Resolve a dot-notation key from a nested object.
 * e.g., resolve("nav.features", { nav: { features: "Features" } }) → "Features"
 */
function resolve(key, obj) {
  return key.split('.').reduce((acc, part) => acc && acc[part], obj);
}

/**
 * Apply translations to all elements with [data-i18n] attribute.
 */
function applyTranslations() {
  const elements = document.querySelectorAll('[data-i18n]');
  elements.forEach(el => {
    const key = el.getAttribute('data-i18n');
    const value = resolve(key, translations);
    if (value !== undefined && value !== null) {
      // Check if it's a placeholder attribute
      if (el.hasAttribute('data-i18n-attr')) {
        const attr = el.getAttribute('data-i18n-attr');
        el.setAttribute(attr, value);
      } else {
        el.textContent = value;
      }
    }
  });

  // Update html lang attribute
  document.documentElement.lang = currentLang;

  // Update active state on language buttons
  document.querySelectorAll('.lang-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.lang === currentLang);
  });
}

/**
 * Switch to a new language.
 */
async function switchLanguage(lang) {
  if (!SUPPORTED_LANGS.includes(lang) || lang === currentLang) return;

  currentLang = lang;
  localStorage.setItem(STORAGE_KEY, lang);
  translations = await loadTranslations(lang);
  applyTranslations();
}

/**
 * Initialize the i18n system.
 */
async function initI18n() {
  currentLang = detectLanguage();
  translations = await loadTranslations(currentLang);
  applyTranslations();

  // Bind language switcher buttons
  document.querySelectorAll('.lang-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      switchLanguage(btn.dataset.lang);
    });
  });
}

// Export for use in main.js
export { initI18n, switchLanguage, currentLang };
