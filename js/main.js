/**
 * Canary — Main Application Logic
 * Handles: navbar, scroll reveals, particle canvas, mobile menu, score animation.
 */

import { initI18n } from './i18n.js';
import { initScannerUI } from './scanner-ui.js';

/* ===========================
   NAVBAR SCROLL EFFECT
   =========================== */
function initNavbar() {
  const navbar = document.getElementById('navbar');
  if (!navbar) return;

  const onScroll = () => {
    navbar.classList.toggle('scrolled', window.scrollY > 40);
  };
  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();

  // Smooth scroll for nav links
  document.querySelectorAll('a[href^="#"]').forEach(link => {
    link.addEventListener('click', (e) => {
      const target = document.querySelector(link.getAttribute('href'));
      if (target) {
        e.preventDefault();
        target.scrollIntoView({ behavior: 'smooth' });
        // Close mobile menu if open
        closeMobileMenu();
      }
    });
  });
}

/* ===========================
   MOBILE MENU
   =========================== */
function initMobileMenu() {
  const toggle = document.getElementById('nav-toggle');
  const menu = document.getElementById('mobile-menu');
  if (!toggle || !menu) return;

  toggle.addEventListener('click', () => {
    const isOpen = menu.classList.toggle('open');
    toggle.classList.toggle('active', isOpen);
    document.body.style.overflow = isOpen ? 'hidden' : '';
  });
}

function closeMobileMenu() {
  const toggle = document.getElementById('nav-toggle');
  const menu = document.getElementById('mobile-menu');
  if (toggle && menu) {
    menu.classList.remove('open');
    toggle.classList.remove('active');
    document.body.style.overflow = '';
  }
}

/* ===========================
   SCROLL REVEAL ANIMATIONS
   =========================== */
function initScrollReveal() {
  const reveals = document.querySelectorAll('.reveal');
  if (!reveals.length) return;

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
        observer.unobserve(entry.target);
      }
    });
  }, {
    threshold: 0.1,
    rootMargin: '0px 0px -60px 0px'
  });

  reveals.forEach(el => observer.observe(el));
}

/* ===========================
   SCORE CIRCLE ANIMATION
   =========================== */
function initScoreAnimation() {
  const circle = document.querySelector('.score-circle');
  if (!circle) return;

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        circle.classList.add('animated');
        animateCounter();
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.5 });

  observer.observe(circle);
}

function animateCounter() {
  const el = document.getElementById('score-number');
  if (!el) return;

  const target = 63;
  const duration = 1500;
  const start = performance.now();

  function update(now) {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
    el.textContent = Math.round(eased * target);

    if (progress < 1) {
      requestAnimationFrame(update);
    }
  }

  requestAnimationFrame(update);
}

/* ===========================
   HERO PARTICLE NETWORK CANVAS
   =========================== */
function initParticleCanvas() {
  const canvas = document.getElementById('hero-canvas');
  if (!canvas) return;

  const ctx = canvas.getContext('2d');
  let width, height, particles, animationId;
  let mouse = { x: null, y: null };

  const PARTICLE_COUNT = 80;
  const MAX_DIST = 150;
  const PARTICLE_COLOR = 'rgba(245, 197, 66, ';
  const LINE_COLOR = 'rgba(245, 197, 66, ';

  function resize() {
    width = canvas.width = canvas.offsetWidth;
    height = canvas.height = canvas.offsetHeight;
  }

  function createParticles() {
    particles = [];
    for (let i = 0; i < PARTICLE_COUNT; i++) {
      particles.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.5,
        vy: (Math.random() - 0.5) * 0.5,
        size: Math.random() * 2 + 1,
        opacity: Math.random() * 0.5 + 0.2,
      });
    }
  }

  function draw() {
    ctx.clearRect(0, 0, width, height);

    // Draw connections
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < MAX_DIST) {
          const opacity = (1 - dist / MAX_DIST) * 0.15;
          ctx.beginPath();
          ctx.strokeStyle = LINE_COLOR + opacity + ')';
          ctx.lineWidth = 0.5;
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.stroke();
        }
      }
    }

    // Draw particles
    particles.forEach(p => {
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
      ctx.fillStyle = PARTICLE_COLOR + p.opacity + ')';
      ctx.fill();
    });
  }

  function update() {
    particles.forEach(p => {
      p.x += p.vx;
      p.y += p.vy;

      // Bounce off edges
      if (p.x < 0 || p.x > width) p.vx *= -1;
      if (p.y < 0 || p.y > height) p.vy *= -1;

      // Mouse interaction (gentle repulsion)
      if (mouse.x !== null) {
        const dx = p.x - mouse.x;
        const dy = p.y - mouse.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 120) {
          p.vx += dx * 0.0005;
          p.vy += dy * 0.0005;
        }
      }

      // Speed limit
      const speed = Math.sqrt(p.vx * p.vx + p.vy * p.vy);
      if (speed > 1) {
        p.vx *= 0.98;
        p.vy *= 0.98;
      }
    });
  }

  function animate() {
    update();
    draw();
    animationId = requestAnimationFrame(animate);
  }

  // Events
  window.addEventListener('resize', () => {
    resize();
    createParticles();
  });

  canvas.addEventListener('mousemove', (e) => {
    const rect = canvas.getBoundingClientRect();
    mouse.x = e.clientX - rect.left;
    mouse.y = e.clientY - rect.top;
  });

  canvas.addEventListener('mouseleave', () => {
    mouse.x = null;
    mouse.y = null;
  });

  // Reduce particles on mobile
  if (window.innerWidth < 768) {
    // Use fewer particles on mobile for performance
    const original = PARTICLE_COUNT;
    // We can't reassign const, but we slice after creation
  }

  resize();
  createParticles();

  // On mobile, reduce particle count
  if (window.innerWidth < 768) {
    particles = particles.slice(0, 35);
  }

  animate();
}

/* ===========================
   STAT COUNTER ANIMATION
   =========================== */
function initStatCounters() {
  const stats = document.querySelectorAll('.problem-stat');
  if (!stats.length) return;

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const el = entry.target;
        const target = parseInt(el.textContent);
        if (!isNaN(target)) {
          animateStat(el, target);
        }
        observer.unobserve(el);
      }
    });
  }, { threshold: 0.5 });

  stats.forEach(el => observer.observe(el));
}

function animateStat(el, target) {
  const duration = 1200;
  const start = performance.now();

  function update(now) {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(eased * target) + '%';

    if (progress < 1) {
      requestAnimationFrame(update);
    }
  }

  el.textContent = '0%';
  requestAnimationFrame(update);
}

/* ===========================
   INIT
   =========================== */
document.addEventListener('DOMContentLoaded', async () => {
  // Initialize i18n first (loads translations and applies text)
  await initI18n();

  // Then init all interactive features
  initNavbar();
  initMobileMenu();
  initScrollReveal();
  initParticleCanvas();
  initScoreAnimation();
  initStatCounters();
  initScannerUI();
});
