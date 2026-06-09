// Nav scroll behavior
const nav = document.getElementById('nav');
window.addEventListener('scroll', () => {
  nav.classList.toggle('scrolled', window.scrollY > 60);
}, { passive: true });

// Mobile burger
const burger = document.getElementById('burger');
const navLinks = document.getElementById('nav-links');

burger.addEventListener('click', () => {
  burger.classList.toggle('open');
  navLinks.classList.toggle('open');
});

document.querySelectorAll('[data-close]').forEach(link => {
  link.addEventListener('click', () => {
    burger.classList.remove('open');
    navLinks.classList.remove('open');
  });
});

// Reveal on scroll
const observer = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.classList.add('visible');
    }
  });
}, { threshold: 0.15 });

document.querySelectorAll('.reveal, .phrase-item').forEach(el => observer.observe(el));

// Form submit
function handleSubmit(e) {
  e.preventDefault();
  const form = document.getElementById('contact-form');
  const success = document.getElementById('form-success');
  form.style.display = 'none';
  success.style.display = 'block';
}

// Smooth parallax for hero orbs
let ticking = false;
window.addEventListener('scroll', () => {
  if (!ticking) {
    requestAnimationFrame(() => {
      const y = window.scrollY;
      const orb1 = document.querySelector('.orb1');
      const orb2 = document.querySelector('.orb2');
      if (orb1) orb1.style.transform = `translateY(${y * 0.15}px)`;
      if (orb2) orb2.style.transform = `translateY(${y * -0.1}px)`;
      ticking = false;
    });
    ticking = true;
  }
}, { passive: true });
