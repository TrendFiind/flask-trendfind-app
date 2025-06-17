// static/js/responsive.js
function updateScaling() {
  const scaleFactor = window.innerWidth < 768 ? 0.95 : 1.25;
  document.documentElement.style.setProperty('--scale-factor', scaleFactor);
}

window.addEventListener('resize', updateScaling);
updateScaling();
