
// static/js/viewport-manager.js
class ViewportManager {
  constructor() {
    this.setViewportScale();
    window.addEventListener('resize', this.debounce(this.setViewportScale));
  }

  setViewportScale() {
    const viewportWidth = window.innerWidth;
    let scaleValue = 1;
    
    if (viewportWidth > 1920) scaleValue = 0.9;
    if (viewportWidth > 1440) scaleValue = 0.95;
    if (viewportWidth < 768) scaleValue = 1;
    
    document.documentElement.style.setProperty('--viewport-scale', scaleValue);
  }

  debounce(func, timeout = 100) {
    let timer;
    return (...args) => {
      clearTimeout(timer);
      timer = setTimeout(() => func.apply(this, args), timeout);
    };
  }
}

new ViewportManager();
