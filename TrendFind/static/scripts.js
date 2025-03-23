// Dark Mode Toggle
document.getElementById('dark-mode-toggle').addEventListener('click', function() {
    document.body.classList.toggle('dark-mode');
    const icon = this.querySelector('i');
    if (document.body.classList.contains('dark-mode')) {
        icon.classList.remove('fa-moon');
        icon.classList.add('fa-sun');
        localStorage.setItem('darkMode', 'enabled'); // Save preference
    } else {
        icon.classList.remove('fa-sun');
        icon.classList.add('fa-moon');
        localStorage.setItem('darkMode', 'disabled'); // Save preference
    }
});

// Check for saved dark mode preference on page load
document.addEventListener('DOMContentLoaded', function() {
    const darkModeToggle = document.getElementById('dark-mode-toggle');
    const icon = darkModeToggle.querySelector('i');
    const darkMode = localStorage.getItem('darkMode');

    if (darkMode === 'enabled') {
        document.body.classList.add('dark-mode');
        icon.classList.remove('fa-moon');
        icon.classList.add('fa-sun');
    } else {
        document.body.classList.remove('dark-mode');
        icon.classList.remove('fa-sun');
        icon.classList.add('fa-moon');
    }
});

// Function to check if an element is in the viewport
function isInViewport(element) {
    const rect = element.getBoundingClientRect();
    return (
        rect.top >= 0 &&
        rect.left >= 0 &&
        rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
        rect.right <= (window.innerWidth || document.documentElement.clientWidth)
    );
}

// Function to handle scroll events
function handleScroll() {
    const futuristicBox = document.querySelector('.futuristic-box');
    if (isInViewport(futuristicBox)) {
        futuristicBox.classList.add('visible');
    }
}

// Add scroll event listener
window.addEventListener('scroll', handleScroll);

// Trigger the animation on page load if the box is already in view
document.addEventListener('DOMContentLoaded', handleScroll);
