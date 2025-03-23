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

// Function to toggle the sidebar
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    sidebar.classList.toggle('open');
}

// Add event listener to the sidebar toggle button
document.querySelector('.sidebar-toggle').addEventListener('click', toggleSidebar);

// Optional: Close sidebar when clicking outside of it
document.addEventListener('click', function(event) {
    const sidebar = document.getElementById('sidebar');
    const toggleButton = document.querySelector('.sidebar-toggle');
    if (!sidebar.contains(event.target) && !toggleButton.contains(event.target)) {
        sidebar.classList.remove('open');
    }
});
