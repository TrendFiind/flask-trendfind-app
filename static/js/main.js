// ===== SIDEBAR FUNCTIONALITY =====
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const toggle = document.querySelector('.sidebar-toggle');

    if (!sidebar || !toggle) return;

    sidebar.classList.toggle('open');

    const spans = toggle.querySelectorAll('span');
    if (sidebar.classList.contains('open')) {
        spans[0].style.transform = 'rotate(45deg) translate(5px, 5px)';
        spans[1].style.opacity = '0';
        spans[2].style.transform = 'rotate(-45deg) translate(5px, -5px)';
    } else {
        spans[0].style.transform = '';
        spans[1].style.opacity = '';
        spans[2].style.transform = '';
    }
}

// Dark Mode Toggle
document.addEventListener('DOMContentLoaded', () => {
    const darkToggle = document.getElementById('dark-mode-toggle');
    if (darkToggle) {
        darkToggle.addEventListener('click', () => {
            document.body.classList.toggle('light-mode');
            const icon = darkToggle.querySelector('i');

            if (document.body.classList.contains('light-mode')) {
                icon.classList.replace('fa-moon', 'fa-sun');
                localStorage.setItem('darkMode', 'disabled');
            } else {
                icon.classList.replace('fa-sun', 'fa-moon');
                localStorage.setItem('darkMode', 'enabled');
            }
        });
    }

    // Restore dark mode preference
    if (localStorage.getItem('darkMode') === 'disabled') {
        document.body.classList.add('light-mode');
        const icon = darkToggle?.querySelector('i');
        icon?.classList.replace('fa-moon', 'fa-sun');
    }

    // Sidebar click binding (NO inline onclick needed)
    const sidebarBtn = document.querySelector('.sidebar-toggle');
    if (sidebarBtn) sidebarBtn.addEventListener('click', toggleSidebar);
});
