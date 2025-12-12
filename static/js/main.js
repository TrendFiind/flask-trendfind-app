    <!-- JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
// ===== SIDEBAR FUNCTIONALITY (Works Across All Pages) =====
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const toggle = document.querySelector('.sidebar-toggle');
    
    sidebar.classList.toggle('open');
    
    // Animate hamburger icon
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
document.getElementById('dark-mode-toggle').addEventListener('click', function() {
    document.body.classList.toggle('light-mode');
    const icon = this.querySelector('i');
    
    if (document.body.classList.contains('light-mode')) {
        icon.classList.remove('fa-moon');
        icon.classList.add('fa-sun');
        localStorage.setItem('darkMode', 'disabled');
    } else {
        icon.classList.remove('fa-sun');
        icon.classList.add('fa-moon');
        localStorage.setItem('darkMode', 'enabled');
    }
});

// Check for saved dark mode preference
document.addEventListener('DOMContentLoaded', function() {
    const darkModeToggle = document.getElementById('dark-mode-toggle');
    const icon = darkModeToggle.querySelector('i');
    const darkMode = localStorage.getItem('darkMode');

    if (darkMode === 'disabled') {
        document.body.classList.add('light-mode');
        icon.classList.remove('fa-moon');
        icon.classList.add('fa-sun');
    }
});

// Close sidebar when clicking outside
document.addEventListener('click', function(event) {
    const sidebar = document.getElementById('sidebar');
    const toggle = document.querySelector('.sidebar-toggle');
    
    if (sidebar.classList.contains('open') && 
        !sidebar.contains(event.target) && 
        !toggle.contains(event.target)) {
        toggleSidebar();
    }
});

        // Animate stats counter
        function animateCounters() {
            const counters = document.querySelectorAll('.stat-number');
            const speed = 200;
            
            counters.forEach(counter => {
                const target = +counter.getAttribute('data-count');
                const count = +counter.innerText;
                const increment = target / speed;
                
                if (count < target) {
                    counter.innerText = Math.ceil(count + increment);
                    setTimeout(animateCounters, 1);
                } else {
                    counter.innerText = target;
                }
            });
        }

        // Initialize counters when stats section is in view
        const statsSection = document.querySelector('.stats-section');
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    animateCounters();
                    observer.unobserve(entry.target);
                }
            });
        }, { threshold: 0.5 });

        observer.observe(statsSection);

        // Animate features on scroll
        const featureCards = document.querySelectorAll('.feature-card');
        const featureObserver = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const delay = entry.target.getAttribute('data-delay') || '0s';
                    entry.target.style.animationDelay = delay;
                    entry.target.classList.add('animate__fadeInUp');
                    featureObserver.unobserve(entry.target);
                }
            });
        }, { threshold: 0.1 });

        featureCards.forEach(card => {
            featureObserver.observe(card);
        });

        // Make feature cards clickable to scroll to features section
        document.querySelectorAll('.feature-card').forEach(card => {
            card.addEventListener('click', function() {
                document.getElementById('features').scrollIntoView({
                    behavior: 'smooth'
                });
            });
        });

        // Testimonial rotation (show one at a time, change every 7 seconds)
        function rotateTestimonials() {
            const testimonials = document.querySelectorAll('.testimonial-card');
            let currentIndex = 0;
            
            // Hide all testimonials except the first one
            testimonials.forEach((testimonial, index) => {
                testimonial.classList.remove('active');
                if (index === 0) {
                    testimonial.classList.add('active');
                }
            });
            
            // Set interval to rotate testimonials
            setInterval(() => {
                testimonials[currentIndex].classList.remove('active');
                currentIndex = (currentIndex + 1) % testimonials.length;
                testimonials[currentIndex].classList.add('active');
            }, 7000);
        }

        // Initialize testimonial rotation
        document.addEventListener('DOMContentLoaded', rotateTestimonials);

        // Smooth scroll for anchor links
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function(e) {
                e.preventDefault();
                document.querySelector(this.getAttribute('href')).scrollIntoView({
                    behavior: 'smooth'
                });
            });
        });

        // Video fallback for mobile
        function checkVideoSupport() {
            const video = document.querySelector('.video-background');
            if (window.innerWidth < 768 || !video.canPlayType('video/mp4')) {
                video.style.display = 'none';
                document.querySelector('.hero-overlay').style.background = 'linear-gradient(135deg, rgba(0,0,0,0.9) 0%, rgba(0,20,30,0.9) 100%)';
            }
        }

        window.addEventListener('load', checkVideoSupport);
        window.addEventListener('resize', checkVideoSupport);
    </script>
