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

// Dark Mode Toggle Functionality
document.getElementById('dark-mode-toggle').addEventListener('click', function() {
    document.body.classList.toggle('dark-mode');
    const icon = this.querySelector('i');
    if (document.body.classList.contains('dark-mode')) {
        icon.classList.remove('fa-moon');
        icon.classList.add('fa-sun');
        localStorage.setItem('darkMode', 'enabled');
    } else {
        icon.classList.remove('fa-sun');
        icon.classList.add('fa-moon');
        localStorage.setItem('darkMode', 'disabled');
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

    // Start the typewriter effect after checking dark mode
    typeWriterTitle();
});

// Typewriter Effect for Hero Title and Subtitle
const heroTitle = document.getElementById('hero-title');
const heroSubtitle = document.getElementById('hero-subtitle');

const titleText = "Discover the Next Best-Selling Products";
const subtitleText = "AI-Powered Precision for Dropshippers and Resellers";

let titleIndex = 0;
let subtitleIndex = 0;

function typeWriterTitle() {
    if (titleIndex < titleText.length) {
        heroTitle.textContent += titleText.charAt(titleIndex);
        titleIndex++;
        setTimeout(typeWriterTitle, 1200); // Adjust typing speed
    } else {
        typeWriterSubtitle();
    }
}

function typeWriterSubtitle() {
    if (subtitleIndex < subtitleText.length) {
        heroSubtitle.textContent += subtitleText.charAt(subtitleIndex);
        subtitleIndex++;
        setTimeout(typeWriterSubtitle, 1200); // Adjust typing speed
    }
}

// Initialize Firebase
const firebaseConfig = {
  apiKey: "AIzaSyB14r8WPw3tXCelx0_VQ7U3-XB95NNEg4c",
  authDomain: "trendfind-1c527.firebaseapp.com",
  projectId: "trendfind-1c527"
};

firebase.initializeApp(firebaseConfig);
const auth = firebase.auth();

function loginWithGoogle() {
  const provider = new firebase.auth.GoogleAuthProvider();
  auth.signInWithPopup(provider)
    .then(result => sendTokenToFlask())
    .catch(error => alert("Login error: " + error.message));
}

function loginWithEmail() {
  const email = document.getElementById("email").value;
  const pass = document.getElementById("password").value;
  auth.signInWithEmailAndPassword(email, pass)
    .then(result => sendTokenToFlask())
    .catch(error => alert("Login error: " + error.message));
  return false;
}

function sendTokenToFlask() {
  auth.currentUser.getIdToken().then(token => {
    fetch("/firebase-login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token })
    }).then(res => res.json()).then(data => {
      if (data.status === "ok") {
        window.location.href = "/profile";
      } else {
        alert("Login failed");
      }
    });
  });
}
