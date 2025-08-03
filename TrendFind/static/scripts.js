// ─────────────────────── Sidebar ───────────────────────
function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  sidebar.classList.toggle('open');
}

document.querySelector('.sidebar-toggle').addEventListener('click', toggleSidebar);

document.addEventListener('click', function(event) {
  const sidebar = document.getElementById('sidebar');
  const toggleButton = document.querySelector('.sidebar-toggle');
  if (!sidebar.contains(event.target) && !toggleButton.contains(event.target)) {
    sidebar.classList.remove('open');
  }
});

// ─────────────────────── Dark Mode ───────────────────────
document.getElementById('dark-mode-toggle')?.addEventListener('click', function() {
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

document.addEventListener('DOMContentLoaded', function() {
  const darkModeToggle = document.getElementById('dark-mode-toggle');
  const icon = darkModeToggle?.querySelector('i');
  const darkMode = localStorage.getItem('darkMode');

  if (darkMode === 'enabled') {
    document.body.classList.add('dark-mode');
    icon?.classList.remove('fa-moon');
    icon?.classList.add('fa-sun');
  } else {
    document.body.classList.remove('dark-mode');
    icon?.classList.remove('fa-sun');
    icon?.classList.add('fa-moon');
  }

  // Typewriter effect starts here
  typeWriterTitle();
});

// ─────────────────────── Hero Typewriter ───────────────────────
const heroTitle = document.getElementById('hero-title');
const heroSubtitle = document.getElementById('hero-subtitle');

const titleText = "Discover the Next Best-Selling Products";
const subtitleText = "AI-Powered Precision for Dropshippers and Resellers";

let titleIndex = 0;
let subtitleIndex = 0;

function typeWriterTitle() {
  if (!heroTitle) return;
  if (titleIndex < titleText.length) {
    heroTitle.textContent += titleText.charAt(titleIndex);
    titleIndex++;
    setTimeout(typeWriterTitle, 120); // Faster speed
  } else {
    typeWriterSubtitle();
  }
}

function typeWriterSubtitle() {
  if (!heroSubtitle) return;
  if (subtitleIndex < subtitleText.length) {
    heroSubtitle.textContent += subtitleText.charAt(subtitleIndex);
    subtitleIndex++;
    setTimeout(typeWriterSubtitle, 120);
  }
}

// ─────────────────────── Firebase Auth ───────────────────────
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
  const email = document.getElementById("email")?.value;
  const pass = document.getElementById("password")?.value;
  if (!email || !pass) {
    alert("Please enter email and password.");
    return;
  }

  auth.signInWithEmailAndPassword(email, pass)
    .then(result => sendTokenToFlask())
    .catch(error => alert("Login error: " + error.message));
}

function sendTokenToFlask() {
  auth.currentUser.getIdToken().then(idToken => {
    fetch("/firebase-login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ idToken })
    })
    .then(res => res.json())
    .then(data => {
      if (data.message === "Login successful") {
        window.location.href = "/profile";
      } else {
        alert("Login failed");
      }
    });
  }).catch(err => {
    console.error("Token error:", err);
    alert("Login failed");
  });
}

// ─────────────────────── Event Listeners ───────────────────────
document.addEventListener("DOMContentLoaded", function () {
  const googleBtn = document.getElementById("google-login-btn");
  if (googleBtn) {
    googleBtn.addEventListener("click", loginWithGoogle);
  }

  const emailLoginBtn = document.getElementById("email-login-btn");
  if (emailLoginBtn) {
    emailLoginBtn.addEventListener("click", function(e) {
      e.preventDefault();
      loginWithEmail();
    });
  }
});
