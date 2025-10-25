// === index.js ===
// Handles sidebar active link + logout only
document.addEventListener("DOMContentLoaded", () => {
  // Highlight active nav
  const links = document.querySelectorAll(".sidebar ul li a");
  const currentPage = location.pathname.split("/").pop();

  links.forEach(link => {
    if (link.getAttribute("href") === currentPage) {
      link.classList.add("active");
    }

    link.addEventListener("click", () => {
      window.location.href = link.getAttribute("href");
    });
  });
});

const hamburger = document.getElementById('hamburger');
  const sidebar = document.querySelector('.sidebar');

  hamburger.addEventListener('click', () => {
    hamburger.classList.toggle('active');
    sidebar.classList.toggle('show');
  });

  document.querySelector(".logout-btn").addEventListener("click", () => {
  localStorage.removeItem("loggedInUser");
  sessionStorage.removeItem("loggedInUser");
  window.location.href = "login.html";
});