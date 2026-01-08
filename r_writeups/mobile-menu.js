// Mobile menu functionality for writeups.html
document.addEventListener('DOMContentLoaded', () => {
  const toggle = document.getElementById("menuToggle");
  const mobileMenu = document.getElementById("mobileMenu");

  if (!toggle || !mobileMenu) {
    console.warn('Elementos del menú móvil no encontrados');
    return;
  }

  toggle.addEventListener("click", () => {
    mobileMenu.classList.toggle("show");
    toggle.classList.toggle("active");
    
    if (toggle.classList.contains("active")) {
      toggle.textContent = "×";
    } else {
      toggle.textContent = "☰";
    }
  });
});