const toggle = document.getElementById("menuToggle");
const mobileMenu = document.getElementById("mobileMenu");

toggle.addEventListener("click", () => {
  mobileMenu.classList.toggle("show");
  toggle.classList.toggle("active");
  
  if (toggle.classList.contains("active")) {
    toggle.textContent = "×";
  } else {
    toggle.textContent = "☰";
  }
});