// static/js/theme.js
if (localStorage.getItem('theme') === 'dark') {
  document.documentElement.classList.add('dark');
}

function toggleDarkMode() {
  const root = document.documentElement;
  const icon = document.getElementById("darkModeIcon") || document.getElementById("theme-icon");

  if (root.classList.contains("dark")) {
    root.classList.remove("dark");
    localStorage.setItem('theme', 'light');
    if (icon) {
      icon.classList.remove("fa-sun");
      icon.classList.add("fa-moon");
    }
  } else {
    root.classList.add("dark");
    localStorage.setItem('theme', 'dark');
    if (icon) {
      icon.classList.remove("fa-moon");
      icon.classList.add("fa-sun");
    }
  }
}

document.addEventListener("DOMContentLoaded", function () {
  const icon = document.getElementById("darkModeIcon") || document.getElementById("theme-icon");
  if (localStorage.getItem('theme') === 'dark') {
    document.documentElement.classList.add('dark');
    if (icon) {
      icon.classList.remove("fa-moon");
      icon.classList.add("fa-sun");
    }
  } else {
    document.documentElement.classList.remove('dark');
    if (icon) {
      icon.classList.remove("fa-sun");
      icon.classList.add("fa-moon");
    }
  }
});
