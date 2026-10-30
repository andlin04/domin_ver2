// Runs in <head> before paint: apply the saved theme so the page doesn't flash.
try {
  const t = localStorage.getItem("domin-theme");
  if (t) document.documentElement.dataset.theme = t;
} catch (e) { /* storage blocked: follow the OS setting */ }
