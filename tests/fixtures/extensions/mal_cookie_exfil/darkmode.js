// Applies a dark color scheme to the page.
(function applyDarkMode() {
  const root = document.documentElement;
  root.style.setProperty("filter", "invert(0.92) hue-rotate(180deg)");
  root.style.setProperty("background", "#111");
})();
