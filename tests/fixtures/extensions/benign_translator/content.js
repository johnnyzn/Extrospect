// Shows a small bubble with the translation of the current selection.
function showBubble(text, rect) {
  const bubble = document.createElement("div");
  bubble.className = "lingvo-bubble";
  bubble.textContent = text;
  bubble.style.top = `${window.scrollY + rect.bottom + 6}px`;
  bubble.style.left = `${window.scrollX + rect.left}px`;
  document.body.appendChild(bubble);
  setTimeout(() => bubble.remove(), 6000);
}

document.addEventListener("mouseup", () => {
  const selection = window.getSelection();
  const text = selection ? selection.toString().trim() : "";
  if (!text || text.length > 2000) {
    return;
  }
  const rect = selection.getRangeAt(0).getBoundingClientRect();
  chrome.runtime.sendMessage({ type: "translate", text }, (reply) => {
    if (reply && reply.ok) {
      showBubble(reply.translation, rect);
    }
  });
});
