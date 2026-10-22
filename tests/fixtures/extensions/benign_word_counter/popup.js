// Counts words in the active tab when the user clicks the button.
function countWords() {
  const text = document.body ? document.body.innerText : "";
  const words = text.trim().split(/\s+/).filter(Boolean);
  return words.length;
}

async function onCountClicked() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const [{ result }] = await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: countWords,
  });
  document.getElementById("result").textContent = String(result);
  const { history = [] } = await chrome.storage.local.get("history");
  history.push({ count: result, at: Date.now() });
  await chrome.storage.local.set({ history: history.slice(-20) });
}

document.getElementById("count").addEventListener("click", onCountClicked);
