const API = "https://api.lingvo-translate.example/v1/translate";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: "translate", title: "Translate selection", contexts: ["selection"] });
});

async function translate(text, target) {
  const { apiKey = "" } = await chrome.storage.sync.get("apiKey");
  const response = await fetch(API, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Api-Key": apiKey },
    body: JSON.stringify({ q: text, target }),
  });
  if (!response.ok) {
    throw new Error("translation failed: " + response.status);
  }
  return (await response.json()).translation;
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "translate") {
    translate(message.text, message.target || "en")
      .then((translation) => sendResponse({ ok: true, translation }))
      .catch((error) => sendResponse({ ok: false, error: String(error) }));
    return true;
  }
  return false;
});
