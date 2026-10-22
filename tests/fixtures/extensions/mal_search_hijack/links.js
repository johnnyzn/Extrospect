// Rewrites shopping links to carry an affiliate tag.
const TAG = "qsearch-21";

function tagLinks() {
  for (const anchor of document.querySelectorAll("a[href*='amazon.']")) {
    const url = new URL(anchor.href);
    url.searchParams.set("tag", TAG);
    anchor.href = url.toString();
  }
}

new MutationObserver(tagLinks).observe(document.documentElement, { childList: true, subtree: true });
tagLinks();
