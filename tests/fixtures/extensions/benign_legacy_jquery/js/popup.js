$(function () {});
chrome.storage.local.get("note", function (data) {
  $("#note").val(data.note || "");
});
$("#note").on("input", function () {
  chrome.storage.local.set({ note: $("#note").val() });
});
