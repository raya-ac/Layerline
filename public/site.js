"use strict";

document.documentElement.classList.add("js");

const tablist = document.querySelector('[role="tablist"]');
const tabs = Array.from(tablist.querySelectorAll('[role="tab"]'));
const panels = Array.from(document.querySelectorAll('[role="tabpanel"]'));

function selectTab(tab, focus = false) {
  for (const item of tabs) {
    const selected = item === tab;
    item.setAttribute("aria-selected", String(selected));
    item.tabIndex = selected ? 0 : -1;
  }
  for (const panel of panels) {
    panel.hidden = panel.id !== tab.getAttribute("aria-controls");
  }
  if (focus) tab.focus();
}

selectTab(tabs[0]);
tablist.hidden = false;
for (const tab of tabs) tab.addEventListener("click", () => selectTab(tab));
tablist.addEventListener("keydown", (event) => {
  const index = tabs.indexOf(document.activeElement);
  if (index < 0) return;
  let next;
  if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
  else if (event.key === "ArrowLeft") next = (index + tabs.length - 1) % tabs.length;
  else if (event.key === "Home") next = 0;
  else if (event.key === "End") next = tabs.length - 1;
  else return;
  event.preventDefault();
  selectTab(tabs[next], true);
});

const copyStatus = document.getElementById("copy-status");
for (const button of document.querySelectorAll(".copy-button")) {
  button.hidden = false;
  button.addEventListener("click", async () => {
    const source = button.dataset.copy
      ? document.getElementById(button.dataset.copy)
      : document.getElementById(button.dataset.copyPanel).querySelector('[role="tabpanel"]:not([hidden]) code');
    const text = source.textContent.trim();
    copyStatus.textContent = "";
    try {
      if (!navigator.clipboard || !window.isSecureContext) throw new Error("Clipboard unavailable");
      await navigator.clipboard.writeText(text);
      button.querySelector("img").src = "/static/icons/check.svg";
      button.title = "Copied";
      button.setAttribute("aria-label", "Copied to clipboard");
      copyStatus.textContent = "Copied to clipboard.";
      window.setTimeout(() => {
        button.title = button.dataset.copy ? "Copy quick start commands" : "Copy site config";
        button.setAttribute("aria-label", button.title);
        button.querySelector("img").src = "/static/icons/copy.svg";
      }, 1800);
    } catch {
      // Keep the text usable when clipboard access is denied or HTTP is insecure.
      const range = document.createRange();
      range.selectNodeContents(source);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      copyStatus.textContent = "Clipboard unavailable. The text is selected for manual copying.";
    }
  });
}

const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
if ("IntersectionObserver" in window && !reducedMotion.matches) {
  document.documentElement.classList.add("motion");
  const observer = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      entry.target.classList.add("is-visible");
      observer.unobserve(entry.target);
    }
  }, { threshold: 0.08 });
  for (const element of document.querySelectorAll(".reveal")) observer.observe(element);
}
