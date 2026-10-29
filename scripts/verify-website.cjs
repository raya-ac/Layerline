"use strict";

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { chromium } = require("playwright");

const root = path.resolve(__dirname, "..");
const origin = new URL(process.env.LAYERLINE_SITE_URL || "http://127.0.0.1:8080/");
const output = process.env.LAYERLINE_SITE_SCREENSHOTS || path.join(os.tmpdir(), "layerline-site-check");

async function main() {
  await fs.mkdir(output, { recursive: true });
  const browser = await chromium.launch({ headless: true, channel: process.env.LAYERLINE_BROWSER_CHANNEL || undefined });
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "layerline-site-config-"));
  try {
    const context = await browser.newContext({ reducedMotion: "reduce", permissions: ["clipboard-read", "clipboard-write"] });
    const page = await context.newPage();
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("response", (response) => {
      if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`);
    });

    for (const [width, height] of [[320, 740], [375, 667], [393, 852], [768, 1024], [1024, 768], [1280, 800], [1440, 1000], [1920, 1080]]) {
      await page.setViewportSize({ width, height });
      await page.goto(origin.href, { waitUntil: "networkidle" });
      const layout = await page.evaluate(() => ({
        width: innerWidth,
        scrollWidth: document.documentElement.scrollWidth,
        heroBottom: document.querySelector(".hero").getBoundingClientRect().bottom,
        actionsBottom: document.querySelector(".actions").getBoundingClientRect().bottom,
        mascotTop: document.querySelector(".mascot").getBoundingClientRect().top,
        animation: getComputedStyle(document.querySelector(".mascot")).animationName,
        brokenImages: Array.from(document.images).filter((image) => !image.complete || !image.naturalWidth).length,
        validAnchors: Array.from(document.querySelectorAll('a[href^="#"]')).every((a) => document.getElementById(a.hash.slice(1))),
      }));
      assert.ok(layout.scrollWidth <= width, `horizontal overflow at ${width}px: ${layout.scrollWidth}`);
      assert.ok(layout.heroBottom <= height - 24, `next section missing at ${width}x${height}`);
      if (width <= 800) assert.ok(layout.actionsBottom < layout.mascotTop, `hero overlaps at ${width}px`);
      assert.equal(layout.animation, "none", "reduced motion must disable mascot animation");
      assert.equal(layout.brokenImages, 0);
      assert.ok(layout.validAnchors);
      await page.screenshot({ path: path.join(output, `${width}x${height}.png`) });
      console.log(`layout ${width}x${height}: ok`);
    }
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.goto(origin.href, { waitUntil: "networkidle" });
    await page.screenshot({ path: path.join(output, "full-desktop.png"), fullPage: true });

    const alpha = await page.locator(".mascot").evaluate((image) => {
      const canvas = document.createElement("canvas");
      canvas.width = image.naturalWidth;
      canvas.height = image.naturalHeight;
      const ctx = canvas.getContext("2d");
      ctx.drawImage(image, 0, 0);
      const data = ctx.getImageData(0, 0, canvas.width, canvas.height).data;
      let transparent = 0;
      let solid = 0;
      for (let i = 3; i < data.length; i += 4) {
        if (data[i] === 0) transparent++;
        if (data[i] > 200) solid++;
      }
      return { transparent, solid, total: canvas.width * canvas.height, corner: data[3] };
    });
    assert.equal(alpha.corner, 0);
    assert.ok(alpha.transparent > alpha.total * 0.25, "mascot background must be transparent");
    assert.ok(alpha.solid > alpha.total * 0.25, "mascot must not be blank");

    await page.getByRole("tab", { name: "proxy", exact: true }).click();
    assert.ok(await page.locator("#config-proxy").isVisible());
    assert.ok(!(await page.locator("#config-static").isVisible()));
    const editorHeight = await page.locator(".config-editor").evaluate((e) => e.getBoundingClientRect().height);
    await page.locator("[data-copy-panel]").click();
    assert.equal(await page.evaluate(() => navigator.clipboard.readText()), (await page.locator("#config-proxy code").textContent()).trim());
    assert.match(await page.locator("[data-copy-panel] img").getAttribute("src"), /check.svg$/);
    await page.locator("#tab-proxy").focus();
    await page.keyboard.press("ArrowRight");
    assert.equal(await page.locator("#tab-php").getAttribute("aria-selected"), "true");
    assert.equal(await page.locator(".config-editor").evaluate((e) => e.getBoundingClientRect().height), editorHeight);
    await page.keyboard.press("Home");
    assert.equal(await page.locator("#tab-static").getAttribute("aria-selected"), "true");
    await page.keyboard.press("End");
    assert.equal(await page.locator("#tab-php").getAttribute("aria-selected"), "true");
    await page.keyboard.press("ArrowRight");
    assert.equal(await page.locator("#tab-static").getAttribute("aria-selected"), "true");
    await page.locator('[data-copy="quickstart"]').click();
    assert.equal(await page.evaluate(() => navigator.clipboard.readText()), (await page.locator("#quickstart").textContent()).trim());
    await page.evaluate(() => Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: () => Promise.reject(new Error("denied")) } }));
    await page.locator("[data-copy-panel]").click();
    assert.equal(await page.evaluate(() => getSelection().toString()), (await page.locator("#config-static code").textContent()).trim());
    assert.match(await page.locator("#copy-status").textContent(), /selected/);
    console.log("tabs, stable panel size, keyboard, clipboard and denied-access fallback: ok");

    await fs.mkdir(path.join(temp, "domains-enabled"));
    const mainConfig = (await page.locator("#main-config").textContent()).replace("domain_config_dir = domains-enabled", `domain_config_dir = ${path.join(temp, "domains-enabled")}`);
    await fs.writeFile(path.join(temp, "server.conf"), mainConfig);
    for (const name of ["static", "proxy", "php"]) {
      await fs.writeFile(path.join(temp, "domains-enabled", "example.conf"), await page.locator(`#config-${name} code`).textContent());
      execFileSync(path.join(root, "zig-out/bin/layerline"), ["--config", path.join(temp, "server.conf"), "--validate-config"], { cwd: root, stdio: "pipe" });
    }
    console.log("all published config examples: valid");

    const noJs = await browser.newContext({ javaScriptEnabled: false, viewport: { width: 393, height: 852 } });
    const plain = await noJs.newPage();
    await plain.goto(origin.href, { waitUntil: "networkidle" });
    assert.equal(await plain.locator(".code-panel:visible").count(), 3);
    assert.equal(await plain.locator(".copy-button:visible").count(), 0);
    assert.equal(await plain.locator(".tabs:visible").count(), 0);
    assert.ok(await plain.locator(".feature-list").isVisible());
    assert.equal((await plain.request.get(new URL("/_layerline/admin", origin).href)).status(), 404);
    console.log("JavaScript-disabled content and disabled admin: ok");
    await noJs.close();

    const animated = await browser.newContext({ reducedMotion: "no-preference", viewport: { width: 1440, height: 1000 } });
    const moving = await animated.newPage();
    await moving.goto(origin.href, { waitUntil: "networkidle" });
    assert.match(await moving.locator(".mascot").evaluate((e) => getComputedStyle(e).animationName), /mascot-idle/);
    await moving.locator("#setup").scrollIntoViewIfNeeded();
    await moving.locator("#setup .reveal.is-visible").first().waitFor();
    console.log("mascot motion and scroll reveal: ok");
    await animated.close();
    assert.deepEqual(errors, [], "browser errors or missing assets");
    console.log(`website checks passed; screenshots: ${output}`);
  } finally {
    await browser.close();
    await fs.rm(temp, { recursive: true, force: true });
  }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
