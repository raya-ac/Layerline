<?php
ob_start();
phpinfo();
$phpinfo = ob_get_clean();

$body_start = stripos($phpinfo, "<body>");
$body_end = stripos($phpinfo, "</body>");
$info_body = $phpinfo;

if ($body_start !== false && $body_end !== false) {
    $info_body = substr($phpinfo, $body_start + strlen("<body>"), $body_end - ($body_start + strlen("<body>")));
}

header("Content-Type: text/html; charset=utf-8");
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Layerline PHP Info</title>
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <style>
    :root {
      color-scheme: light;
      --ink: #11110f;
      --muted: #5d5e58;
      --line: rgba(17, 17, 15, 0.14);
      --paper: #fbfaf6;
      --panel: rgba(251, 250, 246, 0.78);
      --wash: #f0ece2;
      --blue: #b9c2ee;
      --green: #cadbc0;
      --rose: #ead1ca;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      overflow-x: hidden;
      color: var(--ink);
      font: 14px/1.6 ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background:
        radial-gradient(circle at 16% -12%, rgba(255, 255, 255, 0.92), transparent 28%),
        linear-gradient(180deg, #f7f4ed 0%, var(--wash) 46%, #e9e3d6 100%);
    }

    body::before {
      content: "";
      position: fixed;
      inset: 0;
      z-index: -2;
      background:
        linear-gradient(rgba(15, 15, 12, 0.05) 1px, transparent 1px),
        linear-gradient(90deg, rgba(15, 15, 12, 0.05) 1px, transparent 1px);
      background-size: 64px 64px;
      pointer-events: none;
    }

    body::after {
      content: "";
      position: fixed;
      inset: 0;
      z-index: -1;
      background:
        radial-gradient(circle at 50% 18%, transparent 0 28%, rgba(244, 241, 234, 0.28) 62%, rgba(214, 204, 186, 0.42) 100%),
        linear-gradient(90deg, rgba(17, 17, 15, 0.035), transparent 18%, transparent 82%, rgba(17, 17, 15, 0.035));
      pointer-events: none;
    }

    main {
      width: min(1280px, calc(100vw - 44px));
      margin: 0 auto;
      padding: 18px 0 72px;
    }

    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      margin-bottom: 32px;
      padding: 10px;
      border: 1px solid rgba(17, 17, 15, 0.12);
      border-radius: 18px;
      background: rgba(251, 250, 246, 0.82);
      box-shadow: 0 18px 60px rgba(38, 34, 24, 0.09);
      backdrop-filter: blur(22px);
    }

    .brand {
      display: inline-flex;
      align-items: center;
      gap: 12px;
      color: inherit;
      text-decoration: none;
    }

    .brand img {
      display: block;
      width: 40px;
      height: 40px;
      border-radius: 12px;
      box-shadow: 0 18px 36px rgba(17, 17, 15, 0.08);
    }

    .brand strong {
      display: block;
      font-size: 16px;
      line-height: 1.1;
      font-weight: 700;
    }

    .brand small {
      display: block;
      color: #8b8c84;
      font-size: 11px;
      line-height: 1.1;
    }

    .nav {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }

    .button {
      display: inline-flex;
      align-items: center;
      padding: 9px 13px;
      border: 1px solid rgba(15, 15, 12, 0.14);
      border-radius: 12px;
      background: rgba(255, 255, 255, 0.5);
      color: var(--ink);
      text-decoration: none;
      font-weight: 600;
    }

    .hero {
      position: relative;
      min-height: 420px;
      display: grid;
      grid-template-columns: minmax(0, 0.9fr) minmax(320px, 0.55fr);
      gap: clamp(28px, 6vw, 86px);
      align-items: end;
      margin: 0 calc(50% - 50vw) 42px;
      padding: clamp(42px, 8vw, 92px) max(30px, calc((100vw - 1280px) / 2 + 30px));
      border-bottom: 1px solid rgba(15, 15, 12, 0.12);
      overflow: hidden;
      background:
        radial-gradient(circle at 74% 42%, rgba(17, 17, 15, 0.14), transparent 18%),
        linear-gradient(rgba(17, 17, 15, 0.055) 1px, transparent 1px),
        linear-gradient(90deg, rgba(17, 17, 15, 0.055) 1px, transparent 1px),
        linear-gradient(135deg, rgba(251, 250, 246, 0.95), rgba(231, 225, 212, 0.84));
      background-size: auto, 56px 56px, 56px 56px, auto;
    }

    .hero::after {
      content: "PHP";
      position: absolute;
      right: clamp(-20px, 6vw, 80px);
      bottom: clamp(-18px, 2vw, 26px);
      color: rgba(17, 17, 15, 0.045);
      font: 800 clamp(170px, 28vw, 360px)/0.78 ui-sans-serif, system-ui, sans-serif;
      letter-spacing: -0.12em;
      pointer-events: none;
    }

    .eyebrow {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 6px 10px;
      margin-bottom: 16px;
      border: 1px solid rgba(17, 17, 15, 0.18);
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.58);
      color: var(--muted);
      font: 11px/1 ui-monospace, SFMono-Regular, Menlo, monospace;
      letter-spacing: 0.16em;
      text-transform: uppercase;
    }

    h1 {
      max-width: 10ch;
      margin: 0 0 18px;
      font-size: clamp(56px, 8vw, 118px);
      line-height: 0.88;
      letter-spacing: -0.075em;
    }

    .hero p {
      max-width: 56ch;
      margin: 0;
      color: var(--muted);
      font-size: clamp(16px, 1.3vw, 19px);
    }

    .status-panel {
      position: relative;
      z-index: 1;
      border: 1px solid rgba(17, 17, 15, 0.16);
      border-radius: 24px;
      overflow: hidden;
      background: rgba(251, 250, 246, 0.72);
      box-shadow: 0 44px 110px rgba(38, 34, 24, 0.14);
      backdrop-filter: blur(18px);
    }

    .status-panel::before {
      content: "";
      position: absolute;
      inset: 0;
      background:
        linear-gradient(rgba(17, 17, 15, 0.08) 1px, transparent 1px),
        linear-gradient(90deg, rgba(17, 17, 15, 0.08) 1px, transparent 1px);
      background-size: 44px 44px;
    }

    .status-inner {
      position: relative;
      display: grid;
      gap: 16px;
      padding: 22px;
    }

    .metric {
      display: flex;
      justify-content: space-between;
      gap: 16px;
      padding: 14px 0;
      border-bottom: 1px solid rgba(17, 17, 15, 0.12);
    }

    .metric:last-child { border-bottom: 0; }
    .metric span { color: var(--muted); }
    .metric strong { text-align: right; }

    .phpinfo-surface {
      border: 1px solid rgba(17, 17, 15, 0.16);
      border-radius: 18px;
      overflow: auto;
      background: var(--panel);
      box-shadow: 0 32px 90px rgba(38, 34, 24, 0.12);
      backdrop-filter: blur(18px);
    }

    .phpinfo-toolbar {
      position: sticky;
      top: 0;
      z-index: 3;
      display: flex;
      justify-content: space-between;
      gap: 18px;
      align-items: center;
      padding: 14px 18px;
      border-bottom: 1px solid rgba(17, 17, 15, 0.12);
      background: rgba(251, 250, 246, 0.92);
      backdrop-filter: blur(18px);
    }

    .phpinfo-toolbar strong {
      font-size: 16px;
    }

    .phpinfo-toolbar code {
      color: var(--muted);
      font: 12px/1.3 ui-monospace, SFMono-Regular, Menlo, monospace;
    }

    .phpinfo-output {
      min-width: 860px;
      padding: 20px 20px 28px;
      color: var(--ink);
    }

    .phpinfo-output .center {
      text-align: left;
    }

    .phpinfo-output .center table {
      margin: 0 0 18px;
    }

    .phpinfo-output h1,
    .phpinfo-output h2 {
      margin: 22px 0 12px;
      color: var(--ink);
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      letter-spacing: -0.04em;
    }

    .phpinfo-output h1 {
      font-size: 28px;
      line-height: 1.05;
    }

    .phpinfo-output h2 {
      font-size: 20px;
      line-height: 1.15;
    }

    .phpinfo-output table {
      width: 100%;
      border-collapse: collapse;
      border: 1px solid rgba(17, 17, 15, 0.18);
      border-radius: 10px;
      overflow: hidden;
      box-shadow: none;
      background: rgba(255, 255, 255, 0.42);
    }

    .phpinfo-output th,
    .phpinfo-output td {
      padding: 8px 10px;
      border: 1px solid rgba(17, 17, 15, 0.13);
      vertical-align: top;
      font-size: 12px;
      line-height: 1.45;
    }

    .phpinfo-output th {
      position: static;
      background: rgba(17, 17, 15, 0.92);
      color: var(--paper);
      text-align: left;
      font-weight: 700;
    }

    .phpinfo-output td {
      color: var(--ink);
      overflow-wrap: anywhere;
    }

    .phpinfo-output .e {
      width: 300px;
      background: rgba(185, 194, 238, 0.46);
      font-weight: 700;
    }

    .phpinfo-output .v {
      background: rgba(255, 255, 255, 0.62);
    }

    .phpinfo-output .h {
      background: #11110f;
      color: #fbfaf6;
      font-weight: 700;
    }

    .phpinfo-output .p,
    .phpinfo-output .v i {
      color: var(--muted);
    }

    .phpinfo-output a {
      color: inherit;
      text-decoration-color: rgba(17, 17, 15, 0.3);
    }

    .phpinfo-output img {
      max-width: 100%;
      height: auto;
    }

    @media (max-width: 860px) {
      main {
        width: min(100vw - 28px, 1280px);
      }

      .topbar,
      .phpinfo-toolbar {
        align-items: flex-start;
        flex-direction: column;
      }

      .hero {
        grid-template-columns: 1fr;
      }

      .phpinfo-output {
        min-width: 760px;
      }
    }
  </style>
</head>
<body>
  <main>
    <header class="topbar">
      <a class="brand" href="/" aria-label="Layerline home">
        <img src="/favicon.svg" alt="">
        <span><strong>Layerline</strong><small>Modern web server</small></span>
      </a>
      <nav class="nav" aria-label="Diagnostics">
        <a class="button" href="/health">Health</a>
        <a class="button" href="/index.php">JSON PHP</a>
        <a class="button" href="/metrics">Metrics</a>
      </nav>
    </header>

    <section class="hero">
      <div>
        <div class="eyebrow">PHP CGI active</div>
        <h1>PHP info</h1>
        <p>The diagnostic payload below is generated by PHP's own <code>phpinfo()</code> call, then rendered inside Layerline's interface so the route feels native to the server.</p>
      </div>
      <aside class="status-panel" aria-label="Runtime summary">
        <div class="status-inner">
          <div class="metric"><span>PHP version</span><strong><?= htmlspecialchars(PHP_VERSION, ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8") ?></strong></div>
          <div class="metric"><span>SAPI</span><strong><?= htmlspecialchars(php_sapi_name(), ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8") ?></strong></div>
          <div class="metric"><span>Server</span><strong><?= htmlspecialchars($_SERVER["SERVER_SOFTWARE"] ?? "unknown", ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8") ?></strong></div>
          <div class="metric"><span>Script</span><strong><?= htmlspecialchars($_SERVER["SCRIPT_NAME"] ?? "/test.php", ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8") ?></strong></div>
        </div>
      </aside>
    </section>

    <section class="phpinfo-surface" aria-label="Full PHP information">
      <div class="phpinfo-toolbar">
        <strong>Full PHP runtime report</strong>
        <code><?= htmlspecialchars(gmdate("Y-m-d H:i:s") . " UTC", ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8") ?></code>
      </div>
      <div class="phpinfo-output">
        <?= $info_body ?>
      </div>
    </section>
  </main>
</body>
</html>
