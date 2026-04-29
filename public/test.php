<?php
header("Content-Type: text/html; charset=utf-8");

$checks = [
    "PHP version" => PHP_VERSION,
    "SAPI" => php_sapi_name(),
    "Request method" => $_SERVER["REQUEST_METHOD"] ?? "unknown",
    "Script name" => $_SERVER["SCRIPT_NAME"] ?? "unknown",
    "Query string" => $_SERVER["QUERY_STRING"] ?? "",
    "Server software" => $_SERVER["SERVER_SOFTWARE"] ?? "unknown",
    "Generated at" => gmdate("Y-m-d H:i:s") . " UTC",
];

function escape_html(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8");
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Layerline PHP Test</title>
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <style>
    :root {
      color-scheme: light;
      --ink: #11110f;
      --muted: #5d5e58;
      --line: rgba(17, 17, 15, 0.14);
      --paper: #fbfaf6;
      --wash: #f0ece2;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      color: var(--ink);
      font: 15px/1.6 ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background:
        linear-gradient(rgba(17, 17, 15, 0.05) 1px, transparent 1px),
        linear-gradient(90deg, rgba(17, 17, 15, 0.05) 1px, transparent 1px),
        linear-gradient(180deg, #f7f4ed 0%, var(--wash) 50%, #e9e3d6 100%);
      background-size: 56px 56px, 56px 56px, auto;
    }

    main {
      width: min(980px, calc(100vw - 40px));
      margin: 0 auto;
      padding: 56px 0;
    }

    .brand {
      display: inline-flex;
      align-items: center;
      gap: 12px;
      color: inherit;
      text-decoration: none;
      margin-bottom: 46px;
    }

    .brand img {
      width: 42px;
      height: 42px;
      border-radius: 12px;
      box-shadow: 0 18px 36px rgba(17, 17, 15, 0.08);
    }

    .brand strong { display: block; line-height: 1.1; }
    .brand small { display: block; color: #8b8c84; font-size: 12px; line-height: 1.1; }

    .eyebrow {
      display: inline-flex;
      padding: 6px 10px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.58);
      color: var(--muted);
      font: 12px/1 ui-monospace, SFMono-Regular, Menlo, monospace;
      letter-spacing: 0.12em;
      text-transform: uppercase;
    }

    h1 {
      max-width: 9ch;
      margin: 18px 0 16px;
      font-size: clamp(58px, 10vw, 112px);
      line-height: 0.9;
      letter-spacing: -0.06em;
    }

    p {
      max-width: 58ch;
      margin: 0 0 32px;
      color: var(--muted);
      font-size: 18px;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      overflow: hidden;
      border: 1px solid var(--line);
      border-radius: 14px;
      background: rgba(251, 250, 246, 0.78);
      box-shadow: 0 32px 90px rgba(38, 34, 24, 0.12);
    }

    th,
    td {
      padding: 15px 17px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
    }

    tr:last-child th,
    tr:last-child td { border-bottom: 0; }

    th {
      width: 220px;
      color: var(--muted);
      font-weight: 600;
    }

    code {
      font: 14px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace;
      overflow-wrap: anywhere;
    }
  </style>
</head>
<body>
  <main>
    <a class="brand" href="/" aria-label="Layerline home">
      <img src="/favicon.svg" alt="">
      <span><strong>Layerline</strong><small>Modern web server</small></span>
    </a>

    <div class="eyebrow">PHP CGI active</div>
    <h1>PHP test</h1>
    <p>This page was rendered by PHP through Layerline's CGI path. If these values change on refresh, PHP is executing per request.</p>

    <table>
      <tbody>
        <?php foreach ($checks as $label => $value): ?>
          <tr>
            <th><?= escape_html($label) ?></th>
            <td><code><?= escape_html((string) $value) ?></code></td>
          </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </main>
</body>
</html>
