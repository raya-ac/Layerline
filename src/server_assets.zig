pub const SERVER_ICON_SVG =
    \\<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" role="img" aria-labelledby="title desc">
    \\  <title id="title">Layerline</title>
    \\  <desc id="desc">A layered route mark for the Layerline HTTP server.</desc>
    \\  <rect width="128" height="128" rx="30" fill="#fbfaf6"/>
    \\  <rect x="8" y="8" width="112" height="112" rx="24" fill="none" stroke="#11110f" stroke-opacity=".16" stroke-width="4"/>
    \\  <path d="M29 33h70L29 96h70" fill="none" stroke="#11110f" stroke-width="12" stroke-linecap="round" stroke-linejoin="round"/>
    \\  <path d="M40 48h48M40 80h48" fill="none" stroke="#11110f" stroke-opacity=".18" stroke-width="5" stroke-linecap="round"/>
    \\  <circle cx="38" cy="39" r="8" fill="#fbfaf6" stroke="#11110f" stroke-width="5"/>
    \\  <circle cx="90" cy="89" r="8" fill="#fbfaf6" stroke="#11110f" stroke-width="5"/>
    \\  <circle cx="64" cy="64" r="17" fill="none" stroke="#11110f" stroke-opacity=".28" stroke-width="4"/>
    \\</svg>
;

pub const H2_DEFAULT_PAGE =
    \\<!doctype html>
    \\<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    \\<title>Layerline HTTP/2</title><link rel="icon" type="image/svg+xml" href="/favicon.svg">
    \\<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f7f4ed;color:#11110f;font:16px/1.5 system-ui,sans-serif}main{max-width:760px;padding:48px}h1{font-size:clamp(56px,10vw,120px);line-height:.85;margin:0}p{color:#5d5e58;max-width:48ch}.tag{font:12px/1.2 ui-monospace,monospace;text-transform:uppercase;color:#77786f}</style>
    \\</head><body><main><div class="tag">native h2c route</div><h1>Layerline</h1><p>This response came from Layerline's native HTTP/2 frame path: SETTINGS, HPACK request headers, HEADERS, and DATA frames emitted by the Zig server.</p></main></body></html>
;

pub const H3_DEFAULT_PAGE = @embedFile("assets/default.html");
