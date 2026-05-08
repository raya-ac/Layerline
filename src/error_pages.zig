const std = @import("std");

pub fn render(
    allocator: std.mem.Allocator,
    server_name: []const u8,
    server_tagline: []const u8,
    status_code: u16,
    status_text: []const u8,
    detail: []const u8,
) ![]const u8 {
    const eyebrow = if (status_code == 404) "Route not found" else "Request stopped";
    const headline = if (status_code == 404) "Memory has no path here." else status_text;
    const route_label = if (status_code == 404) "unresolved route" else "server response";
    const panel_title = if (status_code == 404) "No matching server surface" else "Boundary held";
    const panel_text = if (status_code == 404) "Try the root page, health check, or static sample." else "The request stopped inside a controlled response path.";

    return std.fmt.allocPrint(
        allocator,
        \\<!doctype html>
        \\<html lang="en">
        \\<head>
        \\<meta charset="utf-8">
        \\<meta name="viewport" content="width=device-width, initial-scale=1">
        \\<title>{d} · {s}</title>
        \\<link rel="icon" type="image/svg+xml" href="/favicon.svg">
        \\</head>
        \\<body style="box-sizing:border-box;margin:0;min-height:100vh;overflow-x:hidden;background:radial-gradient(circle at 16% -12%, rgba(255,255,255,0.92), transparent 28%),linear-gradient(180deg,#f7f4ed 0%,#f0ece2 46%,#e9e3d6 100%);color:#11110f;font:14px/1.6 Instrument Sans,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;">
        \\<div style="position:fixed;inset:0;z-index:-2;background:linear-gradient(rgba(15,15,12,0.05) 1px, transparent 1px),linear-gradient(90deg, rgba(15,15,12,0.05) 1px, transparent 1px);background-size:64px 64px;pointer-events:none;"></div>
        \\<div style="position:fixed;inset:0;z-index:-1;background:radial-gradient(circle at 50% 18%, transparent 0 28%, rgba(244,241,234,0.28) 62%, rgba(214,204,186,0.42) 100%),linear-gradient(90deg,rgba(17,17,15,0.035),transparent 18%,transparent 82%,rgba(17,17,15,0.035));pointer-events:none;"></div>
        \\<main style="max-width:1280px;margin:0 auto;padding:18px 30px 72px;">
        \\<header style="display:flex;align-items:center;justify-content:space-between;gap:16px;margin:0 auto 10px;padding:10px;border:1px solid rgba(17,17,15,0.12);border-radius:18px;background:rgba(251,250,246,0.82);box-shadow:0 18px 60px rgba(38,34,24,0.09);backdrop-filter:blur(22px);">
        \\<a href="/" style="display:flex;gap:12px;align-items:center;color:inherit;text-decoration:none;">
        \\<img src="/favicon.svg" alt="" width="40" height="40" style="display:block;width:40px;height:40px;border-radius:12px;box-shadow:0 18px 36px rgba(17,17,15,0.08);">
        \\<span><strong style="display:block;font-size:16px;line-height:1.1;font-weight:700;letter-spacing:-0.035em;">{s}</strong><small style="display:block;color:#8b8c84;font-size:11px;line-height:1.1;">{s}</small></span>
        \\</a>
        \\<nav style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
        \\<a href="/health" style="display:inline-flex;align-items:center;padding:9px 13px;border-radius:12px;border:1px solid rgba(15,15,12,0.14);background:rgba(255,255,255,0.5);color:#11110f;text-decoration:none;">Health</a>
        \\<a href="/static/hello.txt" style="display:inline-flex;align-items:center;padding:9px 13px;border-radius:12px;border:1px solid rgba(15,15,12,0.14);background:rgba(255,255,255,0.5);color:#11110f;text-decoration:none;">Static</a>
        \\</nav>
        \\</header>
        \\<section style="position:relative;min-height:min(740px,calc(100svh - 130px));display:grid;grid-template-columns:repeat(auto-fit,minmax(min(360px,100%),1fr));gap:clamp(28px,6vw,86px);align-items:center;overflow:hidden;margin:0 calc(50% - 50vw) 56px;padding:clamp(42px,8vw,92px) max(30px,calc((100vw - 1280px) / 2 + 30px));border-bottom:1px solid rgba(15,15,12,0.12);background:radial-gradient(circle at 74% 42%,rgba(17,17,15,0.14),transparent 18%),linear-gradient(rgba(17,17,15,0.055) 1px,transparent 1px),linear-gradient(90deg,rgba(17,17,15,0.055) 1px,transparent 1px),linear-gradient(135deg,rgba(251,250,246,0.95),rgba(231,225,212,0.84));background-size:auto,56px 56px,56px 56px,auto;">
        \\<div style="position:absolute;right:clamp(-36px,3vw,44px);bottom:clamp(-18px,2vw,26px);color:rgba(17,17,15,0.045);font:800 clamp(180px,30vw,420px)/0.78 Instrument Sans,ui-sans-serif,system-ui,sans-serif;letter-spacing:-0.12em;pointer-events:none;">{d}</div>
        \\<div style="position:relative;z-index:2;max-width:650px;">
        \\<div style="display:inline-flex;align-items:center;gap:8px;padding:6px 10px;margin-bottom:16px;border-radius:999px;border:1px solid rgba(17,17,15,0.18);background:rgba(255,255,255,0.58);color:#5d5e58;font:11px/1 IBM Plex Mono,ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:0.16em;text-transform:uppercase;">{s}</div>
        \\<h1 style="margin:0 0 18px;max-width:10ch;font-size:clamp(56px,8vw,118px);line-height:0.88;letter-spacing:-0.075em;">{s}</h1>
        \\<p style="max-width:50ch;margin:0 0 18px;color:#5d5e58;font-size:clamp(16px,1.3vw,19px);">{s}</p>
        \\<div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:24px;">
        \\<a href="/" style="display:inline-flex;align-items:center;padding:9px 13px;border-radius:12px;border:1px solid #11110f;background:#11110f;color:#fbfaf6;text-decoration:none;font-weight:600;box-shadow:0 18px 36px rgba(17,17,15,0.16);">Return home</a>
        \\<a href="/health" style="display:inline-flex;align-items:center;padding:9px 13px;border-radius:12px;border:1px solid rgba(15,15,12,0.14);background:rgba(255,255,255,0.5);color:#11110f;text-decoration:none;">Check health</a>
        \\<a href="/static/hello.txt" style="display:inline-flex;align-items:center;padding:9px 13px;border-radius:12px;border:1px solid rgba(15,15,12,0.14);background:rgba(255,255,255,0.5);color:#11110f;text-decoration:none;">Static sample</a>
        \\</div>
        \\</div>
        \\<aside aria-hidden="true" style="position:relative;z-index:1;min-height:420px;width:100%;border:1px solid rgba(17,17,15,0.16);border-radius:28px;overflow:hidden;background:rgba(251,250,246,0.72);box-shadow:0 44px 110px rgba(38,34,24,0.14);backdrop-filter:blur(18px);">
        \\<div style="position:absolute;inset:0;background:linear-gradient(rgba(17,17,15,0.08) 1px,transparent 1px),linear-gradient(90deg,rgba(17,17,15,0.08) 1px,transparent 1px);background-size:44px 44px;"></div>
        \\<div style="position:absolute;left:28px;right:28px;top:28px;display:flex;justify-content:space-between;gap:16px;padding:12px 14px;border:1px solid rgba(17,17,15,0.14);border-radius:999px;background:rgba(251,250,246,0.86);color:#8b8c84;font:11px/1.2 IBM Plex Mono,ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:0.08em;text-transform:uppercase;"><span>{s}</span><span>/{d}</span></div>
        \\<div style="position:absolute;left:20%;right:24%;top:48%;height:1px;background:repeating-linear-gradient(90deg,rgba(17,17,15,0.42) 0 12px,transparent 12px 22px);transform:rotate(-9deg);"></div>
        \\<div style="position:absolute;left:18%;top:34%;width:12px;height:12px;border-radius:999px;background:#11110f;box-shadow:0 0 0 9px rgba(17,17,15,0.08);"></div>
        \\<div style="position:absolute;right:22%;top:44%;width:12px;height:12px;border-radius:999px;background:#11110f;box-shadow:0 0 0 9px rgba(17,17,15,0.08);"></div>
        \\<div style="position:absolute;left:46%;bottom:24%;width:12px;height:12px;border-radius:999px;background:#11110f;box-shadow:0 0 0 9px rgba(17,17,15,0.08);"></div>
        \\<div style="position:absolute;left:28px;right:28px;bottom:28px;display:grid;grid-template-columns:1fr auto;gap:18px;align-items:end;padding:18px;border-top:1px solid rgba(17,17,15,0.12);background:rgba(251,250,246,0.78);">
        \\<div><strong style="display:block;margin-bottom:5px;font-size:18px;letter-spacing:-0.04em;">{s}</strong><span style="color:#5d5e58;font-size:13px;">{s}</span></div>
        \\<div style="font:600 48px/0.9 Instrument Sans,ui-sans-serif,system-ui,sans-serif;letter-spacing:-0.08em;">{d}</div>
        \\</div>
        \\</aside>
        \\</section>
        \\</main>
        \\</body>
        \\</html>
        \\
    ,
        .{
            status_code,
            server_name,
            server_name,
            server_tagline,
            status_code,
            eyebrow,
            headline,
            detail,
            route_label,
            status_code,
            panel_title,
            panel_text,
            status_code,
        },
    );
}
