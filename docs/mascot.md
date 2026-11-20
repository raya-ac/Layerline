# laina

same character, refreshed artwork: black and teal twin tails, coral clips, a teal scarf and an off-white utility jacket. the original stays in `public/laina.png`; the website and readme use `public/laina-v2.png`.

v2 is a generated edit of the original. keep the background transparent so she doesn't have a white box around her on the site.

## website checks

with the local server running using `examples/local.conf`, and Playwright available to Node:

```sh
node scripts/verify-website.cjs
```

set `LAYERLINE_BROWSER_CHANNEL=chrome` to use Chrome if it's already installed.
use `LAYERLINE_SITE_BINARY` to check the config examples with a different build.
the check runs at eight screen sizes and tries the tabs, copy buttons, and
reduced-motion and no-JavaScript views. it also checks that the artwork is still
transparent and web admin is still off. screenshots go in the temp directory
unless you set `LAYERLINE_SITE_SCREENSHOTS`.
