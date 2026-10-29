# laina

same character, refreshed artwork: black and teal twin tails, coral clips, a teal scarf and an off-white utility jacket. the original stays in `public/laina.png`; the website and readme use `public/laina-v2.png`.

created with the built-in image generation tool using the original artwork as the edit reference.

## artwork prompt

Use case: identity-preserve. Edit target: the provided illustration of Laina, Layerline's anime mascot. Refresh her artwork as a beautifully finished professional 2D anime character key visual, NOT a redesign. Preserve her recognizable face, turquoise eyes, black long twin ponytails with teal inner streaks and tips, single ahoge, coral angular lightning-shaped hair clips, large teal scarf, off-white utility jacket with charcoal technical panels and teal piping, black pleated skirt and belt. Keep the same friendly, quietly confident personality and adult proportions. Crisp elegant anime linework, sophisticated clean cel shading, controlled highlights and fine fabric detail, no photorealism or 3D. Change the pose slightly: three-quarter standing portrait from head to mid-thigh, her left arm relaxed down with its complete hand clearly visible beside her hip, and her right hand raised near shoulder height in a small natural open-palmed greeting, all five fingers visible and anatomically correct on EACH hand. Both hands, all hair, hair clips and scarf stay comfortably inside the frame. No missing limbs, extra fingers, extra hands, or cropped fingers. Remove the surrounding network lines and dots. Isolated character with genuinely transparent alpha background, absolutely no printed checkerboard, no white background, no floor, no vignette, no text, no logos, no surrounding objects or UI. This is a transparent website hero asset. Preserve the established black/teal/coral/off-white character palette and design exactly; improve illustration polish and expression rather than changing outfit or identity.

## cleanup prompt

Keep the exact character, pose and details unchanged. Remove all backdrop, glow, haze and shadows outside the silhouette, including between hair strands and fingers. Preserve clean anti-aliased edges. Output a genuinely transparent character cutout, with no printed checkerboard or background.

## website checks

with the local server running using `examples/local.conf`, and Playwright available to Node:

```sh
node scripts/verify-website.cjs
```

`LAYERLINE_BROWSER_CHANNEL=chrome` uses an installed Chrome instead of Playwright's bundled browser. the check covers eight viewport sizes, artwork transparency, keyboard tabs, clipboard success and denial, no-JavaScript content, reduced motion, config validation and the disabled admin route. screenshots go to the system temp directory by default; set `LAYERLINE_SITE_SCREENSHOTS` to change it.
