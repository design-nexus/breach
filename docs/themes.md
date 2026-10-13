# Crimson

Crimson is the default security-console theme: near-black surfaces, crimson focus and shortcut caps, steel-gray text, cyan data, green success, amber warnings, and red errors. Selected rows use a dark crimson background and lighter crimson text. Titles now use larger native terminal pixel lettering in the solid active theme accent (Crimson #FF4D6D), matching focused borders and shortcut caps. Navigation and other theme colors remain intact.

Open **Ctrl+K**, search for **Crimson theme** or **Aurora theme**, and press Enter. Aurora remains available alongside Follow Omarchy and Terminal. Missing or unknown theme IDs fall back to Crimson; explicit saved choices are preserved.

This installation selects Crimson in the existing config location; only its theme value was changed. Other settings and permissions were preserved, with a backup of an existing config made before the change.

Verification: both security tools passed theme-resolution and config round-trip tests and every screen/pane at 120×40, 100×30, 80×24, and 60×20 in Crimson and Aurora. Actual Foot screenshots were inspected, including menus and confirmations. A compact Breach confirmation overlap and a hidden compact wizard picker were corrected, with selection-visibility regression coverage.

See [navigation verification](navigation.md). README screenshots show actual Foot renders with sample data; no scan or exploitation against a target was run.

Pixel titles were checked in actual Foot screenshots at 120×40, 100×30, 80×24, and 60×20. Native block glyphs replace the smooth Sixel overlay, so the same pixel lettering works without image support. Breach’s compact host list reserves enough room for its selected row beneath the taller header.
