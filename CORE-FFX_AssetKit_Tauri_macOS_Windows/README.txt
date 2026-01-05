CORE FFX Asset Kit (Tauri + macOS + Windows)

Contents:
- png/: PNG exports at multiple sizes
- svg/: SVG wrapper (embedded PNG) for easy placement in docs/web
- macos/core-ffx.icns: macOS icon bundle (PNG-based ICNS)
- windows/core-ffx.ico: Windows multi-size ICO
- tauri/icons/: drop-in folder for src-tauri/icons (icon.png, icon.ico, icon.icns, plus common PNGs)

Usage (Tauri):
- Copy tauri/icons/* into your project at src-tauri/icons/
- Ensure tauri.conf.json points to icons, or keep default naming (icon.png, icon.ico, icon.icns)
