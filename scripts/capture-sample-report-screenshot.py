#!/usr/bin/env python3
"""Capture sample HTML report screenshot (synthetic only)."""
from __future__ import annotations
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
HTML = ROOT / "examples" / "sample-report.html"
OUT = ROOT / "docs" / "images" / "sample-ad-security-posture-report.png"

def main() -> int:
    if not HTML.exists():
        print("sample-report.html missing", file=sys.stderr)
        return 1
    text = HTML.read_text(encoding="utf-8")
    if "SYNTHETIC DEMONSTRATION DATA" not in text:
        print("Refusing non-synthetic HTML", file=sys.stderr)
        return 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    browsers = []
    for name in ("msedge", "chrome", "chromium", "google-chrome"):
        path = shutil.which(name)
        if path:
            browsers.append(path)
    # Windows common paths
    for p in (
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    ):
        if pathlib.Path(p).exists():
            browsers.append(p)
    if not browsers:
        print("No Edge/Chrome/Chromium found", file=sys.stderr)
        return 1
    browser = browsers[0]
    with tempfile.TemporaryDirectory() as td:
        profile = pathlib.Path(td) / "profile"
        profile.mkdir()
        uri = HTML.resolve().as_uri()
        cmd = [
            browser,
            "--headless=new",
            "--disable-gpu",
            f"--user-data-dir={profile}",
            "--hide-scrollbars",
            "--window-size=1440,1000",
            f"--screenshot={OUT}",
            uri,
        ]
        print("Running:", " ".join(cmd))
        subprocess.run(cmd, check=True)
    if not OUT.exists() or OUT.stat().st_size < 1000:
        print("Screenshot missing or empty", file=sys.stderr)
        return 1
    print(f"Wrote {OUT} ({OUT.stat().st_size} bytes)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
