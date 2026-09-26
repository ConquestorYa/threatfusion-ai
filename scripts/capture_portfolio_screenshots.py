from __future__ import annotations

from pathlib import Path

from playwright.sync_api import Page, sync_playwright


BASE_URL = "http://127.0.0.1:8501"
OUT_DIR = Path("docs/screenshots")
APP_SETTLE_MS = 4_000


def wait_for_app(page: Page) -> None:
    page.goto(BASE_URL, wait_until="domcontentloaded", timeout=120_000)
    page.wait_for_selector('[data-testid="stAppViewContainer"]', timeout=120_000)
    page.wait_for_timeout(APP_SETTLE_MS)


def save(page: Page, name: str) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    page.screenshot(
        path=str(OUT_DIR / name),
        full_page=False,
        animations="disabled",
    )


def capture_quick_lookup(page: Page) -> None:
    textbox = page.get_by_label("URL, domain or IP")
    textbox.fill("known-threat.example")
    page.get_by_role("button", name="Check").click()
    page.wait_for_timeout(3_000)
    result = page.get_by_text("Known Threat", exact=False).first
    result.wait_for(timeout=30_000)
    result.evaluate("(el) => el.scrollIntoView({block: 'center'})")
    page.wait_for_timeout(800)
    save(page, "quick-lookup.png")


def open_telemetry(page: Page) -> None:
    page.get_by_role("button", name="Open telemetry analysis").click()
    page.locator('input[type="file"]').first.wait_for(
        state="attached",
        timeout=30_000,
    )
    page.wait_for_timeout(1_500)


def capture_telemetry(page: Page) -> None:
    open_telemetry(page)
    upload = page.locator('input[type="file"]').first
    upload.set_input_files("runtime/portfolio_dns.csv")
    page.wait_for_timeout(1_500)
    analyze = page.get_by_role("button", name="Analyze", exact=True)
    analyze.wait_for(timeout=30_000)
    analyze.click()
    page.wait_for_timeout(5_000)
    findings = page.get_by_text("Priority findings", exact=True)
    findings.wait_for(timeout=45_000)
    findings.scroll_into_view_if_needed()
    page.wait_for_timeout(800)
    save(page, "telemetry-overview.png")


def capture_investigation(page: Page) -> None:
    page.get_by_role("tab", name="Domain investigation").click()
    heading = page.get_by_text("Domain investigation", exact=True).last
    heading.wait_for(timeout=30_000)
    heading.scroll_into_view_if_needed()
    page.wait_for_timeout(1_000)
    save(page, "investigation.png")


def main() -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 960})
        wait_for_app(page)
        capture_quick_lookup(page)
        capture_telemetry(page)
        capture_investigation(page)
        browser.close()


if __name__ == "__main__":
    main()
