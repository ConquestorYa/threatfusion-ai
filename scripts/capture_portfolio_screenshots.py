from __future__ import annotations

from pathlib import Path

from playwright.sync_api import Page, sync_playwright


BASE_URL = "http://127.0.0.1:8501"
OUT_DIR = Path("docs/screenshots")


def wait_for_app(page: Page) -> None:
    page.goto(BASE_URL, wait_until="domcontentloaded", timeout=120_000)
    page.wait_for_selector('[data-testid="stAppViewContainer"]', timeout=120_000)
    page.wait_for_timeout(4_000)


def save(page: Page, name: str) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    page.screenshot(
        path=str(OUT_DIR / name),
        full_page=True,
        animations="disabled",
    )


def capture_quick_lookup(page: Page) -> None:
    textbox = page.get_by_label("URL, domain or IP")
    textbox.fill("known-threat.example")
    page.get_by_role("button", name="Check").click()
    page.wait_for_timeout(3_000)
    page.get_by_text("Known Threat", exact=False).first.wait_for(timeout=30_000)
    save(page, "quick-lookup.png")


def open_telemetry(page: Page) -> None:
    buttons = page.get_by_role("button", name="Analyze telemetry")
    if buttons.count():
        buttons.first.click()
    else:
        page.get_by_text("Analyze telemetry", exact=True).first.click()
    page.wait_for_timeout(2_000)
    page.get_by_text("Upload telemetry", exact=False).first.wait_for(timeout=30_000)


def capture_telemetry(page: Page) -> None:
    open_telemetry(page)
    upload = page.locator('input[type="file"]').first
    upload.set_input_files("runtime/portfolio_dns.csv")
    page.wait_for_timeout(1_500)
    page.get_by_role("button", name="Analyze", exact=True).click()
    page.wait_for_timeout(5_000)
    page.get_by_text("Priority findings", exact=True).wait_for(timeout=45_000)
    save(page, "telemetry-overview.png")


def capture_investigation(page: Page) -> None:
    heading = page.get_by_text("Domain investigation", exact=True)
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
