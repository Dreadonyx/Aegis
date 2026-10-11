"""Run against a fresh local database: AEGIS_TEST_URL defaults to port 8001."""
import json
import os
import socket
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

url = os.environ.get("AEGIS_TEST_URL", "http://127.0.0.1:8000")
if url == "http://127.0.0.1:8000":
    with socket.create_connection(("127.0.0.1", 2222), timeout=5) as connection:
        assert connection.recv(256).startswith(b"SSH-2.0-"), "Cowrie SSH relay is not ready"
Path("test-results").mkdir(exist_ok=True)
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page(viewport={"width": 1440, "height": 1050}, device_scale_factor=1)
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(url)
    if url == "http://127.0.0.1:8000":
        page.wait_for_function("async () => (await (await fetch('/api/overview?source=imported')).json()).events > 0", timeout=10000)
    page.locator("#replay").click()
    expect(page.locator("#metric-events")).to_have_text("18")
    expect(page.locator(".incident-item")).to_have_count(3)
    expect(page.locator(".timeline-event")).not_to_have_count(0)
    page.screenshot(path="test-results/aegis-desktop.png", full_page=True)
    page.locator("#incident-status").select_option("investigating")
    expect(page.locator("#notice")).to_have_text("Incident status saved.")
    page.reload()
    expect(page.locator("#incident-status")).to_have_value("investigating")
    page.locator("#note-text").fill("Reviewed fixture evidence. This is synthetic lab activity.")
    page.locator("#refresh").click()
    expect(page.locator("#note-text")).to_have_value("Reviewed fixture evidence. This is synthetic lab activity.")
    page.get_by_role("button", name="Save note").click()
    expect(page.locator("#notice")).to_have_text("Analyst note saved.")
    page.reload()
    expect(page.locator("#analyst-activity")).to_contain_text("Reviewed fixture evidence.")
    page.locator(".timeline-event .event-link").first.click()
    expect(page.locator("#event-dialog")).to_be_visible()
    expect(page.locator("#event-json")).to_contain_text('"eventid"')
    page.keyboard.press("Escape")
    expect(page.locator("#event-dialog")).not_to_be_visible()
    page.evaluate("window.scrollTo(0, 0)")
    page.screenshot(path="test-results/aegis-desktop.png", full_page=True)
    with page.expect_download() as evidence_download:
        page.get_by_role("link", name="Evidence JSON").click()
    assert evidence_download.value.suggested_filename.endswith("-evidence.json")
    with page.expect_download() as download:
        page.get_by_role("link", name="Export report").click()
    assert "aegis-" in download.value.suggested_filename
    page.locator('[data-view="events"]').click()
    page.locator("#event-search").fill("hostname")
    expect(page.locator("#event-rows tr")).to_have_count(1)
    page.locator('[data-view="rules"]').click()
    expect(page.locator(".rule-row")).to_have_count(11)
    page.locator('[data-view="lab"]').click()
    page.locator("#validate").click()
    expect(page.locator(".evaluation-grid")).to_be_visible()
    expect(page.locator("#check-summary")).to_have_text("31 / 31 passed")
    expect(page.locator("#check-results .check-row")).to_have_count(31)
    expect(page.locator("#baseline-results .check-row")).to_have_count(4)  # cold start shown per metric
    expect(page.locator("#stats-status")).to_contain_text("cold start")
    expect(page.locator("#metric-events")).to_have_text("18")
    malicious_text = '<img src=x onerror="window.injected=true">'
    record = dict(timestamp="2026-10-05T15:00:00Z", eventid="cowrie.command.input", session="browser-import", sensor="local", src_ip="192.0.2.88", input="hostname; "+malicious_text+"\u202e\u001b[31m")
    page.locator("#file-input").set_input_files({"name":"sample.jsonl","mimeType":"application/json","buffer":json.dumps(record).encode()})
    expect(page.locator('[data-source="imported"]')).to_have_class("selected")
    page.locator('[data-view="incidents"]').click()
    expect(page.locator(".timeline-event code")).to_contain_text(malicious_text)
    assert page.evaluate("window.injected") is None
    expect(page.locator(".timeline-event code")).to_contain_text("\\u202e\\u001b[31m")  # bidi override and ANSI escape shown, not applied
    page.locator('[data-source="demo"]').click()
    expect(page.locator(".incident-item")).to_have_count(3)
    page.locator("#workflow-filter").select_option("investigating")
    expect(page.locator(".incident-item")).to_have_count(1)
    page.locator("#workflow-filter").select_option("all")
    page.set_viewport_size({"width":390,"height":844})
    page.screenshot(path="test-results/aegis-mobile.png",full_page=True)
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), "Mobile page overflows"
    assert not errors, errors
    browser.close()
print("Browser smoke passed: replay, status and note persistence, draft preservation, evidence dialog, both exports, search, workflow filters, 31 regression checks, cold-start baselines, import and control-character escaping, mobile layout.")
