from pathlib import Path
import json
import os
import re
import sys
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent

SO_BASE_DIR = ROOT / "detections" / "security-onion"
SO_SURICATA_DIR = SO_BASE_DIR / "suricata"
SO_ZEEK_DIR = SO_BASE_DIR / "zeek"

STATE_FILE = ROOT / "state" / "securityonion_rule_state.json"

SO_UI_URL = os.getenv("SO_UI_URL", "").strip().rstrip("/")
SO_UI_USERNAME = os.getenv("SO_UI_USERNAME", "").strip()
SO_UI_PASSWORD = os.getenv("SO_UI_PASSWORD", "").strip()

SHORT_WAIT_MS = 1500
MEDIUM_WAIT_MS = 3000
LONG_WAIT_MS = 5000

ALLOWED_STATE_ENGINES = {"suricata", "zeek"}


def fail(msg: str):
    print(f"[FAIL] {msg}")
    sys.exit(1)


def log(msg: str):
    print(f"[INFO] {msg}")


def write_debug_html(page, filename: str = "so_debug_page.html"):
    debug_path = ROOT / filename
    debug_path.write_text(page.content(), encoding="utf-8")
    print(f"[INFO] Wrote debug HTML to {debug_path}")


def normalize_rule_content(content: str) -> str:
    return " ".join(content.split())


def extract_msg(content: str, fallback: str) -> str:
    match = re.search(r'msg:"([^"]+)"', content)
    return match.group(1) if match else fallback


def extract_sid(content: str):
    match = re.search(r"sid:(\d+)", content)
    return match.group(1) if match else None


def ensure_state_file_exists():
    if not STATE_FILE.exists():
        fail(
            "Missing required state file: state/securityonion_rule_state.json. "
            "Create it before running deployment."
        )

    if not STATE_FILE.is_file():
        fail(
            "state/securityonion_rule_state.json exists but is not a file. "
            "It must be a JSON file, not a directory."
        )


def load_state() -> dict:
    ensure_state_file_exists()

    try:
        raw = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        fail(f"State file is not valid JSON: {e}")
    except Exception as e:
        fail(f"Unable to read state file: {e}")

    if not isinstance(raw, dict):
        fail("State file must contain a top-level JSON object")

    for engine in ALLOWED_STATE_ENGINES:
        raw.setdefault(engine, {})

    extra_keys = set(raw.keys()) - ALLOWED_STATE_ENGINES
    if extra_keys:
        fail(
            "State file contains unsupported top-level keys: "
            + ", ".join(sorted(extra_keys))
        )

    for engine, entries in raw.items():
        if not isinstance(entries, dict):
            fail(f"State section '{engine}' must be an object")
        for name, content in entries.items():
            if not isinstance(name, str) or not name.strip():
                fail(f"Invalid rule name found in state section '{engine}'")
            if not isinstance(content, str) or not content.strip():
                fail(
                    f"State entry '{engine}:{name}' must contain a non-empty rule string"
                )

    return raw


def save_state(state: dict):
    STATE_FILE.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


def parse_suricata_rule(name: str, content: str) -> dict:
    normalized = normalize_rule_content(content)
    return {
        "engine": "suricata",
        "name": name,
        "content": normalized,
        "msg": extract_msg(normalized, Path(name).stem),
        "sid": extract_sid(normalized),
    }


def collect_repo_state() -> dict:
    repo_state = {
        "suricata": {},
        "zeek": {},
    }

    if SO_SURICATA_DIR.exists():
        if not SO_SURICATA_DIR.is_dir():
            fail("detections/security-onion/suricata must be a directory")
        for path in sorted(SO_SURICATA_DIR.glob("*.rules")):
            content = path.read_text(encoding="utf-8", errors="ignore").strip()
            if not content:
                fail(f"{path.relative_to(ROOT)} is empty")
            repo_state["suricata"][path.name] = normalize_rule_content(content)

    if SO_ZEEK_DIR.exists():
        if not SO_ZEEK_DIR.is_dir():
            fail("detections/security-onion/zeek must be a directory")
        for path in sorted(p for p in SO_ZEEK_DIR.rglob("*") if p.is_file()):
            content = path.read_text(encoding="utf-8", errors="ignore").strip()
            if not content:
                fail(f"{path.relative_to(ROOT)} is empty")
            relative_name = path.relative_to(SO_ZEEK_DIR).as_posix()
            repo_state["zeek"][relative_name] = normalize_rule_content(content)

    return repo_state


def build_repo_state_changes(repo_state: dict, saved_state: dict) -> list[dict]:
    changes = []

    for engine in sorted(ALLOWED_STATE_ENGINES):
        repo_rules = repo_state.get(engine, {})
        state_rules = saved_state.get(engine, {})

        repo_names = set(repo_rules.keys())
        state_names = set(state_rules.keys())

        for name in sorted(repo_names - state_names):
            changes.append(
                {
                    "source": "repo_state",
                    "engine": engine,
                    "action": "create",
                    "name": name,
                    "new_content": repo_rules[name],
                    "old_content": None,
                }
            )

        for name in sorted(state_names - repo_names):
            changes.append(
                {
                    "source": "repo_state",
                    "engine": engine,
                    "action": "delete",
                    "name": name,
                    "new_content": None,
                    "old_content": state_rules[name],
                }
            )

        for name in sorted(repo_names & state_names):
            repo_content = normalize_rule_content(repo_rules[name])
            state_content = normalize_rule_content(state_rules[name])
            if repo_content != state_content:
                changes.append(
                    {
                        "source": "repo_state",
                        "engine": engine,
                        "action": "update",
                        "name": name,
                        "new_content": repo_content,
                        "old_content": state_content,
                    }
                )

    return changes


def ui_login(page):
    page.goto(f"{SO_UI_URL}/login", wait_until="domcontentloaded")
    page.wait_for_timeout(MEDIUM_WAIT_MS)

    email = page.locator('[data-aid="login_email_input"] input')
    password = page.locator('[data-aid="login_password_input"] input')
    button = page.locator('[data-aid="login_password_submit"]')

    email.click()
    email.type(SO_UI_USERNAME, delay=100)
    page.wait_for_timeout(SHORT_WAIT_MS)

    password.click()
    password.type(SO_UI_PASSWORD, delay=100)
    page.wait_for_timeout(MEDIUM_WAIT_MS)

    button.wait_for(state="visible", timeout=10000)
    page.wait_for_function("(el) => !el.disabled", arg=button.element_handle())
    button.click()

    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(LONG_WAIT_MS)
    print("[PASS] Logged into Security Onion UI")


def go_to_detections(page):
    page.goto(f"{SO_UI_URL}/#/detections", wait_until="networkidle")
    page.wait_for_timeout(LONG_WAIT_MS)


def search_for_rule(page, text: str):
    go_to_detections(page)

    search_selectors = [
        'input[placeholder*="search" i]',
        '[data-aid*="search"] input',
        'input[type="text"]',
    ]

    for selector in search_selectors:
        try:
            box = page.locator(selector).first
            if box.count() > 0:
                box.fill("")
                page.wait_for_timeout(SHORT_WAIT_MS)
                box.type(text, delay=60)
                page.wait_for_timeout(MEDIUM_WAIT_MS)
                return
        except Exception:
            pass

    write_debug_html(page)
    fail("Could not find the detections search box")


def rule_candidates(page, rule: dict):
    candidates = []
    if rule.get("sid"):
        candidates.append(page.get_by_text(rule["sid"], exact=False))
    if rule.get("msg"):
        candidates.append(page.get_by_text(rule["msg"], exact=False))
    candidates.append(page.get_by_text(rule["name"], exact=False))
    return candidates


def find_rule_in_ui(page, rule: dict) -> bool:
    lookup = rule.get("sid") or rule.get("msg") or rule["name"]
    search_for_rule(page, lookup)

    for candidate in rule_candidates(page, rule):
        try:
            if candidate.count() > 0:
                return True
        except Exception:
            pass

    return False


def open_rule_in_ui(page, rule: dict) -> bool:
    lookup = rule.get("sid") or rule.get("msg") or rule["name"]
    search_for_rule(page, lookup)

    for candidate in rule_candidates(page, rule):
        try:
            candidate.first.click(force=True, timeout=3000)
            page.wait_for_load_state("networkidle")
            page.wait_for_timeout(LONG_WAIT_MS)
            return True
        except Exception:
            pass

    return False


def open_create_detection_dialog(page):
    go_to_detections(page)

    plus_selectors = [
        '[data-aid*="create"]',
        '[data-aid*="add"]',
        'button[aria-label*="add" i]',
        'button[aria-label*="create" i]',
        'button:has(.fa-plus)',
        'button:has(.mdi-plus)',
        'button:has(svg)',
    ]

    for selector in plus_selectors:
        try:
            locator = page.locator(selector).first
            if locator.is_visible(timeout=2000):
                locator.click(timeout=3000)
                page.wait_for_timeout(MEDIUM_WAIT_MS)
                return
        except Exception:
            pass

    write_debug_html(page)
    fail("Could not find/click the create button on the Detections page")


def fill_suricata_detection_form(page, rule: dict):
    language_selectors = [
        '#detection-language-create',
        '#detection-language-edit',
    ]
    license_selectors = [
        '#detection-license-create',
        '#detection-license-edit',
    ]
    signature_selectors = [
        '#detection-signature-create',
        '#detection-signature-edit',
        'textarea',
        '[data-aid*="signature"] textarea',
    ]

    language = None
    for selector in language_selectors:
        locator = page.locator(selector)
        if locator.count() > 0:
            language = locator.first
            break

    if language is None:
        write_debug_html(page)
        fail("Could not find Language field")

    language.click(force=True)
    page.wait_for_timeout(SHORT_WAIT_MS)
    page.get_by_role("option", name=re.compile(r"^Suricata$", re.I)).click()
    page.wait_for_timeout(MEDIUM_WAIT_MS)

    license_box = None
    for selector in license_selectors:
        locator = page.locator(selector)
        if locator.count() > 0:
            license_box = locator.first
            break

    if license_box is None:
        write_debug_html(page)
        fail("Could not find License field")

    license_box.click(force=True)
    page.wait_for_timeout(SHORT_WAIT_MS)
    page.get_by_role("option", name=re.compile(r"GPL-2.0", re.I)).click()
    page.wait_for_timeout(MEDIUM_WAIT_MS)

    for selector in signature_selectors:
        try:
            locator = page.locator(selector).first
            if locator.count() > 0:
                locator.click(force=True)
                page.wait_for_timeout(SHORT_WAIT_MS)
                locator.fill(rule["content"])
                page.wait_for_timeout(MEDIUM_WAIT_MS)
                return
        except Exception:
            pass

    write_debug_html(page)
    fail("Could not fill Signature field")


def click_first_matching_button(page, patterns: list[str], failure_message: str):
    for pattern in patterns:
        try:
            page.get_by_role("button", name=re.compile(pattern, re.I)).first.click(
                force=True,
                timeout=3000,
            )
            page.wait_for_timeout(MEDIUM_WAIT_MS)
            return
        except Exception:
            pass

    write_debug_html(page)
    fail(failure_message)


def get_current_signature(page) -> str:
    signature_selectors = [
        '#detection-signature-edit',
        '#detection-signature-create',
        'textarea',
        '[data-aid*="signature"] textarea',
    ]
    for selector in signature_selectors:
        try:
            locator = page.locator(selector).first
            if locator.count() > 0:
                return normalize_rule_content(locator.input_value())
        except Exception:
            pass
    return ""


def create_suricata_rule_in_ui(page, rule: dict):
    log(f"Creating detection in UI for {rule['name']}")
    open_create_detection_dialog(page)
    fill_suricata_detection_form(page, rule)
    click_first_matching_button(page, [r"Create"], "Could not click Create button")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(LONG_WAIT_MS)
    print(f"[PASS] Created detection in UI for {rule['name']}")


def verify_suricata_rule_matches_ui(page, rule: dict):
    if not open_rule_in_ui(page, rule):
        fail(f"Rule was not found in UI after deployment: {rule['name']}")

    current_signature = get_current_signature(page)
    desired_signature = normalize_rule_content(rule["content"])

    if current_signature != desired_signature:
        fail(
            f"UI signature mismatch for {rule['name']}. "
            "The detection exists, but the stored signature does not match the repo/state."
        )

    go_to_detections(page)
    print(f"[PASS] Verified detection content in UI for {rule['name']}")


def verify_suricata_rule_absent_in_ui(page, rule: dict):
    if find_rule_in_ui(page, rule):
        fail(f"Rule still appears in UI after deletion: {rule['name']}")
    print(f"[PASS] Verified detection removal in UI for {rule['name']}")


def delete_suricata_rule_in_ui(page, rule: dict):
    log(f"Deleting detection in UI for {rule['name']}")

    if not open_rule_in_ui(page, rule):
        log(f"Rule not found in UI for deletion; continuing: {rule['name']}")
        return

    click_first_matching_button(page, [r"Delete"], "Could not click Delete button")

    try:
        click_first_matching_button(
            page,
            [r"Delete", r"Confirm"],
            "Could not confirm deletion",
        )
    except SystemExit:
        pass

    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(LONG_WAIT_MS)
    go_to_detections(page)
    print(f"[PASS] Deleted detection in UI for {rule['name']}")


def differential_update_suricata(page):
    go_to_detections(page)

    option_selectors = [
        'text=Options',
        '[data-aid*="options"]',
        'button:has-text("Options")',
        '[role="button"]:has-text("Options")',
    ]

    opened = False
    for selector in option_selectors:
        try:
            page.locator(selector).first.click(force=True, timeout=3000)
            opened = True
            break
        except Exception:
            pass

    if not opened:
        write_debug_html(page)
        fail("Could not click Options on the detections list page")

    page.wait_for_timeout(SHORT_WAIT_MS)

    try:
        page.get_by_text(re.compile(r"Differential Update", re.I)).click(force=True)
    except Exception:
        write_debug_html(page)
        fail("Could not click Differential Update")

    page.wait_for_timeout(10000)
    print("[PASS] Ran Suricata Differential Update")


def collect_suricata_ui_drift(page, saved_state: dict) -> list[dict]:
    drifts = []

    for name, content in sorted(saved_state.get("suricata", {}).items()):
        expected_rule = parse_suricata_rule(name, content)
        exists_in_ui = find_rule_in_ui(page, expected_rule)

        if not exists_in_ui:
            drifts.append(
                {
                    "source": "ui_drift",
                    "engine": "suricata",
                    "action": "repair_missing",
                    "name": name,
                    "new_content": content,
                    "old_content": content,
                }
            )
            continue

        if not open_rule_in_ui(page, expected_rule):
            drifts.append(
                {
                    "source": "ui_drift",
                    "engine": "suricata",
                    "action": "repair_missing",
                    "name": name,
                    "new_content": content,
                    "old_content": content,
                }
            )
            continue

        current_signature = get_current_signature(page)
        expected_signature = normalize_rule_content(content)

        if current_signature != expected_signature:
            drifts.append(
                {
                    "source": "ui_drift",
                    "engine": "suricata",
                    "action": "repair_mismatch",
                    "name": name,
                    "new_content": content,
                    "old_content": content,
                }
            )

        go_to_detections(page)

    return drifts


def select_effective_single_change(repo_state_changes: list[dict], ui_drift_changes: list[dict]) -> dict | None:
    total = len(repo_state_changes) + len(ui_drift_changes)

    log(
        "Computed repo/state changes: "
        + (
            ", ".join(f"{c['engine']}:{c['action']}:{c['name']}" for c in repo_state_changes)
            if repo_state_changes
            else "none"
        )
    )
    log(
        "Computed UI drift changes: "
        + (
            ", ".join(f"{c['engine']}:{c['action']}:{c['name']}" for c in ui_drift_changes)
            if ui_drift_changes
            else "none"
        )
    )

    if total == 0:
        return None

    if total > 1:
        combined = repo_state_changes + ui_drift_changes
        formatted = ", ".join(
            f"{item['source']}:{item['engine']}:{item['action']}:{item['name']}"
            for item in combined
        )
        fail(
            "Only one effective Security Onion rule change is allowed per run. "
            f"Detected {total} changes/drifts: {formatted}"
        )

    if repo_state_changes:
        return repo_state_changes[0]

    return ui_drift_changes[0]


def apply_single_change(page, change: dict, saved_state: dict):
    if change["engine"] == "zeek":
        fail(
            "Zeek state tracking is supported, but Zeek UI deployment logic has not "
            "been implemented yet. This run contains a Zeek rule change."
        )

    if change["engine"] != "suricata":
        fail(f"Unsupported detection engine: {change['engine']}")

    old_rule = None
    if change["old_content"]:
        old_rule = parse_suricata_rule(change["name"], change["old_content"])

    new_rule = None
    if change["new_content"]:
        new_rule = parse_suricata_rule(change["name"], change["new_content"])

    if change["source"] == "repo_state" and change["action"] == "create":
        create_suricata_rule_in_ui(page, new_rule)
        differential_update_suricata(page)
        verify_suricata_rule_matches_ui(page, new_rule)
        saved_state["suricata"][change["name"]] = new_rule["content"]
        save_state(saved_state)
        return

    if change["source"] == "repo_state" and change["action"] == "delete":
        delete_suricata_rule_in_ui(page, old_rule)
        differential_update_suricata(page)
        verify_suricata_rule_absent_in_ui(page, old_rule)
        saved_state["suricata"].pop(change["name"], None)
        save_state(saved_state)
        return

    if change["source"] == "repo_state" and change["action"] == "update":
        delete_suricata_rule_in_ui(page, old_rule)
        differential_update_suricata(page)
        verify_suricata_rule_absent_in_ui(page, old_rule)

        create_suricata_rule_in_ui(page, new_rule)
        differential_update_suricata(page)
        verify_suricata_rule_matches_ui(page, new_rule)

        saved_state["suricata"][change["name"]] = new_rule["content"]
        save_state(saved_state)
        return

    if change["source"] == "ui_drift" and change["action"] in {"repair_missing", "repair_mismatch"}:
        if old_rule:
            delete_suricata_rule_in_ui(page, old_rule)
            differential_update_suricata(page)
            verify_suricata_rule_absent_in_ui(page, old_rule)

        create_suricata_rule_in_ui(page, new_rule)
        differential_update_suricata(page)
        verify_suricata_rule_matches_ui(page, new_rule)

        saved_state["suricata"][change["name"]] = new_rule["content"]
        save_state(saved_state)
        return

    fail(
        f"Unsupported change type encountered: "
        f"{change['source']}:{change['action']}:{change['name']}"
    )


def main():
    if not SO_UI_URL or not SO_UI_USERNAME or not SO_UI_PASSWORD:
        fail("Missing SO_UI_URL, SO_UI_USERNAME, or SO_UI_PASSWORD")

    saved_state = load_state()
    repo_state = collect_repo_state()
    repo_state_changes = build_repo_state_changes(repo_state, saved_state)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(ignore_https_errors=True)

        try:
            ui_login(page)

            ui_drift_changes = collect_suricata_ui_drift(page, saved_state)
            effective_change = select_effective_single_change(repo_state_changes, ui_drift_changes)

            if not effective_change:
                print("[PASS] No Security Onion repo/state changes or UI drift detected")
                return

            log(
                f"Processing single effective Security Onion change: "
                f"{effective_change['source']}:{effective_change['engine']}:"
                f"{effective_change['action']}:{effective_change['name']}"
            )

            apply_single_change(page, effective_change, saved_state)
            print("[PASS] Security Onion deployment completed successfully")
        finally:
            browser.close()


if __name__ == "__main__":
    main()