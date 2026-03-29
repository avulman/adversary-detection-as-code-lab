from pathlib import Path
import json
import os
import re
import sys
from urllib.parse import quote

from playwright.sync_api import sync_playwright, Page, BrowserContext, Locator

ROOT = Path(__file__).resolve().parent.parent

SO_BASE_DIR = ROOT / "detections" / "security-onion"
SO_SURICATA_DIR = SO_BASE_DIR / "suricata"
SO_SIGMA_DIR = SO_BASE_DIR / "sigma"

STATE_DIR = ROOT / "state"
STATE_FILE = STATE_DIR / "securityonion_rule_state.json"

SO_UI_URL = os.getenv("SO_UI_URL", "").strip().rstrip("/")
SO_UI_USERNAME = os.getenv("SO_UI_USERNAME", "").strip()
SO_UI_PASSWORD = os.getenv("SO_UI_PASSWORD", "").strip()

SHORT_WAIT_MS = 1500
MEDIUM_WAIT_MS = 3000
LONG_WAIT_MS = 5000

ALLOWED_STATE_ENGINES = {"suricata", "sigma"}


def fail(msg: str):
    print(f"[FAIL] {msg}")
    sys.exit(1)


def log(msg: str):
    print(f"[INFO] {msg}")


def write_debug_html(page: Page, filename: str = "so_debug_page.html"):
    debug_path = ROOT / filename
    debug_path.write_text(page.content(), encoding="utf-8")
    print(f"[INFO] Wrote debug HTML to {debug_path}")


def print_page_debug(page: Page, label: str):
    print(f"[DEBUG] ===== {label} =====")
    try:
        print(f"[DEBUG] URL: {page.url}")
    except Exception as e:
        print(f"[DEBUG] Could not read page URL: {e}")

    try:
        text = page.locator("body").inner_text(timeout=5000)
        if text:
            trimmed = text[:12000]
            print("[DEBUG] Visible page text start")
            print(trimmed)
            if len(text) > len(trimmed):
                print("[DEBUG] ... visible text truncated ...")
            print("[DEBUG] Visible page text end")
        else:
            print("[DEBUG] Visible page text is empty")
    except Exception as e:
        print(f"[DEBUG] Could not read visible page text: {e}")


def normalize_rule_content(content: str) -> str:
    return " ".join(content.split())


def extract_msg(content: str, fallback: str) -> str:
    match = re.search(r'msg:"([^"]+)"', content)
    return match.group(1).strip() if match else fallback


def extract_yaml_title(content: str, fallback: str) -> str:
    match = re.search(r"(?im)^\s*title:\s*(.+?)\s*$", content)
    if not match:
        return fallback

    value = match.group(1).strip()
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        value = value[1:-1].strip()

    return value or fallback


def ensure_state_dir():
    STATE_DIR.mkdir(parents=True, exist_ok=True)


def load_state() -> dict:
    ensure_state_dir()

    if not STATE_FILE.exists():
        return {"suricata": {}, "sigma": {}}

    if not STATE_FILE.is_file():
        fail(
            "state/securityonion_rule_state.json exists but is not a file. "
            "It must be a JSON file, not a directory."
        )

    try:
        raw = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        fail(f"State file is not valid JSON: {e}")
    except Exception as e:
        fail(f"Unable to read state file: {e}")

    if not isinstance(raw, dict):
        fail("State file must contain a top-level JSON object")

    # Allow legacy zeek key to exist and silently drop it.
    if "zeek" in raw:
        raw.pop("zeek", None)

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
    ensure_state_dir()
    STATE_FILE.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


def parse_suricata_rule(name: str, content: str) -> dict:
    normalized = normalize_rule_content(content)
    return {
        "engine": "suricata",
        "name": name,
        "content": normalized,
        "lookup": extract_msg(normalized, Path(name).stem),
    }


def parse_sigma_rule(name: str, content: str) -> dict:
    normalized = normalize_rule_content(content)
    title = extract_yaml_title(content, Path(name).stem)
    return {
        "engine": "sigma",
        "name": name,
        "content": normalized,
        "lookup": title,
        "title": title,
    }


def collect_repo_state() -> dict:
    repo_state = {
        "suricata": {},
        "sigma": {},
    }

    if SO_SURICATA_DIR.exists():
        if not SO_SURICATA_DIR.is_dir():
            fail("detections/security-onion/suricata must be a directory")
        for path in sorted(SO_SURICATA_DIR.glob("*.rules")):
            content = path.read_text(encoding="utf-8", errors="ignore").strip()
            if not content:
                fail(f"{path.relative_to(ROOT)} is empty")
            repo_state["suricata"][path.name] = normalize_rule_content(content)

    if SO_SIGMA_DIR.exists():
        if not SO_SIGMA_DIR.is_dir():
            fail("detections/security-onion/sigma must be a directory")

        sigma_files = sorted(list(SO_SIGMA_DIR.rglob("*.yml")) + list(SO_SIGMA_DIR.rglob("*.yaml")))
        for path in sigma_files:
            content = path.read_text(encoding="utf-8", errors="ignore").strip()
            if not content:
                fail(f"{path.relative_to(ROOT)} is empty")
            relative_name = path.relative_to(SO_SIGMA_DIR).as_posix()
            repo_state["sigma"][relative_name] = normalize_rule_content(content)

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
                        "engine": engine,
                        "action": "update",
                        "name": name,
                        "new_content": repo_content,
                        "old_content": state_content,
                    }
                )

    return changes


def ui_login(page: Page):
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


def go_to_detections(page: Page):
    page.goto(f"{SO_UI_URL}/#/detections", wait_until="domcontentloaded")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(LONG_WAIT_MS)


def open_detections_in_fresh_tab(context: BrowserContext) -> Page:
    page = context.new_page()
    page.goto(f"{SO_UI_URL}/#/detections", wait_until="domcontentloaded")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(LONG_WAIT_MS)
    return page


def build_detection_title_query(title: str) -> str:
    escaped = title.replace('"', '\\"')
    return f'* AND so_detection.title:"{escaped}"'


def search_for_rule(page: Page, text: str):
    query = build_detection_title_query(text)
    encoded_query = quote(query, safe="")
    page.goto(
        f"{SO_UI_URL}/#/detections?q={encoded_query}",
        wait_until="domcontentloaded",
    )
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(LONG_WAIT_MS)


def _row_from_text_locator(text_locator: Locator) -> Locator | None:
    try:
        if text_locator.count() == 0:
            return None
        row = text_locator.locator("xpath=ancestor::tr[1]")
        if row.count() > 0:
            return row.first
    except Exception:
        pass
    return None


def find_rule_row_in_ui(page: Page, rule: dict) -> Locator | None:
    lookup = rule.get("lookup") or rule["name"]
    search_for_rule(page, lookup)

    title_or_msg = rule.get("lookup")
    if title_or_msg:
        exact_locator = page.get_by_text(title_or_msg, exact=True).first
        row = _row_from_text_locator(exact_locator)
        if row is not None:
            return row

        regex_locator = page.get_by_text(
            re.compile(rf"^{re.escape(title_or_msg)}$")
        ).first
        row = _row_from_text_locator(regex_locator)
        if row is not None:
            return row

    exact_name_locator = page.get_by_text(rule["name"], exact=True).first
    row = _row_from_text_locator(exact_name_locator)
    if row is not None:
        return row

    regex_name_locator = page.get_by_text(
        re.compile(rf"^{re.escape(rule['name'])}$")
    ).first
    row = _row_from_text_locator(regex_name_locator)
    if row is not None:
        return row

    return None


def find_rule_in_ui(page: Page, rule: dict) -> bool:
    return find_rule_row_in_ui(page, rule) is not None


def open_create_detection_dialog(page: Page):
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
            if locator.count() > 0 and locator.is_visible(timeout=2000):
                locator.click(timeout=3000)
                page.wait_for_timeout(MEDIUM_WAIT_MS)
                return
        except Exception:
            pass

    write_debug_html(page)
    fail("Could not find/click the create button on the Detections page")


def _select_language(page: Page, value_pattern: str):
    language_selectors = [
        '#detection-language-create',
        '#detection-language-edit',
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
    page.get_by_role("option", name=re.compile(value_pattern, re.I)).click()
    page.wait_for_timeout(MEDIUM_WAIT_MS)


def fill_suricata_detection_form(page: Page, rule: dict):
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

    _select_language(page, r"^Suricata$")

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


def fill_sigma_detection_form(page: Page, rule: dict):
    sigma_selectors = [
        '#detection-signature-create',
        '#detection-signature-edit',
        'textarea',
        '[data-aid*="signature"] textarea',
        '[data-aid*="sigma"] textarea',
    ]

    _select_language(page, r"^Sigma$")

    for selector in sigma_selectors:
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
    fail("Could not fill Sigma rule field")


def click_first_matching_button(page: Page, patterns: list[str], failure_message: str):
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


def create_suricata_rule_in_ui(page: Page, rule: dict):
    log(f"Creating Suricata detection in UI for {rule['name']}")
    open_create_detection_dialog(page)
    fill_suricata_detection_form(page, rule)
    click_first_matching_button(page, [r"^Create$"], "Could not click Create button")

    page.wait_for_timeout(LONG_WAIT_MS)
    go_to_detections(page)
    page.wait_for_timeout(LONG_WAIT_MS)
    print(f"[PASS] Submitted create flow for {rule['name']}")


def create_sigma_rule_in_ui(page: Page, rule: dict):
    log(f"Creating Sigma detection in UI for {rule['name']}")
    open_create_detection_dialog(page)
    fill_sigma_detection_form(page, rule)
    click_first_matching_button(page, [r"^Create$"], "Could not click Create button")

    page.wait_for_timeout(LONG_WAIT_MS)
    go_to_detections(page)
    page.wait_for_timeout(LONG_WAIT_MS)
    print(f"[PASS] Submitted create flow for {rule['name']}")


def verify_rule_present_in_ui(page: Page, rule: dict):
    search_for_rule(page, rule.get("lookup") or rule["name"])
    page.reload(wait_until="networkidle")
    page.wait_for_timeout(LONG_WAIT_MS)

    if not find_rule_in_ui(page, rule):
        write_debug_html(page, "so_debug_verify_present_failure.html")
        print_page_debug(page, f"verify present failure for {rule.get('lookup') or rule['name']}")
        fail(f"Rule was not found in UI after deployment: {rule['name']}")

    go_to_detections(page)
    print(f"[PASS] Verified detection exists in UI for {rule['name']}")


def extract_sid(content: str) -> str | None:
    match = re.search(r"\bsid\s*:\s*(\d+)\b", content, re.IGNORECASE)
    return match.group(1) if match else None


def validate_suricata_sids(repo_state: dict, saved_state: dict):
    repo_rules = repo_state.get("suricata", {})
    state_rules = saved_state.get("suricata", {})

    repo_sid_to_names = {}
    state_sid_to_names = {}

    for name, content in repo_rules.items():
        sid = extract_sid(content)
        if not sid:
            fail(f"Suricata rule missing sid: {name}")
        repo_sid_to_names.setdefault(sid, []).append(name)

    for name, content in state_rules.items():
        sid = extract_sid(content)
        if not sid:
            fail(f"State Suricata rule missing sid: {name}")
        state_sid_to_names.setdefault(sid, []).append(name)

    repo_dupes = {sid: names for sid, names in repo_sid_to_names.items() if len(names) > 1}
    if repo_dupes:
        details = "; ".join(
            f"sid:{sid} -> {', '.join(names)}" for sid, names in sorted(repo_dupes.items())
        )
        fail(f"Duplicate Suricata SID(s) found in repo: {details}")

    collisions = []
    for sid, repo_names in repo_sid_to_names.items():
        if sid not in state_sid_to_names:
            continue

        for repo_name in repo_names:
            for state_name in state_sid_to_names[sid]:
                if repo_name != state_name:
                    collisions.append(
                        f"sid:{sid} -> repo:{repo_name} conflicts with state:{state_name}"
                    )

    if collisions:
        fail("Suricata SID collision(s) found between repo and state: " + "; ".join(collisions))


def verify_rule_absent_in_ui(context: BrowserContext, rule: dict):
    temp_page = open_detections_in_fresh_tab(context)
    try:
        search_for_rule(temp_page, rule.get("lookup") or rule["name"])
        temp_page.reload(wait_until="networkidle")
        temp_page.wait_for_timeout(LONG_WAIT_MS)

        still_present = find_rule_in_ui(temp_page, rule)
        if not still_present:
            print(f"[PASS] Verified detection removal in UI for {rule['name']}")
            return

        write_debug_html(temp_page, "so_debug_verify_absent_failure.html")
        print_page_debug(temp_page, f"verify absent failure for {rule.get('lookup') or rule['name']}")
    finally:
        temp_page.close()

    fail(f"Rule still appears in UI after deletion: {rule['name']}")


def select_filtered_results_checkbox(page: Page, rule: dict) -> bool:
    lookup = rule.get("lookup") or rule["name"]
    search_for_rule(page, lookup)

    checkbox_targets = [
        page.locator('[data-aid="events_checkbox_detections"] .v-selection-control__input').first,
        page.locator('[data-aid="events_checkbox_detections"] [role="checkbox"]').first,
        page.locator('[data-aid="events_checkbox_detections"] input#multiselect-checkbox').first,
        page.locator('input#multiselect-checkbox').first,
    ]

    for target in checkbox_targets:
        try:
            if target.count() == 0:
                continue
            target.click(force=True, timeout=3000)
            page.wait_for_timeout(MEDIUM_WAIT_MS)
            log(f"Confirmed filtered detection checkbox selected for {lookup}")
            return True
        except Exception:
            pass

    write_debug_html(page, "so_debug_filtered_checkbox_failure.html")
    print_page_debug(page, f"filtered checkbox selection failure for {lookup}")
    return False


def choose_bulk_action_delete(page: Page):
    try:
        bulk_label = page.get_by_text(re.compile(r"Bulk Action\s*:", re.I)).first
        if bulk_label.count() > 0:
            container_candidates = [
                bulk_label.locator("xpath=ancestor::*[self::div or self::form or self::section][1]"),
                bulk_label.locator("xpath=ancestor::*[self::div or self::form or self::section][2]"),
            ]

            for container in container_candidates:
                try:
                    if container.count() == 0:
                        continue

                    select_box = container.locator("select").first
                    if select_box.count() > 0:
                        option_count = select_box.locator("option").count()
                        for i in range(option_count):
                            try:
                                option_text = select_box.locator("option").nth(i).inner_text().strip()
                                if option_text.lower() == "delete":
                                    select_box.select_option(label=option_text)
                                    page.wait_for_timeout(MEDIUM_WAIT_MS)
                                    log("Set Bulk Action to Delete")
                                    return
                            except Exception:
                                pass

                    combo_candidates = [
                        container.get_by_role("combobox").first,
                        container.locator('[role="combobox"]').first,
                        container.locator('input[aria-haspopup="listbox"]').first,
                    ]

                    for combo in combo_candidates:
                        try:
                            if combo.count() == 0:
                                continue
                            combo.click(force=True, timeout=3000)
                            page.wait_for_timeout(SHORT_WAIT_MS)
                            page.get_by_role("option", name=re.compile(r"^Delete$", re.I)).click(
                                force=True,
                                timeout=3000,
                            )
                            page.wait_for_timeout(MEDIUM_WAIT_MS)
                            log("Set Bulk Action to Delete")
                            return
                        except Exception:
                            pass
                except Exception:
                    pass
    except Exception:
        pass

    write_debug_html(page, "so_debug_bulk_action_failure.html")
    print_page_debug(page, "bulk action delete failure")
    fail("Could not set Bulk Action to Delete")


def click_go_button(page: Page):
    go_patterns = [r"^GO$", r"^Go$"]

    for pattern in go_patterns:
        try:
            page.get_by_role("button", name=re.compile(pattern)).first.click(
                force=True,
                timeout=3000,
            )
            page.wait_for_timeout(LONG_WAIT_MS)
            log("Clicked GO for bulk action")
            return
        except Exception:
            pass

    try:
        page.locator('button:has-text("GO")').first.click(force=True, timeout=3000)
        page.wait_for_timeout(LONG_WAIT_MS)
        log("Clicked GO for bulk action")
        return
    except Exception:
        pass

    try:
        page.locator('text=GO').first.click(force=True, timeout=3000)
        page.wait_for_timeout(LONG_WAIT_MS)
        log("Clicked GO for bulk action")
        return
    except Exception:
        pass

    write_debug_html(page, "so_debug_go_button_failure.html")
    print_page_debug(page, "go button failure")
    fail("Could not click GO button for bulk action")


def confirm_delete_popup(page: Page):
    yes_patterns = [r"^YES$", r"^Yes$"]

    for pattern in yes_patterns:
        try:
            page.get_by_role("button", name=re.compile(pattern)).first.click(
                force=True,
                timeout=5000,
            )
            page.wait_for_timeout(LONG_WAIT_MS)
            log("Confirmed delete popup with YES")
            return
        except Exception:
            pass

    try:
        page.locator('button:has-text("YES")').first.click(force=True, timeout=5000)
        page.wait_for_timeout(LONG_WAIT_MS)
        log("Confirmed delete popup with YES")
        return
    except Exception:
        pass

    try:
        page.locator('text=YES').first.click(force=True, timeout=5000)
        page.wait_for_timeout(LONG_WAIT_MS)
        log("Confirmed delete popup with YES")
        return
    except Exception:
        pass

    write_debug_html(page, "so_debug_delete_confirm_failure.html")
    print_page_debug(page, "delete confirm popup failure")
    fail('Could not click "YES" on delete confirmation popup')


def delete_rule_in_ui(page: Page, rule: dict):
    log(f"Deleting detection in UI for {rule['name']}")

    if not select_filtered_results_checkbox(page, rule):
        fail(f"Could not select filtered detection checkbox for deletion: {rule['name']}")

    choose_bulk_action_delete(page)
    click_go_button(page)
    confirm_delete_popup(page)
    go_to_detections(page)
    print(f"[PASS] Delete action confirmed in UI for {rule['name']}")


def click_options_on_detections_page(page: Page):
    option_selectors = [
        '[data-aid*="options"]',
        'button:has-text("Options")',
        '[role="button"]:has-text("Options")',
        'text=Options',
        'button[aria-label*="options" i]',
    ]

    for selector in option_selectors:
        try:
            locator = page.locator(selector).first
            if locator.count() > 0 and locator.is_visible(timeout=3000):
                locator.click(force=True, timeout=3000)
                page.wait_for_timeout(MEDIUM_WAIT_MS)
                return
        except Exception:
            pass

    write_debug_html(page, "so_debug_options_failure.html")
    print_page_debug(page, "options click failure")
    fail("Could not click Options on the detections list page")


def differential_update_suricata(context: BrowserContext):
    temp_page = open_detections_in_fresh_tab(context)
    try:
        click_options_on_detections_page(temp_page)

        try:
            temp_page.get_by_text(re.compile(r"Differential Update", re.I)).click(force=True)
        except Exception:
            write_debug_html(temp_page, "so_debug_differential_update_failure.html")
            print_page_debug(temp_page, "differential update click failure")
            fail("Could not click Differential Update")

        temp_page.wait_for_timeout(10000)
        print("[PASS] Ran Suricata Differential Update")
    finally:
        temp_page.close()


def apply_single_change(page: Page, context: BrowserContext, change: dict, saved_state: dict):
    if change["engine"] == "suricata":
        old_rule = None
        if change["old_content"]:
            old_rule = parse_suricata_rule(change["name"], change["old_content"])

        new_rule = None
        if change["new_content"]:
            new_rule = parse_suricata_rule(change["name"], change["new_content"])

        if change["action"] == "create":
            create_suricata_rule_in_ui(page, new_rule)
            differential_update_suricata(context)
            verify_rule_present_in_ui(page, new_rule)
            saved_state["suricata"][change["name"]] = new_rule["content"]
            save_state(saved_state)
            return

        if change["action"] == "delete":
            delete_rule_in_ui(page, old_rule)
            differential_update_suricata(context)
            verify_rule_absent_in_ui(context, old_rule)
            saved_state["suricata"].pop(change["name"], None)
            save_state(saved_state)
            return

        if change["action"] == "update":
            delete_rule_in_ui(page, old_rule)
            differential_update_suricata(context)
            verify_rule_absent_in_ui(context, old_rule)

            create_suricata_rule_in_ui(page, new_rule)
            differential_update_suricata(context)
            verify_rule_present_in_ui(page, new_rule)

            saved_state["suricata"][change["name"]] = new_rule["content"]
            save_state(saved_state)
            return

        fail(f"Unsupported change action: {change['action']}")

    if change["engine"] == "sigma":
        old_rule = None
        if change["old_content"]:
            old_rule = parse_sigma_rule(change["name"], change["old_content"])

        new_rule = None
        if change["new_content"]:
            new_rule = parse_sigma_rule(change["name"], change["new_content"])

        if change["action"] == "create":
            create_sigma_rule_in_ui(page, new_rule)
            verify_rule_present_in_ui(page, new_rule)
            saved_state["sigma"][change["name"]] = new_rule["content"]
            save_state(saved_state)
            return

        if change["action"] == "delete":
            delete_rule_in_ui(page, old_rule)
            verify_rule_absent_in_ui(context, old_rule)
            saved_state["sigma"].pop(change["name"], None)
            save_state(saved_state)
            return

        if change["action"] == "update":
            delete_rule_in_ui(page, old_rule)
            verify_rule_absent_in_ui(context, old_rule)

            create_sigma_rule_in_ui(page, new_rule)
            verify_rule_present_in_ui(page, new_rule)

            saved_state["sigma"][change["name"]] = new_rule["content"]
            save_state(saved_state)
            return

        fail(f"Unsupported change action: {change['action']}")

    fail(f"Unsupported detection engine: {change['engine']}")


def main():
    if not SO_UI_URL or not SO_UI_USERNAME or not SO_UI_PASSWORD:
        fail("Missing SO_UI_URL, SO_UI_USERNAME, or SO_UI_PASSWORD")

    saved_state = load_state()
    repo_state = collect_repo_state()
    validate_suricata_sids(repo_state, saved_state)
    changes = build_repo_state_changes(repo_state, saved_state)

    log(f"Repo suricata rules: {sorted(repo_state['suricata'].keys())}")
    log(f"State suricata rules: {sorted(saved_state['suricata'].keys())}")
    log(f"Repo sigma rules: {sorted(repo_state['sigma'].keys())}")
    log(f"State sigma rules: {sorted(saved_state['sigma'].keys())}")
    log(
        "Computed Security Onion repo/state changes: "
        + (
            ", ".join(f"{c['engine']}:{c['action']}:{c['name']}" for c in changes)
            if changes
            else "none"
        )
    )

    if len(changes) > 1:
        formatted = ", ".join(
            f"{item['engine']}:{item['action']}:{item['name']}" for item in changes
        )
        fail(
            "Only one Security Onion rule change is allowed per push. "
            f"Detected {len(changes)} repo/state changes: {formatted}"
        )

    if not changes:
        print("[PASS] No Security Onion repo/state changes detected")
        return

    change = changes[0]
    log(
        f"Processing single Security Onion repo/state change: "
        f"{change['engine']}:{change['action']}:{change['name']}"
    )

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        try:
            ui_login(page)
            apply_single_change(page, context, change, saved_state)
            print("[PASS] Security Onion deployment completed successfully")
        finally:
            context.close()
            browser.close()


if __name__ == "__main__":
    main()