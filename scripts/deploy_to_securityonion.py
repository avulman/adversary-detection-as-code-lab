from pathlib import Path
import os
import re
import sys
import time
import json
import tempfile
import paramiko
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
SO_SURICATA_DIR = ROOT / "detections" / "security-onion" / "suricata"
STATE_DIR = ROOT / "state"
STATE_FILE = STATE_DIR / "securityonion_rule_state.json"

SO_MANAGER_HOST = os.getenv("SO_MANAGER_HOST", "").strip()
SO_MANAGER_PORT = int(os.getenv("SO_MANAGER_PORT", "22"))
SO_MANAGER_USER = os.getenv("SO_MANAGER_USER", "").strip()
SO_MANAGER_SSH_KEY = os.getenv("SO_MANAGER_SSH_KEY", "")

SO_UI_URL = os.getenv("SO_UI_URL", "").strip().rstrip("/")
SO_UI_USERNAME = os.getenv("SO_UI_USERNAME", "").strip()
SO_UI_PASSWORD = os.getenv("SO_UI_PASSWORD", "").strip()

# Managed SID range for auto-assignment
AUTO_SID_START = 1000000
AUTO_SID_END = 1000999

# UI pacing
SHORT_WAIT_MS = 1500
MEDIUM_WAIT_MS = 3000
LONG_WAIT_MS = 5000


def fail(msg: str):
    print(f"[FAIL] {msg}")
    sys.exit(1)


def log(msg: str):
    print(f"[INFO] {msg}")


def write_debug_html(page, filename: str = "so_debug_page.html"):
    debug_path = ROOT / filename
    debug_path.write_text(page.content(), encoding="utf-8")
    print(f"[INFO] Wrote debug HTML to {debug_path}")


def ensure_state_dir():
    STATE_DIR.mkdir(parents=True, exist_ok=True)


def load_state() -> dict:
    ensure_state_dir()
    if not STATE_FILE.exists():
        return {"managed_rules": {}}
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"managed_rules": {}}


def save_state(state: dict):
    ensure_state_dir()
    STATE_FILE.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


def write_temp_key() -> str:
    if not SO_MANAGER_SSH_KEY:
        fail("SO_MANAGER_SSH_KEY environment variable is not set")

    with tempfile.NamedTemporaryFile(delete=False, mode="w", encoding="utf-8", newline="\n") as f:
        f.write(SO_MANAGER_SSH_KEY)
        key_path = f.name

    os.chmod(key_path, 0o600)
    return key_path


def get_private_key(key_path: str):
    key_loaders = [
        paramiko.Ed25519Key.from_private_key_file,
        paramiko.RSAKey.from_private_key_file,
        paramiko.ECDSAKey.from_private_key_file,
    ]
    last_error = None
    for loader in key_loaders:
        try:
            return loader(key_path)
        except Exception as e:
            last_error = e
    fail(f"Unable to load SSH private key: {last_error}")


def get_ssh_client(key_path: str) -> paramiko.SSHClient:
    if not SO_MANAGER_HOST or not SO_MANAGER_USER:
        fail("Missing SO_MANAGER_HOST or SO_MANAGER_USER")

    key = get_private_key(key_path)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=SO_MANAGER_HOST,
        port=SO_MANAGER_PORT,
        username=SO_MANAGER_USER,
        pkey=key,
        timeout=20,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def exec_ssh(client: paramiko.SSHClient, command: str):
    stdin, stdout, stderr = client.exec_command(command)
    exit_status = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="ignore")
    err = stderr.read().decode("utf-8", errors="ignore")
    return exit_status, out, err


def grep_all_rulesets_for_sid(client: paramiko.SSHClient, sid: str) -> bool:
    command = f"grep -F 'sid:{sid}' /opt/so/rules/suricata/all-rulesets.rules >/dev/null 2>&1"
    code, _, _ = exec_ssh(client, command)
    return code == 0


def rule_exists_in_all_rulesets(client: paramiko.SSHClient, rule: dict) -> bool:
    if rule["sid"]:
        if grep_all_rulesets_for_sid(client, rule["sid"]):
            return True
    command = f"grep -F '{rule['msg']}' /opt/so/rules/suricata/all-rulesets.rules >/dev/null 2>&1"
    code, _, _ = exec_ssh(client, command)
    return code == 0


def normalize_signature(signature: str) -> str:
    return " ".join(signature.split())


def extract_msg(content: str, fallback: str) -> str:
    match = re.search(r'msg:"([^"]+)"', content)
    return match.group(1) if match else fallback


def extract_sid(content: str):
    match = re.search(r"sid:(\d+)", content)
    return match.group(1) if match else None


def replace_or_insert_sid(content: str, sid: str) -> str:
    if re.search(r"sid:\d+", content):
        return re.sub(r"sid:\d+", f"sid:{sid}", content)
    return re.sub(r"\)\s*$", f"; sid:{sid};)", content)


def parse_rule_file(path: Path, assigned_sid: str | None = None):
    raw = path.read_text(encoding="utf-8", errors="ignore").strip()
    if not raw:
        fail(f"{path.name} is empty")

    one_line = normalize_signature(raw)
    sid = extract_sid(one_line)

    if not sid and assigned_sid:
        one_line = replace_or_insert_sid(one_line, assigned_sid)
        sid = assigned_sid

    msg = extract_msg(one_line, path.stem)

    return {
        "path": path,
        "content": one_line,
        "msg": msg,
        "sid": sid,
    }


def collect_repo_rules() -> list[dict]:
    state = load_state()
    managed_state = state.get("managed_rules", {})

    rule_files = sorted(SO_SURICATA_DIR.glob("*.rules"))
    if not rule_files:
        fail("No .rules files found in detections/security-onion/suricata")

    used_sids = set()
    for value in managed_state.values():
        sid = value.get("sid")
        if sid:
            used_sids.add(str(sid))

    parsed_rules = []

    for path in rule_files:
        existing_sid = None
        if path.name in managed_state:
            existing_sid = managed_state[path.name].get("sid")

        rule = parse_rule_file(path, assigned_sid=existing_sid)
        if rule["sid"]:
            used_sids.add(str(rule["sid"]))
        parsed_rules.append(rule)

    # Assign SIDs for any rule still missing one
    next_sid = AUTO_SID_START
    for rule in parsed_rules:
        if rule["sid"]:
            continue

        while str(next_sid) in used_sids and next_sid <= AUTO_SID_END:
            next_sid += 1

        if next_sid > AUTO_SID_END:
            fail("Exhausted managed SID range for auto-assignment")

        assigned = str(next_sid)
        rule["content"] = replace_or_insert_sid(rule["content"], assigned)
        rule["sid"] = assigned
        used_sids.add(assigned)
        next_sid += 1

        log(f"Auto-assigned sid:{assigned} to {rule['path'].name}")

    # Persist auto-assigned SIDs back into the rule files and state
    for rule in parsed_rules:
        rule["path"].write_text(rule["content"] + "\n", encoding="utf-8")
        managed_state[rule["path"].name] = {
            "sid": rule["sid"],
            "msg": rule["msg"],
        }

    state["managed_rules"] = managed_state
    save_state(state)

    return parsed_rules


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


def clear_search_box(page):
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
                return
        except Exception:
            pass


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


def find_rule_in_ui(page, rule: dict) -> bool:
    search_for_rule(page, rule["sid"] or rule["msg"])

    candidates = []
    if rule["sid"]:
        candidates.append(page.get_by_text(rule["sid"], exact=False))
    candidates.append(page.get_by_text(rule["msg"], exact=False))

    for c in candidates:
        try:
            if c.count() > 0:
                return True
        except Exception:
            pass

    return False


def open_rule_in_ui(page, rule: dict) -> bool:
    search_for_rule(page, rule["sid"] or rule["msg"])

    candidates = []
    if rule["sid"]:
        candidates.append(page.get_by_text(rule["sid"], exact=False))
    candidates.append(page.get_by_text(rule["msg"], exact=False))

    for c in candidates:
        try:
            c.first.click(force=True, timeout=3000)
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
    fail("Could not find/click the create (+) button on the Detections page")


def fill_detection_form(page, rule: dict):
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
            page.get_by_role("button", name=re.compile(pattern, re.I)).first.click(force=True, timeout=3000)
            page.wait_for_timeout(MEDIUM_WAIT_MS)
            return
        except Exception:
            pass

    write_debug_html(page)
    fail(failure_message)


def create_rule_in_ui(page, rule: dict):
    log(f"Creating detection in UI for {rule['path'].name}")
    open_create_detection_dialog(page)
    fill_detection_form(page, rule)
    click_first_matching_button(page, [r"Create"], "Could not click Create button")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(LONG_WAIT_MS)
    go_to_detections(page)
    print(f"[PASS] Created detection in UI for {rule['path'].name}")


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
                value = locator.input_value()
                return normalize_signature(value)
        except Exception:
            pass
    return ""


def update_rule_in_ui(page, rule: dict):
    log(f"Updating detection in UI for {rule['path'].name}")

    if not open_rule_in_ui(page, rule):
        fail(f"Rule exists in UI but could not be opened for update: {rule['msg']}")

    current_signature = get_current_signature(page)
    desired_signature = normalize_signature(rule["content"])

    if current_signature == desired_signature:
        log(f"No update required for {rule['path'].name}")
        go_to_detections(page)
        return

    edit_patterns = [r"Edit"]
    edited = False
    for pattern in edit_patterns:
        try:
            page.get_by_role("button", name=re.compile(pattern, re.I)).first.click(force=True, timeout=3000)
            page.wait_for_timeout(MEDIUM_WAIT_MS)
            edited = True
            break
        except Exception:
            pass

    if not edited:
        log(f"Edit button not found for {rule['path'].name}; attempting direct field update")

    fill_detection_form(page, rule)
    click_first_matching_button(page, [r"Save", r"Update", r"Submit"], "Could not save updated rule")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(LONG_WAIT_MS)
    go_to_detections(page)
    print(f"[PASS] Updated detection in UI for {rule['path'].name}")


def delete_rule_in_ui(page, sid: str, msg: str):
    log(f"Deleting detection in UI for sid:{sid} ({msg})")

    pseudo_rule = {"sid": sid, "msg": msg}
    if not open_rule_in_ui(page, pseudo_rule):
        log(f"Rule sid:{sid} not found in UI for deletion; skipping")
        return

    click_first_matching_button(page, [r"Delete"], "Could not click Delete button")

    # confirm if dialog exists
    try:
        click_first_matching_button(page, [r"Delete", r"Confirm"], "Could not confirm deletion")
    except SystemExit:
        pass

    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(LONG_WAIT_MS)
    go_to_detections(page)
    print(f"[PASS] Deleted detection in UI for sid:{sid}")


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
        fail("Could not click Options on the detections LIST page")

    page.wait_for_timeout(SHORT_WAIT_MS)

    try:
        page.get_by_text(re.compile(r"Differential Update", re.I)).click(force=True)
    except Exception:
        write_debug_html(page)
        fail("Could not click Differential Update")

    page.wait_for_timeout(10000)
    print("[PASS] Ran Suricata Differential Update")


def reconcile_state_with_repo(repo_rules: list[dict]) -> tuple[list[dict], list[dict]]:
    state = load_state()
    managed_state = state.get("managed_rules", {})

    repo_by_file = {r["path"].name: r for r in repo_rules}
    repo_sids = {r["sid"] for r in repo_rules}

    delete_candidates = []
    for filename, data in managed_state.items():
        sid = str(data.get("sid", "")).strip()
        msg = data.get("msg", filename)
        if sid and sid not in repo_sids:
            delete_candidates.append({"filename": filename, "sid": sid, "msg": msg})

    return repo_rules, delete_candidates


def main():
    if not SO_UI_URL or not SO_UI_USERNAME or not SO_UI_PASSWORD:
        fail("Missing SO_UI_URL, SO_UI_USERNAME, or SO_UI_PASSWORD")

    repo_rules = collect_repo_rules()
    repo_rules, delete_candidates = reconcile_state_with_repo(repo_rules)

    key_path = write_temp_key()
    client = None

    try:
        client = get_ssh_client(key_path)

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(ignore_https_errors=True)

            ui_login(page)

            processed_rules = []

            # delete rules removed from repo
            for item in delete_candidates:
                delete_rule_in_ui(page, item["sid"], item["msg"])

            # create or update all repo rules
            for rule in repo_rules:
                exists_backend = rule_exists_in_all_rulesets(client, rule)
                log(f"{rule['path'].name} exists in all-rulesets.rules: {exists_backend}")

                exists_ui = find_rule_in_ui(page, rule)
                log(f"{rule['path'].name} exists in UI: {exists_ui}")

                if exists_ui:
                    update_rule_in_ui(page, rule)
                else:
                    create_rule_in_ui(page, rule)

                processed_rules.append(rule)

            # single differential update after all changes
            log("Running Suricata Differential Update in UI")
            differential_update_suricata(page)
            browser.close()

        time.sleep(10)

        # verify activation
        for rule in processed_rules:
            exists = rule_exists_in_all_rulesets(client, rule)
            log(f"Post-update check for {rule['path'].name}: {exists}")
            if not exists:
                fail(
                    f"{rule['path'].name} with sid:{rule['sid']} still not present in "
                    "/opt/so/rules/suricata/all-rulesets.rules after UI update"
                )

        # clean deleted rules from state
        state = load_state()
        managed_state = state.get("managed_rules", {})
        repo_filenames = {r["path"].name for r in repo_rules}
        for filename in list(managed_state.keys()):
            if filename not in repo_filenames:
                del managed_state[filename]
        state["managed_rules"] = managed_state
        save_state(state)

        print("[PASS] Security Onion detections created/updated/deleted and activated successfully")

    finally:
        if client:
            client.close()
        if os.path.exists(key_path):
            os.remove(key_path)


if __name__ == "__main__":
    main()