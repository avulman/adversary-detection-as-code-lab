from pathlib import Path
import os
import re
import sys
import time
import tempfile
import paramiko
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
SO_SURICATA_DIR = ROOT / "detections" / "security-onion" / "suricata"

SO_MANAGER_HOST = os.getenv("SO_MANAGER_HOST", "").strip()
SO_MANAGER_PORT = int(os.getenv("SO_MANAGER_PORT", "22"))
SO_MANAGER_USER = os.getenv("SO_MANAGER_USER", "").strip()
SO_MANAGER_SSH_KEY = os.getenv("SO_MANAGER_SSH_KEY", "")

SO_UI_URL = os.getenv("SO_UI_URL", "").strip().rstrip("/")
SO_UI_USERNAME = os.getenv("SO_UI_USERNAME", "").strip()
SO_UI_PASSWORD = os.getenv("SO_UI_PASSWORD", "").strip()


def fail(msg: str):
    print(f"[FAIL] {msg}")
    sys.exit(1)


def write_debug_html(page, filename: str = "so_debug_page.html"):
    debug_path = ROOT / filename
    debug_path.write_text(page.content(), encoding="utf-8")
    print(f"[INFO] Wrote debug HTML to {debug_path}")


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


def parse_rule_file(path: Path):
    content = path.read_text(encoding="utf-8", errors="ignore").strip()
    if not content:
        fail(f"{path.name} is empty")

    # Flatten to one line for the UI signature field
    content = " ".join(content.split())

    msg_match = re.search(r'msg:"([^"]+)"', content)
    sid_match = re.search(r"sid:(\d+)", content)
    license_match = re.search(r"#\s*license:\s*(.+)", content, re.IGNORECASE)

    msg = msg_match.group(1) if msg_match else path.stem
    sid = sid_match.group(1) if sid_match else None
    license_value = license_match.group(1).strip() if license_match else "GPL-2.0-only"

    return {
        "path": path,
        "content": content,
        "msg": msg,
        "sid": sid,
        "license": license_value,
    }


def rule_exists_in_all_rulesets(client: paramiko.SSHClient, rule: dict) -> bool:
    checks = []
    if rule["sid"]:
        checks.append(f"grep -F 'sid:{rule['sid']}' /opt/so/rules/suricata/all-rulesets.rules >/dev/null 2>&1")
    checks.append(f"grep -F '{rule['msg']}' /opt/so/rules/suricata/all-rulesets.rules >/dev/null 2>&1")

    for cmd in checks:
        stdin, stdout, stderr = client.exec_command(cmd)
        exit_status = stdout.channel.recv_exit_status()
        if exit_status == 0:
            return True
    return False


def ui_login(page):
    page.goto(f"{SO_UI_URL}/login", wait_until="domcontentloaded")
    page.wait_for_timeout(3000)

    email = page.locator('[data-aid="login_email_input"] input')
    password = page.locator('[data-aid="login_password_input"] input')
    button = page.locator('[data-aid="login_password_submit"]')

    email.click()
    email.type(SO_UI_USERNAME, delay=100)

    password.click()
    password.type(SO_UI_PASSWORD, delay=100)

    page.wait_for_timeout(2000)
    button.wait_for(state="visible", timeout=10000)
    page.wait_for_function(
        "(el) => !el.disabled",
        arg=button.element_handle()
    )

    button.click()
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(5000)

    print("[PASS] Logged into Security Onion UI")


def go_to_detections(page):
    page.goto(f"{SO_UI_URL}/#/detections", wait_until="networkidle")
    page.wait_for_timeout(4000)


def open_create_detection_dialog(page):
    plus_clicked = False
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
                plus_clicked = True
                break
        except Exception:
            pass

    if not plus_clicked:
        write_debug_html(page)
        fail("Could not find/click the create (+) button on the Detections page")

    page.wait_for_timeout(2500)


def set_rule_form_fields(page, rule: dict):
    # Language -> Suricata
    language = page.locator('#detection-language-create')
    if language.count() == 0:
        language = page.locator('#detection-language-edit')
    if language.count() == 0:
        write_debug_html(page)
        fail("Could not find Language field")

    language.click(force=True)
    page.wait_for_timeout(1000)
    page.get_by_role("option", name=re.compile(r"^Suricata$", re.I)).click()
    page.wait_for_timeout(1000)

    # License -> GPL-2.0
    license_box = page.locator('#detection-license-create')
    if license_box.count() == 0:
        license_box = page.locator('#detection-license-edit')
    if license_box.count() == 0:
        write_debug_html(page)
        fail("Could not find License field")

    license_box.click(force=True)
    page.wait_for_timeout(1000)
    page.get_by_role("option", name=re.compile(r"GPL-2.0", re.I)).click()
    page.wait_for_timeout(1000)

    # Signature
    signature_selectors = [
        '#detection-signature-create',
        '#detection-signature-edit',
        'textarea',
        '[data-aid*="signature"] textarea',
    ]

    filled = False
    for selector in signature_selectors:
        try:
            locator = page.locator(selector).first
            if locator.count() > 0:
                locator.click(force=True)
                locator.fill(rule["content"])
                filled = True
                break
        except Exception:
            pass

    if not filled:
        write_debug_html(page)
        fail("Could not fill Signature field")

    page.wait_for_timeout(1000)


def click_button_by_name(page, pattern: str, failure_message: str):
    candidates = [
        page.get_by_role("button", name=re.compile(pattern, re.I)),
        page.locator(f'text=/{pattern}/i'),
    ]

    for locator in candidates:
        try:
            locator.first.click(force=True, timeout=3000)
            return
        except Exception:
            pass

    write_debug_html(page)
    fail(failure_message)


def create_suricata_detection(page, rule: dict):
    go_to_detections(page)
    open_create_detection_dialog(page)
    set_rule_form_fields(page, rule)
    click_button_by_name(page, r"Create", "Could not click Create button")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(4000)

    # IMPORTANT: always return to detections list after create
    go_to_detections(page)

    print(f"[PASS] Created detection in UI for {rule['path'].name}")


def rule_exists_in_ui(page, rule: dict) -> bool:
    go_to_detections(page)

    search_selectors = [
        'input[placeholder*="search" i]',
        'input[type="text"]',
        '[data-aid*="search"] input',
    ]

    for selector in search_selectors:
        try:
            box = page.locator(selector).first
            if box.count() > 0:
                box.fill("")
                box.type(rule["msg"], delay=40)
                page.wait_for_timeout(2000)
                break
        except Exception:
            pass

    try:
        if page.get_by_text(rule["msg"], exact=False).count() > 0:
            return True
    except Exception:
        pass

    try:
        if rule["sid"] and page.get_by_text(rule["sid"], exact=False).count() > 0:
            return True
    except Exception:
        pass

    return False


def open_existing_rule(page, rule: dict) -> bool:
    go_to_detections(page)

    search_selectors = [
        'input[placeholder*="search" i]',
        'input[type="text"]',
        '[data-aid*="search"] input',
    ]

    for selector in search_selectors:
        try:
            box = page.locator(selector).first
            if box.count() > 0:
                box.fill("")
                box.type(rule["msg"], delay=40)
                page.wait_for_timeout(2000)
                break
        except Exception:
            pass

    # Try to click the row/title for the rule
    click_targets = [
        page.get_by_text(rule["msg"], exact=False),
    ]

    if rule["sid"]:
        click_targets.append(page.get_by_text(rule["sid"], exact=False))

    for target in click_targets:
        try:
            target.first.click(force=True, timeout=3000)
            page.wait_for_load_state("networkidle")
            page.wait_for_timeout(3000)
            return True
        except Exception:
            pass

    return False


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
                return " ".join(value.split())
        except Exception:
            pass

    return ""


def update_suricata_detection(page, rule: dict):
    opened = open_existing_rule(page, rule)
    if not opened:
        fail(f"Rule exists in UI but could not be opened for update: {rule['msg']}")

    current_signature = get_current_signature(page)
    desired_signature = " ".join(rule["content"].split())

    if current_signature == desired_signature:
        print(f"[INFO] No update required for {rule['path'].name}")
        go_to_detections(page)
        return

    # Try to click Edit if present
    edit_selectors = [
        'button:has-text("Edit")',
        '[role="button"]:has-text("Edit")',
        '[data-aid*="edit"]',
    ]

    edit_clicked = False
    for selector in edit_selectors:
        try:
            page.locator(selector).first.click(force=True, timeout=3000)
            page.wait_for_timeout(2000)
            edit_clicked = True
            break
        except Exception:
            pass

    # Some pages may already be editable
    if not edit_clicked:
        print(f"[INFO] Edit button not found for {rule['path'].name}; attempting direct field update")

    set_rule_form_fields(page, rule)

    save_patterns = [
        r"Save",
        r"Update",
        r"Submit",
    ]

    saved = False
    for pattern in save_patterns:
        try:
            click_button_by_name(page, pattern, f"Could not click {pattern} button")
            saved = True
            break
        except SystemExit:
            pass

    if not saved:
        write_debug_html(page)
        fail(f"Could not save updated rule for {rule['path'].name}")

    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(4000)

    # IMPORTANT: always return to detections list after update
    go_to_detections(page)

    print(f"[PASS] Updated detection in UI for {rule['path'].name}")


def differential_update_suricata(page):
    # Always start from detections list
    go_to_detections(page)

    opened = False
    option_selectors = [
        'text=Options',
        '[data-aid*="options"]',
        'button:has-text("Options")',
        '[role="button"]:has-text("Options")',
    ]

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

    page.wait_for_timeout(1000)

    # Click Differential Update directly
    try:
        page.get_by_text(re.compile(r"Differential Update", re.I)).click(force=True)
    except Exception:
        write_debug_html(page)
        fail("Could not click Differential Update")

    page.wait_for_timeout(8000)
    print("[PASS] Ran Suricata Differential Update")


def main():
    if not SO_UI_URL or not SO_UI_USERNAME or not SO_UI_PASSWORD:
        fail("Missing SO_UI_URL, SO_UI_USERNAME, or SO_UI_PASSWORD")

    rule_files = sorted(SO_SURICATA_DIR.glob("*.rules"))
    if not rule_files:
        fail("No .rules files found in detections/security-onion/suricata")

    rules = [parse_rule_file(path) for path in rule_files]

    key_path = write_temp_key()
    client = None

    try:
        client = get_ssh_client(key_path)

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(ignore_https_errors=True)

            ui_login(page)

            pending_activation = []

            for rule in rules:
                exists_backend = rule_exists_in_all_rulesets(client, rule)
                print(f"[INFO] {rule['path'].name} exists in all-rulesets.rules: {exists_backend}")

                if exists_backend:
                    continue

                exists_ui = rule_exists_in_ui(page, rule)
                print(f"[INFO] {rule['path'].name} exists in UI: {exists_ui}")

                if exists_ui:
                    print(f"[INFO] Updating existing detection in UI for {rule['path'].name}")
                    update_suricata_detection(page, rule)
                else:
                    print(f"[INFO] Creating detection in UI for {rule['path'].name}")
                    create_suricata_detection(page, rule)

                pending_activation.append(rule)

            if not pending_activation:
                print("[PASS] All rules already active in all-rulesets.rules")
                browser.close()
                return

            print("[INFO] Running Suricata Differential Update in UI")
            differential_update_suricata(page)

            browser.close()

        time.sleep(10)

        for rule in pending_activation:
            exists = rule_exists_in_all_rulesets(client, rule)
            print(f"[INFO] Post-update check for {rule['path'].name}: {exists}")
            if not exists:
                fail(
                    f"{rule['path'].name} still not present in "
                    "/opt/so/rules/suricata/all-rulesets.rules after UI update"
                )

        print("[PASS] Security Onion detections created/updated and activated successfully")

    finally:
        if client:
            client.close()
        if os.path.exists(key_path):
            os.remove(key_path)


if __name__ == "__main__":
    main()