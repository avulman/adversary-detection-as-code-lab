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


def create_suricata_detection(page, rule: dict):
    page.goto(f"{SO_UI_URL}/#/detections", wait_until="networkidle")
    page.wait_for_timeout(4000)

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
        print(page.content())
        fail("Could not find/click the create (+) button on the Detections page")

    page.wait_for_timeout(2500)

    # Grab comboboxes in the create dialog
    comboboxes = page.locator('[role="combobox"]')
    if comboboxes.count() < 2:
        print(page.content())
        fail("Could not find the Language/License dropdowns")

    # Language -> Suricata
    language = page.locator('#detection-language-create')
    language.click(force=True)
    page.wait_for_timeout(1000)
    page.get_by_role("option", name=re.compile(r"^Suricata$", re.I)).click()
    page.wait_for_timeout(1000)

    # License -> GPL-2.0
    license_box = page.locator('#detection-license-create')
    license_box.click(force=True)
    page.wait_for_timeout(1000)
    page.get_by_role("option", name=re.compile(r"GPL-2.0", re.I)).click()
    page.wait_for_timeout(1000)

    # Signature
    try:
        page.get_by_label(re.compile(r"Signature", re.I)).fill(rule["content"])
    except Exception:
        try:
            page.locator("textarea").first.fill(rule["content"])
        except Exception:
            print(page.content())
            fail("Could not fill Signature field")

    page.wait_for_timeout(1000)

    # Create
    try:
        page.get_by_role("button", name=re.compile(r"Create", re.I)).click()
    except Exception:
        print(page.content())
        fail("Could not click Create button")

    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(4000)

    print(f"[PASS] Created detection in UI for {rule['path'].name}")


def differential_update_suricata(page):
    page.goto(f"{SO_UI_URL}/#/detections", wait_until="networkidle")
    page.wait_for_timeout(3000)

    page.get_by_role("button", name=re.compile(r"Options", re.I)).click()
    page.wait_for_timeout(1000)

    # Change dropdown from ElastAlert to Suricata
    try:
        page.get_by_text(re.compile(r"ElastAlert", re.I)).click()
    except Exception:
        page.locator('[role="combobox"]').first.click()

    page.wait_for_timeout(1000)
    page.get_by_text(re.compile(r"^Suricata$", re.I)).click()
    page.wait_for_timeout(1000)

    # Run differential update
    page.get_by_role("button", name=re.compile(r"Differential Update", re.I)).click()
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

        missing_rules = []
        for rule in rules:
            exists = rule_exists_in_all_rulesets(client, rule)
            print(f"[INFO] {rule['path'].name} exists in all-rulesets.rules: {exists}")
            if not exists:
                missing_rules.append(rule)

        if not missing_rules:
            print("[PASS] All rules already exist in all-rulesets.rules")
            return

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(ignore_https_errors=True)

            ui_login(page)

            for rule in missing_rules:
                print(f"[INFO] Creating detection in UI for {rule['path'].name}")
                create_suricata_detection(page, rule)

            print("[INFO] Running Suricata Differential Update in UI")
            differential_update_suricata(page)

            browser.close()

        time.sleep(10)

        for rule in missing_rules:
            exists = rule_exists_in_all_rulesets(client, rule)
            print(f"[INFO] Post-update check for {rule['path'].name}: {exists}")
            if not exists:
                fail(
                    f"{rule['path'].name} still not present in "
                    "/opt/so/rules/suricata/all-rulesets.rules after UI update"
                )

        print("[PASS] Security Onion detections created and activated successfully")

    finally:
        if client:
            client.close()
        if os.path.exists(key_path):
            os.remove(key_path)


if __name__ == "__main__":
    main()