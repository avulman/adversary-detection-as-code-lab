from pathlib import Path
import os
import re
import sys
import time
import tempfile
import paramiko
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

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


def run_ssh(client: paramiko.SSHClient, command: str):
    stdin, stdout, stderr = client.exec_command(command)
    exit_status = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="ignore")
    err = stderr.read().decode("utf-8", errors="ignore")
    if exit_status != 0:
        fail(f"Remote command failed: {command}\nSTDOUT:\n{out}\nSTDERR:\n{err}")
    return out


def parse_rule_file(path: Path):
    content = path.read_text(encoding="utf-8", errors="ignore").strip()
    if not content:
        fail(f"{path.name} is empty")

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
    page.get_by_label(re.compile("username", re.I)).fill(SO_UI_USERNAME)
    page.get_by_label(re.compile("password", re.I)).fill(SO_UI_PASSWORD)
    page.get_by_role("button", name=re.compile("log in|sign in", re.I)).click()
    page.wait_for_load_state("networkidle")


def create_suricata_detection(page, rule: dict):
    page.goto(f"{SO_UI_URL}/detections", wait_until="networkidle")

    page.get_by_role("button", name=re.compile(r"^\+$")).click(timeout=10000)

    try:
        page.get_by_label(re.compile("language", re.I)).click()
        page.get_by_role("option", name=re.compile("suricata", re.I)).click()
    except PlaywrightTimeoutError:
        page.get_by_text(re.compile("language", re.I)).click()
        page.get_by_text(re.compile("^suricata$", re.I)).click()

    try:
        page.get_by_label(re.compile("license", re.I)).click()
        page.get_by_role("option", name=re.compile("GPL-2.0", re.I)).click()
    except PlaywrightTimeoutError:
        page.get_by_text(re.compile("license", re.I)).click()
        page.get_by_text(re.compile("GPL-2.0", re.I)).click()

    page.get_by_label(re.compile("signature", re.I)).fill(rule["content"])
    page.get_by_role("button", name=re.compile("create", re.I)).click()
    page.wait_for_load_state("networkidle")


def differential_update_suricata(page):
    page.goto(f"{SO_UI_URL}/detections", wait_until="networkidle")
    page.get_by_role("button", name=re.compile("options", re.I)).click()

    try:
        page.get_by_label(re.compile("elastalert|engine|type", re.I)).click()
        page.get_by_role("option", name=re.compile("suricata", re.I)).click()
    except PlaywrightTimeoutError:
        page.get_by_text(re.compile("elastalert", re.I)).click()
        page.get_by_text(re.compile("^suricata$", re.I)).click()

    page.get_by_role("button", name=re.compile("differential update", re.I)).click()
    page.wait_for_timeout(5000)


def main():
    required_ui = [SO_UI_URL, SO_UI_USERNAME, SO_UI_PASSWORD]
    if not all(required_ui):
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
                print(f"[PASS] Created detection in UI for {rule['path'].name}")

            print("[INFO] Running Suricata Differential Update in UI")
            differential_update_suricata(page)
            browser.close()

        time.sleep(8)

        for rule in missing_rules:
            exists = rule_exists_in_all_rulesets(client, rule)
            print(f"[INFO] Post-update check for {rule['path'].name}: {exists}")
            if not exists:
                fail(f"{rule['path'].name} still not present in /opt/so/rules/suricata/all-rulesets.rules after UI update")

        print("[PASS] Security Onion detections created and activated successfully")

    finally:
        if client:
            client.close()
        if os.path.exists(key_path):
            os.remove(key_path)


if __name__ == "__main__":
    main()