from pathlib import Path
import json
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "detections" / "security-onion" / "suricata"
TESTS_DIR = ROOT / "tests" / "suricata"


def fail(message: str):
    print(f"[FAIL] {message}")
    sys.exit(1)


def parse_rule_metadata(rule_path: Path) -> tuple[str, str]:
    content = rule_path.read_text(encoding="utf-8", errors="ignore").strip()
    if not content:
        fail(f"Empty Suricata rule file: {rule_path.relative_to(ROOT)}")

    sid = None
    msg = None

    for part in content.split(";"):
        part = part.strip()
        if part.startswith("sid:"):
            sid = part.split(":", 1)[1].strip()
        elif part.startswith('msg:"') and part.endswith('"'):
            msg = part[5:-1]

    if not sid:
        fail(f"Could not extract sid from {rule_path.relative_to(ROOT)}")

    if not msg:
        fail(f"Could not extract msg from {rule_path.relative_to(ROOT)}")

    return sid, msg


def load_test_config(rule_stem: str) -> dict:
    config_path = TESTS_DIR / rule_stem / "test_config.json"
    if not config_path.exists():
        fail(f"Missing Suricata test config: {config_path.relative_to(ROOT)}")

    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception as e:
        fail(f"Invalid JSON in {config_path.relative_to(ROOT)}: {e}")

    if not isinstance(data, dict):
        fail(f"Suricata test config must be a JSON object: {config_path.relative_to(ROOT)}")

    return data


def get_suricata_binary() -> str:
    binary = shutil.which("suricata")
    if binary:
        return binary

    fail("Could not find 'suricata' in PATH")


def get_positive_pcaps(rule_stem: str) -> list[Path]:
    positive_dir = TESTS_DIR / rule_stem / "positive"
    if not positive_dir.exists():
        fail(f"Missing Suricata positive fixture directory: {positive_dir.relative_to(ROOT)}")

    pcaps = sorted(positive_dir.glob("*.pcap"))
    if not pcaps:
        fail(f"No Suricata positive pcaps found in {positive_dir.relative_to(ROOT)}")

    return pcaps


def run_suricata_against_pcap(suricata_bin: str, rule_path: Path, pcap_path: Path) -> list[dict]:
    with tempfile.TemporaryDirectory(prefix="suricata-test-") as tmp_dir:
        tmp_path = Path(tmp_dir)
        eve_path = tmp_path / "eve.json"

        cmd = [
            suricata_bin,
            "-r",
            str(pcap_path),
            "-S",
            str(rule_path),
            "-l",
            str(tmp_path),
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            fail(
                f"Suricata execution failed for {pcap_path.relative_to(ROOT)} "
                f"with rule {rule_path.relative_to(ROOT)}:\n"
                f"{result.stderr.strip() or result.stdout.strip()}"
            )

        if not eve_path.exists():
            fail(
                f"Suricata did not produce eve.json for {pcap_path.relative_to(ROOT)} "
                f"using rule {rule_path.relative_to(ROOT)}"
            )

        alerts = []
        for line in eve_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except Exception as e:
                fail(f"Invalid JSON line in eve.json for {pcap_path.relative_to(ROOT)}: {e}")

            if event.get("event_type") == "alert":
                alerts.append(event)

        return alerts


def alert_matches(alert: dict, expected_sid: str, expected_msg: str) -> bool:
    alert_obj = alert.get("alert", {})
    sid = str(alert_obj.get("signature_id", ""))
    msg = str(alert_obj.get("signature", ""))
    return sid == expected_sid and msg == expected_msg


def run_tests():
    suricata_bin = get_suricata_binary()
    rule_files = sorted(RULES_DIR.glob("*.rules"))

    if not rule_files:
        fail(f"No Suricata rule files found in {RULES_DIR.relative_to(ROOT)}")

    for rule_path in rule_files:
        rule_stem = rule_path.stem
        sid, msg = parse_rule_metadata(rule_path)
        load_test_config(rule_stem)
        pcaps = get_positive_pcaps(rule_stem)

        print(f"[INFO] Running Suricata tests for {rule_path.name}")

        for pcap_path in pcaps:
            alerts = run_suricata_against_pcap(suricata_bin, rule_path, pcap_path)

            if not alerts:
                fail(
                    f"No Suricata alerts were generated for {pcap_path.relative_to(ROOT)} "
                    f"using {rule_path.name}"
                )

            if not any(alert_matches(alert, sid, msg) for alert in alerts):
                fail(
                    f"Expected Suricata alert sid={sid} msg=\"{msg}\" was not found for "
                    f"{pcap_path.relative_to(ROOT)}"
                )

            print(f"[PASS] {rule_path.name} matched {pcap_path.name}")

    print("[PASS] All Suricata tests passed")


if __name__ == "__main__":
    run_tests()