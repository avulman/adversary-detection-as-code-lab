from pathlib import Path
import json
import subprocess
import sys
import tempfile
import shutil

ROOT = Path(__file__).resolve().parent.parent

SURICATA_RULES_DIR = ROOT / "detections" / "security-onion" / "suricata"
TESTS_DIR = ROOT / "tests" / "suricata"


def fail(msg: str):
    print(f"[FAIL] {msg}")
    sys.exit(1)


def log(msg: str):
    print(f"[INFO] {msg}")


def check_suricata_installed():
    try:
        subprocess.run(["suricata", "-V"], capture_output=True, check=True)
    except Exception:
        fail("Suricata is not installed or not in PATH on runner")


def load_test_config(rule_stem: str) -> dict:
    config_path = TESTS_DIR / rule_stem / "test_config.json"

    if not config_path.exists():
        fail(f"Missing test_config.json for {rule_stem}")

    return json.loads(config_path.read_text())


def run_suricata_test(rule_file: Path, test_dir: Path):
    rule_stem = rule_file.stem
    config = load_test_config(rule_stem)

    expected_sid = int(config["expected_sid"])
    expected_min = int(config.get("expected_alert_min", 1))

    pcap_dir = test_dir / "positive"
    pcaps = list(pcap_dir.glob("*.pcap"))

    if not pcaps:
        fail(f"No pcap files found for {rule_stem}")

    # temp working dir
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        rules_file = tmp_path / "test.rules"
        rules_file.write_text(rule_file.read_text())

        eve_file = tmp_path / "eve.json"

        for pcap in pcaps:
            log(f"Running Suricata on {pcap.name} for {rule_stem}")

            cmd = [
                "suricata",
                "-r", str(pcap),
                "-S", str(rules_file),
                "-l", str(tmp_path),
                "--init-errors-fatal",
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                fail(f"Suricata failed:\n{result.stderr}")

        if not eve_file.exists():
            fail("Suricata did not produce eve.json")

        alerts = 0

        with eve_file.open() as f:
            for line in f:
                try:
                    event = json.loads(line)
                except:
                    continue

                if event.get("event_type") != "alert":
                    continue

                alert = event.get("alert", {})
                if alert.get("signature_id") == expected_sid:
                    alerts += 1

        log(f"{rule_stem} produced {alerts} alerts (expected >= {expected_min})")

        if alerts < expected_min:
            fail(f"{rule_stem} failed: expected >= {expected_min}, got {alerts}")

        log(f"{rule_stem} passed")


def main():
    check_suricata_installed()

    if not SURICATA_RULES_DIR.exists():
        fail("Suricata rules directory missing")

    for rule_file in SURICATA_RULES_DIR.glob("*.rules"):
        test_dir = TESTS_DIR / rule_file.stem

        if not test_dir.exists():
            fail(
                f"Missing test directory for {rule_file.name}: "
                f"{test_dir.relative_to(ROOT)}"
            )

        if not test_dir.is_dir():
            fail(
                f"Test path for {rule_file.name} is not a directory: "
                f"{test_dir.relative_to(ROOT)}"
            )

        config_path = test_dir / "test_config.json"
        if not config_path.exists():
            fail(
                f"Missing test_config.json for {rule_file.name}: "
                f"{config_path.relative_to(ROOT)}"
            )

        run_suricata_test(rule_file, test_dir)

    print("[PASS] Suricata detection tests passed")


if __name__ == "__main__":
    main()