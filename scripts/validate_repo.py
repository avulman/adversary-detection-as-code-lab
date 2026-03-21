from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
SPLUNK_DIR = ROOT / "detections" / "splunk"
SCENARIO_DIR = ROOT / "validations" / "scenarios"
MATRIX = ROOT / "validations" / "detection-validation-matrix.md"

def fail(msg):
    print(f"[FAIL] {msg}")
    sys.exit(1)

def main():
    if not README.exists():
        fail("README.md is missing")

    if not SPLUNK_DIR.exists():
        fail("detections/splunk directory is missing")

    if not SCENARIO_DIR.exists():
        fail("validations/scenarios directory is missing")

    if not MATRIX.exists():
        fail("validations/detection-validation-matrix.md is missing")

    spl_files = list(SPLUNK_DIR.glob("*.spl"))
    if not spl_files:
        fail("No .spl files found in detections/splunk")

    required_keys = [
        "# name:",
        "# mitre:",
        "# description:",
        "# app:",
        "# cron_schedule:",
        "# alert_type:",
        "# alert_comparator:",
        "# alert_threshold:",
        "# disabled:",
        "# email_to:",
        "# email_subject:",
        "# email_message:",
    ]

    for spl_file in spl_files:
        scenario_file = SCENARIO_DIR / f"{spl_file.stem}.md"
        if not scenario_file.exists():
            fail(f"Missing validation scenario for {spl_file.name}")

        content = spl_file.read_text(encoding="utf-8", errors="ignore").lower()
        for key in required_keys:
            if key not in content:
                fail(f"{spl_file.name} missing metadata line: {key}")

    print("[PASS] Repository validation successful")

if __name__ == "__main__":
    main()