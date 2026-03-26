from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent

README = ROOT / "README.md"
MATRIX = ROOT / "validations" / "detection-validation-matrix.md"
SCENARIO_DIR = ROOT / "validations" / "scenarios"

SPLUNK_DIR = ROOT / "detections" / "splunk" / "mitre-att&ck"
SO_SURICATA_DIR = ROOT / "detections" / "security-onion" / "suricata"

DETECTIONS_DIR = ROOT / "detections"


def fail(msg: str):
    print(f"[FAIL] {msg}")
    sys.exit(1)


def validate_common():
    if not README.exists():
        fail("README.md is missing")

    if not MATRIX.exists():
        fail("validations/detection-validation-matrix.md is missing")

    if not SCENARIO_DIR.exists():
        fail("validations/scenarios directory is missing")


def validate_pipeline_separation():
    splunk_rules = list((ROOT / "detections" / "splunk").rglob("*.rules"))
    so_spl = list((ROOT / "detections" / "security-onion").rglob("*.spl"))

    if splunk_rules:
        fail(
            "Suricata .rules files found under detections/splunk: "
            + ", ".join(str(p.relative_to(ROOT)) for p in splunk_rules)
        )

    if so_spl:
        fail(
            "Splunk .spl files found under detections/security-onion: "
            + ", ".join(str(p.relative_to(ROOT)) for p in so_spl)
        )

    print("[PASS] Pipeline separation validated")


def validate_splunk():
    if not SPLUNK_DIR.exists():
        fail("detections/splunk/mitre-att&ck directory is missing")

    spl_files = sorted(SPLUNK_DIR.glob("*.spl"))
    if not spl_files:
        fail("No .spl files found in detections/splunk/mitre-att&ck")

    required_keys = [
        "# name:",
        "# mitre:",
        "# description:",
        "# app:",
        "# cron_schedule:",
        "# disabled:",
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

        if "index=" not in content:
            fail(f"{spl_file.name} does not appear to contain a Splunk search")

    print(f"[PASS] Validated {len(spl_files)} Splunk detection file(s)")


def validate_security_onion():
    if not SO_SURICATA_DIR.exists():
        fail("detections/security-onion/suricata directory is missing")

    rule_files = sorted(SO_SURICATA_DIR.glob("*.rules"))
    if not rule_files:
        print("[WARN] No .rules files found in detections/security-onion/suricata")
        return

    required_rule_fields = [
        "msg:",
        "sid:",
        "rev:",
    ]

    for rule_file in rule_files:
        scenario_file = SCENARIO_DIR / f"{rule_file.stem}.md"
        if not scenario_file.exists():
            fail(f"Missing validation scenario for {rule_file.name}")

        content = rule_file.read_text(encoding="utf-8", errors="ignore")

        if "alert " not in content.lower():
            fail(f"{rule_file.name} does not appear to contain a Suricata alert rule")

        for field in required_rule_fields:
            if field not in content:
                fail(f"{rule_file.name} missing required Suricata field: {field}")

    print(f"[PASS] Validated {len(rule_files)} Security Onion Suricata rule file(s)")


def main():
    validate_common()
    validate_pipeline_separation()
    validate_splunk()
    validate_security_onion()
    print("[PASS] Repository validation successful")


if __name__ == "__main__":
    main()