from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parent.parent

README_FILE = ROOT / "README.md"

SPLUNK_DIR = ROOT / "detections" / "splunk" / "mitre-att&ck"
SO_BASE_DIR = ROOT / "detections" / "security-onion"
SO_SURICATA_DIR = SO_BASE_DIR / "suricata"
SO_ZEEK_DIR = SO_BASE_DIR / "zeek"

VALIDATIONS_DIR = ROOT / "validations"
SCENARIOS_DIR = VALIDATIONS_DIR / "scenarios"

STATE_DIR = ROOT / "state"
STATE_FILE = STATE_DIR / "securityonion_rule_state.json"

ALLOWED_STATE_ENGINES = {"suricata", "zeek"}


def fail(msg: str):
    print(f"[FAIL] {msg}")
    sys.exit(1)


def log(msg: str):
    print(f"[INFO] {msg}")


def normalize_rule_content(content: str) -> str:
    return " ".join(content.split())


def validate_required_paths():
    required_paths = [
        README_FILE,
        SPLUNK_DIR,
        SO_BASE_DIR,
        VALIDATIONS_DIR,
        SCENARIOS_DIR,
        STATE_DIR,
        STATE_FILE,
    ]

    for path in required_paths:
        if not path.exists():
            fail(f"Required path missing: {path.relative_to(ROOT)}")

    if not README_FILE.is_file():
        fail("README.md must be a file")

    if not SPLUNK_DIR.is_dir():
        fail("detections/splunk/mitre-att&ck must be a directory")

    if not SO_BASE_DIR.is_dir():
        fail("detections/security-onion must be a directory")

    if not VALIDATIONS_DIR.is_dir():
        fail("validations must be a directory")

    if not SCENARIOS_DIR.is_dir():
        fail("validations/scenarios must be a directory")

    if not STATE_DIR.is_dir():
        fail("state must be a directory")

    if not STATE_FILE.is_file():
        fail(
            "state/securityonion_rule_state.json must exist as a JSON file. "
            "It cannot be a directory."
        )


def load_state() -> dict:
    try:
        raw = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        fail(f"{STATE_FILE.relative_to(ROOT)} is not valid JSON: {e}")
    except Exception as e:
        fail(f"Unable to read {STATE_FILE.relative_to(ROOT)}: {e}")

    if not isinstance(raw, dict):
        fail("securityonion_rule_state.json must contain a top-level JSON object")

    for engine in ALLOWED_STATE_ENGINES:
        raw.setdefault(engine, {})

    extra_keys = set(raw.keys()) - ALLOWED_STATE_ENGINES
    if extra_keys:
        fail(
            "securityonion_rule_state.json contains unsupported top-level keys: "
            + ", ".join(sorted(extra_keys))
        )

    for engine, entries in raw.items():
        if not isinstance(entries, dict):
            fail(f"State section '{engine}' must be a JSON object")

        for rule_name, rule_content in entries.items():
            if not isinstance(rule_name, str) or not rule_name.strip():
                fail(f"State section '{engine}' contains an invalid rule name")
            if not isinstance(rule_content, str) or not rule_content.strip():
                fail(
                    f"State section '{engine}' entry '{rule_name}' must contain "
                    "a non-empty rule string"
                )

    return raw


def parse_splunk_detection(path: Path):
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    metadata = {}
    query_lines = []

    for line in lines:
        if line.startswith("# ") and ":" in line:
            key, value = line[2:].split(":", 1)
            metadata[key.strip().lower()] = value.strip()
        else:
            query_lines.append(line)

    query = "\n".join(query_lines).strip()

    required = [
        "name",
        "mitre",
        "description",
        "app",
        "cron_schedule",
        "disabled",
        "email_subject",
        "email_message",
    ]

    missing = [key for key in required if key not in metadata]
    if missing:
        fail(f"{path.name} missing metadata keys: {', '.join(missing)}")

    if not query:
        fail(f"{path.name} has an empty search query")

    return metadata, query


def validate_splunk_detections():
    spl_files = sorted(SPLUNK_DIR.glob("*.spl"))
    if not spl_files:
        fail("No .spl files found in detections/splunk/mitre-att&ck")

    for spl_file in spl_files:
        metadata, query = parse_splunk_detection(spl_file)

        if not metadata["mitre"].upper().startswith("T"):
            fail(f"{spl_file.name} has invalid MITRE technique value: {metadata['mitre']}")

        if "index=" not in query.lower():
            log(f"[WARN] {spl_file.name} may not explicitly reference an index")

        content = spl_file.read_text(encoding="utf-8", errors="ignore")
        if "mitre" not in content.lower() and "attack" not in content.lower():
            print(f"[WARN] {spl_file.name} may not include MITRE ATT&CK reference")


def collect_security_onion_repo_rules() -> dict:
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


def diff_security_onion_repo_vs_state(repo_state: dict, saved_state: dict) -> list[dict]:
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
                }
            )

        for name in sorted(state_names - repo_names):
            changes.append(
                {
                    "engine": engine,
                    "action": "delete",
                    "name": name,
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
                    }
                )

    return changes


def validate_single_security_onion_change():
    saved_state = load_state()
    repo_state = collect_security_onion_repo_rules()

    log(f"Repo suricata rules: {sorted(repo_state['suricata'].keys())}")
    log(f"State suricata rules: {sorted(saved_state['suricata'].keys())}")
    log(f"Repo zeek rules: {sorted(repo_state['zeek'].keys())}")
    log(f"State zeek rules: {sorted(saved_state['zeek'].keys())}")

    changes = diff_security_onion_repo_vs_state(repo_state, saved_state)

    log(
        "Computed Security Onion repo/state changes: "
        + (
            ", ".join(f"{c['engine']}:{c['action']}:{c['name']}" for c in changes)
            if changes
            else "none"
        )
    )

    if len(changes) > 2:
        formatted = ", ".join(
            f"{item['engine']}:{item['action']}:{item['name']}" for item in changes
        )
        fail(
            "Only one Security Onion rule change is allowed per push. "
            f"Detected {len(changes)} repo/state changes: {formatted}"
        )

    if len(changes) == 2:
        item = changes[0]
        log(
            "Validated single Security Onion repo/state change: "
            f"{item['engine']}:{item['action']}:{item['name']}"
        )
    else:
        log("No Security Onion repo/state changes detected against state file")


def main():
    validate_required_paths()
    validate_splunk_detections()
    validate_single_security_onion_change()
    print("[PASS] Repository validation succeeded")


if __name__ == "__main__":
    main()