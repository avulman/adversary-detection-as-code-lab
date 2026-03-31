from pathlib import Path
import json
import re
import sys

ROOT = Path(__file__).resolve().parent.parent

SPLUNK_DIR = ROOT / "detections" / "splunk" / "mitre-att&ck"
SO_BASE_DIR = ROOT / "detections" / "security-onion"
SO_SURICATA_DIR = SO_BASE_DIR / "suricata"
SO_SIGMA_DIR = SO_BASE_DIR / "sigma"

VALIDATIONS_DIR = ROOT / "validations"
SCENARIOS_DIR = VALIDATIONS_DIR / "scenarios"
MATRIX_FILE = VALIDATIONS_DIR / "detection-validation-matrix.md"

STATE_DIR = ROOT / "state"
STATE_FILE = STATE_DIR / "securityonion_rule_state.json"

ALLOWED_STATE_ENGINES = {"suricata", "sigma"}

"""
Validates repository structure and detection standards.

- Ensures required directories and files exist
- Validates detection formatting and metadata
- Enforces consistency across the project
"""


def fail(msg: str):
    print(f"[FAIL] {msg}")
    sys.exit(1)


def log(msg: str):
    print(f"[INFO] {msg}")


def normalize_rule_content(content: str) -> str:
    return " ".join(content.split())


def load_state() -> dict:
    if not STATE_FILE.exists():
        return {"suricata": {}, "sigma": {}}

    if not STATE_FILE.is_file():
        fail(
            "state/securityonion_rule_state.json exists but is not a file. "
            "It must be a JSON file."
        )

    try:
        raw = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        fail(f"State file is not valid JSON: {e}")
    except Exception as e:
        fail(f"Unable to read state file: {e}")

    if not isinstance(raw, dict):
        fail("State file must contain a top-level JSON object")

    # Allow legacy zeek state to exist and drop it.
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
                fail(f"State entry '{engine}:{name}' must contain a non-empty rule string")

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

    missing = [k for k in required if k not in metadata]
    if missing:
        fail(f"{path.name} missing metadata keys: {', '.join(missing)}")

    if not query:
        fail(f"{path.name} has an empty search query")

    return metadata, query


def validate_required_paths():
    required_dirs = [
        SPLUNK_DIR,
        SO_SURICATA_DIR,
        VALIDATIONS_DIR,
        SCENARIOS_DIR,
        STATE_DIR,
    ]

    required_files = [
        MATRIX_FILE,
        STATE_FILE,
    ]

    for path in required_dirs:
        if not path.exists():
            fail(f"Required directory missing: {path.relative_to(ROOT)}")
        if not path.is_dir():
            fail(f"Expected directory but found non-directory: {path.relative_to(ROOT)}")

    for path in required_files:
        if not path.exists():
            fail(f"Required file missing: {path.relative_to(ROOT)}")
        if not path.is_file():
            fail(f"Expected file but found non-file: {path.relative_to(ROOT)}")


def validate_splunk_detections():
    spl_files = sorted(SPLUNK_DIR.glob("*.spl"))
    if not spl_files:
        fail("No .spl files found in detections/splunk/mitre-att&ck")

    for spl_file in spl_files:
        metadata, query = parse_splunk_detection(spl_file)

        if not metadata["mitre"].upper().startswith("T"):
            fail(f"{spl_file.name} has invalid MITRE technique value: {metadata['mitre']}")

        if "index=" not in query.lower():
            print(f"[WARN] {spl_file.name} may not explicitly reference an index")

        content = spl_file.read_text(encoding="utf-8", errors="ignore")
        if "mitre" not in content.lower() and "attack" not in content.lower():
            print(f"[WARN] {spl_file.name} may not include MITRE ATT&CK reference")


def extract_sid(content: str) -> str | None:
    match = re.search(r"\bsid\s*:\s*(\d+)\b", content, re.IGNORECASE)
    return match.group(1) if match else None


def validate_suricata_sids():
    repo_rules = {}

    for path in sorted(SO_SURICATA_DIR.glob("*.rules")):
        content = path.read_text(encoding="utf-8", errors="ignore").strip()
        if not content:
            fail(f"{path.relative_to(ROOT)} is empty")
        repo_rules[path.name] = content

    sid_to_names = {}
    for name, content in repo_rules.items():
        sid = extract_sid(content)
        if not sid:
            fail(f"Suricata rule missing sid: {name}")
        sid_to_names.setdefault(sid, []).append(name)

    repo_dupes = {sid: names for sid, names in sid_to_names.items() if len(names) > 1}
    if repo_dupes:
        details = "; ".join(
            f"sid:{sid} -> {', '.join(names)}" for sid, names in sorted(repo_dupes.items())
        )
        fail(f"Duplicate Suricata SID(s) found in repo: {details}")


def collect_security_onion_repo_rules() -> dict:
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


def extract_technique_from_stem(stem: str) -> str | None:
    match = re.match(r"^(t\d{4}(?:\.\d{3})?)", stem, re.IGNORECASE)
    if not match:
        return None
    return match.group(1).upper()


def extract_sigma_technique_from_tags(path: Path) -> str | None:
    text = path.read_text(encoding="utf-8", errors="ignore")

    dotted = re.search(r"(?im)^\s*-\s*attack\.t(\d{4}\.\d{3})\s*$", text)
    if dotted:
        return f"T{dotted.group(1)}"

    simple = re.search(r"(?im)^\s*-\s*attack\.t(\d{4})\s*$", text)
    if simple:
        return f"T{simple.group(1)}"

    return None


def collect_all_detection_info() -> list[dict]:
    detections = []

    for path in sorted(SPLUNK_DIR.glob("*.spl")):
        metadata, _ = parse_splunk_detection(path)
        detections.append(
            {
                "stem": path.stem,
                "relative_path": str(path.relative_to(ROOT)),
                "technique": metadata["mitre"].strip().upper(),
            }
        )

    for path in sorted(SO_SURICATA_DIR.glob("*.rules")):
        technique = extract_technique_from_stem(path.stem)
        if not technique:
            fail(
                f"Could not derive MITRE technique from Suricata filename: "
                f"{path.relative_to(ROOT)}"
            )
        detections.append(
            {
                "stem": path.stem,
                "relative_path": str(path.relative_to(ROOT)),
                "technique": technique,
            }
        )

    if SO_SIGMA_DIR.exists():
        sigma_files = sorted(list(SO_SIGMA_DIR.rglob("*.yml")) + list(SO_SIGMA_DIR.rglob("*.yaml")))
        for path in sigma_files:
            technique = extract_sigma_technique_from_tags(path) or extract_technique_from_stem(path.stem)
            if not technique:
                fail(
                    f"Could not derive MITRE technique from Sigma file: "
                    f"{path.relative_to(ROOT)}"
                )
            detections.append(
                {
                    "stem": path.stem,
                    "relative_path": str(path.relative_to(ROOT)),
                    "technique": technique,
                }
            )

    return detections


def collect_scenario_stems() -> set[str]:
    stems = set()
    for path in sorted(SCENARIOS_DIR.glob("*.md")):
        if path.name == "_scenarios_template.md":
            continue
        stems.add(path.stem)
    return stems


def validate_detection_scenarios_and_matrix():
    detections = collect_all_detection_info()
    scenarios = collect_scenario_stems()
    matrix_text = MATRIX_FILE.read_text(encoding="utf-8", errors="ignore")

    if not detections:
        fail("No detection files found across Splunk, Suricata, or Sigma")

    missing_scenarios = []
    missing_matrix_entries = []

    for detection in detections:
        stem = detection["stem"]
        rel_path = detection["relative_path"]
        technique = detection["technique"]
        scenario_name = f"{stem}.md"

        if stem not in scenarios:
            missing_scenarios.append(
                f"{rel_path} -> validations/scenarios/{scenario_name}"
            )

        if technique not in matrix_text:
            missing_matrix_entries.append(
                f"{rel_path} -> expected explicit matrix entry containing '{technique}' in "
                f"{MATRIX_FILE.relative_to(ROOT)}"
            )

    if missing_scenarios:
        fail(
            "Detection file(s) missing corresponding validation scenario(s): "
            + "; ".join(missing_scenarios)
        )

    if missing_matrix_entries:
        fail(
            "Detection file(s) missing validation matrix technique entry: "
            + "; ".join(missing_matrix_entries)
        )


def validate_single_security_onion_change():
    saved_state = load_state()
    repo_state = collect_security_onion_repo_rules()

    log(f"Repo suricata rules: {sorted(repo_state['suricata'].keys())}")
    log(f"State suricata rules: {sorted(saved_state['suricata'].keys())}")
    log(f"Repo sigma rules: {sorted(repo_state['sigma'].keys())}")
    log(f"State sigma rules: {sorted(saved_state['sigma'].keys())}")

    changes = diff_security_onion_repo_vs_state(repo_state, saved_state)

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

    if len(changes) == 1:
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
    validate_suricata_sids()
    validate_detection_scenarios_and_matrix()
    validate_single_security_onion_change()
    print("[PASS] Repository validation succeeded")


if __name__ == "__main__":
    main()