from pathlib import Path
import json
import re
import sys

# root directory relative to the path
ROOT = Path(__file__).resolve().parent.parent

# Splunk and Security Onion detection directories
SPLUNK_DIR = ROOT / "detections" / "splunk" / "mitre-att&ck"
SO_BASE_DIR = ROOT / "detections" / "security-onion"
SO_SURICATA_DIR = SO_BASE_DIR / "suricata"
SO_SIGMA_DIR = SO_BASE_DIR / "sigma"

# validation scenarios and matrix directories
VALIDATIONS_DIR = ROOT / "validations"
SCENARIOS_DIR = VALIDATIONS_DIR / "scenarios"
MATRIX_FILE = VALIDATIONS_DIR / "detection-validation-matrix.md"

# state file
STATE_DIR = ROOT / "state"
STATE_FILE = STATE_DIR / "securityonion_rule_state.json"

# Security Onion allowed engines
ALLOWED_STATE_ENGINES = {"suricata", "sigma"}

"""
Validates repository structure and detection standards.

- Ensures required directories and files exist
- Validates detection formatting and metadata
- Enforces consistency across the project
"""


# fail function
def fail(msg: str):
    print(f"[FAIL] {msg}")
    sys.exit(1)


# log function
def log(msg: str):
    print(f"[INFO] {msg}")


# normalize rule content by collapsing all whitespace
def normalize_rule_content(content: str) -> str:
    return " ".join(content.split())


# load persisted state file that tracks deployed detections
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

    # ensure top-level structure is a dictionary
    if not isinstance(raw, dict):
        fail("State file must contain a top-level JSON object")

    # allow legacy zeek state to exist and drop it.
    if "zeek" in raw:
        raw.pop("zeek", None)

    for engine in ALLOWED_STATE_ENGINES:
        raw.setdefault(engine, {})

    # validate no unsupported keys exist
    extra_keys = set(raw.keys()) - ALLOWED_STATE_ENGINES
    if extra_keys:
        fail(
            "State file contains unsupported top-level keys: "
            + ", ".join(sorted(extra_keys))
        )

    # validate structure of each engine section
    for engine, entries in raw.items():
        if not isinstance(entries, dict):
            fail(f"State section '{engine}' must be an object")
        for name, content in entries.items():
            if not isinstance(name, str) or not name.strip():
                fail(f"Invalid rule name found in state section '{engine}'")
            if not isinstance(content, str) or not content.strip():
                fail(f"State entry '{engine}:{name}' must contain a non-empty rule string")

    return raw


# parse splunk detection file into metadata and query
def parse_splunk_detection(path: Path):
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    metadata = {}
    query_lines = []

    # iterates metadata lines
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

    # ensure required metadata is present
    missing = [k for k in required if k not in metadata]
    if missing:
        fail(f"{path.name} missing metadata keys: {', '.join(missing)}")

    # ensure query is not empty
    if not query:
        fail(f"{path.name} has an empty search query")

    return metadata, query


# ensure all required directories and files exist in the repo
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

    # validate directories
    for path in required_dirs:
        if not path.exists():
            fail(f"Required directory missing: {path.relative_to(ROOT)}")
        if not path.is_dir():
            fail(f"Expected directory but found non-directory: {path.relative_to(ROOT)}")

    # validate files
    for path in required_files:
        if not path.exists():
            fail(f"Required file missing: {path.relative_to(ROOT)}")
        if not path.is_file():
            fail(f"Expected file but found non-file: {path.relative_to(ROOT)}")


# validate Splunk detection files for structure and metadata
def validate_splunk_detections():
    spl_files = sorted(SPLUNK_DIR.glob("*.spl"))
    if not spl_files:
        fail("No .spl files found in detections/splunk/mitre-att&ck")

    for spl_file in spl_files:
        metadata, query = parse_splunk_detection(spl_file)

        # ensure mitre technique is properly formatted
        if not metadata["mitre"].upper().startswith("T"):
            fail(f"{spl_file.name} has invalid MITRE technique value: {metadata['mitre']}")

        # warn if query does not explicitly reference as index
        if "index=" not in query.lower():
            print(f"[WARN] {spl_file.name} may not explicitly reference an index")

        # warn if no mitre reference appears in file content
        content = spl_file.read_text(encoding="utf-8", errors="ignore")
        if "mitre" not in content.lower() and "attack" not in content.lower():
            print(f"[WARN] {spl_file.name} may not include MITRE ATT&CK reference")


# extract sid value from Suricata rule content
def extract_sid(content: str) -> str | None:
    match = re.search(r"\bsid\s*:\s*(\d+)\b", content, re.IGNORECASE)
    return match.group(1) if match else None


# ensure all Suricata rules have valid and unique SID values
def validate_suricata_sids():
    repo_rules = {}

    # load all Suricata rules
    for path in sorted(SO_SURICATA_DIR.glob("*.rules")):
        content = path.read_text(encoding="utf-8", errors="ignore").strip()
        if not content:
            fail(f"{path.relative_to(ROOT)} is empty")
        repo_rules[path.name] = content

    sid_to_names = {}
    # build mapping of SID > rule names
    for name, content in repo_rules.items():
        sid = extract_sid(content)
        # ensure every rule has a SID
        if not sid:
            fail(f"Suricata rule missing sid: {name}")
        sid_to_names.setdefault(sid, []).append(name)

    # detect duplicate SIDs
    repo_dupes = {sid: names for sid, names in sid_to_names.items() if len(names) > 1}
    if repo_dupes:
        details = "; ".join(
            f"sid:{sid} -> {', '.join(names)}" for sid, names in sorted(repo_dupes.items())
        )
        fail(f"Duplicate Suricata SID(s) found in repo: {details}")


# collect all Security Onion rules from the repo and normalize them into a unified structure
# this represents the "desired state" of detections across Suricata and Sigma
def collect_security_onion_repo_rules() -> dict:
    repo_state = {
        "suricata": {},
        "sigma": {},
    }

    # process Suricata rules
    if SO_SURICATA_DIR.exists():
        if not SO_SURICATA_DIR.is_dir():
            fail("detections/security-onion/suricata must be a directory")
        # iterate through all .rules files
        for path in sorted(SO_SURICATA_DIR.glob("*.rules")):
            content = path.read_text(encoding="utf-8", errors="ignore").strip()
            # fail if any rule file is empty (invalid detection)
            if not content:
                fail(f"{path.relative_to(ROOT)} is empty")
            # normalize content to ignore formatting differences during comparison
            repo_state["suricata"][path.name] = normalize_rule_content(content)

    # process Sigma rules (recurisve to support nested sturcture)
    if SO_SIGMA_DIR.exists():
        if not SO_SIGMA_DIR.is_dir():
            fail("detections/security-onion/sigma must be a directory")
        sigma_files = sorted(list(SO_SIGMA_DIR.rglob("*.yml")) + list(SO_SIGMA_DIR.rglob("*.yaml")))
        for path in sigma_files:
            content = path.read_text(encoding="utf-8", errors="ignore").strip()
            # fail on empty Sigma files
            if not content:
                fail(f"{path.relative_to(ROOT)} is empty")
            # use relative path to preserve folder sturcture for uniqueness
            relative_name = path.relative_to(SO_SIGMA_DIR).as_posix()
            repo_state["sigma"][relative_name] = normalize_rule_content(content)

    return repo_state


# compare repo state vs saved state to determine create/delete/update operations
# this drives deployment decisions in the pipeline
def diff_security_onion_repo_vs_state(repo_state: dict, saved_state: dict) -> list[dict]:
    changes = []

    # iterate over each supported engine (Suricata, Sigma)
    for engine in sorted(ALLOWED_STATE_ENGINES):
        repo_rules = repo_state.get(engine, {})
        state_rules = saved_state.get(engine, {})

        # compute set differences to identify changes
        repo_names = set(repo_rules.keys())
        state_names = set(state_rules.keys())

        # new rules in repo > create
        for name in sorted(repo_names - state_names):
            changes.append(
                {
                    "engine": engine,
                    "action": "create",
                    "name": name,
                }
            )

        # rules removed from repo > delete
        for name in sorted(state_names - repo_names):
            changes.append(
                {
                    "engine": engine,
                    "action": "delete",
                    "name": name,
                }
            )

        # rules present in both > check for updates
        for name in sorted(repo_names & state_names):
            # normalize both sides to ignore whitespace/formatting differences
            repo_content = normalize_rule_content(repo_rules[name])
            state_content = normalize_rule_content(state_rules[name])
            # if content differs, mark as update
            if repo_content != state_content:
                changes.append(
                    {
                        "engine": engine,
                        "action": "update",
                        "name": name,
                    }
                )

    return changes


# extract technique id from filename (e.g.: t1046_nmap > T1046)
def extract_technique_from_stem(stem: str) -> str | None:
    match = re.match(r"^(t\d{4}(?:\.\d{3})?)", stem, re.IGNORECASE)
    # return uppercase technique id if found, otherwise none
    if not match:
        return None
    return match.group(1).upper()


# extract mitre technique from Sigma tags section inside yaml file
# supports both dotted and simple formats (T1059 vs T1059.001)
def extract_sigma_technique_from_tags(path: Path) -> str | None:
    text = path.read_text(encoding="utf-8", errors="ignore")

    # match attack.txxx.xxx format
    dotted = re.search(r"(?im)^\s*-\s*attack\.t(\d{4}\.\d{3})\s*$", text)
    if dotted:
        return f"T{dotted.group(1)}"

    # match attack.txxx format
    simple = re.search(r"(?im)^\s*-\s*attack\.t(\d{4})\s*$", text)
    if simple:
        return f"T{simple.group(1)}"

    return None


# collect all detections across Splunk, Suricata, and Sigma into a unified structure
# used for validation against scenarios and coverage matrix
def collect_all_detection_info() -> list[dict]:
    detections = []

    # process Splunk detections
    for path in sorted(SPLUNK_DIR.glob("*.spl")):
        metadata, _ = parse_splunk_detection(path)
        detections.append(
            {
                "stem": path.stem,
                "relative_path": str(path.relative_to(ROOT)),
                "technique": metadata["mitre"].strip().upper(),
            }
        )

    # process Suricata detections (derive technique from filename)
    for path in sorted(SO_SURICATA_DIR.glob("*.rules")):
        technique = extract_technique_from_stem(path.stem)
        # fail if technique cannot be derived (enforces naming standard)
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

    # process Sigma detections (prefer tags, fallback to filename)
    if SO_SIGMA_DIR.exists():
        sigma_files = sorted(list(SO_SIGMA_DIR.rglob("*.yml")) + list(SO_SIGMA_DIR.rglob("*.yaml")))
        for path in sigma_files:
            technique = extract_sigma_technique_from_tags(path) or extract_technique_from_stem(path.stem)
            # enforce technique presence for Sigma rules
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


# collect all validation scenario filesnames (excluding template)
# used to ensure every detection has a corresponding test scenario
def collect_scenario_stems() -> set[str]:
    stems = set()
    for path in sorted(SCENARIOS_DIR.glob("*.md")):
        if path.name == "_scenarios_template.md":
            continue
        stems.add(path.stem)
    return stems


# validate that every detection has a corresponding scenario file and mitre entry in coverage matrix
def validate_detection_scenarios_and_matrix():
    detections = collect_all_detection_info()
    scenarios = collect_scenario_stems()
    # load matrix file content once for a lookup
    matrix_text = MATRIX_FILE.read_text(encoding="utf-8", errors="ignore")

    if not detections:
        fail("No detection files found across Splunk, Suricata, or Sigma")

    missing_scenarios = []
    missing_matrix_entries = []

    # validate each detection
    for detection in detections:
        stem = detection["stem"]
        rel_path = detection["relative_path"]
        technique = detection["technique"]
        scenario_name = f"{stem}.md"

        # ensure scenario exists
        if stem not in scenarios:
            missing_scenarios.append(
                f"{rel_path} -> validations/scenarios/{scenario_name}"
            )

        # ensure technique appears in matrix
        if technique not in matrix_text:
            missing_matrix_entries.append(
                f"{rel_path} -> expected explicit matrix entry containing '{technique}' in "
                f"{MATRIX_FILE.relative_to(ROOT)}"
            )

    # fail if any missing scenarios
    if missing_scenarios:
        fail(
            "Detection file(s) missing corresponding validation scenario(s): "
            + "; ".join(missing_scenarios)
        )

    # fail if any missing matrix entries
    if missing_matrix_entries:
        fail(
            "Detection file(s) missing validation matrix technique entry: "
            + "; ".join(missing_matrix_entries)
        )


# enforce rule that only one security onion detection change can occur per push
# prevents unsafe multi-rule deployments in CI/CD
def validate_single_security_onion_change():
    saved_state = load_state()
    repo_state = collect_security_onion_repo_rules()

    # display repo vs state
    log(f"Repo suricata rules: {sorted(repo_state['suricata'].keys())}")
    log(f"State suricata rules: {sorted(saved_state['suricata'].keys())}")
    log(f"Repo sigma rules: {sorted(repo_state['sigma'].keys())}")
    log(f"State sigma rules: {sorted(saved_state['sigma'].keys())}")

    # compute changes between repo and state
    changes = diff_security_onion_repo_vs_state(repo_state, saved_state)

    log(
        "Computed Security Onion repo/state changes: "
        + (
            ", ".join(f"{c['engine']}:{c['action']}:{c['name']}" for c in changes)
            if changes
            else "none"
        )
    )

    # enforce strict single-change constraint
    if len(changes) > 1:
        formatted = ", ".join(
            f"{item['engine']}:{item['action']}:{item['name']}" for item in changes
        )
        fail(
            "Only one Security Onion rule change is allowed per push. "
            f"Detected {len(changes)} repo/state changes: {formatted}"
        )

    # log valid single change
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