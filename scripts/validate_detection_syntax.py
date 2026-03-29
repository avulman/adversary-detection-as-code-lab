from pathlib import Path
import json
import os
import re
import sys

import requests
import yaml

ROOT = Path(__file__).resolve().parent.parent

SIGMA_DIR = ROOT / "detections" / "security-onion" / "sigma"
SURICATA_DIR = ROOT / "detections" / "security-onion" / "suricata"
SPLUNK_DIR = ROOT / "detections" / "splunk" / "mitre-att&ck"

SPLUNK_BASE_URL = os.getenv("SPLUNK_BASE_URL", "").rstrip("/")
SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME", "")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "")

requests.packages.urllib3.disable_warnings()


def fail(msg: str):
    print(f"[FAIL] {msg}")
    sys.exit(1)


def log(msg: str):
    print(f"[INFO] {msg}")


def warn(msg: str):
    print(f"[WARN] {msg}")


def ensure_exists(path: Path, description: str):
    if not path.exists():
        fail(f"Missing {description}: {path.relative_to(ROOT)}")
    if not path.is_dir():
        fail(f"Expected directory for {description}: {path.relative_to(ROOT)}")


def validate_sigma_rules():
    ensure_exists(SIGMA_DIR, "Sigma detections directory")

    files = sorted(list(SIGMA_DIR.rglob("*.yml")) + list(SIGMA_DIR.rglob("*.yaml")))
    if not files:
        warn("No Sigma rules found")
        return

    required_top_level = {"title", "logsource", "detection"}

    for path in files:
        raw = path.read_text(encoding="utf-8", errors="ignore").strip()
        if not raw:
            fail(f"Sigma rule is empty: {path.relative_to(ROOT)}")

        try:
            data = yaml.safe_load(raw)
        except Exception as e:
            fail(f"Invalid YAML in Sigma rule {path.relative_to(ROOT)}: {e}")

        if not isinstance(data, dict):
            fail(f"Sigma rule must be a YAML object: {path.relative_to(ROOT)}")

        missing = sorted(required_top_level - set(data.keys()))
        if missing:
            fail(
                f"Sigma rule missing required keys in {path.relative_to(ROOT)}: "
                + ", ".join(missing)
            )

        if not isinstance(data.get("title"), str) or not data["title"].strip():
            fail(f"Sigma rule title must be a non-empty string: {path.relative_to(ROOT)}")

        if not isinstance(data.get("logsource"), dict) or not data["logsource"]:
            fail(f"Sigma rule logsource must be a non-empty object: {path.relative_to(ROOT)}")

        if not isinstance(data.get("detection"), dict) or not data["detection"]:
            fail(f"Sigma rule detection must be a non-empty object: {path.relative_to(ROOT)}")

        if "condition" not in data["detection"]:
            fail(f"Sigma rule detection must include condition: {path.relative_to(ROOT)}")

        log(f"Sigma syntax OK: {path.relative_to(ROOT)}")


def parse_suricata_options(options_text: str) -> dict[str, str]:
    parsed = {}
    parts = [part.strip() for part in options_text.split(";") if part.strip()]

    for part in parts:
        if ":" in part:
            key, value = part.split(":", 1)
            parsed[key.strip().lower()] = value.strip()
        else:
            parsed[part.strip().lower()] = ""

    return parsed


def validate_suricata_rules():
    ensure_exists(SURICATA_DIR, "Suricata detections directory")

    files = sorted(SURICATA_DIR.glob("*.rules"))
    if not files:
        warn("No Suricata rules found")
        return

    rule_pattern = re.compile(
        r"^(alert|drop|reject|pass)\s+"      # action
        r"(\S+)\s+"                          # proto
        r"(\S+)\s+"                          # src addr
        r"(\S+)\s+"                          # src port
        r"(->|<>)\s+"                        # direction
        r"(\S+)\s+"                          # dst addr
        r"(\S+)\s*"                          # dst port
        r"\((.*)\)\s*$",                     # options
        re.IGNORECASE | re.DOTALL,
    )

    for path in files:
        raw = path.read_text(encoding="utf-8", errors="ignore").strip()
        if not raw:
            fail(f"Suricata rule is empty: {path.relative_to(ROOT)}")

        if raw.count("(") != raw.count(")"):
            fail(f"Unbalanced parentheses in Suricata rule: {path.relative_to(ROOT)}")

        match = rule_pattern.match(raw)
        if not match:
            fail(f"Invalid Suricata rule structure: {path.relative_to(ROOT)}")

        options_text = match.group(8).strip()
        if not options_text:
            fail(f"Suricata rule missing options block: {path.relative_to(ROOT)}")

        options = parse_suricata_options(options_text)

        for required_key in ("msg", "sid", "rev"):
            if required_key not in options or not options[required_key]:
                fail(
                    f"Suricata rule missing required option '{required_key}': "
                    f"{path.relative_to(ROOT)}"
                )

        if not re.fullmatch(r"\d+", options["sid"]):
            fail(f"Suricata sid must be numeric: {path.relative_to(ROOT)}")

        if not re.fullmatch(r"\d+", options["rev"]):
            fail(f"Suricata rev must be numeric: {path.relative_to(ROOT)}")

        log(f"Suricata syntax OK: {path.relative_to(ROOT)}")


def parse_splunk_detection(path: Path) -> tuple[dict, str]:
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
        fail(f"{path.relative_to(ROOT)} missing metadata keys: {', '.join(missing)}")

    if not query:
        fail(f"{path.relative_to(ROOT)} has an empty search query")

    return metadata, query


def splunk_parse_search(query: str, path: Path):
    if not SPLUNK_BASE_URL or not SPLUNK_USERNAME or not SPLUNK_PASSWORD:
        fail(
            "Missing SPLUNK_BASE_URL, SPLUNK_USERNAME, or SPLUNK_PASSWORD "
            "for Splunk SPL syntax validation"
        )

    normalized_query = query.strip()
    if not normalized_query.lower().startswith(("search ", "|", "from ")):
        normalized_query = f"search {normalized_query}"

    url = f"{SPLUNK_BASE_URL}/services/search/parser"

    response = requests.post(
        url,
        auth=(SPLUNK_USERNAME, SPLUNK_PASSWORD),
        verify=False,
        data={
            "q": normalized_query,
            "output_mode": "json",
        },
        timeout=30,
    )

    if response.status_code != 200:
        fail(
            f"Splunk parser rejected {path.relative_to(ROOT)} "
            f"(HTTP {response.status_code}): {response.text[:500]}"
        )

    try:
        payload = response.json()
    except json.JSONDecodeError:
        fail(
            f"Splunk parser returned non-JSON response for {path.relative_to(ROOT)}: "
            f"{response.text[:500]}"
        )

    if isinstance(payload, dict) and payload.get("messages"):
        error_messages = []
        for message in payload["messages"]:
            if str(message.get("type", "")).upper() == "ERROR":
                error_messages.append(message.get("text", "Unknown parser error"))

        if error_messages:
            fail(
                f"Splunk parser reported error(s) for {path.relative_to(ROOT)}: "
                + " | ".join(error_messages)
            )


def validate_splunk_rules():
    ensure_exists(SPLUNK_DIR, "Splunk detections directory")

    files = sorted(SPLUNK_DIR.glob("*.spl"))
    if not files:
        warn("No Splunk rules found")
        return

    for path in files:
        metadata, query = parse_splunk_detection(path)

        if not metadata["mitre"].upper().startswith("T"):
            fail(f"Invalid MITRE value in {path.relative_to(ROOT)}: {metadata['mitre']}")

        splunk_parse_search(query, path)
        log(f"Splunk syntax OK: {path.relative_to(ROOT)}")


def main():
    validate_sigma_rules()
    validate_suricata_rules()
    validate_splunk_rules()
    print("[PASS] Detection syntax validation succeeded")


if __name__ == "__main__":
    main()