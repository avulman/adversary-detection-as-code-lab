from pathlib import Path
import os
import sys
import requests

ROOT = Path(__file__).resolve().parent.parent
DETECTIONS_DIR = ROOT / "detections" / "splunk"

SPLUNK_BASE_URL = os.getenv("SPLUNK_BASE_URL", "").rstrip("/")
SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME", "")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "")

requests.packages.urllib3.disable_warnings()

def fail(msg: str):
    print(f"[FAIL] {msg}")
    sys.exit(1)

def parse_detection_file(path: Path):
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
        "alert_type",
        "alert_comparator",
        "alert_threshold",
        "disabled",
    ]

    missing = [k for k in required if k not in metadata]
    if missing:
        fail(f"{path.name} missing metadata keys: {', '.join(missing)}")

    return metadata, query

def splunk_session():
    if not SPLUNK_BASE_URL or not SPLUNK_USERNAME or not SPLUNK_PASSWORD:
        fail("Missing SPLUNK_BASE_URL, SPLUNK_USERNAME, or SPLUNK_PASSWORD environment variables")

    s = requests.Session()
    s.auth = (SPLUNK_USERNAME, SPLUNK_PASSWORD)
    s.verify = False
    return s

def get_saved_search(session, owner: str, app: str, name: str):
    url = f"{SPLUNK_BASE_URL}/servicesNS/{owner}/{app}/saved/searches/{requests.utils.quote(name, safe='')}"
    r = session.get(url, params={"output_mode": "json"})
    return r

def create_saved_search(session, owner: str, app: str, metadata: dict, query: str):
    url = f"{SPLUNK_BASE_URL}/servicesNS/{owner}/{app}/saved/searches"
    data = {
        "name": metadata["name"],
        "search": query,
        "description": f'{metadata["description"]} | MITRE {metadata["mitre"]}',
        "is_scheduled": "1",
        "cron_schedule": metadata["cron_schedule"],
        "disabled": metadata["disabled"],
        "alert_type": metadata["alert_type"],
        "alert_comparator": metadata["alert_comparator"],
        "alert_threshold": metadata["alert_threshold"],
        "actions": "",
    }
    r = session.post(url, data=data)
    return r

def update_saved_search(session, owner: str, app: str, metadata: dict, query: str):
    url = f"{SPLUNK_BASE_URL}/servicesNS/{owner}/{app}/saved/searches/{requests.utils.quote(metadata['name'], safe='')}"
    data = {
        "search": query,
        "description": f'{metadata["description"]} | MITRE {metadata["mitre"]}',
        "is_scheduled": "1",
        "cron_schedule": metadata["cron_schedule"],
        "disabled": metadata["disabled"],
        "alert_type": metadata["alert_type"],
        "alert_comparator": metadata["alert_comparator"],
        "alert_threshold": metadata["alert_threshold"],
        "actions": "",
    }
    r = session.post(url, data=data)
    return r

def main():
    detection_files = sorted(DETECTIONS_DIR.glob("*.spl"))
    if not detection_files:
        fail("No .spl files found")

    session = splunk_session()
    owner = "nobody"

    for path in detection_files:
        metadata, query = parse_detection_file(path)
        app = metadata["app"]
        name = metadata["name"]

        print(f"[INFO] Processing {path.name} -> saved search '{name}'")

        existing = get_saved_search(session, owner, app, name)

        if existing.status_code == 200:
            r = update_saved_search(session, owner, app, metadata, query)
            if r.ok:
                print(f"[PASS] Updated: {name}")
            else:
                fail(f"Failed to update {name}: {r.status_code} {r.text}")
        elif existing.status_code == 404:
            r = create_saved_search(session, owner, app, metadata, query)
            if r.ok:
                print(f"[PASS] Created: {name}")
            else:
                fail(f"Failed to create {name}: {r.status_code} {r.text}")
        else:
            fail(f"Unexpected response checking {name}: {existing.status_code} {existing.text}")

if __name__ == "__main__":
    main()