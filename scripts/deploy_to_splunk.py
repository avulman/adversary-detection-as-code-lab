from pathlib import Path
import os
import sys
import requests

ROOT = Path(__file__).resolve().parent.parent
MITRE_ATTACK_DIR = ROOT / "detections" / "splunk" / "mitre-att&ck"

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
        "disabled",
        "email_to",
        "email_subject",
        "email_message",
    ]

    missing = [k for k in required if k not in metadata]
    if missing:
        fail(f"{path.name} missing metadata keys: {', '.join(missing)}")

    if not query:
        fail(f"{path.name} has an empty search query")

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
    return session.get(url, params={"output_mode": "json"})


def build_payload(metadata: dict, query: str):
    return {
        "name": metadata["name"],
        "search": query,
        "description": f'{metadata["description"]} | MITRE {metadata["mitre"]}',

        # Scheduling
        "is_scheduled": "1",
        "cron_schedule": metadata["cron_schedule"],
        "disabled": metadata["disabled"],

        # Only trigger if results exist
        "alert_type": "number of events",
        "alert_comparator": "greater than",
        "alert_threshold": "0",
        "alert.track": "1",

        # Search window
        "dispatch.earliest_time": "-5m",
        "dispatch.latest_time": "now",
        "dispatch.ttl": "2p",

        # Email action
        "actions": "email",
        "action.email": "1",
        "action.email.to": metadata["email_to"],
        "action.email.subject": metadata["email_subject"],
        "action.email.message": metadata["email_message"],
        "action.email.include.results_link": "1",
        "action.email.include.search": "1",
        "action.email.include.trigger": "1",
        "action.email.format": "table",
        "action.email.sendresults": "1",
        "action.email.inline": "1",
        "action.email.maxresults": "10",
    }


def create_saved_search(session, owner: str, app: str, metadata: dict, query: str):
    url = f"{SPLUNK_BASE_URL}/servicesNS/{owner}/{app}/saved/searches"
    data = build_payload(metadata, query)
    return session.post(url, data=data)


def update_saved_search(session, owner: str, app: str, metadata: dict, query: str):
    url = f"{SPLUNK_BASE_URL}/servicesNS/{owner}/{app}/saved/searches/{requests.utils.quote(metadata['name'], safe='')}"
    data = build_payload(metadata, query)
    data.pop("name", None)
    return session.post(url, data=data)


def main():
    detection_files = sorted(MITRE_ATTACK_DIR.glob("*.spl"))
    if not detection_files:
        fail("No .spl files found")

    session = splunk_session()
    owner = "nobody"

    for path in detection_files:
        metadata, query = parse_detection_file(path)
        app = metadata["app"]
        name = metadata["name"]

        print(f"[INFO] Processing {path.name} -> alert '{name}'")
        print(f"[DEBUG] App={app} Owner={owner}")
        print(f"[DEBUG] Query={query[:200]}")
        
        existing = get_saved_search(session, owner, app, name)
        print(f"[DEBUG] Existence check status={existing.status_code}")

        if existing.status_code == 200:
            r = update_saved_search(session, owner, app, metadata, query)
            if r.ok:
                print(f"[PASS] Updated alert: {name}")
            else:
                fail(f"Failed to update {name}: {r.status_code} {r.text}")
        elif existing.status_code == 404:
            r = create_saved_search(session, owner, app, metadata, query)
            if r.ok:
                print(f"[PASS] Created alert: {name}")
            else:
                fail(f"Failed to create {name}: {r.status_code} {r.text}")
        else:
            fail(f"Unexpected response checking {name}: {existing.status_code} {existing.text}")


if __name__ == "__main__":
    main()