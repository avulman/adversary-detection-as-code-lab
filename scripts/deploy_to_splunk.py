from pathlib import Path
import os
import sys
import requests

# root directory relative to this program's location
ROOT = Path(__file__).resolve().parent.parent

# directory containing Splunk rules, specifically MITRE ATT&CK
MITRE_ATTACK_DIR = ROOT / "detections" / "splunk" / "mitre-att&ck"

# required Splunk detection files
SPLUNK_BASE_URL = os.getenv("SPLUNK_BASE_URL", "").rstrip("/")
SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME", "")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "")
ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL_TO", "")

# disable SSL cert warnings because lab instance of Splunk
requests.packages.urllib3.disable_warnings()


"""
Deploys Splunk detections as scheduled alerts via REST API.

- Parses detection metadata from SPL files
- Creates or updates saved searches
- Configures alerting and scheduling
"""

# fail helper
def fail(msg: str):
    print(f"[FAIL] {msg}")
    sys.exit(1)


# read Splunk detection file line-by-line
def parse_detection_file(path: Path):
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    # metadata is stored in the commented header liens such as name: Suspicious Activity
    metadata = {}

    # holds actual SPL search
    query_lines = []

    # iterate metadata lines
    for line in lines:
        if line.startswith("# ") and ":" in line:
            key, value = line[2:].split(":", 1)
            metadata[key.strip().lower()] = value.strip()
        else:
            query_lines.append(line)

    # rebuild SPL query from remaining lines
    query = "\n".join(query_lines).strip()

    # every detection file must contain these fields
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

    # fail if detection is missing required metadata fields
    missing = [k for k in required if k not in metadata]
    if missing:
        fail(f"{path.name} missing metadata keys: {', '.join(missing)}")

    # fail if detection has no SPL query content
    if not query:
        fail(f"{path.name} has an empty search query")

    return metadata, query


# establish Splunk connection
def splunk_session():
    # validate required Splunk connection settings
    if not SPLUNK_BASE_URL or not SPLUNK_USERNAME or not SPLUNK_PASSWORD:
        fail("Missing SPLUNK_BASE_URL, SPLUNK_USERNAME, or SPLUNK_PASSWORD environment variables")

    # validate alert recipient config (for email alerts)
    if not ALERT_EMAIL_TO:
        fail("ALERT_EMAIL_TO environment variable is not set")

    # create reusable HTTP session for Splunk REST API calls
    s = requests.Session()
    # configure creds
    s.auth = (SPLUNK_USERNAME, SPLUNK_PASSWORD)
    # disable cert verification for lab
    s.verify = False
    return s


# build REST endpoint for retrieving a specific saved search
def get_saved_search(session, owner: str, app: str, name: str):
    url = f"{SPLUNK_BASE_URL}/servicesNS/{owner}/{app}/saved/searches/{requests.utils.quote(name, safe='')}"
    return session.get(url, params={"output_mode": "json"})


# build full REST payload used for create and update operations
def build_payload(metadata: dict, query: str):
    return {
        # alert nanme, query, description
        "name": metadata["name"],
        "search": query,
        "description": f'{metadata["description"]} | MITRE {metadata["mitre"]}',

        # configure scheduled alert
        "is_scheduled": "1",
        "cron_schedule": metadata["cron_schedule"],
        "disabled": metadata["disabled"],

        # alert triggers whenever result count is greater than zero
        "alert_type": "number of events",
        "alert_comparator": "greater than",
        "alert_threshold": "0",
        "alert.track": "1",

        # search window and job retention settings
        "dispatch.earliest_time": "-5m",
        "dispatch.latest_time": "now",
        "dispatch.ttl": "2p",

        # email action settings for Splunk alert notifications
        "actions": "email",
        "action.email": "1",
        "action.email.to": ALERT_EMAIL_TO,
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


# creates the detection
def create_saved_search(session, owner: str, app: str, metadata: dict, query: str):
    # build REST endpoint for creating new saved search
    url = f"{SPLUNK_BASE_URL}/servicesNS/{owner}/{app}/saved/searches"
    # reuse standard alert payload
    data = build_payload(metadata, query)
    # submit creation (POST) request
    return session.post(url, data=data)

# update detection
def update_saved_search(session, owner: str, app: str, metadata: dict, query: str):
    # build REST endpoint for updating an existing saved search
    url = f"{SPLUNK_BASE_URL}/servicesNS/{owner}/{app}/saved/searches/{requests.utils.quote(metadata['name'], safe='')}"
    # reuse the standard alert payload
    data = build_payload(metadata, query)
    # remove name as update modifies query, not name
    data.pop("name", None)
    # submit update request
    return session.post(url, data=data)


# deployment workflow
def main():
    # collect all Splunk detection files from the MITRE directory
    detection_files = sorted(MITRE_ATTACK_DIR.glob("*.spl"))
    # fail if no detection content exists to deploy
    if not detection_files:
        fail("No .spl files found")

    # create authenticated Splunk API session
    session = splunk_session()
    # app scoped...
    owner = "nobody"

    for path in detection_files:
        # parse metadata annd SPL query from detection file
        metadata, query = parse_detection_file(path)
        app = metadata["app"]
        name = metadata["name"]

        print(f"[INFO] Processing {path.name} -> alert '{name}'")
        print(f"[DEBUG] App={app} Owner={owner}")
        print(f"[DEBUG] Query={query[:200]}")

        # check whether the saved search already exists in Splunk
        existing = get_saved_search(session, owner, app, name)
        print(f"[DEBUG] Existence check status={existing.status_code}")

        # saved search already exists, so upddate it in place
        if existing.status_code == 200:
            r = update_saved_search(session, owner, app, metadata, query)
            if r.ok:
                print(f"[PASS] Updated alert: {name}")
            else:
                fail(f"Failed to update {name}: {r.status_code} {r.text}")
        elif existing.status_code == 404:
            # saved search does not exist yet, so create it
            r = create_saved_search(session, owner, app, metadata, query)
            if r.ok:
                print(f"[PASS] Created alert: {name}")
            else:
                fail(f"Failed to create {name}: {r.status_code} {r.text}")
        else:
            # any other status code is unexpected and should fail this pipeline
            fail(f"Unexpected response checking {name}: {existing.status_code} {existing.text}")


if __name__ == "__main__":
    main()