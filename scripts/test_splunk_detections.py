from pathlib import Path
import json
import os
import sys
import time
import uuid
import warnings

import requests
import urllib3

warnings.filterwarnings("ignore", message="Unverified HTTPS request")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ROOT = Path(__file__).resolve().parent.parent
SPLUNK_DIR = ROOT / "detections" / "splunk" / "mitre-att&ck"
TESTS_DIR = ROOT / "tests" / "splunk"

SPLUNK_BASE_URL = os.getenv("SPLUNK_BASE_URL", "").strip().rstrip("/")
SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME", "").strip()
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "").strip()
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL", "").strip().rstrip("/")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "").strip()
SPLUNK_TEST_INDEX = os.getenv("SPLUNK_TEST_INDEX", "").strip() or "detection_test"


def fail(message: str):
    print(f"[FAIL] {message}")
    sys.exit(1)


def create_session() -> requests.Session:
    if not SPLUNK_BASE_URL or not SPLUNK_USERNAME or not SPLUNK_PASSWORD:
        fail("Missing SPLUNK_BASE_URL, SPLUNK_USERNAME, or SPLUNK_PASSWORD")

    session = requests.Session()
    session.auth = (SPLUNK_USERNAME, SPLUNK_PASSWORD)
    session.verify = False
    return session


def parse_detection_file(path: Path) -> tuple[dict, str]:
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


def load_test_config(rule_stem: str) -> dict:
    config_path = TESTS_DIR / rule_stem / "test_config.json"
    if not config_path.exists():
        fail(f"Missing Splunk test config: {config_path.relative_to(ROOT)}")

    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception as e:
        fail(f"Invalid JSON in {config_path.relative_to(ROOT)}: {e}")

    if not isinstance(data, dict):
        fail(f"Splunk test config must be a JSON object: {config_path.relative_to(ROOT)}")

    required = ["source", "sourcetype", "host"]
    missing = [key for key in required if key not in data or not str(data[key]).strip()]
    if missing:
        fail(f"{config_path.relative_to(ROOT)} missing required keys: {', '.join(missing)}")

    return data


def normalize_fixture_event(raw_event: dict) -> dict:
    if not isinstance(raw_event, dict):
        fail("Fixture event must be a JSON object")

    if "result" in raw_event and isinstance(raw_event["result"], dict):
        return raw_event["result"]

    return raw_event


def read_positive_fixture_events(rule_stem: str) -> list[dict]:
    fixture_dir = TESTS_DIR / rule_stem / "positive"
    if not fixture_dir.exists():
        fail(f"Missing positive fixture directory: {fixture_dir.relative_to(ROOT)}")

    events = []
    for path in sorted(fixture_dir.glob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            events.append(normalize_fixture_event(raw))
        except Exception as e:
            fail(f"Invalid fixture JSON in {path.relative_to(ROOT)}: {e}")

    if not events:
        fail(f"No positive fixtures found in {fixture_dir.relative_to(ROOT)}")

    return events


def hec_healthcheck():
    if not SPLUNK_HEC_URL or not SPLUNK_HEC_TOKEN:
        fail("Missing SPLUNK_HEC_URL or SPLUNK_HEC_TOKEN")

    headers = {
        "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
    }

    try:
        response = requests.get(
            f"{SPLUNK_HEC_URL}/services/collector/health",
            headers=headers,
            verify=False,
            timeout=30,
        )
    except Exception as e:
        fail(f"Unable to reach Splunk HEC health endpoint: {e}")

    if response.status_code not in (200, 400):
        fail(f"Unexpected HEC health response ({response.status_code}): {response.text[:500]}")


def submit_event_to_hec(
    event: dict,
    index: str,
    source: str,
    sourcetype: str,
    host: str,
    channel_id: str,
) -> int | None:
    headers = {
        "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
        "Content-Type": "application/json",
        "X-Splunk-Request-Channel": channel_id,
    }

    payload = {
        "event": event,
        "index": index,
        "source": source,
        "sourcetype": sourcetype,
        "host": host,
    }

    response = requests.post(
        f"{SPLUNK_HEC_URL}/services/collector/event",
        headers=headers,
        json=payload,
        verify=False,
        timeout=30,
    )

    if response.status_code != 200:
        fail(f"HEC event submission failed ({response.status_code}): {response.text[:500]}")

    try:
        body = response.json()
    except Exception:
        fail(f"HEC returned non-JSON response: {response.text[:500]}")

    if body.get("code") != 0:
        fail(f"HEC returned error code for event submission: {body}")

    ack_id = body.get("ackId")
    if ack_id is None:
        ack_id = body.get("ackID")

    return ack_id


def wait_for_ack(channel_id: str, ack_ids: list[int], timeout_seconds: int = 60):
    if not ack_ids:
        time.sleep(6)
        return

    headers = {
        "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
        "Content-Type": "application/json",
        "X-Splunk-Request-Channel": channel_id,
    }

    deadline = time.time() + timeout_seconds

    while time.time() < deadline:
        response = requests.post(
            f"{SPLUNK_HEC_URL}/services/collector/ack",
            headers=headers,
            json={"acks": ack_ids},
            verify=False,
            timeout=30,
        )

        if response.status_code != 200:
            fail(f"HEC ack polling failed ({response.status_code}): {response.text[:500]}")

        try:
            body = response.json()
        except Exception:
            fail(f"HEC ack endpoint returned non-JSON response: {response.text[:500]}")

        acks = body.get("acks", {})
        if all(acks.get(str(ack_id)) is True or acks.get(ack_id) is True for ack_id in ack_ids):
            time.sleep(3)
            return

        time.sleep(2)

    fail(f"Timed out waiting for HEC ack(s): {ack_ids}")


def create_search_job(session: requests.Session, search: str) -> str:
    response = session.post(
        f"{SPLUNK_BASE_URL}/services/search/jobs",
        data={
            "search": search,
            "exec_mode": "normal",
            "output_mode": "json",
        },
        timeout=60,
    )

    if response.status_code != 201:
        fail(f"Failed to create Splunk search job ({response.status_code}): {response.text[:500]}")

    try:
        body = response.json()
    except Exception:
        fail(f"Splunk returned non-JSON search job response: {response.text[:500]}")

    sid = body.get("sid")
    if not sid:
        fail(f"Splunk search job response missing sid: {body}")

    return sid


def wait_for_search_completion(session: requests.Session, sid: str, timeout_seconds: int = 120):
    deadline = time.time() + timeout_seconds

    while time.time() < deadline:
        response = session.get(
            f"{SPLUNK_BASE_URL}/services/search/jobs/{sid}",
            params={"output_mode": "json"},
            timeout=30,
        )

        if response.status_code != 200:
            fail(f"Failed to poll Splunk search job {sid} ({response.status_code}): {response.text[:500]}")

        try:
            body = response.json()
        except Exception:
            fail(f"Splunk job status returned non-JSON response: {response.text[:500]}")

        entries = body.get("entry", [])
        if not entries:
            fail(f"Splunk job status response missing entry for sid {sid}")

        content = entries[0].get("content", {})
        if content.get("isDone") is True:
            return

        time.sleep(2)

    fail(f"Timed out waiting for Splunk search job to complete: {sid}")


def get_search_results_count(session: requests.Session, sid: str) -> int:
    response = session.get(
        f"{SPLUNK_BASE_URL}/services/search/jobs/{sid}/results",
        params={"output_mode": "json", "count": 0},
        timeout=30,
    )

    if response.status_code != 200:
        fail(f"Failed to fetch Splunk search results ({response.status_code}): {response.text[:500]}")

    try:
        body = response.json()
    except Exception:
        fail(f"Splunk search results returned non-JSON response: {response.text[:500]}")

    results = body.get("results", [])
    return len(results)


def build_test_search(query: str) -> str:
    query = query.strip()

    if not query.lower().startswith("search "):
        query = f"search {query}"

    return query


def run_tests():
    spl_files = sorted(SPLUNK_DIR.glob("*.spl"))
    if not spl_files:
        fail(f"No Splunk detection files found in {SPLUNK_DIR.relative_to(ROOT)}")

    hec_healthcheck()
    session = create_session()

    for spl_file in spl_files:
        metadata, query = parse_detection_file(spl_file)
        config = load_test_config(spl_file.stem)
        events = read_positive_fixture_events(spl_file.stem)

        print(f"[INFO] Running Splunk tests for {spl_file.name}")

        channel_id = str(uuid.uuid4())
        ack_ids = []

        for event in events:
            ack_id = submit_event_to_hec(
                event=event,
                index=SPLUNK_TEST_INDEX,
                source=str(config["source"]),
                sourcetype=str(config["sourcetype"]),
                host=str(config["host"]),
                channel_id=channel_id,
            )
            if ack_id is not None:
                ack_ids.append(ack_id)

        wait_for_ack(channel_id, ack_ids)

        search = build_test_search(query)
        sid = create_search_job(session, search)
        wait_for_search_completion(session, sid)
        result_count = get_search_results_count(session, sid)

        if result_count < 1:
            fail(
                f"Splunk detection test failed for {spl_file.name}. "
                f"Search returned 0 results after ingesting positive fixtures."
            )

        print(f"[PASS] {spl_file.name} returned {result_count} result(s)")

    print("[PASS] All Splunk tests passed")


if __name__ == "__main__":
    run_tests()