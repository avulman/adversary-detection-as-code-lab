from pathlib import Path
import json
import os
import re
import sys
import time
import uuid

import requests

ROOT = Path(__file__).resolve().parent.parent

SPLUNK_DIR = ROOT / "detections" / "splunk" / "mitre-att&ck"
TESTS_DIR = ROOT / "tests" / "splunk"

SPLUNK_BASE_URL = os.getenv("SPLUNK_BASE_URL", "").rstrip("/")
SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME", "")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "")
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL", "").rstrip("/")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "")
SPLUNK_TEST_INDEX = os.getenv("SPLUNK_TEST_INDEX", "detection_test")

requests.packages.urllib3.disable_warnings()


def fail(msg: str):
    print(f"[FAIL] {msg}")
    sys.exit(1)


def log(msg: str):
    print(f"[INFO] {msg}")


def splunk_session() -> requests.Session:
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

    missing = [k for k in required if k not in metadata]
    if missing:
        fail(f"{path.name} missing metadata keys: {', '.join(missing)}")

    if not query:
        fail(f"{path.name} has an empty search query")

    return metadata, query


def load_test_config(rule_stem: str) -> dict:
    config_path = TESTS_DIR / rule_stem / "test_config.json"
    if not config_path.exists():
        fail(f"Missing test config: {config_path.relative_to(ROOT)}")

    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception as e:
        fail(f"Invalid JSON in {config_path.relative_to(ROOT)}: {e}")

    if not isinstance(data, dict):
        fail(f"Test config must be a JSON object: {config_path.relative_to(ROOT)}")

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
    pending = {int(x) for x in ack_ids}

    while time.time() < deadline:
        response = requests.post(
            f"{SPLUNK_HEC_URL}/services/collector/ack",
            params={"channel": channel_id},
            headers=headers,
            json={"acks": sorted(pending)},
            verify=False,
            timeout=30,
        )

        if response.status_code != 200:
            fail(f"HEC ack polling failed ({response.status_code}): {response.text[:500]}")

        try:
            body = response.json()
        except Exception:
            fail(f"HEC ack polling returned non-JSON response: {response.text[:500]}")

        ack_map = body.get("acks", {})
        completed = {
            ack_id
            for ack_id in pending
            if ack_map.get(str(ack_id)) is True or ack_map.get(ack_id) is True
        }
        pending -= completed

        if not pending:
            return

        time.sleep(2)

    fail(f"Timed out waiting for HEC ACK(s): {sorted(pending)}")


def split_query_pipeline(query: str) -> tuple[str, str]:
    """
    Split the SPL into:
      - base search before the first pipe
      - remaining pipeline including leading pipe, if any
    """
    parts = query.split("|", 1)
    base = parts[0].strip()
    pipeline = f"|{parts[1]}" if len(parts) > 1 else ""
    return base, pipeline


def rewrite_query_for_test(query: str, index: str, source: str) -> str:
    """
    Rewrite the query so the index/source constraints are part of the base search,
    not appended later as a pipeline-stage search.

    Example:
      index=sysmon EventCode=1 Image="*powershell.exe"
      | table ...
    becomes:
      search index=detection_test source="my_source" EventCode=1 Image="*powershell.exe"
      | table ...
    """
    base, pipeline = split_query_pipeline(query)

    rewritten_base = re.sub(r"\bindex\s*=\s*\S+", f"index={index}", base, count=1)

    if rewritten_base == base:
        rewritten_base = f'index={index} source="{source}" {base}'.strip()
    else:
        rewritten_base = f'source="{source}" {rewritten_base}'.strip()

    final_query = f"search {rewritten_base}"
    if pipeline:
        final_query = f"{final_query} {pipeline}"

    return final_query.strip()


def rest_post(session: requests.Session, endpoint: str, data: dict) -> dict:
    response = session.post(
        f"{SPLUNK_BASE_URL}{endpoint}",
        data=data,
        timeout=60,
    )

    if response.status_code not in (200, 201):
        fail(f"POST {endpoint} failed ({response.status_code}): {response.text[:500]}")

    try:
        return response.json()
    except Exception:
        fail(f"POST {endpoint} returned non-JSON response: {response.text[:500]}")
        return {}


def rest_get(session: requests.Session, endpoint: str, params: dict | None = None) -> dict:
    response = session.get(
        f"{SPLUNK_BASE_URL}{endpoint}",
        params=params or {},
        timeout=60,
    )

    if response.status_code != 200:
        fail(f"GET {endpoint} failed ({response.status_code}): {response.text[:500]}")

    try:
        return response.json()
    except Exception:
        fail(f"GET {endpoint} returned non-JSON response: {response.text[:500]}")
        return {}


def create_search_job(session: requests.Session, query: str) -> str:
    data = rest_post(
        session,
        "/services/search/jobs",
        {
            "search": query if query.lower().startswith("search ") else f"search {query}",
            "output_mode": "json",
            "exec_mode": "normal",
        },
    )

    sid = data.get("sid")
    if not sid:
        fail("Splunk search job creation did not return a sid")

    return sid


def wait_for_job(session: requests.Session, sid: str):
    for _ in range(30):
        payload = rest_get(
            session,
            f"/services/search/jobs/{sid}",
            {"output_mode": "json"},
        )

        entries = payload.get("entry", [])
        if entries:
            content = entries[0].get("content", {})
            if content.get("isDone"):
                return

        time.sleep(2)

    fail(f"Timed out waiting for search job {sid} to finish")


def get_result_count(session: requests.Session, sid: str) -> int:
    payload = rest_get(
        session,
        f"/services/search/jobs/{sid}",
        {"output_mode": "json"},
    )

    entries = payload.get("entry", [])
    if not entries:
        fail(f"No job metadata returned for search job {sid}")

    content = entries[0].get("content", {})
    result_count = content.get("resultCount", 0)

    try:
        return int(float(result_count))
    except Exception:
        return 0


def run_rule_test(rule_path: Path):
    rule_stem = rule_path.stem
    test_dir = TESTS_DIR / rule_stem

    if not test_dir.exists():
        fail(f"Missing Splunk test directory: {test_dir.relative_to(ROOT)}")

    config = load_test_config(rule_stem)
    positive_events = read_positive_fixture_events(rule_stem)
    _, query = parse_detection_file(rule_path)

    source = config.get("source", f"detection_test_{rule_stem}")
    sourcetype = config.get("sourcetype", "_json")
    host = config.get("host", "detection-test-host")
    index = config.get("index", SPLUNK_TEST_INDEX)
    expected_positive_min = int(config.get("expected_positive_min", 1))

    run_source = f"{source}_{uuid.uuid4().hex[:12]}"
    channel_id = str(uuid.uuid4())

    log(f"Submitting {len(positive_events)} positive fixture event(s) for {rule_path.name}")

    ack_ids: list[int] = []
    for event in positive_events:
        ack_id = submit_event_to_hec(
            event=event,
            index=index,
            source=run_source,
            sourcetype=sourcetype,
            host=host,
            channel_id=channel_id,
        )
        if ack_id is not None:
            ack_ids.append(int(ack_id))

    wait_for_ack(channel_id=channel_id, ack_ids=ack_ids)

    session = splunk_session()
    test_query = rewrite_query_for_test(query, index, run_source)
    log(f"Testing {rule_path.name} with query: {test_query}")

    sid = create_search_job(session, test_query)
    wait_for_job(session, sid)
    result_count = get_result_count(session, sid)

    if result_count < expected_positive_min:
        fail(
            f"{rule_path.name} failed Splunk true-positive test: "
            f"result_count={result_count}, expected at least {expected_positive_min}"
        )

    log(
        f"Splunk true-positive test passed for {rule_path.name} "
        f"(results={result_count}, expected_min={expected_positive_min})"
    )


def main():
    if not SPLUNK_DIR.exists():
        fail(f"Missing Splunk detections directory: {SPLUNK_DIR.relative_to(ROOT)}")

    hec_healthcheck()

    files = sorted(SPLUNK_DIR.glob("*.spl"))
    if not files:
        fail("No .spl files found")

    for rule_path in files:
        run_rule_test(rule_path)

    print("[PASS] Splunk-backed detection true-positive tests succeeded")


if __name__ == "__main__":
    main()