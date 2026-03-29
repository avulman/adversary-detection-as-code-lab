from pathlib import Path
import json
import os
import re
import sys
import time
import requests

ROOT = Path(__file__).resolve().parent.parent

SPLUNK_DIR = ROOT / "detections" / "splunk" / "mitre-att&ck"
TESTS_DIR = ROOT / "tests" / "splunk"

SPLUNK_BASE_URL = os.getenv("SPLUNK_BASE_URL", "").rstrip("/")
SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME", "")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "")
SPLUNK_TEST_INDEX = os.getenv("SPLUNK_TEST_INDEX", "detection_test")

requests.packages.urllib3.disable_warnings()


def fail(msg: str):
    print(f"[FAIL] {msg}")
    sys.exit(1)


def log(msg: str):
    print(f"[INFO] {msg}")


def warn(msg: str):
    print(f"[WARN] {msg}")


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
        return json.loads(config_path.read_text(encoding="utf-8"))
    except Exception as e:
        fail(f"Invalid JSON in {config_path.relative_to(ROOT)}: {e}")


def read_fixture_events(rule_stem: str) -> list[dict]:
    fixture_dir = TESTS_DIR / rule_stem / "positive"
    if not fixture_dir.exists():
        fail(f"Missing positive fixture directory: {fixture_dir.relative_to(ROOT)}")

    events = []
    for path in sorted(fixture_dir.glob("*.json")):
        try:
            events.append(json.loads(path.read_text(encoding="utf-8")))
        except Exception as e:
            fail(f"Invalid fixture JSON in {path.relative_to(ROOT)}: {e}")

    if not events:
        fail(f"No positive fixtures found in {fixture_dir.relative_to(ROOT)}")

    return events


def rest_post(session: requests.Session, endpoint: str, data: dict) -> dict:
    url = f"{SPLUNK_BASE_URL}{endpoint}"
    response = session.post(url, data=data, timeout=60)

    if response.status_code not in (200, 201):
        fail(f"POST {endpoint} failed ({response.status_code}): {response.text[:500]}")

    try:
        return response.json()
    except Exception:
        return {"raw_text": response.text}


def rest_get(session: requests.Session, endpoint: str, params: dict | None = None) -> dict:
    url = f"{SPLUNK_BASE_URL}{endpoint}"
    response = session.get(url, params=params or {}, timeout=60)

    if response.status_code != 200:
        fail(f"GET {endpoint} failed ({response.status_code}): {response.text[:500]}")

    try:
        return response.json()
    except Exception:
        return {"raw_text": response.text}


def submit_event(
    session: requests.Session,
    index: str,
    source: str,
    sourcetype: str,
    host: str,
    event: dict,
):
    payload = {
        "index": index,
        "source": source,
        "sourcetype": sourcetype,
        "host": host,
        "event": json.dumps(event),
    }
    rest_post(session, "/services/receivers/simple", payload)


def wait_for_indexing():
    time.sleep(5)


def rewrite_query_for_test(query: str, index: str, source: str) -> str:
    rewritten = re.sub(r"\bindex\s*=\s*\S+", f"index={index}", query, count=1)

    if rewritten == query:
        if rewritten.lower().startswith(("search ", "|", "from ")):
            rewritten = f'{rewritten} | search source="{source}"'
        else:
            rewritten = f'search index={index} source="{source}" {rewritten}'
    else:
        rewritten = f'{rewritten} | search source="{source}"'

    return rewritten


def create_search_job(session: requests.Session, query: str) -> str:
    search_query = query if query.lower().startswith("search ") else f"search {query}"

    data = rest_post(
        session,
        "/services/search/jobs",
        {
            "search": search_query,
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
    config = load_test_config(rule_stem)
    positive_events = read_fixture_events(rule_stem)

    _, query = parse_detection_file(rule_path)

    source = config.get("source", f"detection_test_{rule_stem}")
    sourcetype = config.get("sourcetype", "_json")
    host = config.get("host", "detection-test-host")
    index = config.get("index", SPLUNK_TEST_INDEX)
    expected_positive_min = int(config.get("expected_positive_min", 1))

    session = splunk_session()

    for event in positive_events:
        submit_event(session, index, source, sourcetype, host, event)

    wait_for_indexing()

    test_query = rewrite_query_for_test(query, index, source)
    log(f"Testing {rule_path.name} with query: {test_query}")

    sid = create_search_job(session, test_query)
    wait_for_job(session, sid)
    result_count = get_result_count(session, sid)

    if result_count < expected_positive_min:
        fail(
            f"{rule_path.name} failed true-positive test: "
            f"result_count={result_count}, expected at least {expected_positive_min}"
        )

    log(
        f"True-positive test passed for {rule_path.name} "
        f"(results={result_count}, expected_min={expected_positive_min})"
    )


def main():
    if not SPLUNK_DIR.exists():
        fail(f"Missing Splunk detections directory: {SPLUNK_DIR.relative_to(ROOT)}")

    files = sorted(SPLUNK_DIR.glob("*.spl"))
    if not files:
        fail("No .spl files found")

    for rule_path in files:
        test_dir = TESTS_DIR / rule_path.stem
        if test_dir.exists():
            run_rule_test(rule_path)
        else:
            log(f"Skipping {rule_path.name} because no test directory exists")

    print("[PASS] Splunk detection true-positive tests succeeded")


if __name__ == "__main__":
    main()