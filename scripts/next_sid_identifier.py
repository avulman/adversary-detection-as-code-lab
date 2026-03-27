from pathlib import Path
import json
import re
import sys

ROOT = Path(__file__).resolve().parent.parent

SO_SURICATA_DIR = ROOT / "detections" / "security-onion" / "suricata"
STATE_FILE = ROOT / "state" / "securityonion_rule_state.json"

AUTO_SID_START = 1_000_000


def extract_sid(content: str) -> int | None:
    match = re.search(r"\bsid\s*:\s*(\d+)\b", content, re.IGNORECASE)
    return int(match.group(1)) if match else None


def collect_repo_sids() -> set[int]:
    sids = set()

    if not SO_SURICATA_DIR.exists():
        return sids

    for path in SO_SURICATA_DIR.glob("*.rules"):
        content = path.read_text(encoding="utf-8", errors="ignore")
        sid = extract_sid(content)
        if sid:
            sids.add(sid)

    return sids


def collect_state_sids() -> set[int]:
    sids = set()

    if not STATE_FILE.exists():
        return sids

    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[FAIL] Could not read state file: {e}")
        sys.exit(1)

    for content in data.get("suricata", {}).values():
        sid = extract_sid(content)
        if sid:
            sids.add(sid)

    return sids


def main():
    repo_sids = collect_repo_sids()
    state_sids = collect_state_sids()

    all_sids = repo_sids | state_sids

    if not all_sids:
        print(AUTO_SID_START)
        return

    next_sid = max(all_sids) + 1

    if next_sid < AUTO_SID_START:
        next_sid = AUTO_SID_START

    print(next_sid)


if __name__ == "__main__":
    main()