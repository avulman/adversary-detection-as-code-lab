from pathlib import Path
import json
import sys

import yaml

ROOT = Path(__file__).resolve().parent.parent
SIGMA_DIR = ROOT / "detections" / "security-onion" / "sigma"
TESTS_DIR = ROOT / "tests" / "sigma"


def load_sigma_rule(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def get_nested_value(data: dict, dotted_key: str):
    current = data
    for part in dotted_key.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def match_selection(event: dict, selection: dict) -> bool:
    for field, expected_value in selection.items():
        actual_value = get_nested_value(event, field)
        if actual_value != expected_value:
            return False
    return True


def evaluate_rule(rule: dict, event: dict) -> bool:
    detection = rule.get("detection", {})
    condition = detection.get("condition", "").strip()

    selection_results = {}

    for name, selection in detection.items():
        if name == "condition":
            continue

        if not isinstance(selection, dict):
            return False

        selection_results[name] = match_selection(event, selection)

    if not condition:
        return False

    if " and " in condition:
        parts = [part.strip() for part in condition.split(" and ")]
        return all(selection_results.get(part, False) for part in parts)

    return selection_results.get(condition, False)


def run_tests():
    failures = 0

    sigma_files = sorted(
        list(SIGMA_DIR.rglob("*.yml")) + list(SIGMA_DIR.rglob("*.yaml"))
    )

    if not sigma_files:
        print("[FAIL] No Sigma detection files found")
        sys.exit(1)

    for sigma_file in sigma_files:
        rule = load_sigma_rule(sigma_file)
        relative_rule_path = sigma_file.relative_to(SIGMA_DIR).with_suffix("")
        test_dir = TESTS_DIR / relative_rule_path
        positive_dir = test_dir / "positive"

        if not test_dir.exists():
            print(f"[WARN] No tests for {sigma_file.name}")
            continue

        if positive_dir.exists():
            event_files = sorted(positive_dir.glob("*.json"))
        else:
            event_files = sorted(test_dir.glob("*.json"))

        if not event_files:
            print(f"[FAIL] No positive test events found for {sigma_file.name}")
            failures += 1
            continue

        print(f"[INFO] Running Sigma tests for {sigma_file.name}")

        for event_file in event_files:
            try:
                event = json.loads(event_file.read_text(encoding="utf-8"))
            except Exception as e:
                print(f"[FAIL] Could not parse {event_file}: {e}")
                failures += 1
                continue

            if evaluate_rule(rule, event):
                print(f"[PASS] {sigma_file.name} matched {event_file.name}")
            else:
                print(f"[FAIL] {sigma_file.name} did not match {event_file.name}")
                failures += 1

    if failures > 0:
        print(f"[FAIL] {failures} Sigma test failure(s)")
        sys.exit(1)

    print("[PASS] All Sigma tests passed")


if __name__ == "__main__":
    run_tests()