from pathlib import Path
import json
import sys

import yaml

ROOT = Path(__file__).resolve().parent.parent
SIGMA_DIR = ROOT / "detections" / "security-onion" / "sigma"
TESTS_DIR = ROOT / "tests" / "sigma"


def fail(message: str):
    print(f"[FAIL] {message}")
    sys.exit(1)


def load_sigma_rule(path: Path) -> dict:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as e:
        fail(f"Unable to parse Sigma rule {path.relative_to(ROOT)}: {e}")

    if not isinstance(data, dict):
        fail(f"Sigma rule must be a YAML object: {path.relative_to(ROOT)}")

    if "detection" not in data or not isinstance(data["detection"], dict):
        fail(f"Sigma rule missing detection section: {path.relative_to(ROOT)}")

    return data


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

    if not condition:
        return False

    selection_results = {}

    for name, selection in detection.items():
        if name == "condition":
            continue

        if not isinstance(selection, dict):
            return False

        selection_results[name] = match_selection(event, selection)

    if " and " in condition:
        parts = [part.strip() for part in condition.split(" and ")]
        return all(selection_results.get(part, False) for part in parts)

    return selection_results.get(condition, False)


def validate_test_layout(rule_path: Path) -> tuple[Path, list[Path]]:
    relative_rule_path = rule_path.relative_to(SIGMA_DIR).with_suffix("")
    test_dir = TESTS_DIR / relative_rule_path
    positive_dir = test_dir / "positive"

    if not test_dir.exists():
        fail(f"Missing Sigma test directory: {test_dir.relative_to(ROOT)}")

    if positive_dir.exists():
        event_files = sorted(positive_dir.glob("*.json"))
    else:
        event_files = sorted(test_dir.glob("*.json"))

    if not event_files:
        fail(f"No Sigma positive fixture events found for {rule_path.name} in {test_dir.relative_to(ROOT)}")

    return test_dir, event_files


def run_tests():
    sigma_files = sorted(list(SIGMA_DIR.rglob("*.yml")) + list(SIGMA_DIR.rglob("*.yaml")))

    if not sigma_files:
        fail(f"No Sigma detection files found in {SIGMA_DIR.relative_to(ROOT)}")

    for sigma_file in sigma_files:
        rule = load_sigma_rule(sigma_file)
        _, event_files = validate_test_layout(sigma_file)

        print(f"[INFO] Running Sigma tests for {sigma_file.name}")

        for event_file in event_files:
            try:
                event = json.loads(event_file.read_text(encoding="utf-8"))
            except Exception as e:
                fail(f"Could not parse Sigma fixture {event_file.relative_to(ROOT)}: {e}")

            if not isinstance(event, dict):
                fail(f"Sigma fixture must be a JSON object: {event_file.relative_to(ROOT)}")

            if evaluate_rule(rule, event):
                print(f"[PASS] {sigma_file.name} matched {event_file.name}")
            else:
                fail(f"{sigma_file.name} did not match {event_file.relative_to(ROOT)}")

    print("[PASS] All Sigma tests passed")


if __name__ == "__main__":
    run_tests()