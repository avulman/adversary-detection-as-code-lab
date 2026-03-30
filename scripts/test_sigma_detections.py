# scripts/test_sigma_detections.py

from pathlib import Path
import json
import yaml
import sys

ROOT = Path(__file__).resolve().parent.parent
SIGMA_DIR = ROOT / "detections" / "security-onion" / "sigma"
TESTS_DIR = ROOT / "tests" / "sigma"


def load_sigma_rule(path):
    return yaml.safe_load(path.read_text())


def match_condition(event, selection):
    for field, value in selection.items():
        keys = field.split(".")
        current = event

        for k in keys:
            if k not in current:
                return False
            current = current[k]

        if current != value:
            return False

    return True


def evaluate_rule(rule, event):
    detection = rule["detection"]

    results = {}

    for name, selection in detection.items():
        if name == "condition":
            continue
        results[name] = match_condition(event, selection)

    condition = detection["condition"]

    # Basic evaluator (AND only for now)
    if "and" in condition:
        return all(results.values())

    return False


def run_tests():
    failures = 0

    for sigma_file in SIGMA_DIR.glob("*.yml"):
        rule = load_sigma_rule(sigma_file)
        test_dir = TESTS_DIR / sigma_file.stem

        if not test_dir.exists():
            print(f"[WARN] No tests for {sigma_file.name}")
            continue

        for event_file in (test_dir / "positive").glob("*.json"):
            event = json.loads(event_file.read_text())

            if not evaluate_rule(rule, event):
                print(f"[FAIL] {sigma_file.name} failed positive test: {event_file.name}")
                failures += 1

        for event_file in (test_dir / "negative").glob("*.json"):
            event = json.loads(event_file.read_text())

            if evaluate_rule(rule, event):
                print(f"[FAIL] {sigma_file.name} false positive: {event_file.name}")
                failures += 1

    if failures > 0:
        print(f"[FAIL] {failures} Sigma test failures")
        sys.exit(1)

    print("[PASS] All Sigma tests passed")


if __name__ == "__main__":
    run_tests()