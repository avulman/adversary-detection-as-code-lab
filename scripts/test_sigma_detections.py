from pathlib import Path
import json
import sys

import yaml

# root path relative to this file
ROOT = Path(__file__).resolve().parent.parent
# Sigma rules folder
SIGMA_DIR = ROOT / "detections" / "security-onion" / "sigma"
# Sigma test fixtures
TESTS_DIR = ROOT / "tests" / "sigma"

"""
Basic Sigma syntax evaluator, tests against .json log samples

"""

# fail helper
def fail(message: str):
    print(f"[FAIL] {message}")
    sys.exit(1)


# load and parse a Sigma YAML rule
def load_sigma_rule(path: Path) -> dict:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as e:
        # fail is YAML is malformed or unreadable
        fail(f"Unable to parse Sigma rule {path.relative_to(ROOT)}: {e}")

    # must deserialize into a dictrionary/object
    if not isinstance(data, dict):
        fail(f"Sigma rule must be a YAML object: {path.relative_to(ROOT)}")

    # must contain "detection" section
    if "detection" not in data or not isinstance(data["detection"], dict):
        fail(f"Sigma rule missing detection section: {path.relative_to(ROOT)}")

    return data


# retrieve a nested value from an event
def get_nested_value(data: dict, dotted_key: str):
    current = data
    for part in dotted_key.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


# evaluate whether all field/value paris in a Sigma selection match provided event
def match_selection(event: dict, selection: dict) -> bool:
    for field, expected_value in selection.items():
        actual_value = get_nested_value(event, field)
        if actual_value != expected_value:
            return False
    return True


# pull the Sigma detection section and condition string
def evaluate_rule(rule: dict, event: dict) -> bool:
    detection = rule.get("detection", {})
    condition = detection.get("condition", "").strip()

    # a rule without a condition cannot be evaluated meaningfully
    if not condition:
        return False

    # store boolean results from each Sigma selection block
    selection_results = {}

    # skip the condition field itself
    for name, selection in detection.items():
        if name == "condition":
            continue

        if not isinstance(selection, dict):
            return False

        # evaluate the selection against the event and store the result
        selection_results[name] = match_selection(event, selection)

    # tokenize the Sigma condition expression
    # currently supported: and, or, not
    tokens = condition.split()
    pos = 0

    # parse OR expression with lower precedence than AND
    def parse_or():
        nonlocal pos
        left = parse_and()

        while pos < len(tokens) and tokens[pos].lower() == "or":
            pos += 1
            right = parse_and()
            left = left or right

        return left

    # parse AND expressions with higher precedence than OR
    def parse_and():
        nonlocal pos
        left = parse_not()

        while pos < len(tokens) and tokens[pos].lower() == "and":
            pos += 1
            right = parse_not()
            left = left and right

        return left

    # parse NOT expressions with highest precedence
    def parse_not():
        nonlocal pos
        if pos < len(tokens) and tokens[pos].lower() == "not":
            pos += 1
            return not parse_not()

        # if parsing runs past availble tokens, treat as invalid
        if pos >= len(tokens):
            return False

        # resolve name selection result
        name = tokens[pos]
        pos += 1
        return selection_results.get(name, False)

    # evaluate the full condition expression
    result = parse_or()
    # only return success if all tokens were consumed cleanly
    return result if pos == len(tokens) else False


# ensures the test setup is configured as expected
def validate_test_layout(rule_path: Path) -> tuple[Path, list[Path]]:
    relative_rule_path = rule_path.relative_to(SIGMA_DIR).with_suffix("")
    test_dir = TESTS_DIR / relative_rule_path

    # ensure directory exists
    if not test_dir.exists():
        fail(f"Missing Sigma test directory: {test_dir.relative_to(ROOT)}")

    # ensures path is a directory
    if not test_dir.is_dir():
        fail(f"Sigma test path is not a directory: {test_dir.relative_to(ROOT)}")

    # collect all JSOn fixture events for Sigma rule
    event_files = sorted(test_dir.glob("*.json"))

    # fail if not tests found
    if not event_files:
        fail(f"No Sigma fixture events found for {rule_path.name} in {test_dir.relative_to(ROOT)}")

    return test_dir, event_files


# run the tests
def run_tests():
    sigma_files = sorted(list(SIGMA_DIR.rglob("*.yml")) + list(SIGMA_DIR.rglob("*.yaml")))

    # fail if the repo contains no Sigma detections
    if not sigma_files:
        fail(f"No Sigma detection files found in {SIGMA_DIR.relative_to(ROOT)}")

    # run validation for each Sigma rule
    for sigma_file in sigma_files:
        rule = load_sigma_rule(sigma_file)
        # validate test directory/layout and collect event fixtures
        _, event_files = validate_test_layout(sigma_file)

        print(f"[INFO] Running Sigma tests for {sigma_file.name}")

        # evaluate the Sigma rule against each JSON fixture event
        for event_file in event_files:
            try:
                event = json.loads(event_file.read_text(encoding="utf-8"))
            except Exception as e:
                fail(f"Could not parse Sigma fixture {event_file.relative_to(ROOT)}: {e}")

            # each fixture must be a JSON object/dictionary
            if not isinstance(event, dict):
                fail(f"Sigma fixture must be a JSON object: {event_file.relative_to(ROOT)}")

            # pass if the event satisfies the Sigma rule condition
            if evaluate_rule(rule, event):
                print(f"[PASS] {sigma_file.name} matched {event_file.name}")
            else:
                # fail immediately if a fixture does not match its rule
                fail(f"{sigma_file.name} did not match {event_file.relative_to(ROOT)}")

    print("[PASS] All Sigma tests passed")


if __name__ == "__main__":
    run_tests()