from pathlib import Path
import json
import fnmatch
import re
import sys

ROOT = Path(__file__).resolve().parent.parent

SPLUNK_DIR = ROOT / "detections" / "splunk" / "mitre-att&ck"
TESTS_DIR = ROOT / "tests" / "splunk"


def fail(msg: str):
    print(f"[FAIL] {msg}")
    sys.exit(1)


def log(msg: str):
    print(f"[INFO] {msg}")


def warn(msg: str):
    print(f"[WARN] {msg}")


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


def normalize_fixture_event(raw_event: dict) -> dict:
    """
    Support either:
      { ...fields... }
    or:
      { "preview": true, "result": { ...fields... } }
    """
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


def extract_base_search(query: str) -> str:
    """
    Keep only the predicate portion before the first pipe.
    Example:
      index=sysmon EventCode=1 Image="*powershell.exe"
      | table ...
    becomes:
      index=sysmon EventCode=1 Image="*powershell.exe"
    """
    return query.split("|", 1)[0].strip()


def remove_index_terms(expr: str) -> str:
    """
    Remove index=... tokens because local fixtures are not stored in Splunk indexes.
    """
    expr = re.sub(r"\bindex\s*=\s*\S+", "", expr, flags=re.IGNORECASE)
    return " ".join(expr.split())


def normalize_expression(expr: str) -> str:
    """
    Normalize spacing and fix a few common repo-side quirks.
    """
    expr = expr.replace("\n", " ").replace("\r", " ")
    expr = expr.replace("!=", " != ")
    expr = re.sub(r"(?<![!<>=])=(?!=)", " = ", expr)
    expr = expr.replace("(", " ( ").replace(")", " ) ")
    expr = re.sub(r"\bAND\b", " AND ", expr, flags=re.IGNORECASE)
    expr = re.sub(r"\bOR\b", " OR ", expr, flags=re.IGNORECASE)

    # Fix accidental typo like CommandLine+"*HKCU*"
    expr = re.sub(r'([A-Za-z0-9_.]+)\s*\+\s*(".*?")', r"\1 = \2", expr)

    expr = " ".join(expr.split())
    return expr.strip()


def tokenize(expr: str) -> list[str]:
    tokens = []
    i = 0
    n = len(expr)

    while i < n:
        ch = expr[i]

        if ch.isspace():
            i += 1
            continue

        if ch in "()":
            tokens.append(ch)
            i += 1
            continue

        if ch == '"':
            j = i + 1
            value = ['"']
            escaped = False

            while j < n:
                c = expr[j]
                value.append(c)

                if c == '"' and not escaped:
                    break

                if c == "\\" and not escaped:
                    escaped = True
                else:
                    escaped = False

                j += 1

            tokens.append("".join(value))
            i = j + 1
            continue

        j = i
        while j < n and not expr[j].isspace() and expr[j] not in "()":
            j += 1
        tokens.append(expr[i:j])
        i = j

    return tokens


def is_boolean_token(token: str) -> bool:
    return token.upper() in {"AND", "OR"}


def is_operator_token(token: str) -> bool:
    return token in {"=", "!="}


def starts_comparison(tokens: list[str], index: int) -> bool:
    """
    A comparison starts at position i if tokens[i:i+3] look like:
      field operator value
    """
    if index + 2 >= len(tokens):
        return False

    field = tokens[index]
    operator = tokens[index + 1]
    value = tokens[index + 2]

    if field in {"(", ")"} or is_boolean_token(field) or is_operator_token(field):
        return False

    if not is_operator_token(operator):
        return False

    if value in {"(", ")"} or is_boolean_token(value):
        return False

    return True


def insert_implicit_ands(tokens: list[str]) -> list[str]:
    """
    Splunk base searches often imply AND by adjacency:
      EventCode=1 Image="*powershell.exe"
    becomes:
      EventCode=1 AND Image="*powershell.exe"

    We only insert AND:
    - after a complete comparison when another comparison starts next
    - after a closing ')' when another comparison starts next
    - after a complete comparison when '(' starts next
    - after a closing ')' when '(' starts next
    """
    result = []
    i = 0

    while i < len(tokens):
        # Copy complete comparison as a unit: field op value
        if starts_comparison(tokens, i):
            result.extend(tokens[i:i + 3])
            i += 3

            if i < len(tokens):
                if tokens[i] == "(" or starts_comparison(tokens, i):
                    result.append("AND")
            continue

        # Copy parenthesis
        token = tokens[i]
        result.append(token)
        i += 1

        if token == ")" and i < len(tokens):
            if tokens[i] == "(" or starts_comparison(tokens, i):
                result.append("AND")

    return result


def strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def extract_event_value(event: dict, field: str):
    value = event.get(field)

    # Some exported Splunk fields can come back as arrays; use the last non-empty item.
    if isinstance(value, list):
        non_empty = [str(v) for v in value if str(v).strip()]
        if non_empty:
            return non_empty[-1]
        return ""

    return value


def wildcard_match(actual: object, pattern: str) -> bool:
    actual_str = "" if actual is None else str(actual)
    return fnmatch.fnmatch(actual_str.lower(), pattern.lower())


def compare_field(event: dict, field: str, operator: str, value: str) -> bool:
    actual = extract_event_value(event, field)
    expected = strip_quotes(value)

    if operator == "=":
        return wildcard_match(actual, expected)

    if operator == "!=":
        return not wildcard_match(actual, expected)

    fail(f"Unsupported operator '{operator}' in local SPL evaluator")
    return False


def parse_primary(tokens: list[str], pos: int):
    if pos >= len(tokens):
        fail("Unexpected end of expression")

    token = tokens[pos]

    if token == "(":
        node, pos = parse_or(tokens, pos + 1)
        if pos >= len(tokens) or tokens[pos] != ")":
            fail("Missing closing parenthesis in search expression")
        return node, pos + 1

    if pos + 2 >= len(tokens):
        fail(f"Incomplete comparison near token '{token}'")

    field = tokens[pos]
    operator = tokens[pos + 1]
    value = tokens[pos + 2]

    if not is_operator_token(operator):
        fail(f"Unsupported operator '{operator}' in local SPL evaluator")

    node = ("cmp", field, operator, value)
    return node, pos + 3


def parse_and(tokens: list[str], pos: int):
    left, pos = parse_primary(tokens, pos)

    while pos < len(tokens) and tokens[pos].upper() == "AND":
        right, pos = parse_primary(tokens, pos + 1)
        left = ("and", left, right)

    return left, pos


def parse_or(tokens: list[str], pos: int):
    left, pos = parse_and(tokens, pos)

    while pos < len(tokens) and tokens[pos].upper() == "OR":
        right, pos = parse_and(tokens, pos + 1)
        left = ("or", left, right)

    return left, pos


def eval_ast(node, event: dict) -> bool:
    kind = node[0]

    if kind == "cmp":
        _, field, operator, value = node
        return compare_field(event, field, operator, value)

    if kind == "and":
        return eval_ast(node[1], event) and eval_ast(node[2], event)

    if kind == "or":
        return eval_ast(node[1], event) or eval_ast(node[2], event)

    fail(f"Unsupported AST node '{kind}'")
    return False


def event_matches_base_search(event: dict, base_search: str) -> bool:
    expr = remove_index_terms(base_search)
    expr = normalize_expression(expr)

    if not expr:
        return True

    tokens = tokenize(expr)
    tokens = insert_implicit_ands(tokens)

    ast, pos = parse_or(tokens, 0)

    if pos != len(tokens):
        remaining = " ".join(tokens[pos:])
        fail(f"Could not fully parse search expression. Remaining tokens: {remaining}")

    return eval_ast(ast, event)


def run_rule_test(rule_path: Path):
    rule_stem = rule_path.stem
    config = load_test_config(rule_stem)
    positive_events = read_positive_fixture_events(rule_stem)

    _, query = parse_detection_file(rule_path)
    base_search = extract_base_search(query)

    expected_positive_min = int(config.get("expected_positive_min", 1))

    matched = 0
    for event in positive_events:
        if event_matches_base_search(event, base_search):
            matched += 1

    log(f"Testing {rule_path.name} locally with base search: {base_search}")
    log(f"Matched {matched} of {len(positive_events)} positive fixture event(s)")

    if matched < expected_positive_min:
        fail(
            f"{rule_path.name} failed local true-positive test: "
            f"matched={matched}, expected at least {expected_positive_min}"
        )

    log(
        f"Local true-positive test passed for {rule_path.name} "
        f"(matched={matched}, expected_min={expected_positive_min})"
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

    print("[PASS] Local Splunk detection true-positive tests succeeded")


if __name__ == "__main__":
    main()