from pathlib import Path
import json
import fnmatch
import re
import sys

# root relative to current file
ROOT = Path(__file__).resolve().parent.parent

# mitre-att&ck SPL detection directory
SPLUNK_DIR = ROOT / "detections" / "splunk" / "mitre-att&ck"
# Splunk tests directory
TESTS_DIR = ROOT / "tests" / "splunk"


"""
Builds a query engine for Splunk base searches to validate locally. 
Starts by extracting base search, normalizing it (removing index=..., 
standardizing operators, and cleaning spacing).
Then, tokenizes the string into meaningful pieces (fields, operators, values,
parentheses, AND/OR), as Splunk implies AND between conditions.
Next, tokens turn into an AST (Abstract Syntax Tree), using a recursive parser
that respects operator precedence (NOT > AND > OR). Each node in the AST represents either
a comparison (field=value), or a logical operation.
Finally, it evaluates the AST against each test event, pulling values
from the event, applying wildcard matching, and recursively computing whether the full
condition is true. 
"""

# fail function
def fail(msg: str):
    print(f"[FAIL] {msg}")
    sys.exit(1)


# log function
def log(msg: str):
    print(f"[INFO] {msg}")


# parse the Splunk detection file
def parse_detection_file(path: Path) -> tuple[dict, str]:
    # read the SPL detection file line-by-line so metadata headers can be seperated
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    # stored in comment headers
    metadata = {}
    # query lines hold the actual SPL search body after headers are removed
    query_lines = []

    for line in lines:
        # parse metadata key/value pairs from commented header lines
        if line.startswith("# ") and ":" in line:
            key, value = line[2:].split(":", 1)
            metadata[key.strip().lower()] = value.strip()
        else:
            # everything else is treated as part of the SPL query
            query_lines.append(line)

    # rebuild the SPL query body
    query = "\n".join(query_lines).strip()

    # required metadata fields that query detecion file must define
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

    # fail fast if anything required metadata field is missing
    missing = [k for k in required if k not in metadata]
    if missing:
        fail(f"{path.name} missing metadata keys: {', '.join(missing)}")

    # fail if the detection contains no actual SPL query
    if not query:
        fail(f"{path.name} has an empty search query")

    return metadata, query


def load_test_config(rule_stem: str) -> dict:
    # build the expected path to the per-rule test configuration file
    config_path = TESTS_DIR / rule_stem / "test_config.json"
    # ensure config file exists
    if not config_path.exists():
        fail(f"Missing test config: {config_path.relative_to(ROOT)}")

    # load and parse the JSON config file
    try:
        return json.loads(config_path.read_text(encoding="utf-8"))
    except Exception as e:
        # fail if config JSON is invalid or unreadable
        fail(f"Invalid JSON in {config_path.relative_to(ROOT)}: {e}")


def normalize_fixture_event(raw_event: dict) -> dict:
    # ensure each fixture is a JSON object
    if not isinstance(raw_event, dict):
        fail("Fixture event must be a JSON object")

    # some fixture exports may wrap the real event inside a "result" key
    # normalize that format so downstream evaluation always sees the event body
    if "result" in raw_event and isinstance(raw_event["result"], dict):
        return raw_event["result"]

    return raw_event


def read_positive_fixture_events(rule_stem: str) -> list[dict]:
    # positive test fixtures live under tests/splunk/<rule_stem>/positive
    fixture_dir = TESTS_DIR / rule_stem / "positive"
    # ensure positive fixture directory exists
    if not fixture_dir.exists():
        fail(f"Missing positive fixture directory: {fixture_dir.relative_to(ROOT)}")

    # load all JSON fixtures in deterministic sorted order
    events = []
    for path in sorted(fixture_dir.glob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            events.append(normalize_fixture_event(raw))
        except Exception as e:
            # fail if any fixture file contains invalid JSON
            fail(f"Invalid fixture JSON in {path.relative_to(ROOT)}: {e}")

    # at least one positive fixture is required for a meaningful true-positive test
    if not events:
        fail(f"No positive fixtures found in {fixture_dir.relative_to(ROOT)}")

    return events


# extract only the base search portion before the first pipe
def extract_base_search(query: str) -> str:
    return query.split("|", 1)[0].strip()


# remove index=... termins since local fixture evaluation does not model Splunk indexes
def remove_index_terms(expr: str) -> str:
    expr = re.sub(r"\bindex\s*=\s*\S+", "", expr, flags=re.IGNORECASE)
    return " ".join(expr.split())


def normalize_expression(expr: str) -> str:
    # flatten newlines/carriage returns into spaces for consistent parsing
    expr = expr.replace("\n", " ").replace("\r", " ")
    # add spacing around comparison operators to make tokenization easier
    expr = expr.replace("!=", " != ")
    expr = re.sub(r"(?<![!<>=])=(?!=)", " = ", expr)
    # add spacing around parentheses
    expr = expr.replace("(", " ( ").replace(")", " ) ")
    # normalize boolean operators for easier downstream parsing
    expr = re.sub(r"\bAND\b", " AND ", expr, flags=re.IGNORECASE)
    expr = re.sub(r"\bOR\b", " OR ", expr, flags=re.IGNORECASE)
    expr = re.sub(r'([A-Za-z0-9_.]+)\s*\+\s*(".*?")', r"\1 = \2", expr)

    #collapse repeated whitespace into clean, normalized string
    expr = " ".join(expr.split())
    return expr.strip()


# convert normalized search expression into tokens for parsing
def tokenize(expr: str) -> list[str]:
    # supports: parentheses, quoted strings, bare words/operators
    tokens = []
    i = 0
    n = len(expr)

    while i < n:
        ch = expr[i]

        # skip whitespace
        if ch.isspace():
            i += 1
            continue

        # parentheses are standalone tokens
        if ch in "()":
            tokens.append(ch)
            i += 1
            continue

        # capture quoted string as a single token
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

        # capture bare token until whitespace or parenthesis is reached
        j = i
        while j < n and not expr[j].isspace() and expr[j] not in "()":
            j += 1
        tokens.append(expr[i:j])
        i = j

    return tokens


# identify boolean operators used in the local expression parser
def is_boolean_token(token: str) -> bool:
    return token.upper() in {"AND", "OR"}


# identify boolean operators used in the local expression parser
def is_operator_token(token: str) -> bool:
    return token in {"=", "!="}


# determine whether tokens[index:index+3] form a valid comparison
def starts_comparison(tokens: list[str], index: int) -> bool:
    if index + 2 >= len(tokens):
        return False

    field = tokens[index]
    operator = tokens[index + 1]
    value = tokens[index + 2]

    # field token cannot itself be a parenthesis or operator
    if field in {"(", ")"} or is_boolean_token(field) or is_operator_token(field):
        return False

    # operator must be one of the supported comparison tokens
    if not is_operator_token(operator):
        return False

    # value token cannot be a parenthesis or boolean operator
    if value in {"(", ")"} or is_boolean_token(value):
        return False

    return True


# Splunk base implies AND's between adjacted comparisons
# this helper explicitly inserts them so the parser can handle them
def insert_implicit_ands(tokens: list[str]) -> list[str]:
    result = []
    i = 0

    while i < len(tokens):
        # Copy complete comparison as a unit: field op value
        if starts_comparison(tokens, i):
            result.extend(tokens[i:i + 3])
            i += 3

            # insert implicit AND if the next token starts another comparison
            # or opens a grouped comparison
            if i < len(tokens):
                if tokens[i] == "(" or starts_comparison(tokens, i):
                    result.append("AND")
            continue

        token = tokens[i]
        result.append(token)
        i += 1

        # insert implicit AND after a closing parenthesis if another grouped
        # expression or comparison immediately follows
        if token == ")" and i < len(tokens):
            if tokens[i] == "(" or starts_comparison(tokens, i):
                result.append("AND")

    return result


# remove surrounding double quotes from a token value
def strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


# pull the field value directly form the event
def extract_event_value(event: dict, field: str):
    value = event.get(field)

    # if the event field is a list, choose the last non-empty value
    # helps normalize multi-value fields for a local comparison
    if isinstance(value, list):
        non_empty = [str(v) for v in value if str(v).strip()]
        if non_empty:
            return non_empty[-1]
        return ""

    return value


# compare values using case-insensitive wildcard matching
# approximates common Splunk-style matching behavior for base searches
def wildcard_match(actual: object, pattern: str) -> bool:
    actual_str = "" if actual is None else str(actual)
    return fnmatch.fnmatch(actual_str.lower(), pattern.lower())


def compare_field(event: dict, field: str, operator: str, value: str) -> bool:
    # extract the event value and normalize the comparison target
    actual = extract_event_value(event, field)
    expected = strip_quotes(value)

    # support patterns like "*powershell*"
    if operator == "=":
        return wildcard_match(actual, expected)

    # negate wildcard match result
    if operator == "!=":
        return not wildcard_match(actual, expected)

    # unsupported operators should fail immediately
    fail(f"Unsupported operator '{operator}' in local SPL evaluator")
    return False


def parse_primary(tokens: list[str], pos: int):
    # parse the smallest valid expression
    if pos >= len(tokens):
        fail("Unexpected end of expression")

    token = tokens[pos]

    # handle parenthesized expressions recursively 
    if token == "(":
        node, pos = parse_or(tokens, pos + 1)
        if pos >= len(tokens) or tokens[pos] != ")":
            fail("Missing closing parenthesis in search expression")
        return node, pos + 1

    # comparisons require at least 3 tokens
    if pos + 2 >= len(tokens):
        fail(f"Incomplete comparison near token '{token}'")

    field = tokens[pos]
    operator = tokens[pos + 1]
    value = tokens[pos + 2]

    # only = and != are supported in this local evaluator
    if not is_operator_token(operator):
        fail(f"Unsupported operator '{operator}' in local SPL evaluator")

    # return AST node for comparison and the updated parse position
    node = ("cmp", field, operator, value)
    return node, pos + 3


# parse left-associative AND expressions
def parse_and(tokens: list[str], pos: int):
    left, pos = parse_primary(tokens, pos)

    while pos < len(tokens) and tokens[pos].upper() == "AND":
        right, pos = parse_primary(tokens, pos + 1)
        left = ("and", left, right)

    return left, pos


# parse left-associative OR expressions
def parse_or(tokens: list[str], pos: int):
    left, pos = parse_and(tokens, pos)

    while pos < len(tokens) and tokens[pos].upper() == "OR":
        right, pos = parse_and(tokens, pos + 1)
        left = ("or", left, right)

    return left, pos


# evaluate the parsed expression tree against a single event
def eval_ast(node, event: dict) -> bool:
    kind = node[0]

    if kind == "cmp":
        _, field, operator, value = node
        return compare_field(event, field, operator, value)

    if kind == "and":
        return eval_ast(node[1], event) and eval_ast(node[2], event)

    if kind == "or":
        return eval_ast(node[1], event) or eval_ast(node[2], event)

    # fail if an unexpected AST node type appears
    fail(f"Unsupported AST node '{kind}'")
    return False


def event_matches_base_search(event: dict, base_search: str) -> bool:
    # strip out index terms in local fixture evaluation
    expr = remove_index_terms(base_search)
    # normalize formatting and operators before parsing
    expr = normalize_expression(expr)

    # empty base search matches everything
    if not expr:
        return True

    # tokenize and insert explicit ANDs where Splunk syntax implies them
    tokens = tokenize(expr)
    tokens = insert_implicit_ands(tokens)

    # parse expression into an AST
    ast, pos = parse_or(tokens, 0)

    # ensure the full expression was consumed cleanly
    if pos != len(tokens):
        remaining = " ".join(tokens[pos:])
        fail(f"Could not fully parse search expression. Remaining tokens: {remaining}")

    # evaluate the AST against the event
    return eval_ast(ast, event)


def run_rule_test(rule_path: Path):
    # derive rule stem
    rule_stem = rule_path.stem
    # load test config and positive events
    config = load_test_config(rule_stem)
    positive_events = read_positive_fixture_events(rule_stem)

    # parse the SPL detection file and isolate the base search
    _, query = parse_detection_file(rule_path)
    base_search = extract_base_search(query)

    # minimum number of positive events that must match for the test to pass
    expected_positive_min = int(config.get("expected_positive_min", 1))

    matched = 0
    # evaluate each position event against the base search
    for event in positive_events:
        if event_matches_base_search(event, base_search):
            matched += 1

    log(f"Testing {rule_path.name} locally with base search: {base_search}")
    log(f"Matched {matched} of {len(positive_events)} positive fixture event(s)")

    # fail if the rule does not meet its expected positive threshold
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
    # ensure Splunk detections directory exists
    if not SPLUNK_DIR.exists():
        fail(f"Missing Splunk detections directory: {SPLUNK_DIR.relative_to(ROOT)}")

    # collect all .spl detection files in deterministic order
    files = sorted(SPLUNK_DIR.glob("*.spl"))
    if not files:
        fail("No .spl files found")

    for rule_path in files:
        # each rule must have a matching test directory under test/splunk/<rule_stem>
        test_dir = TESTS_DIR / rule_path.stem
        if not test_dir.exists():
            fail(
                f"Missing test directory for {rule_path.name}: "
                f"{test_dir.relative_to(ROOT)}"
            )
        # test path must be a directory, not a file
        if not test_dir.is_dir():
            fail(
                f"Test path for {rule_path.name} is not a directory: "
                f"{test_dir.relative_to(ROOT)}"
            )
        # each rule must also define a test_config.json file
        config_path = test_dir / "test_config.json"
        if not config_path.exists():
            fail(
                f"Missing test_config.json for {rule_path.name}: "
                f"{config_path.relative_to(ROOT)}"
            )
        # run local true-positive validation for this rule
        run_rule_test(rule_path)

    print("[PASS] Local Splunk detection true-positive tests succeeded")


if __name__ == "__main__":
    main()