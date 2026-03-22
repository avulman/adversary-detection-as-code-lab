from pathlib import Path
import os
import sys
import subprocess

ROOT = Path(__file__).resolve().parent.parent
SURICATA_DIR = ROOT / "detections" / "security-onion" / "suricata"

SO_RULES_DIR = os.getenv("SO_RULES_DIR", "").strip()

def fail(msg: str):
    print(f"[FAIL] {msg}")
    sys.exit(1)

def run(cmd: list[str]):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        fail(f"Command failed: {' '.join(cmd)}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")
    return result

def main():
    if not SO_RULES_DIR:
        fail("SO_RULES_DIR environment variable is not set")

    src_files = sorted(SURICATA_DIR.glob("*.rules"))
    if not src_files:
        fail("No .rules files found in detections/security-onion/suricata")

    target_dir = Path(SO_RULES_DIR)
    target_dir.mkdir(parents=True, exist_ok=True)

    for src in src_files:
        dst = target_dir / src.name
        dst.write_text(src.read_text(encoding="utf-8", errors="ignore"), encoding="utf-8")
        print(f"[PASS] Copied {src.name} -> {dst}")

    print("[INFO] Security Onion rule files copied successfully")
    print("[INFO] Next step on the Security Onion manager:")
    print("       validate with so-suricata-testrule and then reload/sync rules")

if __name__ == "__main__":
    main()