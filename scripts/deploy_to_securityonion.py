from pathlib import Path
import os
import sys
import tempfile
import paramiko

ROOT = Path(__file__).resolve().parent.parent
SO_SURICATA_DIR = ROOT / "detections" / "security-onion" / "suricata"

SO_MANAGER_HOST = os.getenv("SO_MANAGER_HOST", "").strip()
SO_MANAGER_PORT = int(os.getenv("SO_MANAGER_PORT", "22"))
SO_MANAGER_USER = os.getenv("SO_MANAGER_USER", "").strip()
SO_MANAGER_SSH_KEY = os.getenv("SO_MANAGER_SSH_KEY", "")
SO_RULES_DIR = os.getenv("SO_RULES_DIR", "").strip()


def fail(msg: str):
    print(f"[FAIL] {msg}")
    sys.exit(1)


def write_temp_key() -> str:
    if not SO_MANAGER_SSH_KEY:
        fail("SO_MANAGER_SSH_KEY environment variable is not set")

    with tempfile.NamedTemporaryFile(
        delete=False,
        mode="w",
        encoding="utf-8",
        newline="\n",
    ) as f:
        f.write(SO_MANAGER_SSH_KEY)
        key_path = f.name

    os.chmod(key_path, 0o600)
    return key_path


def get_private_key(key_path: str):
    key_loaders = [
        paramiko.Ed25519Key.from_private_key_file,
        paramiko.RSAKey.from_private_key_file,
        paramiko.ECDSAKey.from_private_key_file,
    ]

    last_error = None
    for loader in key_loaders:
        try:
            return loader(key_path)
        except Exception as e:
            last_error = e

    fail(f"Unable to load SSH private key: {last_error}")


def get_ssh_client(key_path: str) -> paramiko.SSHClient:
    if not SO_MANAGER_HOST:
        fail("SO_MANAGER_HOST environment variable is not set")
    if not SO_MANAGER_USER:
        fail("SO_MANAGER_USER environment variable is not set")
    if not SO_RULES_DIR:
        fail("SO_RULES_DIR environment variable is not set")

    key = get_private_key(key_path)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=SO_MANAGER_HOST,
        port=SO_MANAGER_PORT,
        username=SO_MANAGER_USER,
        pkey=key,
        timeout=20,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def run_ssh(client: paramiko.SSHClient, command: str):
    stdin, stdout, stderr = client.exec_command(command)
    exit_status = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="ignore")
    err = stderr.read().decode("utf-8", errors="ignore")

    if exit_status != 0:
        fail(
            f"Remote command failed: {command}\n"
            f"STDOUT:\n{out}\n"
            f"STDERR:\n{err}"
        )

    return out, err


def main():
    rule_files = sorted(SO_SURICATA_DIR.glob("*.rules"))
    if not rule_files:
        fail("No .rules files found in detections/security-onion/suricata")

    key_path = write_temp_key()
    client = None

    try:
        client = get_ssh_client(key_path)
        sftp = client.open_sftp()

        run_ssh(client, f"mkdir -p {SO_RULES_DIR}")

        for rule_file in rule_files:
            remote_path = f"{SO_RULES_DIR}/{rule_file.name}"
            print(f"[INFO] Uploading {rule_file.name} -> {remote_path}")
            sftp.put(str(rule_file), remote_path)
            print(f"[PASS] Uploaded {rule_file.name}")

        sftp.close()

        out, _ = run_ssh(client, f"ls -lah {SO_RULES_DIR}")
        print("[INFO] Remote directory contents:")
        print(out)

        print("[PASS] Security Onion Suricata rule upload complete")
        print("[INFO] Next step in Security Onion UI: Detections -> Options -> Suricata -> Differential Update")

    finally:
        if client:
            client.close()
        if os.path.exists(key_path):
            os.remove(key_path)


if __name__ == "__main__":
    main()