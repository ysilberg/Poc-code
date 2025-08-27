import hashlib
import time

LOG_FILE = "./logs/file_log.txt"
MALICIOUS_HASHES = {"5d41402abc4b2a76b9719d911017c592"}


def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()


def check_file(file_path):
    file_hash = calculate_hash(file_path)
    if file_hash in MALICIOUS_HASHES:
        alert = f"[ALERT] Malicious file detected: {file_path} (hash={file_hash})"
        print(alert)

        with open(LOG_FILE, "a") as f:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
            f.write(f"{timestamp} - {alert}\n")
    else:
        print(f"[INFO] File {file_path} is clean.")
