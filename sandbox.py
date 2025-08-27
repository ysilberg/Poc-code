import subprocess
import psutil
import time

LOG_FILE = "./logs/sandbox_log.txt"


def run_in_sandbox(file_path, timeout=10):
    print(f"[SANDBOX] Running {file_path}...")
    proc = subprocess.Popen([file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    suspicious = False
    start = time.time()

    while time.time() - start < timeout:
        for conn in psutil.net_connections(kind="inet"):
            if conn.pid == proc.pid:
                suspicious = True
                alert = f"[ALERT] Suspicious behavior: {file_path} opened network connection {conn.laddr} -> {conn.raddr}"
                print(alert)

                with open(LOG_FILE, "a") as f:
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
                    f.write(f"{timestamp} - {alert}\n")

        time.sleep(1)

    proc.kill()

    if not suspicious:
        print(f"[INFO] {file_path} finished, no suspicious behavior detected.")
