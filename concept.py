import time
import random
from datetime import datetime
from typing import Tuple

def get_network_packet():
    packets = [
        "TCP normal packet",
        "UDP normal",
        "TCP exploit attempt",
        "DNS request",
        "MALWARE signature in traffic"
    ]
    return random.choice(packets)

def get_file_event():
    files = [
        "document.pdf",
        "installer.exe",
        "malware_payload.dll",
        "harmless.txt",
        "trojan_app.apk"
    ]
    return random.choice(files)

def get_process_event():
    processes = [
        "chrome.exe",
        "python.exe",
        "system idle",
        "malicious_trojan.exe",
        "svchost.exe"
    ]
    return random.choice(processes)

def analyze_data(source: str, data: str) -> Tuple[bool, str]:
    data_lower = data.lower()
    if "malware" in data_lower:
        return True, "High"
    elif "trojan" in data_lower:
        return True, "Medium"
    elif "exploit" in data_lower:
        return True, "Low"
    else:
        return False, "None"

def log_event(event: str, source: str, is_threat: bool, severity: str):
    """מתעד אירוע לקובץ לוג"""
    with open("netguard_log.txt", "a", encoding="utf-8") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status = f"THREAT (Severity={severity})" if is_threat else "CLEAN"
        f.write(f"[{timestamp}] Source={source} | Data={event} | Status={status}\n")

def alert_client(source: str, event: str, severity: str):
    print(f"🚨 ALERT [{severity}] - {source}: {event}")

def run_netguard_core():
    sources = {
        "Network": get_network_packet,
        "File": get_file_event,
        "Process": get_process_event
    }

    while True:
        for src_name, generator in sources.items():
            event = generator()
            print(f"Analyzing {src_name}: {event}")

            threat, severity = analyze_data(src_name, event)
            log_event(event, src_name, threat, severity)

            if threat:
                alert_client(src_name, event, severity)

        time.sleep(2)

if __name__ == "__main__":
    run_netguard_core()
