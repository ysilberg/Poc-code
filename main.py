import threading
import os
from network_sniffer import start_sniffer
from file_checker import check_file
from sandbox import run_in_sandbox


def ensure_logs_dir():
    if not os.path.exists("./logs"):
        os.makedirs("./logs")


def main():
    ensure_logs_dir()

    sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
    sniffer_thread.start()

    #test_file = "test.exe"
    #if os.path.exists(test_file):
    #    check_file(test_file)
    #    run_in_sandbox(test_file)

    sniffer_thread.join()


if __name__ == "__main__":
    main()
