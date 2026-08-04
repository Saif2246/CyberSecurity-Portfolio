import socket
import threading
import time
import argparse
from datetime import datetime

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    8000: "HTTP-Alt"
}


parser = argparse.ArgumentParser(
    description="Network Service Enumeration Tool"
)

parser.add_argument(
    "-t",
    "--target",
    required=True,
    help="Target IP Address"
)

args = parser.parse_args()

target = args.target

start_time = time.time()

file = open("results.txt", "w")

file.write("================================\n")
file.write("SERVICE ENUMERATION REPORT\n")
file.write("================================\n\n")
file.write(f"Target: {target}\n")
file.write(f"Date: {datetime.now()}\n\n")


open_ports = 0
lock = threading.Lock()

ports = list(COMMON_PORTS.keys())

print(f"\nScanning {target}...\n")


def grab_banner(sock):
    try:
        sock.send(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner
    except:
        return "No Banner"


def scan_port(port):
    global open_ports

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)

    result = sock.connect_ex((target, port))

    if result == 0:
        service = COMMON_PORTS.get(port, "Unknown")

        banner = grab_banner(sock)

        with lock:
            open_ports += 1

            file.write("--------------------------------\n")
            file.write(f"Port: {port}\n")
            file.write(f"Service: {service}\n")
            file.write(f"Banner: {banner}\n\n")

        print(f"[OPEN] Port {port} - {service}")
        print(f"Banner: {banner}\n")

    sock.close()


threads = []

for port in ports:
    thread = threading.Thread(target=scan_port, args=(port,))
    threads.append(thread)
    thread.start()


for thread in threads:
    thread.join()


end_time = time.time()
scan_time = end_time - start_time


file.write("================================\n")
file.write("SCAN SUMMARY\n")
file.write("================================\n")
file.write(f"Target: {target}\n")
file.write(f"Ports Scanned: {len(ports)}\n")
file.write(f"Open Ports: {open_ports}\n")
file.write(f"Scan Time: {scan_time:.2f} seconds\n")

file.close()


print("==============================")
print("Scan Completed.")
print("==============================")
print(f"Target: {target}")
print(f"Ports Scanned: {len(ports)}")
print(f"Open Ports: {open_ports}")
print(f"Scan Time: {scan_time:.2f} seconds")
print("Results Saved: results.txt")