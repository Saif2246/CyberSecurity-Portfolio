import socket
import threading
import time
import argparse
import json
import mysql.connector
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
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="123456",
    database="Network_Security_DB"
)

cursor = db.cursor()

start_time = time.time()


file = open("results.txt", "w")


file.write("================================\n")
file.write("SERVICE ENUMERATION REPORT\n")
file.write("================================\n\n")

file.write(f"Target: {target}\n")
file.write(f"Date: {datetime.now()}\n\n")



open_ports = 0

scan_results = []

lock = threading.Lock()


ports = list(COMMON_PORTS.keys())



print(f"\nScanning {target}...\n")



def grab_banner(sock):

    try:

        sock.send(
            b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )


        banner = sock.recv(1024).decode(
            errors="ignore"
        ).strip()


        if banner:
            return banner


        return "No Banner"



    except socket.timeout:

        return "Banner Timeout"



    except Exception:

        return "Banner Not Available"





def scan_port(port):

    global open_ports


    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )


    sock.settimeout(2)



    try:

        result = sock.connect_ex(
            (target, port)
        )



        if result == 0:


            service = COMMON_PORTS.get(
                port,
                "Unknown"
            )


            banner = grab_banner(sock)



            with lock:


                open_ports += 1



                file.write("--------------------------------\n")
                file.write(f"Port: {port}\n")
                file.write(f"Service: {service}\n")
                file.write(f"Banner: {banner}\n\n")



                scan_results.append({

                    "port": port,

                    "service": service,

                    "banner": banner

                })
                cursor.execute(
                    """
                    INSERT INTO Service_Enumeration_Results
                    (target_ip, port, service, banner)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (target, port, service, banner)
                )

                db.commit()


            print(
                f"[OPEN] Port {port} - {service}"
            )


            print(
                f"Banner: {banner}\n"
            )





    except socket.timeout:


        print(
            f"[TIMEOUT] Port {port}"
        )



    except ConnectionRefusedError:

        pass



    except Exception as error:


        print(
            f"[ERROR] Port {port}: {error}"
        )



    finally:

        sock.close()





threads = []



for port in ports:


    thread = threading.Thread(

        target=scan_port,

        args=(port,)

    )


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

file.write(
    f"Scan Time: {scan_time:.2f} seconds\n"
)


file.close()





# JSON REPORT GENERATION

json_report = {


    "target": target,

    "date": str(datetime.now()),

    "ports_scanned": len(ports),

    "open_ports": open_ports,

    "scan_time": f"{scan_time:.2f} seconds",

    "results": scan_results

}



with open("results.json", "w") as json_file:


    json.dump(

        json_report,

        json_file,

        indent=4

    )





print("==============================")

print("Scan Completed.")

print("==============================")


print(f"Target: {target}")

print(f"Ports Scanned: {len(ports)}")

print(f"Open Ports: {open_ports}")

print(f"Scan Time: {scan_time:.2f} seconds")


print("Results Saved: results.txt")

print("JSON Report Saved: results.json")
cursor.close()
db.close()