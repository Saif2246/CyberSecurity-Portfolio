import xml.etree.ElementTree as ET
import mysql.connector

# Database Connection
conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="Network_Security_DB"
)

print("Database Connected Successfully")
print("Connection Status:", conn.is_connected())

cursor = conn.cursor()

# Parse XML File
tree = ET.parse("scan_result.xml")
root = tree.getroot()

print("\nNmap Scan Results")
print("-" * 30)

for host in root.findall("host"):
    address = host.find("address")

    if address is not None:
        ip_address = address.attrib["addr"]
        print("IP Address:", ip_address)

        # Insert IP Address into Database
        cursor.execute(
            "INSERT INTO Scanned_Devices (IP_Address) VALUES (%s)",
            (ip_address,)
        )
        print("Insert query executed")
        conn.commit()
        print("Data committed to database")
        device_id = cursor.lastrowid
        print("Device inserted with ID:", device_id)

    ports = host.find("ports")

    if ports is not None:
        for port in ports.findall("port"):
            protocol = port.attrib["protocol"]
            portid = port.attrib["portid"]

            state = port.find("state")
            service = port.find("service")

            if state is not None:
                print("Port:", portid + "/" + protocol)
                print("State:", state.attrib["state"])

                if service is not None:
                    print("Service:", service.attrib.get("name", "Unknown"))

                print("-" * 30)

cursor.close()
conn.close()

print("Database Connection Closed")