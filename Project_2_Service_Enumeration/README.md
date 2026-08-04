# Network Service Enumeration Tool

## Project Overview

Network Service Enumeration Tool is a Python-based security utility designed to scan TCP ports, identify running services, capture service banners, and generate a detailed scan report.

This project demonstrates practical concepts of networking, socket programming, multithreading, and basic security assessment.

---

## Features

- TCP Port Scanning
- Service Identification
- Multithreaded Port Scanning
- Banner Grabbing
- Command Line Interface (CLI)
- Open Port Detection
- Scan Time Calculation
- Automated Security Report Generation
- Thread Synchronization using Lock

---

## Technologies Used

- **Programming Language:** Python 3
- **Operating System:** Kali Linux
- **Libraries:**
  - Socket
  - Threading
  - Argparse
  - Time
  - Datetime

---

## Project Structure

```text
Project_2_Service_Enumeration

├── scanner.py
├── results.txt
├── README.md
└── screenshots
    ├── scan_output.png
    ├── report_output.png
    └── project_structure.png
``` 

## Installation

Clone the repository:

git clone <repository-url>

Navigate to the project directory:

cd Project_2_Service_Enumeration

---

## Usage

Run the scanner:

python3 scanner.py -t <target-ip>

Example:

python3 scanner.py -t 127.0.0.1
## Sample Output

```text
Scanning 127.0.0.1...

[OPEN] Port 8000 - HTTP-Alt

Banner:
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.13.12

==============================
Scan Completed.
==============================
Target: 127.0.0.1
Ports Scanned: 14
Open Ports: 1
Scan Time: 0.02 seconds
Results Saved: results.txt
```
## Report Generation

The tool automatically generates a detailed report file:

```text
results.txt
```
The report contains:

- Target IP Address
- Open Ports
- Detected Services
- Service Banners
- Scan Summary
- Scan Time


## Screenshots

Scan Output

## Report Output

Project Structure

## Learning Outcomes

Through this project, I learned:

- TCP socket programming in Python
- Port scanning techniques
- Service enumeration concepts
- Banner grabbing methodology
- Multithreading implementation
- Command line tool development
- Basic security assessment workflow
## Future Improvements
Custom port range scanning
UDP scanning support
JSON report generation
Database integration
Vulnerability risk mapping

## Author

Saif Ali

BS Information Technology Student

Aspiring Cloud Security & GRC Professional

## Disclaimer

This tool is developed for educational purposes and authorized security testing only.