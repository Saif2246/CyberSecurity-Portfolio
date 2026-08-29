# Nmap Security Testing Cheat Sheet

## Purpose
Nmap is a network discovery and security auditing tool for authorized labs, testing environments, and defensive assessments.

## Host Discovery

### Ping Scan
nmap -sn 192.168.1.0/24

### Single Host
nmap 192.168.1.10

## Service Enumeration

### Service Version Detection
nmap -sV 192.168.1.10

### OS Detection
nmap -O 192.168.1.10

### Service and OS Detection
nmap -sV -O 192.168.1.10

## Port Scanning

### Specific Ports
nmap -p 22,80,443 192.168.1.10

### Port Range
nmap -p 1-1000 192.168.1.10

### All TCP Ports
nmap -p- 192.168.1.10

## Output

### Normal Text
nmap -oN scan.txt 192.168.1.10

### XML
nmap -oX scan.xml 192.168.1.10

## Defensive Investigation

### Check SSH Exposure
nmap -p 22 -sV 192.168.1.10

### Check Web Services
nmap -p 80,443 -sV 192.168.1.10

## Interpretation

Nmap results can identify open ports, exposed services, service versions, and potential attack-surface changes.

An open port does not by itself prove compromise.

## Security Guidance

- Scan only authorized targets.
- Use lab or testing environments for experimentation.
- Preserve scan results when relevant to an investigation.
- Correlate Nmap findings with authentication, firewall, and host logs.
