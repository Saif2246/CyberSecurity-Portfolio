# Automated Firewall & ACL Auditor

## **Project Overview**

Automated Firewall & ACL Auditor is a Python-based security auditing tool designed to automatically analyze Firewall and Access Control List (ACL) rules, identify security weaknesses, evaluate compliance, calculate risk, and generate structured security audit reports.

The project simulates a practical enterprise firewall auditing workflow by detecting common security issues such as overly permissive access, unrestricted protocols and ports, insecure services, duplicate rules, and conflicting firewall policies.

The project demonstrates practical concepts in:

* Network Security
* Firewall Security
* ACL Auditing
* Least Privilege
* Network Access Control
* Security Controls
* Compliance Assessment
* Risk Assessment
* Security Automation
* Security Reporting
* GRC-oriented Security Analysis

---

## **Key Features**

* Automated Firewall Rule Analysis
* ACL Security Assessment
* Broad Source Access Detection
* Unrestricted Protocol Detection
* Unrestricted Port Detection
* Insecure Service Detection
* Duplicate Rule Detection
* Conflicting Rule Detection
* Security Severity Classification
* Compliance Status Evaluation
* Security Control Mapping
* Requirement Mapping
* Risk Score Calculation
* Overall Risk Classification
* Firewall Rule Statistics
* Remediation Recommendations
* JSON Report Generation
* HTML Security Dashboard
* Tkinter Security Auditor GUI
* Finding Details Viewer
* CSV Rule Dataset Support
* Modular Python Architecture
* Exception Handling
* Automated Security Reporting

---

## **Technical Write-up**

Read the complete technical breakdown of this project on DEV Community:

[Read the Full Article on DEV Community](https://dev.to/saif2246/firewall-acl-auditor-python-security-toolsecurity-python-linux-networksecurity-458a)

---

## **Security Checks**

The auditor currently performs the following security checks.

### **1. Broad Source Access**

Detects firewall rules that allow traffic from any IPv4 source:

```text
0.0.0.0/0
```

This represents unrestricted IPv4 source access.

**Severity:** HIGH

**Security Concern:**

Allowing traffic from any source can unnecessarily expose a service or network resource.

**Recommended Approach:**

Restrict the source to an approved IP address, subnet, or administrative network.

---

### **2. Unrestricted Protocol and Port Access**

Detects rules where both protocol and port are unrestricted:

```text
Protocol: any
Port: any
```

**Severity:** HIGH

**Security Concern:**

Allowing any protocol and any port creates an overly permissive network access rule.

**Recommended Approach:**

Allow only the required protocols and ports.

---

### **3. Insecure Services**

Detects commonly insecure services such as:

| Service | Port |
| ------- | ---: |
| FTP     |   21 |
| Telnet  |   23 |

**Severity:** HIGH

**Security Concern:**

Legacy services such as Telnet transmit sensitive information without adequate encryption.

**Recommended Approach:**

Disable unnecessary insecure services or replace them with secure alternatives such as SSH.

---

### **4. Duplicate Firewall Rules**

Detects multiple firewall rules containing the same traffic criteria and action.

**Severity:** MEDIUM

**Security Concern:**

Duplicate rules can make firewall policies harder to maintain and audit.

**Recommended Approach:**

Review duplicate rules and remove unnecessary entries.

---

### **5. Conflicting Firewall Rules**

Detects rules that match the same traffic but use different actions, such as:

```text
ALLOW
DENY
```

**Severity:** HIGH

**Security Concern:**

Conflicting rules can create unexpected firewall behavior depending on rule order and implementation.

**Recommended Approach:**

Review the conflicting rules and correct the policy or rule ordering.

---

## **Risk Assessment**

The auditor classifies findings according to severity.

| Severity   | Description                                         |
| ---------- | --------------------------------------------------- |
| **HIGH**   | Significant security weakness requiring attention   |
| **MEDIUM** | Security or configuration weakness requiring review |
| **LOW**    | Minor security or configuration issue               |

The tool also calculates a numerical **Risk Score** and determines an overall risk level.

### **Final Audit Result**

The current test dataset contains **20 firewall rules** and produced **12 security findings**.

| Metric             |       Result |
| ------------------ | -----------: |
| **Total Findings** |           12 |
| **HIGH**           |           10 |
| **MEDIUM**         |            2 |
| **LOW**            |            0 |
| **Risk Score**     |          110 |
| **Overall Risk**   | **CRITICAL** |

The risk score is generated from the findings identified during the audit.

---

## **Compliance Assessment**

Each security finding can be associated with a security control, requirement, and compliance status.

### **Example Control Mapping**

| Security Finding           | Security Control               |
| -------------------------- | ------------------------------ |
| Broad Source Access        | Network Access Control         |
| Unrestricted Protocol/Port | Least Privilege Network Access |
| Insecure Service           | Secure Services                |
| Duplicate Rule             | Firewall Rule Management       |
| Conflicting Rule           | Firewall Rule Management       |

This allows the project to move beyond basic vulnerability detection toward a **GRC-oriented security assessment workflow**.

---

## **Project Workflow**

```text
Firewall / ACL Rules
        │
        ▼
Read CSV Rule Dataset
        │
        ▼
Parse Firewall Rules
        │
        ▼
Run Security Checks
        │
        ├── Broad Source Access
        ├── Any Protocol / Port
        ├── Insecure Services
        ├── Duplicate Rules
        └── Conflicting Rules
        │
        ▼
Generate Security Findings
        │
        ▼
Map Findings to Controls
        │
        ▼
Evaluate Compliance
        │
        ▼
Generate Recommendations
        │
        ▼
Calculate Risk Score
        │
        ▼
Generate Rule Statistics
        │
        ├── JSON Report
        ├── HTML Dashboard
        └── Tkinter GUI
```

---

## **Project Structure**

```text
Project_3_Automated_Firewall_ACL_Auditor/
│
├── data/
│   └── firewall_rules.csv
│
├── reports/
│   ├── firewall_audit_report.json
│   └── firewall_audit_report.html
│
├── screenshots/
│   ├── terminal-audit.png
│   ├── html-dashboard.png
│   └── gui-dashboard.png
│
├── src/
│   ├── analyzer.py
│   ├── parser.py
│   ├── report_generator.py
│   ├── html_report.py
│   └── gui.py
│
├── .gitignore
└── README.md
```

The `.gitignore` file prevents unnecessary Python cache files and environment files from being committed to the repository.

---

## **Technologies Used**

### **Programming Language**

* Python 3

### **Operating System**

* Kali Linux

### **Data Formats**

* CSV
* JSON
* HTML

### **Python Standard Libraries**

* `csv`
* `json`
* `pathlib`
* `subprocess`
* `threading`
* `webbrowser`
* `tkinter`

### **Security Concepts**

* Firewall Security
* ACL Auditing
* Network Access Control
* Least Privilege
* Secure Services
* Firewall Rule Management
* Compliance Assessment
* Risk Assessment
* Security Remediation
* Security Automation

---

## **Installation**

### **1. Clone the Portfolio Repository**

```bash
git clone https://github.com/Saif2246/CyberSecurity-Portfolio.git
```

### **2. Navigate to Project 3**

```bash
cd CyberSecurity-Portfolio/Project_3_Automated_Firewall_ACL_Auditor
```

### **3. Verify Project Files**

```bash
find . -maxdepth 2 -type f | sort
```

**Expected structure:**

```text
./.gitignore
./README.md
./data/firewall_rules.csv
./reports/firewall_audit_report.html
./reports/firewall_audit_report.json
./screenshots/gui-dashboard.png
./screenshots/html-dashboard.png
./screenshots/terminal-audit.png
./src/analyzer.py
./src/gui.py
./src/html_report.py
./src/parser.py
./src/report_generator.py
```

---

## **Usage**

### **1. Run the Security Analyzer**

From the project root:

```bash
python3 src/analyzer.py
```

The analyzer will:

* Read the firewall rule dataset
* Parse firewall rules
* Perform security checks
* Generate security findings
* Evaluate compliance
* Calculate the risk score
* Generate the JSON report
* Display the audit summary

---

### **2. View the Audit Summary**

After running the analyzer:

```bash
python3 -c "import json; r=json.load(open('reports/firewall_audit_report.json')); print(r.get('summary', {}))"
```

**Current test result:**

```text
{
    'total_findings': 12,
    'high': 10,
    'medium': 2,
    'low': 0,
    'compliant': 0,
    'non_compliant': 12,
    'risk_score': 110,
    'overall_risk': 'CRITICAL'
}
```

---

### **3. View Rule Statistics**

```bash
python3 -c "import json; r=json.load(open('reports/firewall_audit_report.json')); print(r.get('statistics', {}))"
```

**Current test result:**

```text
{
    'total_rules': 20,
    'allow_rules': 17,
    'deny_rules': 3,
    'tcp_rules': 14,
    'udp_rules': 3,
    'icmp_rules': 1,
    'any_protocol_rules': 2
}
```

---

### **4. Generate HTML Security Dashboard**

Run:

```bash
python3 src/html_report.py
```

**Expected output:**

```text
HTML report saved to:
reports/firewall_audit_report.html
```

Open the dashboard:

```bash
xdg-open reports/firewall_audit_report.html
```

The HTML dashboard provides a visual representation of the firewall security assessment.

It includes:

* Total Rules
* Total Findings
* Risk Score
* Overall Risk
* Allow Rules
* Deny Rules
* TCP Rules
* UDP Rules
* ICMP Rules
* Any Protocol Rules
* Severity Summary
* Security Findings
* Compliance Status
* Security Controls
* Remediation Guidance

---

### **5. Run the GUI Security Auditor**

The project also includes a Tkinter-based graphical interface.

Run:

```bash
python3 src/gui.py
```

The GUI provides:

* CSV file selection
* Security audit execution
* Security overview
* Rules audited
* Total findings
* Risk score
* Overall risk
* HIGH / MEDIUM / LOW summary
* Compliant / Non-Compliant counts
* Firewall rule statistics
* Security findings table
* Finding details window
* HTML report access

The GUI automatically executes the analyzer and loads the generated JSON report.

---

## **Final Audit Output**

The current test dataset contains:

| Metric                  |       Result |
| ----------------------- | -----------: |
| **Total Rules Audited** |           20 |
| **Total Findings**      |           12 |
| **HIGH**                |           10 |
| **MEDIUM**              |            2 |
| **LOW**                 |            0 |
| **Compliant**           |            0 |
| **Non-Compliant**       |           12 |
| **Risk Score**          |          110 |
| **Overall Risk**        | **CRITICAL** |

### **Rule Statistics**

| Rule Statistic         | Count |
| ---------------------- | ----: |
| **Total Rules**        |    20 |
| **ALLOW Rules**        |    17 |
| **DENY Rules**         |     3 |
| **TCP Rules**          |    14 |
| **UDP Rules**          |     3 |
| **ICMP Rules**         |     1 |
| **ANY Protocol Rules** |     2 |

---

## **JSON Security Report**

The analyzer generates:

```text
reports/firewall_audit_report.json
```

The report contains:

* Security summary
* Risk score
* Overall risk
* Firewall statistics
* Security findings
* Severity
* Compliance status
* Security controls
* Requirements
* Reasons
* Recommendations
* Remediation guidance

### **Example Structure**

```json
{
    "summary": {
        "total_findings": 12,
        "high": 10,
        "medium": 2,
        "low": 0,
        "compliant": 0,
        "non_compliant": 12,
        "risk_score": 110,
        "overall_risk": "CRITICAL"
    },
    "statistics": {
        "total_rules": 20,
        "allow_rules": 17,
        "deny_rules": 3,
        "tcp_rules": 14,
        "udp_rules": 3,
        "icmp_rules": 1,
        "any_protocol_rules": 2
    },
    "findings": []
}
```

### **View JSON Report**

To inspect the complete report:

```bash
cat reports/firewall_audit_report.json
```

For a cleaner summary:

```bash
python3 -c "import json; r=json.load(open('reports/firewall_audit_report.json')); print(json.dumps({'summary': r['summary'], 'statistics': r['statistics']}, indent=4))"
```

---

## **Screenshots**

### **1. Terminal Security Audit**

The terminal screenshot demonstrates the command-line execution of the automated firewall audit, including security findings, severity classification, compliance status, risk score, and rule statistics.

### **2. HTML Security Dashboard**

The HTML dashboard provides a visual security assessment containing risk information, firewall statistics, security findings, compliance information, and remediation guidance.

### **3. GUI Security Dashboard**

The Tkinter GUI provides an interactive interface for running the firewall audit, viewing security metrics, reviewing findings, and opening the generated HTML report.

---

## **Real-World Problem Solved**

Enterprise firewalls and ACLs can contain hundreds or thousands of rules.

Manually reviewing large firewall rule sets can be:

* Time-consuming
* Error-prone
* Difficult to maintain
* Difficult to audit consistently
* Difficult to identify security weaknesses quickly

This project automates the initial security review by analyzing firewall rules and identifying common configuration weaknesses.

For example, the tool can detect:

```text
0.0.0.0/0
```

which represents unrestricted IPv4 source access.

It can also detect:

```text
protocol = any
port = any
```

which may provide unnecessarily broad network access.

The tool therefore helps security teams identify:

* Overly permissive rules
* Insecure services
* Duplicate rules
* Conflicting rules
* Non-compliant configurations

before they become larger security or operational risks.

---

## **Example Findings**

### **1. Broad Source Access**

**Rule:** 2 — Broad Source Access

**Severity:** HIGH

**Compliance:** NON-COMPLIANT

**Reason:**

The rule allows traffic from any IPv4 source.

**Remediation:**

Replace `0.0.0.0/0` with an approved internal or administrative IP range.

---

### **2. Insecure Service**

**Rule:** 5 — Insecure Service

**Severity:** HIGH

**Compliance:** NON-COMPLIANT

**Reason:**

Telnet is an insecure service that should not normally be exposed.

**Remediation:**

Disable the insecure service or replace it with a secure alternative such as SSH.

---

### **3. Conflicting Rule**

**Rule:** 9 — Conflicting Firewall Rule

**Severity:** HIGH

**Compliance:** NON-COMPLIANT

**Reason:**

The rule conflicts with another rule because both rules match the same traffic but use different actions.

**Remediation:**

Review the conflicting rules and correct the rule order or remove the unnecessary rule.

---

## **Learning Outcomes**

Through this project, I gained practical experience in:

* Firewall Rule Auditing
* ACL Security Analysis
* Network Access Control
* Least Privilege
* Security Control Mapping
* Compliance Assessment
* Risk Assessment
* Risk Scoring
* Security Finding Classification
* Security Remediation
* JSON Report Generation
* HTML Report Generation
* GUI Development with Tkinter
* Python Modular Development
* CSV Data Processing
* Exception Handling
* Security Automation
* Security Reporting

---

## **Skills Demonstrated**

### **Cybersecurity**

* Cybersecurity
* Firewall Security
* ACL Auditing
* Network Security
* Security Assessment
* Security Controls
* Least Privilege
* Secure Service Analysis
* Security Remediation

### **GRC**

* GRC
* Compliance Mapping
* Control Identification
* Requirement Mapping
* Risk Assessment
* Risk Scoring
* Non-Compliance Identification
* Audit Reporting

### **Programming**

* Python
* Modular Programming
* File Handling
* CSV Processing
* JSON Processing
* Exception Handling
* Threading
* GUI Development
* Automated Reporting

### **Reporting**

* Structured JSON Reports
* HTML Security Dashboards
* Interactive GUI Dashboard
* Security Finding Reports
* Risk Summaries
* Remediation Reports

---

## **Future Improvements**

Future versions may include:

* Enterprise Firewall Configuration Parsing
* Cisco ACL Support
* AWS Security Group Auditing
* Azure Network Security Group Auditing
* Cloud Firewall Auditing
* Rule Shadowing Detection
* Unused Rule Detection
* Overlapping CIDR Detection
* Rule Expiration Detection
* CVSS-Based Risk Scoring
* NIST Control Mapping
* CIS Benchmark Mapping
* CSV/PDF Report Export
* Database Storage
* REST API Integration
* SIEM Integration
* Enterprise GRC Dashboard

---

## **Author**

**Saif Ali**

BS Information Technology Student
Aspiring Cloud Security & GRC Professional
University of Layyah

**GitHub:** [Saif2246](https://github.com/Saif2246)

**LinkedIn:** [saif-ali-a22230409](https://www.linkedin.com/in/saif-ali-a22230409/)

---

## **Disclaimer**

This project was developed for educational and ethical cybersecurity purposes only.

The firewall rules used in this project are simulated/test data. The tool should only be used to audit systems, networks, firewalls, and ACLs that you own or have explicit authorization to assess.

The author is not responsible for unauthorized use or misuse of this project.

---

## **Acknowledgements**

This project was developed as part of my cybersecurity learning journey to strengthen practical skills in:

* Network Security
* Firewall Auditing
* Security Automation
* Compliance Assessment
* Risk Analysis
* Security Reporting
* GRC-oriented Security Analysis

The project was designed to demonstrate how security automation can support both technical security assessment and basic GRC workflows.
