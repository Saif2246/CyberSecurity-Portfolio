from parser import parse_firewall_rules
from pathlib import Path
from report_generator import save_json_report

def check_broad_source(rule):
    """Detect rules that allow traffic from any IPv4 source."""

    findings = []

    if (
        rule["source"] == "0.0.0.0/0"
        and rule["action"] == "allow"
    ):
        findings.append({
            "rule_id": rule["rule_id"],
            "finding": "Broad Source Access",
            "severity": "HIGH",
            "reason": (
                "The rule allows traffic from any IPv4 source."
            ),
            "recommendation": (
                "Restrict the source to approved networks or IP ranges."
            ),
        })

    return findings


def check_any_access(rule):
    """Detect rules allowing any protocol or any port."""

    findings = []

    if rule["action"] != "allow":
        return findings

    if (
        rule["protocol"] == "any"
        and str(rule["port"]).lower() == "any"
    ):
        findings.append({
            "rule_id": rule["rule_id"],
            "finding": "Unrestricted Protocol and Port Access",
            "severity": "HIGH",
            "reason": (
                "The rule allows any protocol and any destination port."
            ),
            "recommendation": (
                "Restrict access to only the protocols and ports "
                "required by the application."
            ),
        })

    return findings


INSECURE_SERVICES = {
    21: "FTP",
    23: "Telnet",
}


def check_insecure_service(rule):
    """Detect insecure services such as FTP and Telnet."""

    findings = []

    if (
        rule["action"] == "allow"
        and isinstance(rule["port"], int)
        and rule["port"] in INSECURE_SERVICES
    ):
        service = INSECURE_SERVICES[rule["port"]]

        findings.append({
            "rule_id": rule["rule_id"],
            "finding": "Insecure Service",
            "severity": "HIGH",
            "reason": (
                f"{service} is an insecure service that "
                "should not normally be exposed."
            ),
            "recommendation": (
                f"Disable {service} or replace it with a "
                "secure alternative."
            ),
        })

    return findings


def check_duplicate_rules(rules):
    """Detect duplicate firewall rules."""

    findings = []
    seen_rules = {}

    for rule in rules:
        rule_key = (
            rule["source"],
            rule["destination"],
            rule["protocol"],
            str(rule["port"]).lower(),
            rule["action"],
        )

        if rule_key in seen_rules:
            findings.append({
                "rule_id": rule["rule_id"],
                "finding": "Duplicate Firewall Rule",
                "severity": "MEDIUM",
                "reason": (
                    f"This rule duplicates Rule "
                    f"{seen_rules[rule_key]}."
                ),
                "recommendation": (
                    "Remove the duplicate rule after verification."
                ),
            })
        else:
            seen_rules[rule_key] = rule["rule_id"]

    return findings


def check_conflicting_rules(rules):
    """Detect rules with the same traffic criteria but different actions."""

    findings = []
    seen_rules = {}

    for rule in rules:
        rule_key = (
            rule["source"],
            rule["destination"],
            rule["protocol"],
            str(rule["port"]).lower(),
        )

        if rule_key in seen_rules:
            previous_rule = seen_rules[rule_key]

            if previous_rule["action"] != rule["action"]:
                findings.append({
                    "rule_id": rule["rule_id"],
                    "finding": "Conflicting Firewall Rule",
                    "severity": "HIGH",
                    "reason": (
                        f"This rule conflicts with Rule "
                        f"{previous_rule['rule_id']} because both "
                        "rules match the same traffic but use "
                        "different actions."
                    ),
                    "recommendation": (
                        "Review rule order and remove or correct "
                        "the conflicting rule."
                    ),
                })
        else:
            seen_rules[rule_key] = rule

    return findings


def map_compliance(finding):
    """Map security findings to compliance controls."""

    compliance_map = {
        "Broad Source Access": {
            "control": "Network Access Control",
            "requirement": (
                "Network access must be restricted to approved sources."
            ),
        },
        "Unrestricted Protocol and Port Access": {
            "control": "Least Privilege Network Access",
            "requirement": (
                "Only required protocols and ports should be allowed."
            ),
        },
        "Insecure Service": {
            "control": "Secure Services",
            "requirement": (
                "Insecure network services should be disabled or replaced."
            ),
        },
        "Duplicate Firewall Rule": {
            "control": "Firewall Rule Management",
            "requirement": (
                "Firewall rules should be unique and properly managed."
            ),
        },
        "Conflicting Firewall Rule": {
            "control": "Firewall Rule Management",
            "requirement": (
                "Firewall rules should not contain conflicting actions."
            ),
        },
    }

    finding_name = finding["finding"]

    if finding_name in compliance_map:
        control = compliance_map[finding_name]

        finding["control"] = control["control"]
        finding["requirement"] = control["requirement"]
        finding["compliance"] = "NON-COMPLIANT"

    return finding


def get_remediation(finding):
    """Provide remediation guidance for each security finding."""

    remediation_map = {
        "Broad Source Access": (
            "Replace 0.0.0.0/0 with an approved "
            "internal or administrative IP range."
        ),
        "Unrestricted Protocol and Port Access": (
            "Replace 'any' protocol and port with only "
            "the protocols and ports required by the application."
        ),
        "Insecure Service": (
            "Disable the insecure service or replace it "
            "with a secure alternative such as SSH."
        ),
        "Duplicate Firewall Rule": (
            "Remove the duplicate rule after verifying "
            "that the original rule is still required."
        ),
        "Conflicting Firewall Rule": (
            "Review the conflicting rules and correct the "
            "rule order or remove the unnecessary rule."
        ),
    }

    finding_name = finding["finding"]

    finding["remediation"] = remediation_map.get(
        finding_name,
        "Review the security finding and apply an appropriate fix."
    )

    return finding


def analyze_rules(rules):
    """Run security checks against parsed firewall rules."""

    findings = []

    for rule in rules:
        findings.extend(check_broad_source(rule))
        findings.extend(check_any_access(rule))
        findings.extend(check_insecure_service(rule))

    findings.extend(check_duplicate_rules(rules))
    findings.extend(check_conflicting_rules(rules))

    for finding in findings:
        map_compliance(finding)
        get_remediation(finding)

    return findings
def generate_risk_summary(findings):
    """Generate an overall security risk summary."""

    summary = {
        "total_findings": len(findings),
        "high": 0,
        "medium": 0,
        "low": 0,
        "compliant": 0,
        "non_compliant": 0,
        "risk_score": 0,
    }

    risk_points = {
        "HIGH": 10,
        "MEDIUM": 5,
        "LOW": 2,
    }

    for finding in findings:
        severity = finding["severity"].upper()

        if severity == "HIGH":
            summary["high"] += 1
        elif severity == "MEDIUM":
            summary["medium"] += 1
        elif severity == "LOW":
            summary["low"] += 1

        summary["risk_score"] += risk_points.get(severity, 0)

        if finding.get("compliance") == "COMPLIANT":
            summary["compliant"] += 1
        elif finding.get("compliance") == "NON-COMPLIANT":
            summary["non_compliant"] += 1

    if summary["risk_score"] >= 50:
        summary["overall_risk"] = "CRITICAL"
    elif summary["risk_score"] >= 30:
        summary["overall_risk"] = "HIGH"
    elif summary["risk_score"] >= 15:
        summary["overall_risk"] = "MEDIUM"
    else:
        summary["overall_risk"] = "LOW"

    return summary
def generate_rule_statistics(rules):
    """Generate firewall rule statistics."""

    statistics = {
        "total_rules": len(rules),
        "allow_rules": 0,
        "deny_rules": 0,
        "tcp_rules": 0,
        "udp_rules": 0,
        "icmp_rules": 0,
        "any_protocol_rules": 0,
    }

    for rule in rules:
        action = rule["action"].lower()
        protocol = rule["protocol"].lower()

        if action == "allow":
            statistics["allow_rules"] += 1
        elif action == "deny":
            statistics["deny_rules"] += 1

        if protocol == "tcp":
            statistics["tcp_rules"] += 1
        elif protocol == "udp":
            statistics["udp_rules"] += 1
        elif protocol == "icmp":
            statistics["icmp_rules"] += 1
        elif protocol == "any":
            statistics["any_protocol_rules"] += 1

    return statistics

if __name__ == "__main__":
    project_root = Path(__file__).resolve().parent.parent
    csv_file = project_root / "data" / "firewall_rules.csv"

    try:
        rules = parse_firewall_rules(csv_file)
        findings = analyze_rules(rules)
        summary = generate_risk_summary(findings)
        statistics = generate_rule_statistics(rules)
        report = {
            "summary": summary,
            "statistics": statistics,
            "findings": findings
        }

        report_file = project_root / "reports" / "firewall_audit_report.json"
        save_json_report(report, report_file)

        print(f"Security findings: {len(findings)}")
        print("\n===== SECURITY AUDIT SUMMARY =====")
        print(f"Total Rules Audited: {len(rules)}")
        print(f"Total Findings: {summary['total_findings']}")
        print(f"HIGH: {summary['high']}")
        print(f"MEDIUM: {summary['medium']}")
        print(f"LOW: {summary['low']}")
        print(f"Compliant: {summary['compliant']}")
        print(f"Non-Compliant: {summary['non_compliant']}")
        print(f"Risk Score: {summary['risk_score']}")
        print(f"Overall Risk: {summary['overall_risk']}")
        print("==================================\n")
        print("\n===== RULE STATISTICS =====")
        print(f"Total Rules: {statistics['total_rules']}")
        print(f"ALLOW Rules: {statistics['allow_rules']}")
        print(f"DENY Rules: {statistics['deny_rules']}")
        print(f"TCP Rules: {statistics['tcp_rules']}")
        print(f"UDP Rules: {statistics['udp_rules']}")
        print(f"ICMP Rules: {statistics['icmp_rules']}")
        print(f"ANY Protocol Rules: {statistics['any_protocol_rules']}")
        print("============================\n")
        for finding in findings:
            print(
                f"\nRule {finding['rule_id']}: "
                f"{finding['finding']}"
            )
            print(f"Severity: {finding['severity']}")
            print(f"Reason: {finding['reason']}")
            print(f"Control: {finding['control']}")
            print(f"Requirement: {finding['requirement']}")
            print(f"Compliance: {finding['compliance']}")
            print(f"Recommendation: {finding['recommendation']}")
            print(f"Remediation: {finding['remediation']}")

    except (FileNotFoundError, ValueError) as error:
        print(f"Analyzer error: {error}")

