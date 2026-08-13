import ipaddress
from pathlib import Path

from parser import parse_firewall_rules
from report_generator import save_json_report


# ============================================================
# BASIC SECURITY CHECKS
# ============================================================

def check_broad_source(rule):
    """Detect rules that allow traffic from any IPv4 source."""

    findings = []

    if (
        str(rule["source"]).strip() == "0.0.0.0/0"
        and rule["action"].lower() == "allow"
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
    """Detect rules allowing any protocol and any port."""

    findings = []

    if rule["action"].lower() != "allow":
        return findings

    if (
        str(rule["protocol"]).lower() == "any"
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


# ============================================================
# INSECURE SERVICES
# ============================================================

INSECURE_SERVICES = {
    21: "FTP",
    23: "Telnet",
}


def check_insecure_service(rule):
    """Detect insecure services such as FTP and Telnet."""

    findings = []

    if (
        rule["action"].lower() == "allow"
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


# ============================================================
# DUPLICATE RULE DETECTION
# ============================================================

def check_duplicate_rules(rules):
    """Detect duplicate firewall rules."""

    findings = []
    seen_rules = {}

    for rule in rules:
        rule_key = (
            str(rule["source"]).strip().lower(),
            str(rule["destination"]).strip().lower(),
            str(rule["protocol"]).strip().lower(),
            str(rule["port"]).strip().lower(),
            str(rule["action"]).strip().lower(),
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


# ============================================================
# CONFLICTING RULE DETECTION
# ============================================================

def check_conflicting_rules(rules):
    """Detect rules with identical traffic criteria but different actions."""

    findings = []
    seen_rules = {}

    for rule in rules:
        rule_key = (
            str(rule["source"]).strip().lower(),
            str(rule["destination"]).strip().lower(),
            str(rule["protocol"]).strip().lower(),
            str(rule["port"]).strip().lower(),
        )

        if rule_key in seen_rules:
            previous_rule = seen_rules[rule_key]

            if (
                previous_rule["action"].lower()
                != rule["action"].lower()
            ):
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


# ============================================================
# CIDR HELPER FUNCTIONS
# ============================================================

def parse_network(value):
    """
    Convert an IPv4/IPv6 CIDR value into an ipaddress network.

    Returns None for values such as 'any' or invalid networks.
    """

    if value is None:
        return None

    value = str(value).strip()

    if value.lower() in ("any", "all", "*"):
        return None

    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def networks_overlap(network_a_value, network_b_value):
    """Check whether two CIDR networks overlap."""

    network_a = parse_network(network_a_value)
    network_b = parse_network(network_b_value)

    if network_a is None or network_b is None:
        return False

    if network_a.version != network_b.version:
        return False

    return network_a.overlaps(network_b)


def network_contains(parent_value, child_value):
    """Check whether one CIDR network completely contains another."""

    parent_network = parse_network(parent_value)
    child_network = parse_network(child_value)

    if parent_network is None or child_network is None:
        return False

    if parent_network.version != child_network.version:
        return False

    return child_network.subnet_of(parent_network)


def network_criteria_overlap(value_a, value_b):
    """
    Determine whether two network criteria overlap.

    'any', 'all' and '*' are treated as unrestricted network criteria.
    """

    value_a = str(value_a).strip().lower()
    value_b = str(value_b).strip().lower()

    if value_a in ("any", "all", "*"):
        return True

    if value_b in ("any", "all", "*"):
        return True

    return networks_overlap(value_a, value_b)


def network_criteria_covers(parent_value, child_value):
    """
    Determine whether parent network criteria completely cover
    child network criteria.
    """

    parent = str(parent_value).strip().lower()
    child = str(child_value).strip().lower()

    if parent in ("any", "all", "*"):
        return True

    if child in ("any", "all", "*"):
        return parent == child

    if parent == child:
        return True

    return network_contains(parent, child)


# ============================================================
# PROTOCOL / PORT HELPERS
# ============================================================

def protocol_criteria_overlap(protocol_a, protocol_b):
    """Check whether two protocol criteria can match the same traffic."""

    protocol_a = str(protocol_a).strip().lower()
    protocol_b = str(protocol_b).strip().lower()

    if protocol_a in ("any", "all", "*"):
        return True

    if protocol_b in ("any", "all", "*"):
        return True

    return protocol_a == protocol_b


def protocol_covers(earlier_protocol, later_protocol):
    """
    Determine whether an earlier protocol criterion covers
    a later protocol criterion.
    """

    earlier = str(earlier_protocol).strip().lower()
    later = str(later_protocol).strip().lower()

    if earlier in ("any", "all", "*"):
        return True

    return earlier == later


def normalize_port(port):
    """Normalize a port value for comparison."""

    return str(port).strip().lower()


def port_criteria_overlap(port_a, port_b):
    """
    Check whether two port criteria overlap.

    Current dataset supports exact ports and 'any'.
    """

    port_a = normalize_port(port_a)
    port_b = normalize_port(port_b)

    if port_a in ("any", "all", "*"):
        return True

    if port_b in ("any", "all", "*"):
        return True

    return port_a == port_b


def port_covers(earlier_port, later_port):
    """
    Determine whether an earlier port criterion covers
    a later port criterion.
    """

    earlier = normalize_port(earlier_port)
    later = normalize_port(later_port)

    if earlier in ("any", "all", "*"):
        return True

    return earlier == later


# ============================================================
# CIDR OVERLAP DETECTION
# ============================================================

def check_cidr_overlap(rules):
    """
    Detect meaningful overlapping firewall traffic scopes.

    A CIDR overlap finding is generated only when:

    1. Source networks overlap
    2. Destination networks overlap
    3. Protocol criteria overlap
    4. Port criteria overlap

    This prevents unrelated rules from producing false-positive
    CIDR overlap findings.
    """

    findings = []
    reported_pairs = set()

    for i, rule_a in enumerate(rules):
        for rule_b in rules[i + 1:]:

            rule_a_id = rule_a["rule_id"]
            rule_b_id = rule_b["rule_id"]

            pair_key = tuple(
                sorted(
                    (str(rule_a_id), str(rule_b_id))
                )
            )

            if pair_key in reported_pairs:
                continue

            # ------------------------------------------------
            # SOURCE MUST OVERLAP
            # ------------------------------------------------

            source_overlap = network_criteria_overlap(
                rule_a["source"],
                rule_b["source"]
            )

            if not source_overlap:
                continue

            # ------------------------------------------------
            # DESTINATION MUST ALSO OVERLAP
            # ------------------------------------------------

            destination_overlap = network_criteria_overlap(
                rule_a["destination"],
                rule_b["destination"]
            )

            if not destination_overlap:
                continue

            # ------------------------------------------------
            # PROTOCOL MUST OVERLAP
            # ------------------------------------------------

            protocol_overlap = protocol_criteria_overlap(
                rule_a["protocol"],
                rule_b["protocol"]
            )

            if not protocol_overlap:
                continue

            # ------------------------------------------------
            # PORT MUST OVERLAP
            # ------------------------------------------------

            port_overlap = port_criteria_overlap(
                rule_a["port"],
                rule_b["port"]
            )

            if not port_overlap:
                continue

            # ------------------------------------------------
            # EXACT SAME TRAFFIC DEFINITION
            # ------------------------------------------------

            same_traffic = (
                str(rule_a["source"]).strip().lower()
                == str(rule_b["source"]).strip().lower()
                and
                str(rule_a["destination"]).strip().lower()
                == str(rule_b["destination"]).strip().lower()
                and
                str(rule_a["protocol"]).strip().lower()
                == str(rule_b["protocol"]).strip().lower()
                and
                normalize_port(rule_a["port"])
                == normalize_port(rule_b["port"])
            )

            if same_traffic:
                continue

            # ------------------------------------------------
            # RECORD UNIQUE PAIR
            # ------------------------------------------------

            reported_pairs.add(pair_key)

            findings.append({
                "rule_id": rule_b_id,
                "finding": "CIDR Network Overlap",
                "severity": "MEDIUM",
                "reason": (
                    f"Rule {rule_a_id} and Rule {rule_b_id} "
                    "match overlapping source and destination "
                    "network scopes with overlapping protocol "
                    "and port criteria."
                ),
                "recommendation": (
                    "Review the overlapping network scopes and "
                    "restrict access to the minimum required range."
                ),
                "related_rule": rule_a_id,
            })

    return findings


# ============================================================
# SHADOW RULE DETECTION
# ============================================================

def rule_covers(earlier_rule, later_rule):
    """
    Determine whether an earlier rule completely covers
    the traffic matched by a later rule.
    """

    source_covers = network_criteria_covers(
        earlier_rule["source"],
        later_rule["source"]
    )

    destination_covers = network_criteria_covers(
        earlier_rule["destination"],
        later_rule["destination"]
    )

    protocol_covers_rule = protocol_covers(
        earlier_rule["protocol"],
        later_rule["protocol"]
    )

    port_covers_rule = port_covers(
        earlier_rule["port"],
        later_rule["port"]
    )

    return (
        source_covers
        and destination_covers
        and protocol_covers_rule
        and port_covers_rule
    )


def check_shadow_rules(rules):
    """
    Detect later rules that are completely covered by
    an earlier rule with the same action.

    Example:

        Rule 1:
        10.0.0.0/8 -> ALLOW

        Rule 2:
        10.10.0.0/16 -> ALLOW

    Rule 2 is potentially shadowed because Rule 1
    already covers its traffic scope.
    """

    findings = []

    for later_index, later_rule in enumerate(rules):

        for earlier_rule in rules[:later_index]:

            if (
                earlier_rule["action"].lower()
                != later_rule["action"].lower()
            ):
                continue

            if (
                earlier_rule["rule_id"]
                == later_rule["rule_id"]
            ):
                continue

            if rule_covers(
                earlier_rule,
                later_rule
            ):

                findings.append({
                    "rule_id": later_rule["rule_id"],
                    "finding": "Shadowed Firewall Rule",
                    "severity": "MEDIUM",
                    "reason": (
                        f"Rule {later_rule['rule_id']} is covered "
                        f"by earlier Rule {earlier_rule['rule_id']} "
                        "with the same action. The later rule may "
                        "never be reached."
                    ),
                    "recommendation": (
                        "Review the rule order and remove or "
                        "consolidate unnecessary shadowed rules."
                    ),
                    "related_rule": earlier_rule["rule_id"],
                })

                # Only one shadow finding per later rule.
                break

    return findings


# ============================================================
# COMPLIANCE MAPPING
# ============================================================

def map_compliance(finding):
    """
    Map findings to internal security controls,
    NIST SP 800-53 and CIS Controls.
    """

    compliance_map = {

        "Broad Source Access": {
            "control": "Network Access Control",
            "requirement": (
                "Network access must be restricted to approved sources."
            ),
            "nist": "NIST SP 800-53 Rev. 5 AC-4",
            "nist_title": "Information Flow Enforcement",
            "cis": "CIS Control 12",
            "cis_title": "Network Infrastructure Management",
        },

        "Unrestricted Protocol and Port Access": {
            "control": "Least Privilege Network Access",
            "requirement": (
                "Only required protocols and ports should be allowed."
            ),
            "nist": "NIST SP 800-53 Rev. 5 AC-6",
            "nist_title": "Least Privilege",
            "cis": "CIS Control 4",
            "cis_title": (
                "Secure Configuration of Enterprise Assets "
                "and Software"
            ),
        },

        "Insecure Service": {
            "control": "Secure Services",
            "requirement": (
                "Insecure network services should be disabled "
                "or replaced."
            ),
            "nist": "NIST SP 800-53 Rev. 5 CM-7",
            "nist_title": "Least Functionality",
            "cis": "CIS Control 4",
            "cis_title": (
                "Secure Configuration of Enterprise Assets "
                "and Software"
            ),
        },

        "Duplicate Firewall Rule": {
            "control": "Firewall Rule Management",
            "requirement": (
                "Firewall rules should be unique and properly managed."
            ),
            "nist": "NIST SP 800-53 Rev. 5 CM-3",
            "nist_title": "Configuration Change Control",
            "cis": "CIS Control 4",
            "cis_title": (
                "Secure Configuration of Enterprise Assets "
                "and Software"
            ),
        },

        "Conflicting Firewall Rule": {
            "control": "Firewall Rule Management",
            "requirement": (
                "Firewall rules should not contain conflicting actions."
            ),
            "nist": "NIST SP 800-53 Rev. 5 CM-3",
            "nist_title": "Configuration Change Control",
            "cis": "CIS Control 12",
            "cis_title": "Network Infrastructure Management",
        },

        "CIDR Network Overlap": {
            "control": "Network Segmentation and Access Control",
            "requirement": (
                "Network ranges should be clearly defined and "
                "overlapping access scopes should be reviewed."
            ),
            "nist": "NIST SP 800-53 Rev. 5 AC-4",
            "nist_title": "Information Flow Enforcement",
            "cis": "CIS Control 12",
            "cis_title": "Network Infrastructure Management",
        },

        "Shadowed Firewall Rule": {
            "control": "Firewall Rule Management",
            "requirement": (
                "Firewall rules should be ordered and maintained "
                "so that required rules remain effective."
            ),
            "nist": "NIST SP 800-53 Rev. 5 CM-3",
            "nist_title": "Configuration Change Control",
            "cis": "CIS Control 4",
            "cis_title": (
                "Secure Configuration of Enterprise Assets "
                "and Software"
            ),
        },
    }

    finding_name = finding["finding"]

    if finding_name in compliance_map:

        control = compliance_map[finding_name]

        finding["control"] = control["control"]
        finding["requirement"] = control["requirement"]

        finding["nist_control"] = control["nist"]
        finding["nist_control_title"] = control["nist_title"]

        finding["cis_control"] = control["cis"]
        finding["cis_control_title"] = control["cis_title"]

        finding["compliance"] = "NON-COMPLIANT"

    return finding


# ============================================================
# REMEDIATION
# ============================================================

def get_remediation(finding):
    """Provide remediation guidance for each security finding."""

    remediation_map = {

        "Broad Source Access": (
            "Replace 0.0.0.0/0 with an approved internal "
            "or administrative IP range."
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

        "CIDR Network Overlap": (
            "Review overlapping source or destination CIDR "
            "ranges and reduce them to the minimum required "
            "network scope."
        ),

        "Shadowed Firewall Rule": (
            "Review the earlier covering rule and remove or "
            "consolidate the later rule if it is unnecessary."
        ),
    }

    finding_name = finding["finding"]

    finding["remediation"] = remediation_map.get(
        finding_name,
        "Review the security finding and apply an appropriate fix."
    )

    return finding


# ============================================================
# COMPLETE RULE ANALYSIS
# ============================================================

def analyze_rules(rules):
    """Run all security checks against parsed firewall rules."""

    findings = []

    # --------------------------------------------------------
    # Rule-level checks
    # --------------------------------------------------------

    for rule in rules:
        findings.extend(
            check_broad_source(rule)
        )

        findings.extend(
            check_any_access(rule)
        )

        findings.extend(
            check_insecure_service(rule)
        )

    # --------------------------------------------------------
    # Rule relationship checks
    # --------------------------------------------------------

    findings.extend(
        check_duplicate_rules(rules)
    )

    findings.extend(
        check_conflicting_rules(rules)
    )

    # --------------------------------------------------------
    # Advanced checks
    # --------------------------------------------------------

    findings.extend(
        check_cidr_overlap(rules)
    )

    findings.extend(
        check_shadow_rules(rules)
    )

    # --------------------------------------------------------
    # Compliance + remediation
    # --------------------------------------------------------

    for finding in findings:
        map_compliance(finding)
        get_remediation(finding)

    return findings


# ============================================================
# RISK SUMMARY
# ============================================================

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

        severity = str(
            finding["severity"]
        ).upper()

        if severity == "HIGH":
            summary["high"] += 1

        elif severity == "MEDIUM":
            summary["medium"] += 1

        elif severity == "LOW":
            summary["low"] += 1

        summary["risk_score"] += risk_points.get(
            severity,
            0
        )

        if finding.get("compliance") == "COMPLIANT":
            summary["compliant"] += 1

        elif finding.get("compliance") == "NON-COMPLIANT":
            summary["non_compliant"] += 1

    # --------------------------------------------------------
    # Overall Risk Classification
    # --------------------------------------------------------

    if summary["risk_score"] >= 50:
        summary["overall_risk"] = "CRITICAL"

    elif summary["risk_score"] >= 30:
        summary["overall_risk"] = "HIGH"

    elif summary["risk_score"] >= 15:
        summary["overall_risk"] = "MEDIUM"

    else:
        summary["overall_risk"] = "LOW"

    return summary


# ============================================================
# FIREWALL RULE STATISTICS
# ============================================================

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

        action = str(
            rule["action"]
        ).lower()

        protocol = str(
            rule["protocol"]
        ).lower()

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


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    project_root = Path(__file__).resolve().parent.parent

    csv_file = (
        project_root
        / "data"
        / "firewall_rules.csv"
    )

    try:

        # ----------------------------------------------------
        # Load firewall rules
        # ----------------------------------------------------

        rules = parse_firewall_rules(csv_file)

        # ----------------------------------------------------
        # Run complete security analysis
        # ----------------------------------------------------

        findings = analyze_rules(rules)

        # ----------------------------------------------------
        # Generate summary and statistics
        # ----------------------------------------------------

        summary = generate_risk_summary(
            findings
        )

        statistics = generate_rule_statistics(
            rules
        )

        # ----------------------------------------------------
        # Build final report
        # ----------------------------------------------------

        report = {
            "summary": summary,
            "statistics": statistics,
            "findings": findings,
        }

        # ----------------------------------------------------
        # Save JSON report
        # ----------------------------------------------------

        report_file = (
            project_root
            / "reports"
            / "firewall_audit_report.json"
        )

        save_json_report(
            report,
            report_file
        )

        # ----------------------------------------------------
        # Display audit summary
        # ----------------------------------------------------

        print(
            f"Security findings: {len(findings)}"
        )

        print(
            "\n===== SECURITY AUDIT SUMMARY ====="
        )

        print(
            f"Total Rules Audited: {len(rules)}"
        )

        print(
            f"Total Findings: {summary['total_findings']}"
        )

        print(
            f"HIGH: {summary['high']}"
        )

        print(
            f"MEDIUM: {summary['medium']}"
        )

        print(
            f"LOW: {summary['low']}"
        )

        print(
            f"Compliant: {summary['compliant']}"
        )

        print(
            f"Non-Compliant: {summary['non_compliant']}"
        )

        print(
            f"Risk Score: {summary['risk_score']}"
        )

        print(
            f"Overall Risk: {summary['overall_risk']}"
        )

        print(
            "==================================\n"
        )

        # ----------------------------------------------------
        # Display rule statistics
        # ----------------------------------------------------

        print(
            "===== RULE STATISTICS ====="
        )

        print(
            f"Total Rules: {statistics['total_rules']}"
        )

        print(
            f"ALLOW Rules: {statistics['allow_rules']}"
        )

        print(
            f"DENY Rules: {statistics['deny_rules']}"
        )

        print(
            f"TCP Rules: {statistics['tcp_rules']}"
        )

        print(
            f"UDP Rules: {statistics['udp_rules']}"
        )

        print(
            f"ICMP Rules: {statistics['icmp_rules']}"
        )

        print(
            f"ANY Protocol Rules: "
            f"{statistics['any_protocol_rules']}"
        )

        print(
            "============================\n"
        )

        # ----------------------------------------------------
        # Display findings
        # ----------------------------------------------------

        for finding in findings:

            print(
                f"\nRule {finding['rule_id']}: "
                f"{finding['finding']}"
            )

            print(
                f"Severity: {finding['severity']}"
            )

            print(
                f"Reason: {finding['reason']}"
            )

            print(
                f"Control: {finding['control']}"
            )

            print(
                f"Requirement: "
                f"{finding['requirement']}"
            )

            print(
                f"NIST Control: "
                f"{finding['nist_control']}"
            )

            print(
                f"NIST Title: "
                f"{finding['nist_control_title']}"
            )

            print(
                f"CIS Control: "
                f"{finding['cis_control']}"
            )

            print(
                f"CIS Title: "
                f"{finding['cis_control_title']}"
            )

            print(
                f"Compliance: "
                f"{finding['compliance']}"
            )

            print(
                f"Recommendation: "
                f"{finding['recommendation']}"
            )

            print(
                f"Remediation: "
                f"{finding['remediation']}"
            )

            if "related_rule" in finding:
                print(
                    f"Related Rule: "
                    f"{finding['related_rule']}"
                )

    except (FileNotFoundError, ValueError) as error:

        print(
            f"Analyzer error: {error}"
        )