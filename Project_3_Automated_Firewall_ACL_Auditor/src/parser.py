import csv
import ipaddress
from pathlib import Path


REQUIRED_COLUMNS = {
    "rule_id",
    "source",
    "destination",
    "protocol",
    "port",
    "action",
    "description",
}


VALID_PROTOCOLS = {"tcp", "udp", "icmp", "any"}
VALID_ACTIONS = {"allow", "deny"}


def validate_rule(rule, row_number):
    """Validate and normalize a single firewall rule."""

    # Check required fields
    for column in REQUIRED_COLUMNS:
        if not rule.get(column, "").strip():
            raise ValueError(
                f"Row {row_number}: Missing value in '{column}'"
            )

    # Normalize text fields
    rule["protocol"] = rule["protocol"].strip().lower()
    rule["action"] = rule["action"].strip().lower()
    rule["source"] = rule["source"].strip()
    rule["destination"] = rule["destination"].strip()
    rule["port"] = rule["port"].strip()

    # Validate protocol
    if rule["protocol"] not in VALID_PROTOCOLS:
        raise ValueError(
            f"Row {row_number}: Invalid protocol '{rule['protocol']}'"
        )

    # Validate action
    if rule["action"] not in VALID_ACTIONS:
        raise ValueError(
            f"Row {row_number}: Invalid action '{rule['action']}'"
        )

    # Validate source network/IP
    try:
        rule["source_network"] = ipaddress.ip_network(
            rule["source"], strict=False
        )
    except ValueError:
        raise ValueError(
            f"Row {row_number}: Invalid source IP/network "
            f"'{rule['source']}'"
        )

    # Validate destination IP/network
    try:
        rule["destination_network"] = ipaddress.ip_network(
            rule["destination"], strict=False
        )
    except ValueError:
        raise ValueError(
            f"Row {row_number}: Invalid destination IP/network "
            f"'{rule['destination']}'"
        )

    # Validate port
    if rule["port"].lower() != "any":
        try:
            port = int(rule["port"])

            if not 1 <= port <= 65535:
                raise ValueError

            rule["port"] = port

        except ValueError:
            raise ValueError(
                f"Row {row_number}: Invalid port '{rule['port']}'"
            )

    return rule


def parse_firewall_rules(file_path):
    """Read, validate, and return firewall rules from CSV."""

    rules = []

    with open(file_path, "r", newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)

        # Validate CSV columns
        if reader.fieldnames is None:
            raise ValueError("CSV file has no header.")

        missing_columns = REQUIRED_COLUMNS - set(reader.fieldnames)

        if missing_columns:
            raise ValueError(
                f"Missing required columns: {sorted(missing_columns)}"
            )

        # Process every rule
        for row_number, rule in enumerate(reader, start=2):

            # Ignore completely empty rows
            if not any(value.strip() for value in rule.values() if value):
                continue

            validated_rule = validate_rule(rule, row_number)
            rules.append(validated_rule)

    return rules


if __name__ == "__main__":

    project_root = Path(__file__).resolve().parent.parent
    csv_file = project_root / "data" / "firewall_rules.csv"

    try:
        firewall_rules = parse_firewall_rules(csv_file)

        print(f"Successfully parsed {len(firewall_rules)} firewall rules.")

        for rule in firewall_rules:
            print(
                f"Rule {rule['rule_id']}: "
                f"{rule['action'].upper()} "
                f"{rule['protocol'].upper()} "
                f"{rule['source']} -> "
                f"{rule['destination']}:{rule['port']}"
            )

    except (FileNotFoundError, ValueError) as error:
        print(f"Parser error: {error}")