import json
from pathlib import Path


def save_json_report(report, output_file):
    """Save the security audit report as a JSON file."""

    output_file = Path(output_file)

    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print(f"JSON report saved to: {output_file}")