import json
from pathlib import Path


def generate_html_report(json_file, html_file):
    """Generate a professional HTML security audit report."""

    with open(json_file, "r", encoding="utf-8") as file:
        report = json.load(file)

    summary = report["summary"]
    statistics = report["statistics"]
    findings = report["findings"]

    rows = ""

    for finding in findings:
        rows += f"""
        <tr>
            <td>{finding["rule_id"]}</td>
            <td>{finding["finding"]}</td>
            <td>{finding["severity"]}</td>
            <td>{finding["compliance"]}</td>
            <td>{finding["control"]}</td>
            <td>{finding["remediation"]}</td>
        </tr>
        """

    html = f"""
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Firewall Security Audit Report</title>

    <style>

        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background-color: #f4f6f8;
            color: #222;
        }}

        h1 {{
            color: #1f2937;
        }}

        h2 {{
            margin-top: 35px;
            color: #374151;
        }}

        .summary {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin: 25px 0;
        }}

        .card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.1);
        }}

        .card h3 {{
            margin: 0 0 10px;
            color: #374151;
        }}

        .card p {{
            font-size: 24px;
            font-weight: bold;
            margin: 0;
        }}

        .statistics {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin: 25px 0;
        }}

        .stat {{
            background: white;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.08);
        }}

        .stat strong {{
            display: block;
            font-size: 20px;
            margin-top: 5px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
        }}

        th, td {{
            padding: 12px;
            border: 1px solid #ddd;
            text-align: left;
        }}

        th {{
            background-color: #1f2937;
            color: white;
        }}

        tr:nth-child(even) {{
            background-color: #f9fafb;
        }}

        .critical {{
            color: #b91c1c;
        }}

        .high {{
            color: #dc2626;
        }}

        .medium {{
            color: #d97706;
        }}

    </style>

</head>

<body>

    <h1>Firewall Security Audit Report</h1>

    <p>
        Automated security assessment of firewall and ACL rules.
    </p>


    <h2>Security Risk Summary</h2>

    <div class="summary">

        <div class="card">
            <h3>Total Rules</h3>
            <p>{statistics["total_rules"]}</p>
        </div>

        <div class="card">
            <h3>Total Findings</h3>
            <p>{summary["total_findings"]}</p>
        </div>

        <div class="card">
            <h3>Risk Score</h3>
            <p>{summary["risk_score"]}</p>
        </div>

        <div class="card">
            <h3>Overall Risk</h3>
            <p class="critical">{summary["overall_risk"]}</p>
        </div>

    </div>


    <h2>Rule Statistics</h2>

    <div class="statistics">

        <div class="stat">
            ALLOW Rules
            <strong>{statistics["allow_rules"]}</strong>
        </div>

        <div class="stat">
            DENY Rules
            <strong>{statistics["deny_rules"]}</strong>
        </div>

        <div class="stat">
            TCP Rules
            <strong>{statistics["tcp_rules"]}</strong>
        </div>

        <div class="stat">
            UDP Rules
            <strong>{statistics["udp_rules"]}</strong>
        </div>

        <div class="stat">
            ICMP Rules
            <strong>{statistics["icmp_rules"]}</strong>
        </div>

        <div class="stat">
            ANY Protocol
            <strong>{statistics["any_protocol_rules"]}</strong>
        </div>

        <div class="stat">
            HIGH Findings
            <strong class="high">{summary["high"]}</strong>
        </div>

        <div class="stat">
            MEDIUM Findings
            <strong class="medium">{summary["medium"]}</strong>
        </div>

    </div>


    <h2>Security Findings</h2>

    <table>

        <thead>
            <tr>
                <th>Rule</th>
                <th>Finding</th>
                <th>Severity</th>
                <th>Compliance</th>
                <th>Control</th>
                <th>Remediation</th>
            </tr>
        </thead>

        <tbody>
            {rows}
        </tbody>

    </table>

</body>

</html>
"""

    html_file = Path(html_file)
    html_file.parent.mkdir(parents=True, exist_ok=True)

    with open(html_file, "w", encoding="utf-8") as file:
        file.write(html)

    print(f"HTML report saved to: {html_file}")


if __name__ == "__main__":

    project_root = Path(__file__).resolve().parent.parent

    json_file = (
        project_root
        / "reports"
        / "firewall_audit_report.json"
    )

    html_file = (
        project_root
        / "reports"
        / "firewall_audit_report.html"
    )

    generate_html_report(json_file, html_file)