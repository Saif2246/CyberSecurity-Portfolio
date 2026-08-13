import json
from pathlib import Path
from html import escape


def generate_html_report(json_file, html_file):
    """Generate a professional HTML security audit report."""

    with open(json_file, "r", encoding="utf-8") as file:
        report = json.load(file)

    summary = report["summary"]
    statistics = report["statistics"]
    findings = report["findings"]

    # ------------------------------------------------------------
    # Helper functions
    # ------------------------------------------------------------

    def safe(value):
        return escape(str(value))

    def severity_badge(severity):
        severity = str(severity).upper()

        return (
            f'<span class="badge severity-{severity.lower()}">'
            f'{safe(severity)}'
            f'</span>'
        )

    def compliance_badge(compliance):
        compliance = str(compliance).upper()

        css_class = (
            "compliant"
            if compliance == "COMPLIANT"
            else "non-compliant"
        )

        return (
            f'<span class="badge {css_class}">'
            f'{safe(compliance)}'
            f'</span>'
        )

    # ------------------------------------------------------------
    # Generate findings
    # ------------------------------------------------------------

    findings_html = ""

    for index, finding in enumerate(findings, start=1):

        related_rule = finding.get("related_rule", "N/A")

        findings_html += f"""
        <div class="finding-card">

            <div class="finding-header">

                <div>
                    <span class="finding-number">
                        Finding #{index}
                    </span>

                    <h3>
                        Rule {safe(finding["rule_id"])}:
                        {safe(finding["finding"])}
                    </h3>
                </div>

                <div>
                    {severity_badge(finding["severity"])}
                    {compliance_badge(finding["compliance"])}
                </div>

            </div>

            <div class="finding-grid">

                <div class="detail-box">
                    <h4>Reason</h4>
                    <p>{safe(finding["reason"])}</p>
                </div>

                <div class="detail-box">
                    <h4>Control</h4>
                    <p>{safe(finding["control"])}</p>
                </div>

                <div class="detail-box">
                    <h4>Requirement</h4>
                    <p>{safe(finding["requirement"])}</p>
                </div>

                <div class="detail-box">
                    <h4>Related Rule</h4>
                    <p>{safe(related_rule)}</p>
                </div>

            </div>

            <div class="compliance-section">

                <div>
                    <span class="label">NIST Control</span>
                    <strong>{safe(finding["nist_control"])}</strong>
                    <small>
                        {safe(finding["nist_control_title"])}
                    </small>
                </div>

                <div>
                    <span class="label">CIS Control</span>
                    <strong>{safe(finding["cis_control"])}</strong>
                    <small>
                        {safe(finding["cis_control_title"])}
                    </small>
                </div>

            </div>

            <div class="recommendation">
                <h4>Recommendation</h4>
                <p>{safe(finding["recommendation"])}</p>
            </div>

            <div class="remediation">
                <h4>Remediation</h4>
                <p>{safe(finding["remediation"])}</p>
            </div>

        </div>
        """

    # ------------------------------------------------------------
    # Overall risk class
    # ------------------------------------------------------------

    overall_risk = str(summary["overall_risk"]).upper()

    risk_class = overall_risk.lower()

    # ------------------------------------------------------------
    # HTML
    # ------------------------------------------------------------

    html = f"""
<!DOCTYPE html>

<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <title>Firewall & ACL Security Audit Report</title>

    <style>

        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            font-family:
                Inter,
                -apple-system,
                BlinkMacSystemFont,
                "Segoe UI",
                Arial,
                sans-serif;

            background: #f3f4f6;
            color: #111827;
        }}

        .container {{
            width: 92%;
            max-width: 1400px;
            margin: auto;
        }}

        /* ----------------------------------------------------
           Header
        ---------------------------------------------------- */

        .header {{
            background:
                linear-gradient(
                    135deg,
                    #111827,
                    #1f2937
                );

            color: white;
            padding: 42px 0;
            margin-bottom: 30px;
        }}

        .header-content {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 30px;
        }}

        .header h1 {{
            margin: 0;
            font-size: 34px;
        }}

        .header p {{
            margin: 10px 0 0;
            color: #d1d5db;
            font-size: 16px;
        }}

        .risk-banner {{
            padding: 18px 28px;
            border-radius: 12px;
            text-align: center;
            min-width: 180px;
            background: rgba(255,255,255,0.08);
            border: 1px solid rgba(255,255,255,0.15);
        }}

        .risk-banner span {{
            display: block;
            font-size: 13px;
            color: #d1d5db;
            margin-bottom: 6px;
        }}

        .risk-banner strong {{
            font-size: 25px;
        }}

        /* ----------------------------------------------------
           Section
        ---------------------------------------------------- */

        section {{
            margin-bottom: 35px;
        }}

        .section-title {{
            font-size: 23px;
            margin-bottom: 18px;
            color: #1f2937;
        }}

        /* ----------------------------------------------------
           Summary cards
        ---------------------------------------------------- */

        .summary-grid {{
            display: grid;
            grid-template-columns:
                repeat(auto-fit, minmax(190px, 1fr));

            gap: 18px;
        }}

        .summary-card {{
            background: white;
            padding: 24px;
            border-radius: 12px;

            border: 1px solid #e5e7eb;

            box-shadow:
                0 4px 12px rgba(0,0,0,0.05);
        }}

        .summary-card h3 {{
            margin: 0;
            font-size: 14px;
            color: #6b7280;
            font-weight: 600;
        }}

        .summary-card .value {{
            margin-top: 10px;
            font-size: 32px;
            font-weight: 700;
        }}

        .summary-card small {{
            display: block;
            margin-top: 6px;
            color: #9ca3af;
        }}

        .risk {{
            color: #b91c1c;
        }}

        .high-text {{
            color: #dc2626;
        }}

        .medium-text {{
            color: #d97706;
        }}

        .low-text {{
            color: #2563eb;
        }}

        /* ----------------------------------------------------
           Statistics
        ---------------------------------------------------- */

        .statistics-grid {{
            display: grid;
            grid-template-columns:
                repeat(auto-fit, minmax(160px, 1fr));

            gap: 15px;
        }}

        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;

            border: 1px solid #e5e7eb;
        }}

        .stat-card span {{
            color: #6b7280;
            font-size: 14px;
        }}

        .stat-card strong {{
            display: block;
            font-size: 25px;
            margin-top: 6px;
        }}

        /* ----------------------------------------------------
           Badges
        ---------------------------------------------------- */

        .badge {{
            display: inline-block;
            padding: 6px 11px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: 700;
            margin-left: 6px;
        }}

        .severity-high {{
            background: #fee2e2;
            color: #b91c1c;
        }}

        .severity-medium {{
            background: #fef3c7;
            color: #92400e;
        }}

        .severity-low {{
            background: #dbeafe;
            color: #1d4ed8;
        }}

        .compliant {{
            background: #dcfce7;
            color: #166534;
        }}

        .non-compliant {{
            background: #fee2e2;
            color: #991b1b;
        }}

        /* ----------------------------------------------------
           Findings
        ---------------------------------------------------- */

        .finding-card {{
            background: white;
            border: 1px solid #e5e7eb;
            border-radius: 14px;

            margin-bottom: 20px;
            padding: 25px;

            box-shadow:
                0 4px 12px rgba(0,0,0,0.04);
        }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 20px;

            padding-bottom: 18px;
            border-bottom: 1px solid #e5e7eb;
        }}

        .finding-number {{
            font-size: 12px;
            color: #6b7280;
            font-weight: 600;
        }}

        .finding-header h3 {{
            margin: 7px 0 0;
            font-size: 20px;
            color: #111827;
        }}

        .finding-grid {{
            display: grid;
            grid-template-columns:
                repeat(auto-fit, minmax(250px, 1fr));

            gap: 15px;
            margin-top: 20px;
        }}

        .detail-box {{
            background: #f9fafb;
            padding: 17px;
            border-radius: 9px;
            border: 1px solid #e5e7eb;
        }}

        .detail-box h4 {{
            margin: 0 0 8px;
            font-size: 13px;
            color: #4b5563;
            text-transform: uppercase;
        }}

        .detail-box p {{
            margin: 0;
            line-height: 1.6;
            font-size: 14px;
        }}

        /* ----------------------------------------------------
           Compliance
        ---------------------------------------------------- */

        .compliance-section {{
            display: grid;
            grid-template-columns:
                repeat(auto-fit, minmax(250px, 1fr));

            gap: 15px;

            margin-top: 18px;
            padding: 18px;

            background: #f9fafb;
            border-radius: 9px;
        }}

        .compliance-section div {{
            display: flex;
            flex-direction: column;
            gap: 5px;
        }}

        .label {{
            font-size: 12px;
            color: #6b7280;
            text-transform: uppercase;
            font-weight: 600;
        }}

        .compliance-section strong {{
            font-size: 15px;
        }}

        .compliance-section small {{
            color: #6b7280;
        }}

        /* ----------------------------------------------------
           Recommendation / Remediation
        ---------------------------------------------------- */

        .recommendation,
        .remediation {{
            margin-top: 18px;
            padding: 18px;
            border-radius: 9px;
        }}

        .recommendation {{
            background: #eff6ff;
            border-left: 4px solid #2563eb;
        }}

        .remediation {{
            background: #f0fdf4;
            border-left: 4px solid #16a34a;
        }}

        .recommendation h4,
        .remediation h4 {{
            margin: 0 0 8px;
            font-size: 14px;
        }}

        .recommendation p,
        .remediation p {{
            margin: 0;
            line-height: 1.6;
            font-size: 14px;
        }}

        /* ----------------------------------------------------
           Footer
        ---------------------------------------------------- */

        footer {{
            margin-top: 50px;
            padding: 25px 0;

            border-top: 1px solid #d1d5db;

            color: #6b7280;
            text-align: center;

            font-size: 13px;
        }}

        /* ----------------------------------------------------
           Responsive
        ---------------------------------------------------- */

        @media (max-width: 800px) {{

            .header-content {{
                flex-direction: column;
                align-items: flex-start;
            }}

            .risk-banner {{
                width: 100%;
            }}

            .finding-header {{
                flex-direction: column;
            }}

        }}

    </style>

</head>


<body>

    <header class="header">

        <div class="container header-content">

            <div>

                <h1>
                    Firewall & ACL Security Audit
                </h1>

                <p>
                    Automated security assessment of
                    firewall and access control rules.
                </p>

            </div>

            <div class="risk-banner">

                <span>OVERALL RISK</span>

                <strong>
                    {safe(overall_risk)}
                </strong>

            </div>

        </div>

    </header>


    <main class="container">

        <!-- =================================================
             SECURITY SUMMARY
        ================================================== -->

        <section>

            <h2 class="section-title">
                Security Risk Summary
            </h2>

            <div class="summary-grid">

                <div class="summary-card">

                    <h3>Total Rules Audited</h3>

                    <div class="value">
                        {statistics["total_rules"]}
                    </div>

                    <small>
                        Firewall rules analyzed
                    </small>

                </div>


                <div class="summary-card">

                    <h3>Total Findings</h3>

                    <div class="value">
                        {summary["total_findings"]}
                    </div>

                    <small>
                        Security issues identified
                    </small>

                </div>


                <div class="summary-card">

                    <h3>Risk Score</h3>

                    <div class="value risk">
                        {summary["risk_score"]}
                    </div>

                    <small>
                        Calculated security risk
                    </small>

                </div>


                <div class="summary-card">

                    <h3>Overall Risk</h3>

                    <div class="value risk">
                        {safe(overall_risk)}
                    </div>

                    <small>
                        Current security posture
                    </small>

                </div>

            </div>

        </section>


        <!-- =================================================
             SEVERITY SUMMARY
        ================================================== -->

        <section>

            <h2 class="section-title">
                Finding Severity
            </h2>

            <div class="summary-grid">

                <div class="summary-card">

                    <h3>HIGH</h3>

                    <div class="value high-text">
                        {summary["high"]}
                    </div>

                    <small>
                        High-risk findings
                    </small>

                </div>


                <div class="summary-card">

                    <h3>MEDIUM</h3>

                    <div class="value medium-text">
                        {summary["medium"]}
                    </div>

                    <small>
                        Medium-risk findings
                    </small>

                </div>


                <div class="summary-card">

                    <h3>LOW</h3>

                    <div class="value low-text">
                        {summary["low"]}
                    </div>

                    <small>
                        Low-risk findings
                    </small>

                </div>


                <div class="summary-card">

                    <h3>Non-Compliant</h3>

                    <div class="value risk">
                        {summary["non_compliant"]}
                    </div>

                    <small>
                        Compliance failures
                    </small>

                </div>

            </div>

        </section>


        <!-- =================================================
             RULE STATISTICS
        ================================================== -->

        <section>

            <h2 class="section-title">
                Firewall Rule Statistics
            </h2>

            <div class="statistics-grid">

                <div class="stat-card">
                    <span>ALLOW Rules</span>
                    <strong>
                        {statistics["allow_rules"]}
                    </strong>
                </div>

                <div class="stat-card">
                    <span>DENY Rules</span>
                    <strong>
                        {statistics["deny_rules"]}
                    </strong>
                </div>

                <div class="stat-card">
                    <span>TCP Rules</span>
                    <strong>
                        {statistics["tcp_rules"]}
                    </strong>
                </div>

                <div class="stat-card">
                    <span>UDP Rules</span>
                    <strong>
                        {statistics["udp_rules"]}
                    </strong>
                </div>

                <div class="stat-card">
                    <span>ICMP Rules</span>
                    <strong>
                        {statistics["icmp_rules"]}
                    </strong>
                </div>

                <div class="stat-card">
                    <span>ANY Protocol</span>
                    <strong>
                        {statistics["any_protocol_rules"]}
                    </strong>
                </div>

            </div>

        </section>


        <!-- =================================================
             SECURITY FINDINGS
        ================================================== -->

        <section>

            <h2 class="section-title">
                Detailed Security Findings
            </h2>

            {findings_html}

        </section>

    </main>


    <footer>

        Firewall & ACL Security Auditor
        <br>
        Automated Security Assessment Report

    </footer>

</body>

</html>
"""

    # ------------------------------------------------------------
    # Save report
    # ------------------------------------------------------------

    html_file = Path(html_file)

    html_file.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        html_file,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(html)

    print(
        f"HTML report saved to: {html_file}"
    )


# ================================================================
# MAIN
# ================================================================

if __name__ == "__main__":

    project_root = (
        Path(__file__).resolve().parent.parent
    )

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

    generate_html_report(
        json_file,
        html_file
    )