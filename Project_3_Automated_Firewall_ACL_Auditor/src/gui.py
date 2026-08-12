import json
import subprocess
import threading
import webbrowser
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox


# =========================================================
# Project Paths
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

ANALYZER = PROJECT_ROOT / "src" / "analyzer.py"

REPORT_JSON = (
    PROJECT_ROOT
    / "reports"
    / "firewall_audit_report.json"
)

REPORT_HTML = (
    PROJECT_ROOT
    / "reports"
    / "firewall_audit_report.html"
)


# =========================================================
# Firewall Auditor GUI
# =========================================================

class FirewallAuditorGUI:

    # =====================================================
    # Initialization
    # =====================================================

    def __init__(self, root):

        self.root = root

        self.root.title(
            "Firewall & ACL Security Auditor"
        )

        self.root.geometry(
            "1100x800"
        )

        self.root.minsize(
            950,
            600
        )

        self.findings = []

        self.setup_style()
        self.create_widgets()

    # =====================================================
    # Styling
    # =====================================================

    def setup_style(self):

        style = ttk.Style()

        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "Title.TLabel",
            font=("Arial", 20, "bold")
        )

        style.configure(
            "Subtitle.TLabel",
            font=("Arial", 10)
        )

        style.configure(
            "CardTitle.TLabel",
            font=("Arial", 10, "bold")
        )

        style.configure(
            "Metric.TLabel",
            font=("Arial", 18, "bold")
        )

        style.configure(
            "RiskMetric.TLabel",
            font=("TkDefaultFont", 16, "bold"),
            foreground="#C62828"
        )

        style.configure(
            "CriticalMetric.TLabel",
            font=("TkDefaultFont", 16, "bold"),
            foreground="#C62828"
        )

        style.configure(
            "HighMetric.TLabel",
            font=("TkDefaultFont", 16, "bold"),
            foreground="#C62828"
        )

        style.configure(
            "MediumMetric.TLabel",
            font=("TkDefaultFont", 16, "bold"),
            foreground="#EF6C00"
        )

        style.configure(
            "LowMetric.TLabel",
            font=("TkDefaultFont", 16, "bold"),
            foreground="#2E7D32"
        )

        style.configure(
            "Treeview",
            rowheight=28,
            font=("Arial", 9)
        )

        style.configure(
            "Treeview.Heading",
            font=("Arial", 9, "bold")
        )

    # =====================================================
    # Main GUI
    # =====================================================

    def create_widgets(self):

        # -------------------------------------------------
        # Header
        # -------------------------------------------------

        header = ttk.Frame(
            self.root,
            padding=15
        )

        header.pack(
            fill="x"
        )

        ttk.Label(
            header,
            text="Firewall & ACL Security Auditor",
            style="Title.TLabel"
        ).pack(
            anchor="w"
        )

        ttk.Label(
            header,
            text="Automated Firewall Security Assessment & Risk Analysis",
            style="Subtitle.TLabel"
        ).pack(
            anchor="w",
            pady=(3, 0)
        )

        # -------------------------------------------------
        # Input Section
        # -------------------------------------------------

        file_frame = ttk.LabelFrame(
            self.root,
            text="Audit Input",
            padding=10
        )

        file_frame.pack(
            fill="x",
            padx=15,
            pady=5
        )

        self.csv_var = tk.StringVar(
            value=str(
                PROJECT_ROOT
                / "data"
                / "firewall_rules.csv"
            )
        )

        ttk.Entry(
            file_frame,
            textvariable=self.csv_var
        ).pack(
            side="left",
            fill="x",
            expand=True,
            padx=(0, 8)
        )

        ttk.Button(
            file_frame,
            text="Browse CSV",
            command=self.browse_csv
        ).pack(
            side="left"
        )

        self.run_button = ttk.Button(
            file_frame,
            text="RUN SECURITY AUDIT",
            command=self.start_audit
        )

        self.run_button.pack(
            side="left",
            padx=(8, 0)
        )

        # -------------------------------------------------
        # Status
        # -------------------------------------------------

        self.status_var = tk.StringVar(
            value="Status: Ready"
        )

        ttk.Label(
            self.root,
            textvariable=self.status_var
        ).pack(
            anchor="w",
            padx=18,
            pady=(3, 5)
        )

        # -------------------------------------------------
        # Security Overview
        # -------------------------------------------------

        overview = ttk.LabelFrame(
            self.root,
            text="Security Overview",
            padding=10
        )

        overview.pack(
            fill="x",
            padx=15,
            pady=5
        )

        self.metric_rules = self.create_metric(
            overview,
            "Rules Audited"
        )

        self.metric_findings = self.create_metric(
            overview,
            "Findings"
        )

        self.metric_risk = self.create_metric(
            overview,
            "Risk Score"
        )

        self.metric_overall = self.create_metric(
            overview,
            "Overall Risk"
        )

        # -------------------------------------------------
        # Severity Summary
        # -------------------------------------------------

        severity_frame = ttk.Frame(
            overview
        )

        severity_frame.pack(
            fill="x",
            pady=(10, 0)
        )

        self.high_var = tk.StringVar(
            value="HIGH: 0"
        )

        self.medium_var = tk.StringVar(
            value="MEDIUM: 0"
        )

        self.low_var = tk.StringVar(
            value="LOW: 0"
        )

        self.compliant_var = tk.StringVar(
            value="COMPLIANT: 0"
        )

        self.non_compliant_var = tk.StringVar(
            value="NON-COMPLIANT: 0"
        )

        ttk.Label(
            severity_frame,
            textvariable=self.high_var
        ).pack(
            side="left",
            padx=10
        )

        ttk.Label(
            severity_frame,
            textvariable=self.medium_var
        ).pack(
            side="left",
            padx=10
        )

        ttk.Label(
            severity_frame,
            textvariable=self.low_var
        ).pack(
            side="left",
            padx=10
        )

        ttk.Label(
            severity_frame,
            textvariable=self.compliant_var
        ).pack(
            side="left",
            padx=10
        )

        ttk.Label(
            severity_frame,
            textvariable=self.non_compliant_var
        ).pack(
            side="left",
            padx=10
        )

        # -------------------------------------------------
        # Rule Statistics
        # -------------------------------------------------

        stats_frame = ttk.LabelFrame(
            self.root,
            text="Rule Statistics",
            padding=10
        )

        stats_frame.pack(
            fill="x",
            padx=15,
            pady=5
        )

        self.stats_var = tk.StringVar(
            value="No audit results loaded."
        )

        ttk.Label(
            stats_frame,
            textvariable=self.stats_var
        ).pack(
            anchor="w"
        )

        # -------------------------------------------------
        # Findings Table
        # -------------------------------------------------

        findings_frame = ttk.LabelFrame(
            self.root,
            text="Security Findings",
            padding=10
        )

        findings_frame.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=5
        )

        columns = (
            "rule_id",
            "finding",
            "severity",
            "compliance"
        )

        self.tree = ttk.Treeview(
            findings_frame,
            columns=columns,
            show="headings",
            height=8
        )

        # -------------------------------------------------
        # Severity Row Colors
        # -------------------------------------------------

        self.tree.tag_configure(
            "HIGH",
            foreground="#C62828"
        )

        self.tree.tag_configure(
            "MEDIUM",
            foreground="#EF6C00"
        )

        self.tree.tag_configure(
            "LOW",
            foreground="#2E7D32"
        )

        # -------------------------------------------------
        # Table Headings
        # -------------------------------------------------

        self.tree.heading(
            "rule_id",
            text="Rule ID"
        )

        self.tree.heading(
            "finding",
            text="Finding"
        )

        self.tree.heading(
            "severity",
            text="Severity"
        )

        self.tree.heading(
            "compliance",
            text="Compliance"
        )

        # -------------------------------------------------
        # Table Columns
        # -------------------------------------------------

        self.tree.column(
            "rule_id",
            width=80,
            anchor="center"
        )

        self.tree.column(
            "finding",
            width=350
        )

        self.tree.column(
            "severity",
            width=120,
            anchor="center"
        )

        self.tree.column(
            "compliance",
            width=180,
            anchor="center"
        )

        # -------------------------------------------------
        # Scrollbar
        # -------------------------------------------------

        scrollbar = ttk.Scrollbar(
            findings_frame,
            orient="vertical",
            command=self.tree.yview
        )

        self.tree.configure(
            yscrollcommand=scrollbar.set
        )

        self.tree.pack(
            side="left",
            fill="both",
            expand=True
        )

        scrollbar.pack(
            side="right",
            fill="y"
        )

        self.tree.bind(
            "<<TreeviewSelect>>",
            self.show_finding_details
        )

        # -------------------------------------------------
        # Bottom Buttons
        # -------------------------------------------------

        bottom = ttk.Frame(
            self.root,
            padding=10
        )

        bottom.pack(
            fill="x"
        )

        ttk.Button(
            bottom,
            text="View Finding Details",
            command=self.show_selected_details
        ).pack(
            side="left"
        )

        ttk.Button(
            bottom,
            text="Open HTML Report",
            command=self.open_html_report
        ).pack(
            side="right"
        )

    # =====================================================
    # Metric Card
    # =====================================================

    def create_metric(
        self,
        parent,
        title
    ):

        frame = ttk.Frame(
            parent,
            relief="ridge",
            padding=10
        )

        frame.pack(
            side="left",
            fill="x",
            expand=True,
            padx=5
        )

        ttk.Label(
            frame,
            text=title,
            style="CardTitle.TLabel"
        ).pack()

        value = ttk.Label(
            frame,
            text="0",
            style="Metric.TLabel"
        )

        value.pack(
            pady=5
        )

        return value

    # =====================================================
    # Browse CSV
    # =====================================================

    def browse_csv(self):

        file_path = filedialog.askopenfilename(
            title="Select Firewall Rules CSV",
            filetypes=[
                ("CSV Files", "*.csv"),
                ("All Files", "*.*")
            ]
        )

        if file_path:

            self.csv_var.set(
                file_path
            )

    # =====================================================
    # Start Audit
    # =====================================================

    def start_audit(self):

        csv_file = Path(
            self.csv_var.get()
        )

        if not csv_file.exists():

            messagebox.showerror(
                "File Error",
                "Selected CSV file does not exist."
            )

            return

        self.run_button.config(
            state="disabled"
        )

        self.status_var.set(
            "Status: Running security audit..."
        )

        thread = threading.Thread(
            target=self.run_analyzer,
            args=(csv_file,),
            daemon=True
        )

        thread.start()

    # =====================================================
    # Run Analyzer
    # =====================================================

    def run_analyzer(
        self,
        csv_file
    ):

        try:

            result = subprocess.run(
                [
                    "python3",
                    str(ANALYZER)
                ],
                cwd=str(PROJECT_ROOT),
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode != 0:

                error_message = (
                    result.stderr.strip()
                    or result.stdout.strip()
                    or "Unknown analyzer error."
                )

                self.root.after(
                    0,
                    lambda: self.audit_failed(
                        error_message
                    )
                )

                return

            if not REPORT_JSON.exists():

                self.root.after(
                    0,
                    lambda: self.audit_failed(
                        "JSON audit report was not generated."
                    )
                )

                return

            with open(
                REPORT_JSON,
                "r",
                encoding="utf-8"
            ) as file:

                report = json.load(
                    file
                )

            self.root.after(
                0,
                lambda: self.update_dashboard(
                    report
                )
            )

        except subprocess.TimeoutExpired:

            self.root.after(
                0,
                lambda: self.audit_failed(
                    "Audit timed out after 120 seconds."
                )
            )

        except json.JSONDecodeError:

            self.root.after(
                0,
                lambda: self.audit_failed(
                    "Generated JSON report is invalid."
                )
            )

        except Exception as error:

            self.root.after(
                0,
                lambda: self.audit_failed(
                    str(error)
                )
            )

    # =====================================================
    # Update Dashboard
    # =====================================================

    def update_dashboard(
        self,
        report
    ):

        summary = report.get(
            "summary",
            {}
        )

        statistics = report.get(
            "statistics",
            {}
        )

        self.findings = report.get(
            "findings",
            []
        )

        # -------------------------------------------------
        # Basic Metrics
        # -------------------------------------------------

        self.metric_rules.config(
            text=statistics.get(
                "total_rules",
                0
            )
        )

        self.metric_findings.config(
            text=summary.get(
                "total_findings",
                0
            )
        )

        # -------------------------------------------------
        # Dynamic Risk Score Color
        # -------------------------------------------------

        risk_score = summary.get(
            "risk_score",
            0
        )

        if risk_score >= 30:
            risk_style = "HighMetric.TLabel"

        elif risk_score >= 15:
            risk_style = "MediumMetric.TLabel"

        else:
            risk_style = "LowMetric.TLabel"

        self.metric_risk.config(
            text=risk_score,
            style=risk_style
        )

        # -------------------------------------------------
        # Dynamic Overall Risk Color
        # -------------------------------------------------

        overall_risk = summary.get(
            "overall_risk",
            "UNKNOWN"
        )

        if overall_risk == "LOW":

            overall_style = "LowMetric.TLabel"

        elif overall_risk == "MEDIUM":

            overall_style = "MediumMetric.TLabel"

        else:

            overall_style = "HighMetric.TLabel"

        self.metric_overall.config(
            text=overall_risk,
            style=overall_style
        )

        # -------------------------------------------------
        # Severity Summary
        # -------------------------------------------------

        self.high_var.set(
            f"HIGH: {summary.get('high', 0)}"
        )

        self.medium_var.set(
            f"MEDIUM: {summary.get('medium', 0)}"
        )

        self.low_var.set(
            f"LOW: {summary.get('low', 0)}"
        )

        self.compliant_var.set(
            f"COMPLIANT: {summary.get('compliant', 0)}"
        )

        self.non_compliant_var.set(
            f"NON-COMPLIANT: "
            f"{summary.get('non_compliant', 0)}"
        )

        # -------------------------------------------------
        # Rule Statistics
        # -------------------------------------------------

        stats_text = (
            f"ALLOW: {statistics.get('allow_rules', 0)}    "
            f"DENY: {statistics.get('deny_rules', 0)}    "
            f"TCP: {statistics.get('tcp_rules', 0)}    "
            f"UDP: {statistics.get('udp_rules', 0)}    "
            f"ICMP: {statistics.get('icmp_rules', 0)}    "
            f"ANY Protocol: "
            f"{statistics.get('any_protocol_rules', 0)}"
        )

        self.stats_var.set(
            stats_text
        )

        # -------------------------------------------------
        # Clear Old Findings
        # -------------------------------------------------

        for item in self.tree.get_children():

            self.tree.delete(
                item
            )

        # -------------------------------------------------
        # Add New Findings
        # -------------------------------------------------

        for index, finding in enumerate(
            self.findings
        ):

            severity = finding.get(
                "severity",
                ""
            ).upper()

            self.tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    finding.get(
                        "rule_id",
                        ""
                    ),
                    finding.get(
                        "finding",
                        ""
                    ),
                    finding.get(
                        "severity",
                        ""
                    ),
                    finding.get(
                        "compliance",
                        ""
                    )
                ),
                tags=(
                    severity,
                )
            )

        # -------------------------------------------------
        # Completion Status
        # -------------------------------------------------

        self.status_var.set(
            "Status: Audit completed successfully."
        )

        self.run_button.config(
            state="normal"
        )

    # =====================================================
    # Audit Failure
    # =====================================================

    def audit_failed(
        self,
        error_message
    ):

        self.status_var.set(
            "Status: Audit failed."
        )

        self.run_button.config(
            state="normal"
        )

        messagebox.showerror(
            "Audit Error",
            error_message
        )

    # =====================================================
    # Finding Details
    # =====================================================

    def show_finding_details(
        self,
        event=None
    ):

        selected = self.tree.selection()

        if not selected:
            return

        index = int(
            selected[0]
        )

        if index >= len(
            self.findings
        ):
            return

        self.open_details_window(
            self.findings[index]
        )

    # =====================================================
    # Selected Finding Details
    # =====================================================

    def show_selected_details(
        self
    ):

        selected = self.tree.selection()

        if not selected:

            messagebox.showinfo(
                "No Selection",
                "Please select a security finding first."
            )

            return

        index = int(
            selected[0]
        )

        if index >= len(
            self.findings
        ):
            return

        self.open_details_window(
            self.findings[index]
        )

    # =====================================================
    # Finding Details Window
    # =====================================================

    def open_details_window(
        self,
        finding
    ):

        window = tk.Toplevel(
            self.root
        )

        window.title(
            "Security Finding Details"
        )

        window.geometry(
            "750x600"
        )

        frame = ttk.Frame(
            window,
            padding=15
        )

        frame.pack(
            fill="both",
            expand=True
        )

        fields = [
            ("Rule ID", "rule_id"),
            ("Finding", "finding"),
            ("Severity", "severity"),
            ("Compliance", "compliance"),
            ("Control", "control"),
            ("Requirement", "requirement"),
            ("Reason", "reason"),
            ("Recommendation", "recommendation"),
            ("Remediation", "remediation"),
        ]

        for title, key in fields:

            ttk.Label(
                frame,
                text=f"{title}:",
                font=("Arial", 9, "bold")
            ).pack(
                anchor="w",
                pady=(5, 0)
            )

            text = tk.Text(
                frame,
                height=2,
                wrap="word"
            )

            text.insert(
                "1.0",
                str(
                    finding.get(
                        key,
                        ""
                    )
                )
            )

            text.config(
                state="disabled"
            )

            text.pack(
                fill="x",
                pady=(2, 4)
            )

        ttk.Button(
            frame,
            text="Close",
            command=window.destroy
        ).pack(
            pady=10
        )

    # =====================================================
    # Open HTML Report
    # =====================================================

    def open_html_report(
        self
    ):

        if not REPORT_HTML.exists():

            messagebox.showerror(
                "Report Not Found",
                "HTML report has not been generated yet."
            )

            return

        webbrowser.open(
            REPORT_HTML.resolve().as_uri()
        )


# =========================================================
# Application Entry Point
# =========================================================

if __name__ == "__main__":

    root = tk.Tk()

    app = FirewallAuditorGUI(
        root
    )

    root.mainloop()