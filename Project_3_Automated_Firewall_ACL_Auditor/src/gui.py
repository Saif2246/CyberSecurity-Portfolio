import json
import shutil
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path

import tkinter as tk
from tkinter import ttk, filedialog, messagebox


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

ANALYZER = PROJECT_ROOT / "src" / "analyzer.py"
HTML_REPORT_GENERATOR = PROJECT_ROOT / "src" / "html_report.py"

DEFAULT_CSV = PROJECT_ROOT / "data" / "firewall_rules.csv"

REPORT_JSON = PROJECT_ROOT / "reports" / "firewall_audit_report.json"
REPORT_HTML = PROJECT_ROOT / "reports" / "firewall_audit_report.html"


# ============================================================
# MAIN GUI APPLICATION
# ============================================================

class FirewallAuditorGUI:

    def __init__(self, root):

        self.root = root

        self.root.title(
            "Firewall & ACL Security Auditor"
        )

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.on_close
        )

        # ====================================================
        # RESPONSIVE WINDOW
        # ====================================================

        self.root.update_idletasks()

        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        window_width = min(
            1200,
            screen_width - 60
        )

        window_height = min(
            850,
            screen_height - 120
        )

        min_width = min(
            950,
            screen_width - 60
        )

        min_height = min(
            600,
            screen_height - 120
        )

        self.root.geometry(
            f"{window_width}x{window_height}"
        )

        self.root.minsize(
            min_width,
            min_height
        )

        x = max(
            0,
            (screen_width - window_width) // 2
        )

        y = max(
            0,
            (screen_height - window_height) // 2
        )

        self.root.geometry(
            f"{window_width}x{window_height}+{x}+{y}"
        )

        # ====================================================
        # DATA
        # ====================================================

        self.findings = []
        self.filtered_findings = []
        self.current_report = None

        self.audit_running = False
        self.closing = False

        # ====================================================
        # INITIALIZE
        # ====================================================

        self.setup_style()
        self.create_widgets()

    # ========================================================
    # STYLE
    # ========================================================

    def setup_style(self):

        style = ttk.Style()

        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "Title.TLabel",
            font=("Arial", 22, "bold")
        )

        style.configure(
            "Subtitle.TLabel",
            font=("Arial", 10)
        )

        style.configure(
            "Section.TLabelframe.Label",
            font=("Arial", 10, "bold")
        )

        style.configure(
            "CardTitle.TLabel",
            font=("Arial", 9, "bold")
        )

        style.configure(
            "Metric.TLabel",
            font=("Arial", 20, "bold")
        )

        style.configure(
            "HighMetric.TLabel",
            font=("Arial", 20, "bold"),
            foreground="#C62828"
        )

        style.configure(
            "MediumMetric.TLabel",
            font=("Arial", 20, "bold"),
            foreground="#EF6C00"
        )

        style.configure(
            "LowMetric.TLabel",
            font=("Arial", 20, "bold"),
            foreground="#2E7D32"
        )

        style.configure(
            "Treeview",
            rowheight=32,
            font=("Arial", 9)
        )

        style.configure(
            "Treeview.Heading",
            font=("Arial", 9, "bold")
        )

        style.configure(
            "Status.TLabel",
            font=("Arial", 9, "italic")
        )

        style.configure(
            "Footer.TFrame",
            padding=5
        )

    # ========================================================
    # CREATE MAIN GUI
    # ========================================================

    def create_widgets(self):

        # ====================================================
        # HEADER
        # ====================================================

        header = ttk.Frame(
            self.root,
            padding=(20, 10)
        )

        header.pack(
            side="top",
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

        # ====================================================
        # FOOTER
        # ====================================================

        bottom = ttk.Frame(
            self.root,
            style="Footer.TFrame"
        )

        bottom.pack(
            side="bottom",
            fill="x"
        )

        bottom.pack_propagate(False)

        bottom.configure(
            height=65
        )

        ttk.Separator(
            bottom,
            orient="horizontal"
        ).pack(
            fill="x",
            pady=(0, 6)
        )

        button_container = ttk.Frame(
            bottom
        )

        button_container.pack(
            fill="x",
            padx=15,
            pady=(0, 5)
        )

        ttk.Button(
            button_container,
            text="View Finding Details",
            command=self.show_selected_details
        ).pack(
            side="left"
        )

        ttk.Button(
            button_container,
            text="Open HTML Report",
            command=self.open_html_report
        ).pack(
            side="left",
            padx=(8, 0)
        )

        ttk.Button(
            button_container,
            text="Save JSON Report",
            command=self.save_json_report
        ).pack(
            side="left",
            padx=(8, 0)
        )

        # ====================================================
        # MAIN CONTENT
        # ====================================================

        content = ttk.Frame(
            self.root
        )

        content.pack(
            side="top",
            fill="both",
            expand=True
        )

        # ====================================================
        # AUDIT INPUT
        # ====================================================

        input_frame = ttk.LabelFrame(
            content,
            text="Audit Input",
            padding=10,
            style="Section.TLabelframe"
        )

        input_frame.pack(
            fill="x",
            padx=20,
            pady=4
        )

        self.csv_var = tk.StringVar(
            value=str(DEFAULT_CSV)
        )

        self.csv_entry = ttk.Entry(
            input_frame,
            textvariable=self.csv_var
        )

        self.csv_entry.pack(
            side="left",
            fill="x",
            expand=True,
            padx=(0, 8)
        )

        ttk.Button(
            input_frame,
            text="Browse CSV",
            command=self.browse_csv
        ).pack(
            side="left"
        )

        self.run_button = ttk.Button(
            input_frame,
            text="RUN SECURITY AUDIT",
            command=self.start_audit
        )

        self.run_button.pack(
            side="left",
            padx=(8, 0)
        )

        # ====================================================
        # STATUS
        # ====================================================

        status_frame = ttk.Frame(
            content,
            padding=(20, 1)
        )

        status_frame.pack(
            fill="x"
        )

        self.status_var = tk.StringVar(
            value="Status: Ready — press RUN SECURITY AUDIT to begin."
        )

        ttk.Label(
            status_frame,
            textvariable=self.status_var,
            style="Status.TLabel"
        ).pack(
            anchor="w"
        )

        # ====================================================
        # SECURITY OVERVIEW
        # ====================================================

        overview = ttk.LabelFrame(
            content,
            text="Security Overview",
            padding=10,
            style="Section.TLabelframe"
        )

        overview.pack(
            fill="x",
            padx=20,
            pady=4
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

        # ====================================================
        # SEVERITY SUMMARY
        # ====================================================

        severity_frame = ttk.Frame(
            overview
        )

        severity_frame.pack(
            fill="x",
            pady=(8, 0)
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

        # ====================================================
        # ADVANCED SECURITY SUMMARY
        # ====================================================

        advanced_frame = ttk.Frame(
            overview
        )

        advanced_frame.pack(
            fill="x",
            pady=(8, 0)
        )

        self.overlap_var = tk.StringVar(
            value="CIDR OVERLAPS: 0"
        )

        self.shadow_var = tk.StringVar(
            value="SHADOW RULES: 0"
        )

        self.nist_var = tk.StringVar(
            value="NIST MAPPINGS: 0"
        )

        self.cis_var = tk.StringVar(
            value="CIS MAPPINGS: 0"
        )

        ttk.Label(
            advanced_frame,
            textvariable=self.overlap_var
        ).pack(
            side="left",
            padx=10
        )

        ttk.Label(
            advanced_frame,
            textvariable=self.shadow_var
        ).pack(
            side="left",
            padx=10
        )

        ttk.Label(
            advanced_frame,
            textvariable=self.nist_var
        ).pack(
            side="left",
            padx=10
        )

        ttk.Label(
            advanced_frame,
            textvariable=self.cis_var
        ).pack(
            side="left",
            padx=10
        )

        # ====================================================
        # RULE STATISTICS
        # ====================================================

        stats_frame = ttk.LabelFrame(
            content,
            text="Firewall Rule Statistics",
            padding=10,
            style="Section.TLabelframe"
        )

        stats_frame.pack(
            fill="x",
            padx=20,
            pady=4
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

        # ====================================================
        # FINDINGS FRAME
        # ====================================================

        findings_frame = ttk.LabelFrame(
            content,
            text="Security Findings",
            padding=10,
            style="Section.TLabelframe"
        )

        findings_frame.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=4
        )

        # ====================================================
        # SEARCH / FILTER BAR
        # ====================================================

        filter_frame = ttk.Frame(
            findings_frame
        )

        filter_frame.pack(
            fill="x",
            pady=(0, 8)
        )

        ttk.Label(
            filter_frame,
            text="Search Findings:"
        ).pack(
            side="left"
        )

        self.search_var = tk.StringVar()

        self.search_entry = ttk.Entry(
            filter_frame,
            textvariable=self.search_var
        )

        self.search_entry.pack(
            side="left",
            fill="x",
            expand=True,
            padx=(8, 8)
        )

        self.search_entry.bind(
            "<KeyRelease>",
            self.filter_findings
        )

        ttk.Button(
            filter_frame,
            text="Clear",
            command=self.clear_search
        ).pack(
            side="left"
        )

        self.filter_count_var = tk.StringVar(
            value="0 findings"
        )

        ttk.Label(
            filter_frame,
            textvariable=self.filter_count_var
        ).pack(
            side="right",
            padx=(10, 0)
        )

        # ====================================================
        # TABLE
        # ====================================================

        table_frame = ttk.Frame(
            findings_frame
        )

        table_frame.pack(
            fill="both",
            expand=True
        )

        columns = (
            "number",
            "rule_id",
            "finding",
            "severity",
            "compliance"
        )

        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse"
        )

        self.tree.heading(
            "number",
            text="#"
        )

        self.tree.heading(
            "rule_id",
            text="Rule ID"
        )

        self.tree.heading(
            "finding",
            text="Security Finding"
        )

        self.tree.heading(
            "severity",
            text="Severity"
        )

        self.tree.heading(
            "compliance",
            text="Compliance"
        )

        self.tree.column(
            "number",
            width=50,
            minwidth=50,
            anchor="center",
            stretch=False
        )

        self.tree.column(
            "rule_id",
            width=80,
            minwidth=70,
            anchor="center",
            stretch=False
        )

        self.tree.column(
            "finding",
            width=600,
            minwidth=300,
            anchor="w",
            stretch=True
        )

        self.tree.column(
            "severity",
            width=110,
            minwidth=90,
            anchor="center",
            stretch=False
        )

        self.tree.column(
            "compliance",
            width=190,
            minwidth=130,
            anchor="center",
            stretch=False
        )

        # ====================================================
        # ROW COLORS
        # ====================================================

        self.tree.tag_configure(
            "HIGH",
            foreground="#C62828"
        )

        self.tree.tag_configure(
            "CRITICAL",
            foreground="#B71C1C"
        )

        self.tree.tag_configure(
            "MEDIUM",
            foreground="#EF6C00"
        )

        self.tree.tag_configure(
            "LOW",
            foreground="#2E7D32"
        )

        # ====================================================
        # SCROLLBARS
        # ====================================================

        vertical_scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.tree.yview
        )

        horizontal_scrollbar = ttk.Scrollbar(
            table_frame,
            orient="horizontal",
            command=self.tree.xview
        )

        self.tree.configure(
            yscrollcommand=vertical_scrollbar.set,
            xscrollcommand=horizontal_scrollbar.set
        )

        self.tree.pack(
            side="left",
            fill="both",
            expand=True
        )

        vertical_scrollbar.pack(
            side="right",
            fill="y"
        )

        horizontal_scrollbar.pack(
            side="bottom",
            fill="x"
        )

        # ====================================================
        # EVENTS
        # ====================================================

        self.tree.bind(
            "<Double-1>",
            lambda event: self.show_selected_details()
        )

        self.tree.bind(
            "<Button-4>",
            self.scroll_tree_up
        )

        self.tree.bind(
            "<Button-5>",
            self.scroll_tree_down
        )

        self.tree.bind(
            "<MouseWheel>",
            self.scroll_tree_windows
        )

        self.tree.bind(
            "<Next>",
            self.scroll_tree_page_down
        )

        self.tree.bind(
            "<Prior>",
            self.scroll_tree_page_up
        )

        self.tree.bind(
            "<Home>",
            self.scroll_tree_home
        )

        self.tree.bind(
            "<End>",
            self.scroll_tree_end
        )

    # ========================================================
    # TREE SCROLLING
    # ========================================================

    def scroll_tree_up(self, event=None):

        self.tree.yview_scroll(
            -3,
            "units"
        )

        return "break"

    def scroll_tree_down(self, event=None):

        self.tree.yview_scroll(
            3,
            "units"
        )

        return "break"

    def scroll_tree_windows(self, event):

        if event.delta:

            amount = int(
                -1 * (event.delta / 120)
            )

            if amount == 0:
                amount = -1 if event.delta > 0 else 1

            self.tree.yview_scroll(
                amount,
                "units"
            )

        return "break"

    def scroll_tree_page_down(self, event=None):

        self.tree.yview_scroll(
            10,
            "units"
        )

        return "break"

    def scroll_tree_page_up(self, event=None):

        self.tree.yview_scroll(
            -10,
            "units"
        )

        return "break"

    def scroll_tree_home(self, event=None):

        self.tree.yview_moveto(
            0
        )

        return "break"

    def scroll_tree_end(self, event=None):

        self.tree.yview_moveto(
            1
        )

        return "break"

    # ========================================================
    # METRIC CARD
    # ========================================================

    def create_metric(
        self,
        parent,
        title
    ):

        frame = ttk.Frame(
            parent,
            relief="ridge",
            padding=8
        )

        frame.pack(
            side="left",
            fill="x",
            expand=True,
            padx=4
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
            pady=3
        )

        return value

    # ========================================================
    # BROWSE CSV
    # ========================================================

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

            self.status_var.set(
                "Status: CSV file selected."
            )

    # ========================================================
    # START AUDIT
    # ========================================================

    def start_audit(self):

        if self.audit_running:

            return

        csv_file = Path(
            self.csv_var.get().strip()
        )

        if not csv_file.exists():

            messagebox.showerror(
                "File Error",
                f"Selected CSV file does not exist:\n\n{csv_file}"
            )

            return

        if not csv_file.is_file():

            messagebox.showerror(
                "File Error",
                f"Selected path is not a file:\n\n{csv_file}"
            )

            return

        if not ANALYZER.exists():

            messagebox.showerror(
                "Analyzer Error",
                f"Analyzer not found:\n\n{ANALYZER}"
            )

            return

        self.audit_running = True

        self.run_button.config(
            state="disabled"
        )

        self.status_var.set(
            "Status: Running security audit..."
        )

        self.clear_dashboard()

        thread = threading.Thread(
            target=self.run_analyzer,
            args=(csv_file,),
            daemon=True
        )

        thread.start()

    # ========================================================
    # CLEAR DASHBOARD
    # ========================================================

    def clear_dashboard(self):

        self.current_report = None

        self.findings = []

        self.filtered_findings = []

        self.metric_rules.config(
            text="0",
            style="Metric.TLabel"
        )

        self.metric_findings.config(
            text="0",
            style="Metric.TLabel"
        )

        self.metric_risk.config(
            text="0",
            style="Metric.TLabel"
        )

        self.metric_overall.config(
            text="UNKNOWN",
            style="Metric.TLabel"
        )

        self.high_var.set(
            "HIGH: 0"
        )

        self.medium_var.set(
            "MEDIUM: 0"
        )

        self.low_var.set(
            "LOW: 0"
        )

        self.compliant_var.set(
            "COMPLIANT: 0"
        )

        self.non_compliant_var.set(
            "NON-COMPLIANT: 0"
        )

        self.overlap_var.set(
            "CIDR OVERLAPS: 0"
        )

        self.shadow_var.set(
            "SHADOW RULES: 0"
        )

        self.nist_var.set(
            "NIST MAPPINGS: 0"
        )

        self.cis_var.set(
            "CIS MAPPINGS: 0"
        )

        self.stats_var.set(
            "Running audit..."
        )

        self.search_var.set("")

        for item in self.tree.get_children():

            self.tree.delete(
                item
            )

        self.filter_count_var.set(
            "0 findings"
        )

    # ========================================================
    # RUN ANALYZER
    # ========================================================

    def run_analyzer(
        self,
        csv_file
    ):

        try:

            REPORT_JSON.parent.mkdir(
                parents=True,
                exist_ok=True
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(ANALYZER),
                    str(csv_file)
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
                    lambda msg=error_message:
                    self.audit_failed(msg)
                )

                return

            if not REPORT_JSON.exists():

                self.root.after(
                    0,
                    lambda:
                    self.audit_failed(
                        "JSON audit report was not generated."
                    )
                )

                return

            # =================================================
            # LOAD JSON
            # =================================================

            with open(
                REPORT_JSON,
                "r",
                encoding="utf-8"
            ) as file:

                report = json.load(
                    file
                )

            if not isinstance(report, dict):

                self.root.after(
                    0,
                    lambda:
                    self.audit_failed(
                        "Generated JSON report has an invalid structure."
                    )
                )

                return

            # =================================================
            # GENERATE HTML
            # =================================================

            html_error = None

            if HTML_REPORT_GENERATOR.exists():

                html_result = subprocess.run(
                    [
                        sys.executable,
                        str(HTML_REPORT_GENERATOR)
                    ],
                    cwd=str(PROJECT_ROOT),
                    capture_output=True,
                    text=True,
                    timeout=120
                )

                if html_result.returncode != 0:

                    html_error = (
                        html_result.stderr.strip()
                        or html_result.stdout.strip()
                        or "HTML generation failed."
                    )

            # =================================================
            # UPDATE GUI
            # =================================================

            self.root.after(
                0,
                lambda report_data=report:
                self.update_dashboard(
                    report_data
                )
            )

            if html_error:

                self.root.after(
                    0,
                    lambda msg=html_error:
                    self.status_var.set(
                        "Status: Audit completed, "
                        "but HTML generation failed."
                    )
                )

        except subprocess.TimeoutExpired:

            self.root.after(
                0,
                lambda:
                self.audit_failed(
                    "Audit timed out after 120 seconds."
                )
            )

        except json.JSONDecodeError:

            self.root.after(
                0,
                lambda:
                self.audit_failed(
                    "Generated JSON report is invalid."
                )
            )

        except Exception as error:

            error_message = str(error)

            self.root.after(
                0,
                lambda msg=error_message:
                self.audit_failed(msg)
            )

    # ========================================================
    # UPDATE DASHBOARD
    # ========================================================

    def update_dashboard(
        self,
        report,
        loaded_existing=False,
        silent=False
    ):

        self.current_report = report

        summary = report.get(
            "summary",
            {}
        )

        statistics = report.get(
            "statistics",
            {}
        )

        if not isinstance(summary, dict):
            summary = {}

        if not isinstance(statistics, dict):
            statistics = {}

        self.findings = report.get(
            "findings",
            []
        )

        if not isinstance(
            self.findings,
            list
        ):

            self.findings = []

        self.filtered_findings = list(
            self.findings
        )

        # ====================================================
        # BASIC METRICS
        # ====================================================

        total_rules = statistics.get(
            "total_rules",
            0
        )

        total_findings = summary.get(
            "total_findings",
            len(self.findings)
        )

        self.metric_rules.config(
            text=total_rules,
            style="Metric.TLabel"
        )

        self.metric_findings.config(
            text=total_findings,
            style="Metric.TLabel"
        )

        # ====================================================
        # RISK SCORE
        # ====================================================

        risk_score = summary.get(
            "risk_score",
            0
        )

        try:

            risk_score_number = float(
                risk_score
            )

        except (
            TypeError,
            ValueError
        ):

            risk_score_number = 0

        if risk_score_number >= 30:

            risk_style = "HighMetric.TLabel"

        elif risk_score_number >= 15:

            risk_style = "MediumMetric.TLabel"

        else:

            risk_style = "LowMetric.TLabel"

        self.metric_risk.config(
            text=risk_score,
            style=risk_style
        )

        # ====================================================
        # OVERALL RISK
        # ====================================================

        overall_risk = str(
            summary.get(
                "overall_risk",
                "UNKNOWN"
            )
        ).upper()

        if overall_risk in (
            "CRITICAL",
            "HIGH"
        ):

            overall_style = "HighMetric.TLabel"

        elif overall_risk == "MEDIUM":

            overall_style = "MediumMetric.TLabel"

        elif overall_risk == "LOW":

            overall_style = "LowMetric.TLabel"

        else:

            overall_style = "Metric.TLabel"

        self.metric_overall.config(
            text=overall_risk,
            style=overall_style
        )

        # ====================================================
        # SEVERITY
        # ====================================================

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

        # ====================================================
        # ADVANCED COUNTS
        # ====================================================

        overlap_count = self.get_overlap_count(
            report
        )

        shadow_count = self.get_shadow_count(
            report
        )

        nist_count = self.get_mapping_count(
            self.findings,
            "nist_control"
        )

        cis_count = self.get_mapping_count(
            self.findings,
            "cis_control"
        )

        self.overlap_var.set(
            f"CIDR OVERLAPS: {overlap_count}"
        )

        self.shadow_var.set(
            f"SHADOW RULES: {shadow_count}"
        )

        self.nist_var.set(
            f"NIST MAPPINGS: {nist_count}"
        )

        self.cis_var.set(
            f"CIS MAPPINGS: {cis_count}"
        )

        # ====================================================
        # RULE STATISTICS
        # ====================================================

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

        # ====================================================
        # CLEAR TABLE
        # ====================================================

        self.clear_tree()

        # ====================================================
        # RESET SEARCH
        # ====================================================

        self.search_var.set("")

        # ====================================================
        # INSERT FINDINGS
        # ====================================================

        self.insert_findings(
            self.findings
        )

        self.filter_count_var.set(
            f"{len(self.findings)} findings"
        )

        # ====================================================
        # RESET SCROLL
        # ====================================================

        if self.tree.get_children():

            self.tree.yview_moveto(
                0
            )

        # ====================================================
        # STATUS
        # ====================================================

        if not silent:

            if loaded_existing:

                self.status_var.set(
                    "Status: Existing audit report loaded successfully."
                )

            else:

                self.status_var.set(
                    "Status: Audit completed successfully."
                )

        self.audit_running = False

        self.run_button.config(
            state="normal"
        )

    # ========================================================
    # CLEAR TREE
    # ========================================================

    def clear_tree(self):

        for item in self.tree.get_children():

            self.tree.delete(
                item
            )

    # ========================================================
    # INSERT FINDINGS
    # ========================================================

    def insert_findings(
        self,
        findings
    ):

        for display_index, finding in enumerate(
            findings,
            start=1
        ):

            severity = str(
                finding.get(
                    "severity",
                    ""
                )
            ).upper()

            # Store the actual object index safely
            try:

                original_index = self.findings.index(
                    finding
                )

            except ValueError:

                original_index = display_index - 1

            item_id = f"finding_{original_index}"

            # Ensure unique Treeview ID
            if item_id in self.tree.get_children():

                item_id = (
                    f"finding_{original_index}_{display_index}"
                )

            self.tree.insert(
                "",
                "end",
                iid=item_id,
                values=(
                    display_index,
                    finding.get(
                        "rule_id",
                        ""
                    ),
                    finding.get(
                        "finding",
                        ""
                    ),
                    severity,
                    finding.get(
                        "compliance",
                        ""
                    )
                ),
                tags=(
                    severity,
                )
            )

    # ========================================================
    # GET SELECTED FINDING
    # ========================================================

    def get_selected_finding(self):

        selected = self.tree.selection()

        if not selected:

            return None

        item_id = selected[0]

        try:

            parts = item_id.split("_")

            index = int(
                parts[1]
            )

        except (
            ValueError,
            IndexError
        ):

            return None

        if index < 0 or index >= len(
            self.findings
        ):

            return None

        return self.findings[index]

    # ========================================================
    # SEARCH / FILTER
    # ========================================================

    def filter_findings(
        self,
        event=None
    ):

        search_text = (
            self.search_var.get()
            .strip()
            .lower()
        )

        if not search_text:

            filtered = list(
                self.findings
            )

        else:

            filtered = []

            for finding in self.findings:

                searchable_values = [

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
                    ),

                    finding.get(
                        "control",
                        ""
                    ),

                    finding.get(
                        "requirement",
                        ""
                    ),

                    finding.get(
                        "reason",
                        ""
                    ),

                    finding.get(
                        "recommendation",
                        ""
                    ),

                    finding.get(
                        "remediation",
                        ""
                    ),

                    finding.get(
                        "nist_control",
                        ""
                    ),

                    finding.get(
                        "cis_control",
                        ""
                    ),

                    finding.get(
                        "related_rule",
                        ""
                    ),

                    finding.get(
                        "shadow_rule",
                        ""
                    ),

                    finding.get(
                        "shadowed_by",
                        ""
                    ),
                ]

                combined_text = " ".join(
                    str(value)
                    for value in searchable_values
                    if value is not None
                ).lower()

                if search_text in combined_text:

                    filtered.append(
                        finding
                    )

        self.filtered_findings = filtered

        self.clear_tree()

        self.insert_findings(
            filtered
        )

        self.filter_count_var.set(
            f"{len(filtered)} of "
            f"{len(self.findings)} findings"
        )

        if self.tree.get_children():

            self.tree.yview_moveto(
                0
            )

    # ========================================================
    # CLEAR SEARCH
    # ========================================================

    def clear_search(self):

        self.search_var.set("")

        self.filter_findings()

    # ========================================================
    # COUNT CIDR OVERLAPS
    # ========================================================

    def get_overlap_count(
        self,
        report
    ):

        possible_keys = [
            "cidr_overlaps",
            "overlap_count",
            "cidr_overlap_count"
        ]

        for key in possible_keys:

            value = report.get(
                key
            )

            if value is not None:

                try:

                    return int(
                        value
                    )

                except (
                    TypeError,
                    ValueError
                ):

                    pass

        statistics = report.get(
            "statistics",
            {}
        )

        for key in possible_keys:

            value = statistics.get(
                key
            )

            if value is not None:

                try:

                    return int(
                        value
                    )

                except (
                    TypeError,
                    ValueError
                ):

                    pass

        count = 0

        for finding in self.findings:

            text = str(
                finding.get(
                    "finding",
                    ""
                )
            ).lower()

            if (
                "cidr" in text
                and "overlap" in text
            ):

                count += 1

        return count

    # ========================================================
    # COUNT SHADOW RULES
    # ========================================================

    def get_shadow_count(
        self,
        report
    ):

        possible_keys = [
            "shadow_rules",
            "shadow_rule_count",
            "shadow_rules_count"
        ]

        for key in possible_keys:

            value = report.get(
                key
            )

            if value is not None:

                try:

                    return int(
                        value
                    )

                except (
                    TypeError,
                    ValueError
                ):

                    pass

        statistics = report.get(
            "statistics",
            {}
        )

        for key in possible_keys:

            value = statistics.get(
                key
            )

            if value is not None:

                try:

                    return int(
                        value
                    )

                except (
                    TypeError,
                    ValueError
                ):

                    pass

        count = 0

        for finding in self.findings:

            text = str(
                finding.get(
                    "finding",
                    ""
                )
            ).lower()

            if "shadow" in text:

                count += 1

        return count

    # ========================================================
    # COUNT MAPPINGS
    # ========================================================

    def get_mapping_count(
        self,
        findings,
        key
    ):

        count = 0

        for finding in findings:

            value = finding.get(
                key
            )

            if value not in (
                None,
                "",
                "N/A",
                "n/a"
            ):

                count += 1

        return count

    # ========================================================
    # AUDIT FAILED
    # ========================================================

    def audit_failed(
        self,
        error_message
    ):

        self.audit_running = False

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

    # ========================================================
    # SELECTED DETAILS BUTTON
    # ========================================================

    def show_selected_details(
        self
    ):

        finding = self.get_selected_finding()

        if finding is None:

            messagebox.showinfo(
                "No Selection",
                "Please select a security finding first."
            )

            return

        self.open_details_window(
            finding
        )

    # ========================================================
    # FINDING DETAILS WINDOW
    # ========================================================

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
            "900x750"
        )

        window.minsize(
            700,
            500
        )

        window.transient(
            self.root
        )

        # ====================================================
        # MAIN FRAME
        # ====================================================

        main_frame = ttk.Frame(
            window,
            padding=12
        )

        main_frame.pack(
            fill="both",
            expand=True
        )

        rule_id = finding.get(
            "rule_id",
            ""
        )

        finding_name = finding.get(
            "finding",
            "Security Finding"
        )

        ttk.Label(
            main_frame,
            text=f"Rule {rule_id}: {finding_name}",
            font=("Arial", 16, "bold")
        ).pack(
            anchor="w",
            pady=(0, 10)
        )

        # ====================================================
        # SCROLL CONTAINER
        # ====================================================

        scroll_container = ttk.Frame(
            main_frame
        )

        scroll_container.pack(
            fill="both",
            expand=True
        )

        canvas = tk.Canvas(
            scroll_container,
            highlightthickness=0
        )

        canvas.pack(
            side="left",
            fill="both",
            expand=True
        )

        scrollbar = ttk.Scrollbar(
            scroll_container,
            orient="vertical",
            command=canvas.yview
        )

        scrollbar.pack(
            side="right",
            fill="y"
        )

        canvas.configure(
            yscrollcommand=scrollbar.set
        )

        details_frame = ttk.Frame(
            canvas,
            padding=(5, 5, 10, 5)
        )

        canvas_window = canvas.create_window(
            (0, 0),
            window=details_frame,
            anchor="nw"
        )

        # ====================================================
        # SCROLL REGION
        # ====================================================

        def update_scroll_region(event=None):

            canvas.configure(
                scrollregion=canvas.bbox("all")
            )

        details_frame.bind(
            "<Configure>",
            update_scroll_region
        )

        # ====================================================
        # RESIZE INNER FRAME
        # ====================================================

        def resize_inner_frame(event):

            canvas.itemconfigure(
                canvas_window,
                width=event.width
            )

        canvas.bind(
            "<Configure>",
            resize_inner_frame
        )

        # ====================================================
        # MOUSE SCROLL
        # ====================================================

        def mouse_wheel(event):

            if event.delta:

                amount = int(
                    -1 * (
                        event.delta / 120
                    )
                )

                if amount == 0:

                    amount = (
                        -1
                        if event.delta > 0
                        else 1
                    )

                canvas.yview_scroll(
                    amount,
                    "units"
                )

            return "break"

        window.bind(
            "<MouseWheel>",
            mouse_wheel
        )

        window.bind(
            "<Button-4>",
            lambda event: (
                canvas.yview_scroll(
                    -3,
                    "units"
                ),
                "break"
            )[1]
        )

        window.bind(
            "<Button-5>",
            lambda event: (
                canvas.yview_scroll(
                    3,
                    "units"
                ),
                "break"
            )[1]
        )

        # ====================================================
        # KEYBOARD SCROLL
        # ====================================================

        def page_down(event=None):

            canvas.yview_scroll(
                8,
                "units"
            )

            return "break"

        def page_up(event=None):

            canvas.yview_scroll(
                -8,
                "units"
            )

            return "break"

        def scroll_home(event=None):

            canvas.yview_moveto(
                0
            )

            return "break"

        def scroll_end(event=None):

            canvas.yview_moveto(
                1
            )

            return "break"

        window.bind(
            "<Next>",
            page_down
        )

        window.bind(
            "<Prior>",
            page_up
        )

        window.bind(
            "<Home>",
            scroll_home
        )

        window.bind(
            "<End>",
            scroll_end
        )

        # ====================================================
        # SECURITY DETAILS
        # ====================================================

        fields = [

            ("Rule ID", "rule_id"),

            ("Finding", "finding"),

            ("Severity", "severity"),

            ("Compliance", "compliance"),

            ("Control", "control"),

            ("Requirement", "requirement"),

            ("Reason", "reason"),

            ("Related Rule", "related_rule"),

            ("CIDR Overlap", "cidr_overlap"),

            ("Overlapping Rule", "overlapping_rule"),

            ("Shadow Rule", "shadow_rule"),

            ("Shadowed By", "shadowed_by"),

            ("NIST Control", "nist_control"),

            ("NIST Control Title", "nist_control_title"),

            ("CIS Control", "cis_control"),

            ("CIS Control Title", "cis_control_title"),

            ("Recommendation", "recommendation"),

            ("Remediation", "remediation"),
        ]

        for title, key in fields:

            value = finding.get(
                key,
                "N/A"
            )

            if value is None or value == "":

                value = "N/A"

            ttk.Label(
                details_frame,
                text=f"{title}:",
                font=("Arial", 9, "bold")
            ).pack(
                anchor="w",
                pady=(8, 3)
            )

            text_widget = tk.Text(
                details_frame,
                height=2,
                wrap="word",
                font=("Arial", 9),
                relief="solid",
                borderwidth=1
            )

            text_widget.insert(
                "1.0",
                str(value)
            )

            text_widget.config(
                state="disabled"
            )

            text_widget.pack(
                fill="x",
                expand=True
            )

        details_frame.update_idletasks()

        canvas.configure(
            scrollregion=canvas.bbox("all")
        )

        # ====================================================
        # CLOSE
        # ====================================================

        button_frame = ttk.Frame(
            main_frame
        )

        button_frame.pack(
            fill="x",
            pady=(10, 0)
        )

        ttk.Button(
            button_frame,
            text="Close",
            command=window.destroy
        ).pack(
            side="right"
        )

        window.protocol(
            "WM_DELETE_WINDOW",
            window.destroy
        )

    # ========================================================
    # OPEN HTML REPORT
    # ========================================================

    def open_html_report(
        self
    ):

        if not REPORT_HTML.exists():

            if not REPORT_JSON.exists():

                messagebox.showerror(
                    "Report Not Found",
                    "No JSON audit report is available.\n\n"
                    "Please run the security audit first."
                )

                return

            if not HTML_REPORT_GENERATOR.exists():

                messagebox.showerror(
                    "Generator Not Found",
                    f"HTML report generator not found:\n\n"
                    f"{HTML_REPORT_GENERATOR}"
                )

                return

            try:

                result = subprocess.run(
                    [
                        sys.executable,
                        str(HTML_REPORT_GENERATOR)
                    ],
                    cwd=str(PROJECT_ROOT),
                    capture_output=True,
                    text=True,
                    timeout=120
                )

                if result.returncode != 0:

                    messagebox.showerror(
                        "HTML Report Error",
                        result.stderr.strip()
                        or result.stdout.strip()
                        or "Failed to generate HTML report."
                    )

                    return

            except subprocess.TimeoutExpired:

                messagebox.showerror(
                    "HTML Report Error",
                    "HTML report generation timed out."
                )

                return

            except Exception as error:

                messagebox.showerror(
                    "HTML Report Error",
                    str(error)
                )

                return

        if not REPORT_HTML.exists():

            messagebox.showerror(
                "Report Error",
                "HTML report was not created."
            )

            return

        try:

            webbrowser.open(
                REPORT_HTML.resolve().as_uri()
            )

            self.status_var.set(
                "Status: HTML report opened in browser."
            )

        except Exception as error:

            messagebox.showerror(
                "Browser Error",
                str(error)
            )

    # ========================================================
    # SAVE JSON REPORT
    # ========================================================

    def save_json_report(
        self
    ):

        if not REPORT_JSON.exists():

            messagebox.showinfo(
                "No Report",
                "No JSON audit report exists yet.\n\n"
                "Run the security audit first."
            )

            return

        file_path = filedialog.asksaveasfilename(
            title="Save Firewall Audit Report",
            defaultextension=".json",
            filetypes=[
                ("JSON Files", "*.json"),
                ("All Files", "*.*")
            ],
            initialfile="firewall_audit_report.json"
        )

        if not file_path:

            return

        try:

            shutil.copy2(
                REPORT_JSON,
                file_path
            )

            self.status_var.set(
                "Status: JSON report saved successfully."
            )

            messagebox.showinfo(
                "Report Saved",
                f"JSON audit report saved successfully:\n\n"
                f"{file_path}"
            )

        except Exception as error:

            messagebox.showerror(
                "Save Error",
                str(error)
            )

    # ========================================================
    # APPLICATION CLOSE
    # ========================================================

    def on_close(self):

        if self.audit_running:

            confirm = messagebox.askyesno(
                "Audit Running",
                "A security audit is still running.\n\n"
                "Are you sure you want to close the application?"
            )

            if not confirm:

                return

        self.closing = True

        self.root.destroy()


# ============================================================
# APPLICATION ENTRY POINT
# ============================================================

if __name__ == "__main__":

    root = tk.Tk()

    app = FirewallAuditorGUI(
        root
    )

    root.mainloop()