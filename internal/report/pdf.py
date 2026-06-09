import json
import sys
from datetime import datetime

try:
    from fpdf import FPDF
except ModuleNotFoundError:
    sys.stderr.write("fpdf2 is required to generate PDF reports. Install it with: python3 -m pip install fpdf2\n")
    raise


INDIGO_DARK = (30, 27, 75)
INDIGO = (79, 70, 229)
INDIGO_SOFT = (238, 242, 255)
SLATE = (15, 23, 42)
MUTED = (100, 116, 139)
LINE = (226, 232, 240)
WHITE = (255, 255, 255)

SEVERITY_COLORS = {
    "CRITICAL": (220, 38, 38),
    "HIGH": (234, 88, 12),
    "MEDIUM": (217, 119, 6),
    "LOW": (22, 163, 74),
    "INFO": (37, 99, 235),
}

REPLACEMENTS = {
    "\u2014": "-",
    "\u2013": "-",
    "\u2026": "...",
    "\u201c": '"',
    "\u201d": '"',
    "\u2018": "'",
    "\u2019": "'",
    "\u2192": "->",
}


def main():
    report = json.load(sys.stdin)
    pdf = SecurityReportPDF(report)
    pdf.render()
    sys.stdout.buffer.write(bytes(pdf.output()))


def clean(text):
    if text is None:
        return ""

    text = str(text)
    for old, new in REPLACEMENTS.items():
        text = text.replace(old, new)

    return text.encode("latin-1", "replace").decode("latin-1")


def pretty_date(value):
    if not value:
        return "Unknown"

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.strftime("%B %d, %Y at %H:%M UTC")
    except ValueError:
        return value


def count_by_severity(findings):
    counts = {name: 0 for name in SEVERITY_COLORS}
    for finding in list_value(findings):
        counts[finding.get("severity", "INFO")] = counts.get(finding.get("severity", "INFO"), 0) + 1

    return counts


def list_value(value):
    return value if isinstance(value, list) else []


def dict_value(value):
    return value if isinstance(value, dict) else {}


class SecurityReportPDF(FPDF):
    def __init__(self, report):
        super().__init__(format="A4")
        self.report = report
        self.counts = count_by_severity(report.get("findings"))
        self.set_auto_page_break(auto=True, margin=18)
        self.set_margins(16, 16, 16)

    def footer(self):
        if self.page_no() == 1:
            return

        self.set_y(-12)
        self.set_font("Helvetica", size=7)
        self.set_text_color(*MUTED)
        self.cell(0, 6, clean("frameseven CLI v1 - confidential security report"), align="L")
        self.cell(0, 6, clean(f"Page {self.page_no()} / {{nb}}"), align="R")

    def render(self):
        self.alias_nb_pages()
        self.cover()
        self.add_page()
        self.executive_summary()
        self.attack_surface()
        self.scan_errors()
        self.findings()

    def cover(self):
        self.add_page()
        target = self.report.get("target", "")
        findings = list_value(self.report.get("findings"))
        errors = list_value(self.report.get("errors"))

        self.set_fill_color(*INDIGO_DARK)
        self.rect(0, 0, self.w, 122, style="F")

        self.set_xy(16, 24)
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(165, 180, 252)
        self.cell(0, 6, clean("F R A M E S E V E N"), new_x="LMARGIN", new_y="NEXT")

        self.set_xy(16, 40)
        self.set_font("Helvetica", "B", 26)
        self.set_text_color(*WHITE)
        self.cell(0, 12, clean("Web Application"), new_x="LMARGIN", new_y="NEXT")
        self.set_x(16)
        self.cell(0, 12, clean("Security Report"), new_x="LMARGIN", new_y="NEXT")

        self.set_x(16)
        self.ln(2)
        self.set_font("Helvetica", size=10)
        self.set_text_color(199, 210, 254)
        self.multi_cell(
            0,
            5,
            clean("Reconnaissance, validation evidence, impact, and remediation guidance."),
            new_x="LMARGIN",
            new_y="NEXT",
        )

        self.set_xy(16, 88)
        self.set_fill_color(40, 38, 100)
        self.set_text_color(*WHITE)
        self.set_font("Helvetica", "B", 11)
        self.multi_cell(0, 8, clean(f"Target: {target}"), fill=True, padding=(3, 4, 3, 4))

        self.set_xy(16, 136)
        cards = [
            ("FINDINGS", str(len(findings))),
            ("CRITICAL/HIGH", str(self.counts.get("CRITICAL", 0) + self.counts.get("HIGH", 0))),
            ("TOOL ERRORS", str(len(errors))),
            ("STATUS", "Incomplete" if errors else "Complete"),
        ]
        self.metric_cards(cards)

        self.set_xy(16, 174)
        self.set_fill_color(255, 251, 235)
        self.set_text_color(146, 64, 14)
        self.set_font("Helvetica", size=8)
        self.multi_cell(
            0,
            4.4,
            clean(
                "Confidential report generated from an authorized active security scan. "
                "Handle findings, proof of concept data, and request evidence as sensitive material."
            ),
            fill=True,
            padding=(3, 4, 3, 4),
        )

    def metric_cards(self, cards):
        width = (self.w - 32 - 18) / 4
        height = 27
        top = self.get_y()
        x = 16.0

        for label, value in cards:
            self.set_fill_color(248, 250, 252)
            self.set_draw_color(*LINE)
            self.rect(x, top, width, height, style="DF")

            self.set_xy(x + 3, top + 4)
            self.set_font("Helvetica", "B", 6.5)
            self.set_text_color(*MUTED)
            self.cell(width - 6, 4, clean(label), new_x="LMARGIN", new_y="NEXT")

            self.set_xy(x + 3, top + 10)
            self.set_font("Helvetica", "B", 12 if len(value) < 10 else 8)
            self.set_text_color(*INDIGO_DARK)
            self.multi_cell(width - 6, 5, clean(value))

            x += width + 6

        self.set_y(top + height)

    def heading(self, text):
        self.ln(3)
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(*INDIGO_DARK)
        self.cell(0, 8, clean(text), new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*LINE)
        y = self.get_y()
        self.line(self.l_margin, y, self.w - self.r_margin, y)
        self.ln(3)

    def label(self, text):
        self.ln(2)
        self.set_font("Helvetica", "B", 7.5)
        self.set_text_color(*INDIGO)
        self.cell(0, 5, clean(text.upper()), new_x="LMARGIN", new_y="NEXT")

    def body(self, text, size=9.5):
        self.set_font("Helvetica", size=size)
        self.set_text_color(*SLATE)
        self.multi_cell(0, 4.7, clean(text), new_x="LMARGIN", new_y="NEXT")

    def executive_summary(self):
        findings = list_value(self.report.get("findings"))
        total = len(findings)

        self.heading("Executive summary")
        self.body(f"Target: {self.report.get('target', '')}")
        self.body(f"Started: {pretty_date(self.report.get('started_at', ''))}")
        self.body(f"Duration: {self.report.get('duration', '')}")
        self.body(f"Schema version: {self.report.get('schema_version', 'v1')}")

        if total == 0:
            self.ln(3)
            self.body("No findings were recorded during this scan.")
            return

        self.ln(4)
        bar_width = self.w - self.l_margin - self.r_margin
        x = self.l_margin
        y = self.get_y()
        for severity, color in SEVERITY_COLORS.items():
            count = self.counts.get(severity, 0)
            if count == 0:
                continue

            segment = bar_width * count / total
            self.set_fill_color(*color)
            self.rect(x, y, segment, 4, style="F")
            x += segment

        self.ln(8)
        for severity, color in SEVERITY_COLORS.items():
            self.severity_row(severity, self.counts.get(severity, 0), color)

    def severity_row(self, severity, count, color):
        y = self.get_y()
        self.set_fill_color(*color)
        self.rect(self.l_margin, y + 1.9, 2.8, 2.8, style="F")
        self.set_xy(self.l_margin + 5, y)
        self.set_font("Helvetica", size=9)
        self.set_text_color(*SLATE)
        self.cell(70, 6, clean(severity.title()))
        self.set_font("Helvetica", "B", 9)
        self.cell(0, 6, str(count), align="R", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*LINE)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())

    def attack_surface(self):
        surface = dict_value(self.report.get("surface"))
        self.heading("Attack surface")

        values = [
            ("Host", surface.get("host", "")),
            ("Base URL", surface.get("base_url", "")),
            ("Technologies", str(len(list_value(surface.get("technologies"))))),
            ("Endpoints", str(len(list_value(surface.get("endpoints"))))),
            ("Parameters", str(len(list_value(surface.get("params"))))),
            ("Sensitive files", str(len(list_value(surface.get("sensitive_files"))))),
        ]

        for label, value in values:
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(*MUTED)
            self.cell(38, 5, clean(label + ":"))
            self.set_font("Helvetica", size=8.5)
            self.set_text_color(*SLATE)
            self.multi_cell(0, 5, clean(value), new_x="LMARGIN", new_y="NEXT")

        self.compact_list("Technologies", [
            f"{item.get('name', '')} {item.get('version', '')}".strip()
            for item in list_value(surface.get("technologies"))
        ])
        self.compact_list("Endpoints", list_value(surface.get("endpoints"))[:12])
        self.compact_list("Parameters", [
            f"{item.get('name', '')} [{item.get('method', '')}] {item.get('endpoint', '')}"
            for item in list_value(surface.get("params"))[:12]
        ])
        self.compact_list("Sensitive files", list_value(surface.get("sensitive_files"))[:12])

    def compact_list(self, title, values):
        if not values:
            return

        self.label(title)
        self.set_font("Helvetica", size=8)
        self.set_text_color(*SLATE)
        for value in values:
            self.multi_cell(0, 4.2, clean(f"- {value}"), new_x="LMARGIN", new_y="NEXT")

    def scan_errors(self):
        errors = list_value(self.report.get("errors"))
        if not errors:
            return

        self.heading("Scan errors")
        for error in errors:
            self.callout(
                error.get("module", "unknown"),
                error.get("message", ""),
                (234, 88, 12),
                (255, 247, 237),
            )

    def findings(self):
        findings = list_value(self.report.get("findings"))
        self.heading("Security findings")

        if not findings:
            self.body("No findings were recorded during this scan.")
            return

        for index, finding in enumerate(findings, start=1):
            self.finding(index, finding)

    def finding(self, index, finding):
        if self.get_y() > self.h - 76:
            self.add_page()

        severity = finding.get("severity", "INFO")
        color = SEVERITY_COLORS.get(severity, MUTED)
        y = self.get_y()

        self.set_fill_color(250, 251, 252)
        self.rect(self.l_margin, y, self.w - self.l_margin - self.r_margin, 23, style="F")
        self.set_fill_color(*color)
        self.rect(self.l_margin, y, 2.4, 23, style="F")

        self.set_xy(self.l_margin + 6, y + 3)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*INDIGO)
        self.cell(0, 4, clean(f"FS-{index:03d}"), new_x="LMARGIN", new_y="NEXT")

        self.set_x(self.l_margin + 6)
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(*SLATE)
        self.multi_cell(0, 5.5, clean(finding.get("title", "")), new_x="LMARGIN", new_y="NEXT")

        self.set_x(self.l_margin + 6)
        self.badge(severity, WHITE, color)
        self.badge(finding.get("module", ""), INDIGO, INDIGO_SOFT)
        if finding.get("cvss"):
            self.badge(f"CVSS {finding.get('cvss')}", MUTED, (241, 245, 249))
        if finding.get("cwe"):
            self.badge(finding.get("cwe", ""), MUTED, (241, 245, 249))
        if finding.get("owasp"):
            self.badge(finding.get("owasp", ""), MUTED, (241, 245, 249))

        self.set_xy(self.l_margin, y + 27)
        self.label("Description")
        self.body(finding.get("description", ""))

        evidence = dict_value(finding.get("evidence"))
        if evidence.get("extracted"):
            self.code_block("Extracted evidence", evidence.get("extracted", ""))
        if evidence.get("request"):
            self.code_block("HTTP request", evidence.get("request", ""))
        if evidence.get("response"):
            self.code_block("HTTP response", evidence.get("response", ""))

        steps = list_value(finding.get("next_steps"))
        if steps:
            self.callout("Recommended next steps", "\n".join(f"- {step}" for step in steps), (34, 197, 94), (240, 253, 244))

        self.ln(4)

    def badge(self, text, fg, bg):
        if not text:
            return

        self.set_font("Helvetica", "B", 6.5)
        text = clean(text)
        width = self.get_string_width(text) + 5
        x = self.get_x()
        y = self.get_y()

        if x + width > self.w - self.r_margin:
            x = self.l_margin + 6
            y += 5.8
            self.set_xy(x, y)

        self.set_fill_color(*bg)
        self.rect(x, y, width, 4.8, style="F", round_corners=True, corner_radius=2.3)
        self.set_text_color(*fg)
        self.set_xy(x, y - 0.2)
        self.cell(width, 5, text, align="C")
        self.set_xy(x + width + 2, y)

    def code_block(self, label, text):
        self.label(label)
        self.set_font("Courier", size=7.5)
        self.set_fill_color(*SLATE)
        self.set_text_color(226, 232, 240)
        self.multi_cell(0, 4, clean(text), fill=True, padding=3, new_x="LMARGIN", new_y="NEXT")
        self.ln(1.5)

    def callout(self, label, text, rgb, bg):
        self.label(label)
        self.set_fill_color(*bg)
        self.set_draw_color(*rgb)
        self.set_text_color(*SLATE)
        self.set_font("Helvetica", size=9)

        y0 = self.get_y()
        self.multi_cell(0, 4.6, clean(text), fill=True, padding=(3, 4, 3, 6), new_x="LMARGIN", new_y="NEXT")
        y1 = self.get_y()
        self.set_fill_color(*rgb)
        self.rect(self.l_margin, y0, 1.6, y1 - y0, style="F")
        self.ln(1.5)


if __name__ == "__main__":
    main()
