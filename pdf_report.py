from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether
)

from analytics import calculate_severity_counts

DARK = colors.HexColor("#111827")
GREY = colors.HexColor("#6b7280")
LIGHT = colors.HexColor("#f3f4f6")

SEVERITY_COLOURS = {
    "HIGH": colors.HexColor("#dc2626"),
    "MEDIUM": colors.HexColor("#d97706"),
    "LOW": colors.HexColor("#16a34a")
}

GRADE_COLOURS = {
    "A": colors.HexColor("#16a34a"),
    "B": colors.HexColor("#65a30d"),
    "C": colors.HexColor("#d97706"),
    "D": colors.HexColor("#ea580c"),
    "F": colors.HexColor("#dc2626")
}


def build_styles():

    styles = getSampleStyleSheet()

    return {
        "title": ParagraphStyle(
            "title", parent=styles["Title"],
            fontSize=20, textColor=DARK, alignment=0, spaceAfter=2
        ),
        "subtitle": ParagraphStyle(
            "subtitle", parent=styles["Normal"],
            fontSize=10, textColor=GREY, spaceAfter=12
        ),
        "heading": ParagraphStyle(
            "heading", parent=styles["Heading2"],
            fontSize=13, textColor=DARK, spaceBefore=12, spaceAfter=6
        ),
        "body": ParagraphStyle(
            "body", parent=styles["Normal"],
            fontSize=10, leading=14
        ),
        "finding_title": ParagraphStyle(
            "finding_title", parent=styles["Normal"],
            fontSize=11, leading=14, fontName="Helvetica-Bold"
        ),
        "small": ParagraphStyle(
            "small", parent=styles["Normal"],
            fontSize=9, leading=12, textColor=GREY
        )
    }


def summary_table(findings, risk_score, security_grade):

    counts = calculate_severity_counts(findings)

    data = [
        ["Security Grade", "Risk Score", "Findings", "High", "Medium", "Low"],
        [
            security_grade,
            str(risk_score),
            str(len(findings)),
            str(counts["high"]),
            str(counts["medium"]),
            str(counts["low"])
        ]
    ]

    table = Table(data, colWidths=[30 * mm] * 6)

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, 1), 16),
        ("TEXTCOLOR", (0, 1), (0, 1),
            GRADE_COLOURS.get(security_grade, DARK)),
        ("TEXTCOLOR", (3, 1), (3, 1), SEVERITY_COLOURS["HIGH"]),
        ("TEXTCOLOR", (4, 1), (4, 1), SEVERITY_COLOURS["MEDIUM"]),
        ("TEXTCOLOR", (5, 1), (5, 1), SEVERITY_COLOURS["LOW"]),
        ("BACKGROUND", (0, 1), (-1, 1), LIGHT),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 1), (-1, 1), 10),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 10)
    ]))

    return table


def finding_block(finding, styles):

    severity = finding.get("severity", "")
    colour = SEVERITY_COLOURS.get(severity, DARK)

    rows = [
        [Paragraph(
            f'{finding["title"]} '
            f'<font color="#{colour.hexval()[2:]}">[{severity}]</font>',
            styles["finding_title"]
        )],
        [Paragraph(f"<b>Resource:</b> {finding['resource']}", styles["body"])],
        [Paragraph(
            f"<b>Recommendation:</b> {finding['recommendation']}",
            styles["body"]
        )]
    ]

    cis = finding.get("cis")

    if cis and cis["framework"] != "Not Mapped":
        rows.append([Paragraph(
            f"Benchmark: {cis['framework']} - {cis['control']}",
            styles["small"]
        )])

    table = Table(rows, colWidths=[180 * mm])

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT),
        ("LINEBEFORE", (0, 0), (0, -1), 3, colour),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3)
    ]))

    return KeepTogether([table, Spacer(1, 6)])


def add_page_number(canvas, doc):

    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(GREY)
    canvas.drawString(15 * mm, 10 * mm, "AzureGuard Security Audit Report")
    canvas.drawRightString(195 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def generate_pdf_report(findings, risk_score, security_grade,
                        scan_time="", source=""):

    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=18 * mm,
        title="AzureGuard Security Audit Report"
    )

    styles = build_styles()

    source_label = {
        "live": "Live Azure scan",
        "upload": "Uploaded snapshot"
    }.get(source, "Not specified")

    story = [
        Paragraph("AzureGuard Security Audit Report", styles["title"]),
        Paragraph(
            f"Scan time: {scan_time or 'N/A'} &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"Source: {source_label}",
            styles["subtitle"]
        ),
        summary_table(findings, risk_score, security_grade),
        Paragraph("Findings", styles["heading"])
    ]

    if not findings:
        story.append(Paragraph("No security findings detected.", styles["body"]))

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

    for finding in sorted(findings, key=lambda f: order.get(f["severity"], 3)):
        story.append(finding_block(finding, styles))

    doc.build(
        story,
        onFirstPage=add_page_number,
        onLaterPages=add_page_number
    )

    return buffer.getvalue()
