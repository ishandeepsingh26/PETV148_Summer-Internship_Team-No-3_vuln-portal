import csv
import io
from datetime import datetime

from flask import Blueprint, Response, render_template, send_file
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
)

from .db import get_db
from .auth import login_required

bp = Blueprint("reports", __name__, url_prefix="/reports")


def _fetch_vulns(db):
    return db.execute(
        """
        SELECT v.*, a.name AS asset_name, u.username AS assignee
        FROM vulnerability v
        LEFT JOIN asset a ON v.asset_id = a.id
        LEFT JOIN user u ON v.assigned_to = u.id
        ORDER BY v.cvss_score DESC
        """
    ).fetchall()


@bp.route("/")
@login_required
def index():
    return render_template("reports/index.html")


@bp.route("/export/csv")
@login_required
def export_csv():
    db = get_db()
    vulns = _fetch_vulns(db)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Title", "Asset", "Assignee", "CVSS Score", "CVSS Severity",
        "CVSS Vector", "OWASP Risk Level", "Status", "Due Date", "Created At"
    ])
    for v in vulns:
        writer.writerow([
            v["id"], v["title"], v["asset_name"] or "", v["assignee"] or "",
            v["cvss_score"], v["cvss_severity"], v["cvss_vector"],
            v["owasp_risk_level"], v["status"], v["due_date"] or "", v["created_at"],
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=vuln_report_{datetime.now():%Y%m%d}.csv"},
    )


@bp.route("/export/pdf")
@login_required
def export_pdf():
    db = get_db()
    vulns = _fetch_vulns(db)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, title="Vulnerability Report")
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("Vulnerability Management Report", styles["Title"]))
    elements.append(Paragraph(f"Generated: {datetime.now():%Y-%m-%d %H:%M}", styles["Normal"]))
    elements.append(Spacer(1, 16))

    total = len(vulns)
    critical = sum(1 for v in vulns if v["cvss_severity"] == "Critical")
    high = sum(1 for v in vulns if v["cvss_severity"] == "High")
    open_count = sum(1 for v in vulns if v["status"] == "open")
    summary = (
        f"Total findings: {total} &nbsp;|&nbsp; Critical: {critical} &nbsp;|&nbsp; "
        f"High: {high} &nbsp;|&nbsp; Open: {open_count}"
    )
    elements.append(Paragraph(summary, styles["Normal"]))
    elements.append(Spacer(1, 16))

    data = [["ID", "Title", "Asset", "CVSS", "Severity", "Risk", "Status"]]
    for v in vulns:
        data.append([
            str(v["id"]),
            Paragraph(v["title"] or "", styles["Normal"]),
            v["asset_name"] or "-",
            str(v["cvss_score"] or "-"),
            v["cvss_severity"] or "-",
            v["owasp_risk_level"] or "-",
            v["status"],
        ])

    table = Table(data, colWidths=[30, 160, 80, 40, 55, 55, 70], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
    ]))
    elements.append(table)

    doc.build(elements)
    buf.seek(0)

    return send_file(
        buf,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"vuln_report_{datetime.now():%Y%m%d}.pdf",
    )
