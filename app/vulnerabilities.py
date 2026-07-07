from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)

from .db import get_db
from .auth import login_required, role_required
from .cvss import calculate_cvss, severity_label
from .owasp_risk import calculate_owasp_risk, LIKELIHOOD_FACTORS, IMPACT_FACTORS

bp = Blueprint("vulnerabilities", __name__)


@bp.route("/")
@login_required
def dashboard():
    db = get_db()
    vulns = db.execute(
        """
        SELECT v.*, a.name AS asset_name, u.username AS assignee
        FROM vulnerability v
        LEFT JOIN asset a ON v.asset_id = a.id
        LEFT JOIN user u ON v.assigned_to = u.id
        ORDER BY v.cvss_score DESC, v.created_at DESC
        """
    ).fetchall()

    stats = {
        "total": len(vulns),
        "open": sum(1 for v in vulns if v["status"] == "open"),
        "in_progress": sum(1 for v in vulns if v["status"] == "in_progress"),
        "remediated": sum(1 for v in vulns if v["status"] == "remediated"),
        "critical": sum(1 for v in vulns if v["cvss_severity"] == "Critical"),
        "high": sum(1 for v in vulns if v["cvss_severity"] == "High"),
        "medium": sum(1 for v in vulns if v["cvss_severity"] == "Medium"),
        "low": sum(1 for v in vulns if v["cvss_severity"] == "Low"),
    }

    status_filter = request.args.get("status")
    severity_filter = request.args.get("severity")
    if status_filter:
        vulns = [v for v in vulns if v["status"] == status_filter]
    if severity_filter:
        vulns = [v for v in vulns if v["cvss_severity"] == severity_filter]

    return render_template("vulnerabilities/dashboard.html", vulns=vulns, stats=stats,
                            status_filter=status_filter, severity_filter=severity_filter)


@bp.route("/vulnerabilities/new", methods=("GET", "POST"))
@login_required
@role_required("admin", "analyst")
def create():
    db = get_db()
    assets = db.execute("SELECT * FROM asset ORDER BY name").fetchall()
    users = db.execute("SELECT * FROM user ORDER BY username").fetchall()

    if request.method == "POST":
        title = request.form["title"].strip()
        description = request.form.get("description", "").strip()
        asset_id = request.form.get("asset_id") or None
        assigned_to = request.form.get("assigned_to") or None
        due_date = request.form.get("due_date") or None

        error = None
        if not title:
            error = "Title is required."

        # CVSS inputs
        av = request.form.get("cvss_av", "N")
        ac = request.form.get("cvss_ac", "L")
        pr = request.form.get("cvss_pr", "N")
        ui = request.form.get("cvss_ui", "N")
        s = request.form.get("cvss_s", "U")
        c = request.form.get("cvss_c", "N")
        i = request.form.get("cvss_i", "N")
        a = request.form.get("cvss_a", "N")

        if error is None:
            score, severity, vector = calculate_cvss(av, ac, pr, ui, s, c, i, a)

            # OWASP risk rating inputs (0-9 each factor)
            likelihood_factors = {}
            for f in LIKELIHOOD_FACTORS:
                likelihood_factors[f] = float(request.form.get(f"owasp_{f}", 0) or 0)
            impact_factors = {}
            for f in IMPACT_FACTORS:
                impact_factors[f] = float(request.form.get(f"owasp_{f}", 0) or 0)

            likelihood_score, impact_score, risk_level = calculate_owasp_risk(
                likelihood_factors, impact_factors
            )

            db.execute(
                """
                INSERT INTO vulnerability (
                    title, description, asset_id, reported_by, assigned_to,
                    cvss_av, cvss_ac, cvss_pr, cvss_ui, cvss_s, cvss_c, cvss_i, cvss_a,
                    cvss_score, cvss_severity, cvss_vector,
                    owasp_likelihood, owasp_impact, owasp_risk_score, owasp_risk_level,
                    status, due_date
                ) VALUES (?,?,?,?,?, ?,?,?,?,?,?,?,?, ?,?,?, ?,?,?,?, ?,?)
                """,
                (
                    title, description, asset_id, g.user["id"], assigned_to,
                    av, ac, pr, ui, s, c, i, a,
                    score, severity, vector,
                    likelihood_score, impact_score, max(likelihood_score, impact_score), risk_level,
                    "open", due_date,
                ),
            )
            db.commit()
            flash(f"Vulnerability '{title}' created (CVSS {score} / {severity}).", "success")
            return redirect(url_for("vulnerabilities.dashboard"))

        flash(error, "danger")

    return render_template("vulnerabilities/form.html", assets=assets, users=users,
                            vuln=None, likelihood_factors=LIKELIHOOD_FACTORS,
                            impact_factors=IMPACT_FACTORS)


@bp.route("/vulnerabilities/<int:vuln_id>")
@login_required
def view(vuln_id):
    db = get_db()
    vuln = db.execute(
        """
        SELECT v.*, a.name AS asset_name, u.username AS assignee, r.username AS reporter
        FROM vulnerability v
        LEFT JOIN asset a ON v.asset_id = a.id
        LEFT JOIN user u ON v.assigned_to = u.id
        LEFT JOIN user r ON v.reported_by = r.id
        WHERE v.id = ?
        """,
        (vuln_id,),
    ).fetchone()
    if vuln is None:
        flash("Vulnerability not found.", "danger")
        return redirect(url_for("vulnerabilities.dashboard"))

    history = db.execute(
        """
        SELECT h.*, u.username FROM vuln_history h
        LEFT JOIN user u ON h.changed_by = u.id
        WHERE h.vuln_id = ? ORDER BY h.changed_at DESC
        """,
        (vuln_id,),
    ).fetchall()

    return render_template("vulnerabilities/view.html", vuln=vuln, history=history)


@bp.route("/vulnerabilities/<int:vuln_id>/status", methods=("POST",))
@login_required
@role_required("admin", "analyst")
def update_status(vuln_id):
    db = get_db()
    new_status = request.form.get("status")
    notes = request.form.get("remediation_notes", "")

    vuln = db.execute("SELECT * FROM vulnerability WHERE id = ?", (vuln_id,)).fetchone()
    if vuln is None:
        flash("Vulnerability not found.", "danger")
        return redirect(url_for("vulnerabilities.dashboard"))

    old_status = vuln["status"]
    db.execute(
        "UPDATE vulnerability SET status = ?, remediation_notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (new_status, notes, vuln_id),
    )
    db.execute(
        """
        INSERT INTO vuln_history (vuln_id, changed_by, field_changed, old_value, new_value)
        VALUES (?, ?, 'status', ?, ?)
        """,
        (vuln_id, g.user["id"], old_status, new_status),
    )
    db.commit()
    flash("Status updated.", "success")
    return redirect(url_for("vulnerabilities.view", vuln_id=vuln_id))


@bp.route("/vulnerabilities/<int:vuln_id>/delete", methods=("POST",))
@login_required
@role_required("admin")
def delete(vuln_id):
    db = get_db()
    db.execute("DELETE FROM vulnerability WHERE id = ?", (vuln_id,))
    db.commit()
    flash("Vulnerability deleted.", "info")
    return redirect(url_for("vulnerabilities.dashboard"))


# ---- Assets ----

@bp.route("/assets", methods=("GET", "POST"))
@login_required
def assets():
    db = get_db()
    if request.method == "POST":
        if g.user["role"] not in ("admin", "analyst"):
            flash("You do not have permission to add assets.", "danger")
            return redirect(url_for("vulnerabilities.assets"))
        name = request.form["name"].strip()
        asset_type = request.form.get("asset_type", "")
        owner = request.form.get("owner", "")
        if name:
            db.execute(
                "INSERT INTO asset (name, asset_type, owner) VALUES (?, ?, ?)",
                (name, asset_type, owner),
            )
            db.commit()
            flash(f"Asset '{name}' added.", "success")
        return redirect(url_for("vulnerabilities.assets"))

    asset_list = db.execute(
        """
        SELECT a.*, COUNT(v.id) AS vuln_count
        FROM asset a LEFT JOIN vulnerability v ON v.asset_id = a.id
        GROUP BY a.id ORDER BY a.name
        """
    ).fetchall()
    return render_template("vulnerabilities/assets.html", assets=asset_list)


@bp.route("/assets/<int:asset_id>/delete", methods=("POST",))
@login_required
@role_required("admin")
def delete_asset(asset_id):
    db = get_db()
    db.execute("DELETE FROM asset WHERE id = ?", (asset_id,))
    db.commit()
    flash("Asset deleted.", "info")
    return redirect(url_for("vulnerabilities.assets"))
