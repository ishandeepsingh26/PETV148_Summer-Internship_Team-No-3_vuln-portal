# Vulnerability Report Management Portal

A centralized Flask portal to track discovered vulnerabilities, score them with
CVSS v3.1 and OWASP Risk Rating Methodology, monitor remediation status, and
generate reports.

## Stack
- Python / Flask
- SQLite (stdlib sqlite3)
- bcrypt (password hashing)
- zxcvbn (password strength estimation, client + server side)
- reportlab (PDF report generation)

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python run.py
```

The app initializes the SQLite schema automatically in `instance/vulndb.sqlite`
on first run. Visit http://localhost:5000, register an account, and start
logging findings.

## Features
- **Auth**: bcrypt-hashed passwords, zxcvbn strength gate on registration
  (server-enforced, with a live client-side meter), role-based access
  (admin / analyst / viewer).
- **CVSS v3.1 scoring**: full base-metric calculator (`app/cvss.py`) following
  the FIRST.org spec, with a live JS preview on the finding form and the
  Python implementation as the authoritative source of truth.
- **OWASP Risk Rating**: likelihood/impact factor sliders (8 likelihood +
  8 impact factors, 0-9 scale) combined via the standard OWASP risk matrix
  (`app/owasp_risk.py`).
- **Vulnerability lifecycle**: open -> in_progress -> remediated /
  accepted_risk / false_positive, with full audit history per finding.
- **Asset inventory**: track which system/app each finding belongs to.
- **Reporting**: CSV export and a formatted PDF executive report
  (reportlab), both reflecting current CVSS/OWASP data.

## Project layout
```
app/
  __init__.py        Flask app factory
  db.py               SQLite schema + connection handling
  auth.py             Registration/login, bcrypt, zxcvbn
  cvss.py             CVSS v3.1 base score calculator
  owasp_risk.py        OWASP Risk Rating Methodology calculator
  vulnerabilities.py  Dashboard, CRUD, status workflow, assets
  reports.py          CSV/PDF report generation
  templates/          Jinja2 + Bootstrap 5 UI
run.py                 Entry point
```

## Notes
- Set `SECRET_KEY` env var in production.
- This is a learning/demo project; for production use, add CSRF protection
  (Flask-WTF), rate limiting on auth routes, and migrate off SQLite if
  multi-user concurrency becomes a concern.

## Admin account

There is no "add admin" anywhere in the app. The Admin account is a single,
pre-configured account seeded automatically the first time the app starts:

- Default username: `admin`
- Default password: `ChangeMe123!`

**Change these before running anywhere real** by setting environment
variables before starting the app:

```cmd
set ADMIN_USERNAME=admin
set ADMIN_PASSWORD=YourRealPasswordHere
python run.py
```

Admin can only log in — it can't be created, added, or promoted to from the
registration page or the Admin panel. The Admin panel can create/edit/delete
Analyst and Viewer accounts only.
