import os
from flask import Flask


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-secret-change-me"),
        DATABASE=os.path.join(app.instance_path, "vulndb.sqlite"),
    )

    if test_config:
        app.config.update(test_config)

    if not os.environ.get("DATABASE_URL"):
        # Only needed for the local SQLite file. On Vercel/Postgres the
        # filesystem is read-only anyway, so this is skipped entirely.
        os.makedirs(app.instance_path, exist_ok=True)

    from . import db
    db.init_app(app)

    from . import auth
    app.register_blueprint(auth.bp)

    from . import vulnerabilities
    app.register_blueprint(vulnerabilities.bp)
    app.add_url_rule("/", endpoint="index")

    from . import reports
    app.register_blueprint(reports.bp)

    @app.template_filter("fmtdate")
    def fmtdate_filter(value, fmt="%Y-%m-%d"):
        """Safely format a date whether it's a datetime object or a string."""
        if value is None:
            return "—"
        from datetime import datetime as dt
        if isinstance(value, dt):
            return value.strftime(fmt)
        # It's a string — just truncate to keep the date part
        return str(value)[:10]

    @app.context_processor
    def inject_helpers():
        from .cvss import severity_label, severity_color
        return dict(severity_label=severity_label, severity_color=severity_color)

    return app
