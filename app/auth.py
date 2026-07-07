import functools
import re
from typing import Optional
import bcrypt
from zxcvbn import zxcvbn
from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)

from .db import get_db

bp = Blueprint("auth", __name__, url_prefix="/auth")

MIN_ZXCVBN_SCORE = 2  # 0 (weak) - 4 (strong); require at least "fair"

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# Requires a leading + and country code, e.g. +1 5551234567, +91 9876543210
PHONE_RE = re.compile(r"^\+[1-9]\d{0,3}[\s-]?\d{6,12}$")


def validate_email(email: str) -> Optional[str]:
    if not email or not EMAIL_RE.match(email.strip()):
        return "Enter a valid email address (e.g. name@example.com)."
    return None


def validate_phone(phone: str) -> Optional[str]:
    if not phone or not PHONE_RE.match(phone.strip()):
        return "Enter a valid phone number with country code (e.g. +1 5551234567 or +919876543210)."
    return None


def hash_password(plain_password: str) -> str:
    return bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def check_password(plain_password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False


def evaluate_password_strength(password: str, user_inputs=None):
    result = zxcvbn(password, user_inputs=user_inputs or [])
    return {
        "score": result["score"],  # 0-4
        "warning": result["feedback"].get("warning", ""),
        "suggestions": result["feedback"].get("suggestions", []),
    }


@bp.route("/register", methods=("GET", "POST"))
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form["password"]
        confirm = request.form.get("confirm_password", "")
        # Public self-registration can NEVER create an admin account. Admin
        # is a single seeded account (see db.py) that can only log in — it
        # cannot be created, added, or promoted to from anywhere in the app.
        requested_role = request.form.get("role", "viewer")
        role = requested_role if requested_role in ("viewer", "analyst") else "viewer"

        db = get_db()
        error = None

        if not username or not password:
            error = "Username and password are required."
        elif not email:
            error = "Email address is required."
        elif not phone:
            error = "Phone number (with country code) is required."
        elif password != confirm:
            error = "Passwords do not match."
        else:
            error = validate_email(email) or validate_phone(phone)

        if error is None:
            strength = evaluate_password_strength(password, user_inputs=[username, email])
            if strength["score"] < MIN_ZXCVBN_SCORE:
                error = (
                    f"Password is too weak ({strength['warning'] or 'low entropy'}). "
                    f"Suggestions: {'; '.join(strength['suggestions']) or 'use a longer, less predictable password'}."
                )

        if error is None:
            existing = db.execute(
                "SELECT id FROM user WHERE username = ?", (username,)
            ).fetchone()
            existing_email = db.execute(
                "SELECT id FROM user WHERE email = ?", (email,)
            ).fetchone()
            if existing:
                error = f"User '{username}' is already registered."
            elif existing_email:
                error = "An account with that email address already exists."
            else:
                db.execute(
                    "INSERT INTO user (username, email, phone, password_hash, role) VALUES (?, ?, ?, ?, ?)",
                    (username, email, phone, hash_password(password), role),
                )
                db.commit()
                flash("Registration successful. Please log in.", "success")
                return redirect(url_for("auth.login"))

        flash(error, "danger")

    return render_template("auth/register.html")


@bp.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        db = get_db()

        user = db.execute(
            "SELECT * FROM user WHERE username = ?", (username,)
        ).fetchone()

        if user is None or not check_password(password, user["password_hash"]):
            flash("Incorrect username or password.", "danger")
            return render_template("auth/login.html")

        session.clear()
        session["user_id"] = user["id"]
        flash(f"Welcome back, {user['username']}.", "success")
        return redirect(url_for("vulnerabilities.dashboard"))

    return render_template("auth/login.html")


@bp.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get("user_id")
    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            "SELECT * FROM user WHERE id = ?", (user_id,)
        ).fetchone()


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("auth.login"))
        return view(**kwargs)
    return wrapped_view


def role_required(*roles):
    def decorator(view):
        @functools.wraps(view)
        def wrapped_view(**kwargs):
            if g.user is None:
                return redirect(url_for("auth.login"))
            if g.user["role"] not in roles:
                flash("You do not have permission to perform that action.", "danger")
                return redirect(url_for("vulnerabilities.dashboard"))
            return view(**kwargs)
        return wrapped_view
    return decorator


# ---------------------------------------------------------------------------
# Admin-only user management
#
# IMPORTANT: The admin account is seeded once (see db.py: seed_admin) and is
# never created, added, or promoted-to through the application. Admin can
# only log in with the seeded credentials. This panel manages analyst/viewer
# accounts only.
# ---------------------------------------------------------------------------

MANAGEABLE_ROLES = ("analyst", "viewer")  # admin is intentionally excluded


@bp.route("/users")
@login_required
@role_required("admin")
def manage_users():
    db = get_db()
    users = db.execute("SELECT * FROM user ORDER BY role, username").fetchall()
    return render_template("auth/users.html", users=users)


@bp.route("/users/new", methods=("POST",))
@login_required
@role_required("admin")
def add_user():
    username = request.form["username"].strip()
    email = request.form.get("email", "").strip().lower()
    phone = request.form.get("phone", "").strip()
    password = request.form["password"]
    role = request.form.get("role", "viewer")

    db = get_db()
    error = None

    if not username or not password:
        error = "Username and password are required."
    elif not email:
        error = "Email address is required."
    elif not phone:
        error = "Phone number (with country code) is required."
    elif role not in MANAGEABLE_ROLES:
        error = "Invalid role. Admin accounts cannot be created here."
    else:
        error = validate_email(email) or validate_phone(phone)

    if error is None:
        strength = evaluate_password_strength(password, user_inputs=[username, email])
        if strength["score"] < MIN_ZXCVBN_SCORE:
            error = f"Password is too weak ({strength['warning'] or 'low entropy'})."

    if error is None:
        existing = db.execute("SELECT id FROM user WHERE username = ?", (username,)).fetchone()
        existing_email = db.execute("SELECT id FROM user WHERE email = ?", (email,)).fetchone()
        if existing:
            error = f"User '{username}' already exists."
        elif existing_email:
            error = "An account with that email address already exists."
        else:
            db.execute(
                "INSERT INTO user (username, email, phone, password_hash, role) VALUES (?, ?, ?, ?, ?)",
                (username, email, phone, hash_password(password), role),
            )
            db.commit()
            flash(f"User '{username}' created with role '{role}'.", "success")
            return redirect(url_for("auth.manage_users"))

    flash(error, "danger")
    return redirect(url_for("auth.manage_users"))


@bp.route("/users/<int:user_id>/role", methods=("POST",))
@login_required
@role_required("admin")
def change_role(user_id):
    new_role = request.form.get("role")
    db = get_db()

    if new_role not in MANAGEABLE_ROLES:
        flash("Invalid role. No one can be promoted to Admin through this panel.", "danger")
        return redirect(url_for("auth.manage_users"))

    target = db.execute("SELECT * FROM user WHERE id = ?", (user_id,)).fetchone()
    if target is None:
        flash("User not found.", "danger")
        return redirect(url_for("auth.manage_users"))

    if target["role"] == "admin":
        flash("The Admin account cannot be modified here.", "warning")
        return redirect(url_for("auth.manage_users"))

    db.execute("UPDATE user SET role = ? WHERE id = ?", (new_role, user_id))
    db.commit()
    flash(f"Updated {target['username']}'s role to '{new_role}'.", "success")
    return redirect(url_for("auth.manage_users"))


@bp.route("/users/<int:user_id>/delete", methods=("POST",))
@login_required
@role_required("admin")
def delete_user(user_id):
    db = get_db()
    target = db.execute("SELECT * FROM user WHERE id = ?", (user_id,)).fetchone()

    if target is None:
        flash("User not found.", "danger")
    elif target["role"] == "admin":
        flash("The Admin account cannot be deleted.", "warning")
    elif target["id"] == g.user["id"]:
        flash("You cannot delete your own account while logged in as it.", "warning")
    else:
        db.execute("DELETE FROM user WHERE id = ?", (user_id,))
        db.commit()
        flash(f"User '{target['username']}' deleted.", "info")

    return redirect(url_for("auth.manage_users"))


# ---------------------------------------------------------------------------
# Profile editing
#
# Every user (including admin) can edit their own profile. Admin can also
# edit anyone else's profile fields (username/email/phone/password) — but
# this still goes through the same code path as everything else: it never
# lets anyone change a `role`, so it can't be used as a backdoor to grant
# admin or alter permissions. Role changes stay exclusively in change_role,
# which already refuses to touch the admin account.
# ---------------------------------------------------------------------------

def _update_profile(target, form, *, require_current_password):
    """
    Shared logic for updating a user record (self-edit or admin-edit).
    Returns an error string, or None on success.
    """
    db = get_db()

    username = form.get("username", "").strip()
    email = form.get("email", "").strip().lower()
    phone = form.get("phone", "").strip()
    new_password = form.get("new_password", "")
    confirm_password = form.get("confirm_password", "")
    current_password = form.get("current_password", "")

    if not username:
        return "Username is required."
    if not email:
        return "Email address is required."
    if not phone:
        return "Phone number (with country code) is required."

    error = validate_email(email) or validate_phone(phone)
    if error:
        return error

    if require_current_password and (new_password or username != target["username"] or email != (target["email"] or "") or phone != (target["phone"] or "")):
        if not current_password or not check_password(current_password, target["password_hash"]):
            return "Current password is incorrect."

    if new_password:
        if new_password != confirm_password:
            return "New passwords do not match."
        strength = evaluate_password_strength(new_password, user_inputs=[username, email])
        if strength["score"] < MIN_ZXCVBN_SCORE:
            return f"New password is too weak ({strength['warning'] or 'low entropy'})."

    name_clash = db.execute(
        "SELECT id FROM user WHERE username = ? AND id != ?", (username, target["id"])
    ).fetchone()
    if name_clash:
        return f"Username '{username}' is already taken."

    email_clash = db.execute(
        "SELECT id FROM user WHERE email = ? AND id != ?", (email, target["id"])
    ).fetchone()
    if email_clash:
        return "That email address is already in use by another account."

    if new_password:
        db.execute(
            "UPDATE user SET username = ?, email = ?, phone = ?, password_hash = ? WHERE id = ?",
            (username, email, phone, hash_password(new_password), target["id"]),
        )
    else:
        db.execute(
            "UPDATE user SET username = ?, email = ?, phone = ? WHERE id = ?",
            (username, email, phone, target["id"]),
        )
    db.commit()
    return None


@bp.route("/profile", methods=("GET", "POST"))
@login_required
def profile():
    if request.method == "POST":
        error = _update_profile(g.user, request.form, require_current_password=True)
        if error:
            flash(error, "danger")
        else:
            flash("Profile updated.", "success")
            return redirect(url_for("auth.profile"))

    return render_template("auth/profile.html", target=g.user, is_self=True)


@bp.route("/users/<int:user_id>/edit", methods=("GET", "POST"))
@login_required
@role_required("admin")
def edit_user(user_id):
    db = get_db()
    target = db.execute("SELECT * FROM user WHERE id = ?", (user_id,)).fetchone()
    if target is None:
        flash("User not found.", "danger")
        return redirect(url_for("auth.manage_users"))

    if target["role"] == "admin" and target["id"] != g.user["id"]:
        flash("The Admin account cannot be edited here.", "warning")
        return redirect(url_for("auth.manage_users"))

    if request.method == "POST":
        # Admin editing someone else's profile doesn't need that other
        # person's current password — admin authority already gated this
        # route. Admin editing their own profile still confirms identity.
        require_current = target["id"] == g.user["id"]
        error = _update_profile(target, request.form, require_current_password=require_current)
        if error:
            flash(error, "danger")
        else:
            flash(f"Profile for '{target['username']}' updated.", "success")
            return redirect(url_for("auth.manage_users"))
        target = db.execute("SELECT * FROM user WHERE id = ?", (user_id,)).fetchone()

    return render_template("auth/profile.html", target=target, is_self=(target["id"] == g.user["id"]))
