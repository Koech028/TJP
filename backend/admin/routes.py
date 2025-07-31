from flask import render_template, redirect, url_for, flash, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from functools import wraps
from datetime import datetime

from models import db, User, ContactMessage
from flask_mail import Message as MailMsg
from .blueprint import admin_bp
from flask import current_app

# Decorator
def admin_required(view):
    @jwt_required()
    def wrapper(*args, **kwargs):
        user = User.query.get(int(get_jwt_identity()))
        if not user or not user.is_admin:
            flash("Admins only.", "danger")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    wrapper.__name__ = view.__name__
    return wrapper

# ---------------- Admin Home ----------------
@admin_bp.route("/")
@admin_required
def admin_home():
    total_users = User.query.count()
    blocked_users = User.query.filter_by(is_blocked=True).count()
    grouped = {
        "forex": User.query.filter_by(user_group="forex").count(),
        "stock": User.query.filter_by(user_group="stock").count(),
        "crypto": User.query.filter_by(user_group="crypto").count(),
        "multi_asset": User.query.filter_by(user_group="multi_asset").count(),
    }
    unread_msgs = ContactMessage.query.filter_by(status="unread").count()
    return render_template("admin/home.html",
                           total_users=total_users,
                           blocked_users=blocked_users,
                           groups=grouped,
                           unread_msgs=unread_msgs)

# ---------------- Users ----------------
@admin_bp.route("/users")
@admin_required
def list_users():
    search = request.args.get("q", "")
    query = User.query
    if search:
        like = f"%{search}%"
        query = query.filter(User.name.ilike(like) | User.email.ilike(like))
    users = query.order_by(User.created_at.desc()).all()
    return render_template("admin/home.html", users=users, search=search)

@admin_bp.route("/users/<int:user_id>/toggle-block", methods=["POST"])
@admin_required
def toggle_block(user_id):
    u = User.query.get_or_404(user_id)
    u.is_blocked = not u.is_blocked
    db.session.commit()
    flash(f"{'Blocked' if u.is_blocked else 'Unblocked'} {u.email}", "success")
    return redirect(url_for(".list_users"))

@admin_bp.route("/users/<int:user_id>/set-group", methods=["POST"])
@admin_required
def set_group(user_id):
    group = request.form.get("group")
    if group not in {"forex", "stock", "crypto", "multi_asset"}:
        flash("Invalid group.", "danger")
        return redirect(url_for(".list_users"))
    u = User.query.get_or_404(user_id)
    u.user_group = group
    db.session.commit()
    flash(f"Updated group for {u.email} → {group}", "success")
    return redirect(url_for(".list_users"))

# ---------------- Messages ----------------
@admin_bp.route("/messages")
@admin_required
def inbox():
    msgs = ContactMessage.query.order_by(ContactMessage.created_at.desc()).all()
    return render_template("admin/messages.html", msgs=msgs)

@admin_bp.route("/messages/<int:msg_id>/reply", methods=["POST"])
@admin_required
def reply_message(msg_id):
    msg_obj = ContactMessage.query.get_or_404(msg_id)
    body = request.form.get("reply")
    if not body:
        flash("Reply body is required.", "danger")
        return redirect(url_for(".inbox"))

    current_app.extensions['mail'].send(MailMsg(
        subject="Trading Journal Pro – Support Reply",
        recipients=[msg_obj.email],
        body=body
    ))
    msg_obj.status = "replied"
    msg_obj.replied_at = datetime.utcnow()
    db.session.commit()
    flash("Reply sent!", "success")
    return redirect(url_for(".inbox"))




