from flask import Flask
from flask import redirect
from flask import render_template
from flask import request
from flask import jsonify
from flask import session
from flask import url_for
import requests
from flask_wtf import CSRFProtect
from flask_csp.csp import csp_header
import logging
import userManagement as dbHandler

import math

import bcrypt
import os
import datetime

# Code snippet for logging a message
# app.logger.critical("message")

app_log = logging.getLogger(__name__)
logging.basicConfig(
    filename="security_log.log",
    encoding="utf-8",
    level=logging.DEBUG,
    format="%(asctime)s %(message)s",
)

# Generate a unique basic 16 key: https://acte.ltd/utils/randomkeygen
app = Flask(__name__)
app.secret_key = b"_5TvTgyH61Hn1pr9v;apl"
csrf = CSRFProtect(app)

app.config["SESSION_COOKIE_SECURE"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = datetime.timedelta(minutes=30)


@app.before_request
def check_session_timeout():
    if "email" in session:
        session.permanent = True
        if "last_activity" in session:
            last_timestamp = session["last_activity"]
            if isinstance(last_timestamp, datetime.datetime):
                last_timestamp = last_timestamp.timestamp()
            current_timestamp = datetime.datetime.now().timestamp()
            time_elapsed = current_timestamp - last_timestamp
            if time_elapsed > 1800:
                app_log.warning("Session timeout")
                session.clear()
                return redirect("/login.html?timeout=true")
        session["last_activity"] = datetime.datetime.now().timestamp()


# Redirect index.html to domain root for consistent UX
@app.route("/index", methods=["GET"])
@app.route("/index.htm", methods=["GET"])
@app.route("/index.asp", methods=["GET"])
@app.route("/index.php", methods=["GET"])
@app.route("/index.html", methods=["GET"])
def root():
    return redirect("/", 302)


@app.route("/", methods=["POST", "GET"])
@csp_header(
    {
        # Server Side CSP is consistent with meta CSP in layout.html
        "base-uri": "'self'",
        "default-src": "'self'",
        "style-src": "'self'",
        "script-src": "'self'",
        "img-src": "'self' data:",
        "media-src": "'self'",
        "font-src": "'self'",
        "object-src": "'self'",
        "child-src": "'self'",
        "connect-src": "'self'",
        "worker-src": "'self'",
        "report-uri": "/csp_report",
        "frame-ancestors": "'none'",
        "form-action": "'self'",
        "frame-src": "'none'",
    }
)
def index():
    return render_template("/login.html")


@app.route("/devlog.html", methods=["GET", "POST"])
def devlog():
    if "email" in session:
        user = session["email"]
        if request.method == "POST":
            name = dbHandler.getName(user)
            proj_name = request.form.get("proj_name")
            start_time_str = request.form.get("start_time")  # convert to py date
            end_time_str = request.form.get("end_time")  # convert to py date
            repo = request.form.get("repo")
            notes = request.form.get("notes")
            if (
                not proj_name
                or not start_time_str
                or not end_time_str
                or not repo
                or not notes
            ):
                return (
                    render_template("/devlog.html", error="All fields are required"),
                    400,
                )
            try:
                start_time = datetime.datetime.fromisoformat(start_time_str)
                end_time = datetime.datetime.fromisoformat(end_time_str)
            except ValueError:
                return render_template("/devlog.html", error="Invalid date format"), 400
            if end_time <= start_time:
                return (
                    render_template(
                        "/devlog.html", error="End time must be after start time"
                    ),
                    400,
                )
            notes = notes.strip()
            time_diff = end_time - start_time
            total_minutes = time_diff.total_seconds() / 60
            time_worked = math.ceil(total_minutes / 15) * 15
            entry_time = datetime.datetime.now()
            dbHandler.addLogs(
                user,
                name,
                proj_name,
                start_time,
                end_time,
                entry_time,
                time_worked,
                repo,
                notes,
            )
            entries = dbHandler.getLogs()
            return render_template(
                "/devlog.html", success="Entry added", entries=entries
            )
        search_term = request.args.get("search", "").strip()
        filter_date = request.args.get("filter_date", "").strip()
        sort_by = request.args.get("sort_by", "entry_time")
        sort_order = request.args.get("sort_order", "DESC")
        entries = dbHandler.getLogs(
            search_term=search_term if search_term else None,
            filter_by=filter_date if filter_date else None,
            sort_by=sort_by,
            sort_order=sort_order,
        )
        return render_template(
            "/devlog.html",
            success=f"Logged in as {user}",
            entries=entries,
            search_term=search_term,
            filter_date=filter_date,
            sort_by=sort_by,
            sort_order=sort_order,
        )
    else:
        return render_template("/login.html")


@app.route("/privacy.html", methods=["GET"])
def privacy():
    return render_template("/privacy.html")


# example CSRF protected form

# @app.route("/form.html", methods=["POST", "GET"])
# def form():
#     if request.method == "POST":
#         email = request.form["email"]
#         text = request.form["text"]
#         return render_template("/form.html")
#     else:
#         return render_template("/form.html")


@app.route("/login.html", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        if not email or not password:
            return (
                render_template("/login.html", error="Email and password required"),
                400,
            )
        hashedpw = dbHandler.getUsers(email)
        if not hashedpw:
            return render_template("/login.html", error="Invalid credentials"), 401
        if bcrypt.checkpw(password.encode(), hashedpw):
            session["email"] = email
            return redirect("/devlog.html")
        else:
            return render_template("/login.html", error="Invalid credentials"), 401
    else:
        return render_template("/login.html")


@app.route("/signup.html", methods=["POST", "GET"])
def signup():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        if not email or not password or not name:
            return (
                render_template(
                    "/signup.html", error="Email, name and password required"
                ),
                400,
            )
        encodedpass = password.encode()
        hashedpw = bcrypt.hashpw(encodedpass, bcrypt.gensalt(6))
        if dbHandler.insertContact(email.lower().strip(), name.strip(), hashedpw):
            return render_template("/login.html", success="Account created"), 200
        else:
            return render_template("/signup.html", error="Email already exists"), 409
    else:
        return render_template("/signup.html")


@app.route("/logout")
def logout():
    # remove the username from the session if it's there
    session.pop("email", None)
    return redirect("/login.html")


# Endpoint for logging CSP violations
@app.route("/csp_report", methods=["POST"])
@csrf.exempt
def csp_report():
    app.logger.critical(request.data.decode())
    return "done"


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
