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

import bcrypt
import os
from datetime import timedelta

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
    return render_template("/index.html")


@app.route("/devlog.html", methods=["GET", "POST"])
def devlog():
    if "email" in session:
        if request.method == "POST":
            print()
            # todo: add form thing for adding devlogs
        user = session["email"]
        return render_template("/devlog.html", success=f"Logged in as {user}")
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
        if dbHandler.insertContact(email, name, hashedpw):
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
