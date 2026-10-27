from __future__ import annotations

import argparse
import logging
import secrets
from datetime import datetime
from functools import wraps
from typing import Callable

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

DEMO_PASSWORDS = {
    "alice": "alice123",
    "mallory": "mallory123",
    "bob": "bob123",
}


def create_app(mode: str) -> Flask:
    app = Flask(__name__)

    # -----------------------------------------------------------------------
    # Demo state.
    #
    # In memory on purpose: the assignment is about CSRF, not databases.
    # Each app instance starts with Alice at 1,000 and Mallory at 0.
    # -----------------------------------------------------------------------
    users: dict[str, dict[str, object]] = {
        "alice": {
            "password_hash": generate_password_hash(DEMO_PASSWORDS["alice"]),
            "balance": 1000,
        },
        "mallory": {
            "password_hash": generate_password_hash(DEMO_PASSWORDS["mallory"]),
            "balance": 0,
        },
        "bob": {
            "password_hash": generate_password_hash(DEMO_PASSWORDS["bob"]),
            "balance": 500,
        },
    }
    transfers: list[dict[str, object]] = []

    # A random key is fine for a local demo. Restarting invalidates sessions.
    app.config.update(
        SECRET_KEY=secrets.token_hex(32),
        SESSION_COOKIE_NAME="csrf_demo_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=False,  # local HTTP demo; use HTTPS + Secure in production
        # This is the only security-relevant difference between the two modes.
        SESSION_COOKIE_SAMESITE="Lax" if mode == "vulnerable" else "Strict",
        MODE=mode,
    )

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    def current_user() -> str | None:
        username = session.get("user")
        if username not in users:
            return None
        return username

    def login_required(view: Callable) -> Callable:
        @wraps(view)
        def wrapped(*args, **kwargs):
            if current_user() is None:
                return redirect(url_for("login"))
            return view(*args, **kwargs)

        return wrapped

    @app.context_processor
    def inject_globals() -> dict[str, object]:
        return {
            "mode": app.config["MODE"],
            "current_user": current_user(),
        }

    @app.get("/")
    def index():
        if current_user() is not None:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            if current_user() is not None:
                return redirect(url_for("dashboard"))
            return render_template("login.html")

        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        user = users.get(username)

        if user is None or not check_password_hash(str(user["password_hash"]), password):
            app.logger.warning(
                "LOGIN_FAILED user=%r remote=%s", username, request.remote_addr
            )
            flash("Invalid username or password.", "error")
            return render_template("login.html"), 401

        session.clear()
        session["user"] = username
        app.logger.info(
            "LOGIN_OK user=%s remote=%s cookie_samesite=%s",
            username,
            request.remote_addr,
            app.config["SESSION_COOKIE_SAMESITE"],
        )
        return redirect(url_for("dashboard"))

    @app.get("/logout")
    def logout():
        username = current_user()
        session.clear()
        app.logger.info("LOGOUT user=%s", username)
        return redirect(url_for("login"))

    @app.get("/dashboard")
    @login_required
    def dashboard():
        username = current_user()
        assert username is not None
        user = users[username]
        recipients = [name for name in users if name != username]
        recent = [
            transfer
            for transfer in transfers
            if transfer["from"] == username or transfer["to"] == username
        ][-10:]
        recent.reverse()

        return render_template(
            "dashboard.html",
            username=username,
            balance=user["balance"],
            recipients=recipients,
            transfers=recent,
            all_balances={name: data["balance"] for name, data in users.items()},
        )

    # ------------------------------------------------------------------
    # THE VULNERABLE CODE PATH
    #
    # A state-changing action is performed on a GET request, authorized only
    # by the session cookie. In vulnerable mode the cookie is SameSite=Lax,
    # which is still sent on a cross-site top-level GET navigation.
    #
    # THE FIX
    #
    # In secure mode the same cookie is SameSite=Strict. The browser does not
    # attach it to a cross-site request (including a top-level GET), so the
    # forged request arrives unauthenticated and is rejected below.
    # ------------------------------------------------------------------
    @app.get("/transfer")
    def transfer():
        username = current_user()
        cookie_header_present = bool(request.headers.get("Cookie"))

        app.logger.info(
            "TRANSFER_REQUEST mode=%s args=%s session_user=%s "
            "cookie_header=%s referer=%s remote=%s ua=%s",
            app.config["MODE"],
            dict(request.args),
            username,
            "present" if cookie_header_present else "absent",
            request.referrer or "-",
            request.remote_addr,
            request.user_agent.string or "-",
        )

        if username is None:
            if app.config["MODE"] == "secure":
                app.logger.warning(
                    "BLOCKED mode=secure reason=no_session_cookie args=%s "
                    "referer=%s remote=%s",
                    dict(request.args),
                    request.referrer or "-",
                    request.remote_addr,
                )
                abort(
                    403,
                    description=(
                        "Blocked: this cross-site GET arrived without the session "
                        "cookie. SameSite=Strict prevented the browser from "
                        "attaching it, so no transfer was performed."
                    ),
                )
            return redirect(url_for("login"))

        to = (request.args.get("to") or "").strip()
        amount_raw = (request.args.get("amount") or "").strip()

        if to not in users:
            flash("Unknown recipient.", "error")
            return redirect(url_for("dashboard"))

        if to == username:
            flash("You cannot transfer money to yourself.", "error")
            return redirect(url_for("dashboard"))

        try:
            amount = int(amount_raw)
        except ValueError:
            flash("Amount must be a whole number.", "error")
            return redirect(url_for("dashboard"))

        if amount <= 0:
            flash("Amount must be positive.", "error")
            return redirect(url_for("dashboard"))

        if amount > int(users[username]["balance"]):
            flash("Insufficient balance.", "error")
            return redirect(url_for("dashboard"))

        users[username]["balance"] = int(users[username]["balance"]) - amount
        users[to]["balance"] = int(users[to]["balance"]) + amount

        entry = {
            "from": username,
            "to": to,
            "amount": amount,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "mode": app.config["MODE"],
            "referer": request.referrer or "-",
            "remote": request.remote_addr,
        }
        transfers.append(entry)

        app.logger.info(
            "TRANSFER_COMPLETED mode=%s from=%s to=%s amount=%d "
            "alice_balance=%s mallory_balance=%s referer=%s",
            app.config["MODE"],
            username,
            to,
            amount,
            users["alice"]["balance"],
            users["mallory"]["balance"],
            request.referrer or "-",
        )

        flash(f"Sent Rs. {amount:,} to {to}.", "success")
        return redirect(url_for("dashboard"))

    @app.errorhandler(403)
    def forbidden(error):
        return (
            render_template(
                "error.html",
                code=403,
                title="Request blocked",
                message=getattr(error, "description", "Forbidden."),
            ),
            403,
        )

    @app.errorhandler(404)
    def not_found(error):
        return (
            render_template(
                "error.html",
                code=404,
                title="Not found",
                message="That page does not exist.",
            ),
            404,
        )

    return app


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="GET-based CSRF lab app")
    parser.add_argument(
        "--mode",
        choices=["vulnerable", "secure"],
        default="secure",
        help="vulnerable: SameSite=Lax; secure: SameSite=Strict (default: secure)",
    )
    parser.add_argument("--port", type=int, default=5000, help="port to listen on")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    app = create_app(args.mode)
    banner = (
        "VULNERABLE MODE: session cookie is SameSite=Lax"
        if args.mode == "vulnerable"
        else "SECURE MODE: session cookie is SameSite=Strict"
    )
    print("\n" + "=" * 72)
    print(f" {banner}")
    print(f" Victim app: http://localhost:{args.port}")
    print(" Attacker page: http://127.0.0.1:5001/")
    print("=" * 72 + "\n")
    app.run(
        host="127.0.0.1",
        port=args.port,
        debug=False,
        use_reloader=False,
        threaded=True,
    )


if __name__ == "__main__":
    main()
