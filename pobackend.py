from flask import Flask, request, jsonify, render_template, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime
import os
import re


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "change-this-secret-key-in-production"
)

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL",
    "sqlite:///portfolio.db"
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


db = SQLAlchemy(app)


# ============================================================
# RATE LIMITING
# ============================================================

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)


# ============================================================
# DATABASE MODELS
# ============================================================

class ContactMessage(db.Model):

    __tablename__ = "contact_messages"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    name = db.Column(
        db.String(100),
        nullable=False
    )

    email = db.Column(
        db.String(255),
        nullable=False,
        index=True
    )

    message = db.Column(
        db.Text,
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    def to_dict(self):

        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "message": self.message,
            "created_at": self.created_at.isoformat()
        }


class Admin(db.Model):

    __tablename__ = "admins"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(80),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

with app.app_context():

    db.create_all()


# ============================================================
# INPUT VALIDATION
# ============================================================

def clean_text(value, max_length):

    if not isinstance(value, str):
        return ""

    value = value.strip()

    if len(value) > max_length:
        return ""

    return value


def valid_email(email):

    pattern = r"^[^\s@]+@[^\s@]+\.[^\s@]+$"

    return bool(
        re.match(pattern, email)
    )


# ============================================================
# SECURITY HEADERS
# ============================================================

@app.after_request
def security_headers(response):

    response.headers["X-Content-Type-Options"] = "nosniff"

    response.headers["X-Frame-Options"] = "SAMEORIGIN"

    response.headers[
        "Referrer-Policy"
    ] = "strict-origin-when-cross-origin"

    response.headers[
        "Permissions-Policy"
    ] = "camera=(), microphone=(), geolocation=()"

    return response


# ============================================================
# HOME PAGE
# ============================================================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# ============================================================
# CONTACT API
# ============================================================

@app.route(
    "/api/contact",
    methods=["POST"]
)
@limiter.limit("5 per minute")
def contact():

    try:

        data = request.get_json(
            silent=True
        )

        if not data:

            return jsonify({
                "success": False,
                "message": "Invalid JSON request."
            }), 400


        name = clean_text(
            data.get("name"),
            100
        )

        email = clean_text(
            data.get("email"),
            255
        )

        message = clean_text(
            data.get("message"),
            2000
        )


        # Validate fields

        if not name:

            return jsonify({
                "success": False,
                "message": "Name is required."
            }), 400


        if not email or not valid_email(email):

            return jsonify({
                "success": False,
                "message": "Valid email is required."
            }), 400


        if not message:

            return jsonify({
                "success": False,
                "message": "Message is required."
            }), 400


        # Save to database

        new_message = ContactMessage(
            name=name,
            email=email,
            message=message
        )

        db.session.add(
            new_message
        )

        db.session.commit()


        return jsonify({
            "success": True,
            "message": "Your message has been sent successfully."
        }), 201


    except Exception:

        db.session.rollback()

        return jsonify({
            "success": False,
            "message": "Server error. Please try again later."
        }), 500


# ============================================================
# ADMIN REGISTRATION
# ============================================================

@app.route(
    "/api/admin/register",
    methods=["POST"]
)
def admin_register():

    try:

        data = request.get_json(
            silent=True
        )

        if not data:

            return jsonify({
                "success": False,
                "message": "Invalid request."
            }), 400


        username = clean_text(
            data.get("username"),
            80
        )

        password = data.get(
            "password",
            ""
        )


        if not username or len(username) < 3:

            return jsonify({
                "success": False,
                "message": "Username must contain at least 3 characters."
            }), 400


        if not isinstance(password, str) or len(password) < 8:

            return jsonify({
                "success": False,
                "message": "Password must contain at least 8 characters."
            }), 400


        existing_admin = Admin.query.filter_by(
            username=username
        ).first()


        if existing_admin:

            return jsonify({
                "success": False,
                "message": "Username already exists."
            }), 400


        # Never store the plain-text password.
        password_hash = generate_password_hash(
            password
        )


        admin = Admin(
            username=username,
            password_hash=password_hash
        )


        db.session.add(admin)

        db.session.commit()


        return jsonify({
            "success": True,
            "message": "Admin account created."
        }), 201


    except Exception:

        db.session.rollback()

        return jsonify({
            "success": False,
            "message": "Server error."
        }), 500


# ============================================================
# ADMIN LOGIN
# ============================================================

@app.route(
    "/api/admin/login",
    methods=["POST"]
)
@limiter.limit("5 per minute")
def admin_login():

    try:

        data = request.get_json(
            silent=True
        )

        if not data:

            return jsonify({
                "success": False,
                "message": "Invalid request."
            }), 400


        username = clean_text(
            data.get("username"),
            80
        )

        password = data.get(
            "password",
            ""
        )


        admin = Admin.query.filter_by(
            username=username
        ).first()


        if (
            not admin
            or not check_password_hash(
                admin.password_hash,
                password
            )
        ):

            return jsonify({
                "success": False,
                "message": "Invalid username or password."
            }), 401


        session.clear()

        session["admin_id"] = admin.id


        return jsonify({
            "success": True,
            "message": "Login successful."
        })


    except Exception:

        return jsonify({
            "success": False,
            "message": "Server error."
        }), 500


# ============================================================
# ADMIN LOGOUT
# ============================================================

@app.route(
    "/api/admin/logout",
    methods=["POST"]
)
def admin_logout():

    session.clear()

    return jsonify({
        "success": True,
        "message": "Logged out successfully."
    })


# ============================================================
# ADMIN MESSAGES
# ============================================================

@app.route(
    "/api/admin/messages",
    methods=["GET"]
)
def get_messages():

    if "admin_id" not in session:

        return jsonify({
            "success": False,
            "message": "Unauthorized."
        }), 401


    messages = ContactMessage.query.order_by(
        ContactMessage.created_at.desc()
    ).all()


    return jsonify({
        "success": True,
        "messages": [
            message.to_dict()
            for message in messages
        ]
    })


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def not_found(error):

    return jsonify({
        "success": False,
        "message": "Resource not found."
    }), 404


@app.errorhandler(429)
def rate_limit_error(error):

    return jsonify({
        "success": False,
        "message": "Too many requests. Please try again later."
    }), 429


@app.errorhandler(500)
def server_error(error):

    db.session.rollback()

    return jsonify({
        "success": False,
        "message": "Internal server error."
    }), 500


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )