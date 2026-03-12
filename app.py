import os
from datetime import datetime, timedelta
import secrets

from flask import Flask, jsonify, request
from flask_cors import CORS
from passlib.hash import bcrypt
import jwt

from models import db, User, Patient, Referral, Report


def create_app():
    """
    Create and configure the Flask application.
    """
    app = Flask(__name__)

    base_dir = os.path.abspath(os.path.dirname(__file__))
    db_dir = os.path.abspath(os.path.join(base_dir, "..", "database"))
    os.makedirs(db_dir, exist_ok=True)
    db_path = os.path.join(db_dir, "arogya_vahini.db")

    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
    }
    # For hackathon/demo purposes we embed a default secret; in production use env vars.
    app.config["JWT_SECRET"] = os.environ.get("AROGYA_JWT_SECRET", "change-this-secret-in-prod")

    db.init_app(app)
    CORS(
        app,
        resources={r"/*": {"origins": ["http://localhost:5173", "http://127.0.0.1:5173"]}},
        supports_credentials=True,
    )

    with app.app_context():
        db.drop_all()  # Clean slate for testing auth
        db.create_all()

    register_routes(app)
    return app


def generate_jwt(user_id, role, secret, expires_minutes=60 * 8):
    """
    Generate a short-lived JWT for authenticating dashboard calls.
    """
    payload = {
        "sub": user_id,
        "role": role,
        "exp": datetime.utcnow() + timedelta(minutes=expires_minutes),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_jwt(token, secret):
    try:
        return jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None


def auth_required(role=None):
    """
    Simple decorator-like helper for endpoints that require JWT auth.

    Usage inside route:
        user = auth_required("doctor")()
        if isinstance(user, tuple):  # error response
            return user
    """

    def inner():
        from flask import current_app

        auth_header = request.headers.get("Authorization", "")
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return jsonify({"message": "Missing or invalid Authorization header"}), 401
        token = parts[1]
        data = decode_jwt(token, current_app.config["JWT_SECRET"])
        if not data:
            return jsonify({"message": "Invalid or expired token"}), 401
        try:
            user_id = int(data["sub"])
        except (ValueError, KeyError):
            return jsonify({"message": "Invalid user ID in token"}), 401
        user = User.query.get(user_id)
        if not user:
            return jsonify({"message": "User not found"}), 401
        if role and user.role != role:
            return jsonify({"message": "Insufficient permissions"}), 403
        return user

    return inner


def serialize_patient(patient: Patient):
    return {
        "id": patient.id,
        "name": patient.name,
        "age": patient.age,
        "gender": patient.gender,
        "village": patient.village,
        "created_by": patient.created_by_doctor,
    }


def serialize_referral(ref: Referral):
    return {
        "id": ref.id,
        "patient_id": ref.patient_id,
        "diagnosis": ref.diagnosis,
        "hospital": ref.hospital,
        "token": ref.token,
        "date": ref.date.strftime("%Y-%m-%d %H:%M"),
    }


def register_routes(app: Flask):
    """
    Define all REST endpoints for the Arogya-Vahini backend.
    """

    @app.route("/register", methods=["POST"])
    def register():
        data = request.get_json() or {}
        name = data.get("name")
        email = data.get("email")
        password = data.get("password")
        role = data.get("role")

        if not all([name, email, password, role]):
            return jsonify({"message": "Missing required fields"}), 400
        if role not in ("doctor", "patient"):
            return jsonify({"message": "Role must be 'doctor' or 'patient'"}), 400

        if User.query.filter_by(email=email).first():
            return jsonify({"message": "Email already registered"}), 400

        try:
            user = User(
                name=name,
                email=email,
                password_hash=bcrypt.hash(password),
                role=role,
            )
            db.session.add(user)
            db.session.commit()
            print(f"User registered successfully: {email}")  # Debug
        except Exception as e:
            db.session.rollback()
            print(f"Register error: {str(e)}")  # Debug
            return jsonify({"message": "Registration failed", "error": str(e)}), 500

        from flask import current_app

        token = generate_jwt(user.id, user.role, current_app.config["JWT_SECRET"])
        return (
            jsonify(
                {
                    "token": token,
                    "user": {
                        "id": user.id,
                        "name": user.name,
                        "email": user.email,
                        "role": user.role,
                    },
                }
            ),
            201,
        )

    @app.route("/login", methods=["POST"])
    def login():
        data = request.get_json() or {}
        email = data.get("email")
        password = data.get("password")
        # expected_role = data.get("role")  # Commented to avoid 403 issues

        if not all([email, password]):
            return jsonify({"message": "Missing credentials"}), 400

        try:
            user = User.query.filter_by(email=email).first()
            print(f"Login attempt for email: {email}, user found: {user is not None}")  # Debug
            if not user or not bcrypt.verify(password, user.password_hash):
                print("Auth failed: invalid credentials")  # Debug
                return jsonify({"message": "Invalid email or password"}), 401

            # if expected_role and user.role != expected_role:
            #     return jsonify({"message": "Role mismatch for this account"}), 403

            from flask import current_app

            token = generate_jwt(user.id, user.role, current_app.config["JWT_SECRET"])

            payload = {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "role": user.role,
            }

            if user.role == "patient":
                # For patients, try to link to their patient record if present.
                patient = Patient.query.filter_by(created_by_doctor=user.id).first()
                if patient:
                    payload["patient_id"] = patient.id

            print(f"Login successful for: {user.email}")  # Debug
            return jsonify({"token": token, "user": payload})
        except Exception as e:
            db.session.rollback()
            print(f"Login error: {str(e)}")  # Debug
            return jsonify({"message": "Login failed", "error": str(e)}), 500

    @app.route("/add_patient", methods=["POST"])
    def add_patient():
        doctor = auth_required("doctor")()
        if isinstance(doctor, tuple):
            return doctor

        data = request.get_json() or {}
        name = data.get("name")
        age = data.get("age")
        gender = data.get("gender")
        village = data.get("village")
        created_by_doctor = data.get("created_by_doctor") or doctor.id

        if not all([name, age is not None, gender, village]):
            return jsonify({"message": "Missing required patient fields"}), 400

        patient = Patient(
            name=name,
            age=int(age),
            gender=gender,
            village=village,
            created_by_doctor=created_by_doctor,
        )
        db.session.add(patient)
        db.session.commit()

        return jsonify({"id": patient.id, "patient": serialize_patient(patient)}), 201

    @app.route("/create_referral", methods=["POST"])
    def create_referral():
        doctor = auth_required("doctor")()
        if isinstance(doctor, tuple):
            return doctor

        data = request.get_json() or {}
        patient_id = data.get("patient_id")
        diagnosis = data.get("diagnosis")
        hospital = data.get("hospital")

        if not all([patient_id, diagnosis, hospital]):
            return jsonify({"message": "Missing referral fields"}), 400

        patient = Patient.query.get(patient_id)
        if not patient:
            return jsonify({"message": "Patient not found"}), 404

        # Generate an opaque, URL-safe token that will be embedded in the QR code.
        token = secrets.token_urlsafe(16)

        referral = Referral(
            patient_id=patient.id,
            diagnosis=diagnosis,
            hospital=hospital,
            token=token,
        )
        db.session.add(referral)
        db.session.commit()

        return (
            jsonify(
                {
                    "id": referral.id,
                    "token": referral.token,
                    "referral": serialize_referral(referral),
                }
            ),
            201,
        )

    @app.route("/patient/<string:token>", methods=["GET"])
    def get_patient_by_token(token):
        """
        Resolve a QR token into the patient summary and referral history.
        """
        referral = Referral.query.filter_by(token=token).first()
        if not referral:
            return jsonify({"message": "Referral not found"}), 404

        patient = referral.patient
        # Show the full referral history for continuity of care.
        history = Referral.query.filter_by(patient_id=patient.id).order_by(
            Referral.date.desc()
        )

        return jsonify(
            {
                "patient": serialize_patient(patient),
                "active_referral": serialize_referral(referral),
                "referrals": [serialize_referral(r) for r in history],
            }
        )

    @app.route("/patient_history/<int:patient_id>", methods=["GET"])
    def patient_history(patient_id):
        """
        Show patient demographics and their full referral + report history.
        """
        patient = Patient.query.get(patient_id)
        if not patient:
            return jsonify({"message": "Patient not found"}), 404

        referrals = Referral.query.filter_by(patient_id=patient.id).order_by(
            Referral.date.desc()
        )
        reports = Report.query.filter_by(patient_id=patient.id).order_by(
            Report.date.desc()
        )

        return jsonify(
            {
                "patient": serialize_patient(patient),
                "referrals": [serialize_referral(r) for r in referrals],
                "reports": [
                    {
                        "id": rep.id,
                        "file": rep.file,
                        "description": rep.description,
                        "date": rep.date.strftime("%Y-%m-%d %H:%M"),
                    }
                    for rep in reports
                ],
            }
        )

    @app.route("/stats", methods=["GET"])
    def stats():
        """
        Basic dashboard statistics for hackathon demo.
        """
        total_patients = Patient.query.count()
        total_referrals = Referral.query.count()
        active_hospitals = (
            db.session.query(Referral.hospital).distinct().count()
        )
        return jsonify(
            {
                "total_patients": total_patients,
                "total_referrals": total_referrals,
                "active_hospitals": active_hospitals,
            }
        )


app = create_app()

if __name__ == "__main__":
    # Run in debug for hackathon convenience.
    app.run(host="0.0.0.0", port=5000, debug=True)

