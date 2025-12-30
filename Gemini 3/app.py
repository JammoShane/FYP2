import os
import re
import enum
from datetime import datetime

from flask import Flask, render_template, request, jsonify, session
from dotenv import load_dotenv
from google import genai

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "change-me")

# ----------------------------
# Database config
# ----------------------------
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# ----------------------------
# Gemini client
# ----------------------------
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

# in-memory cache of Gemini chat objects (keyed by conversation id)
chat_sessions = {}

# ----------------------------
# Roles + models
# ----------------------------
class Role(enum.Enum):
    STAKEHOLDER = "Stakeholder"
    DEVELOPER = "Developer"
    HR = "Human Resources"
    FINANCE = "Finance"
    PRODUCT = "Product Manager"
    OPS = "Operations"
    SUPPORT = "Customer Support"
    LEGAL = "Legal/Compliance"
    SECURITY = "Security"
    QA = "QA/Tester"
    SALES = "Sales"
    DATA = "Data/Analytics"
    UX = "UX/UI Designer"
    EXEC = "Executive"


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    role = db.Column(db.Enum(Role), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    title = db.Column(db.String(200), default="Requirements Interview")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey("conversation.id"), nullable=False, index=True)
    sender = db.Column(db.String(20), nullable=False)  # "user" / "assistant"
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ----------------------------
# Role-aware prompt
# ----------------------------
ROLE_STYLE = {
    Role.FINANCE: (
        "Use finance-friendly terminology (budget, ROI, cost centers, approvals, audit trail). "
        "Ask about cost constraints, CAPEX/OPEX, reporting needs, compliance, and approval workflows."
    ),
    Role.DEVELOPER: (
        "Use more technical terms where helpful (APIs, data models, auth, performance, logging). "
        "Ask about integrations, edge cases, non-functional requirements, and constraints."
    ),
    Role.HR: (
        "Use HR-friendly terminology (headcount, onboarding, leave, performance appraisal, access levels). "
        "Ask about policies, privacy, approvals, and reporting."
    ),
    Role.SECURITY: (
        "Emphasize security requirements (RBAC, encryption, audit logs, data retention). "
        "Ask about access control, compliance needs, and incident response."
    ),
}

BASE_SYSTEM_PROMPT = """
You are an AI Requirements Interviewer designed to elicit software requirements via a structured conversation.

User name: {user_name}
User job role: {role_name}
Role guidance: {role_guidance}

Conversation rules:
- If the user message is just a greeting (e.g., "hi", "hello", "hey"), respond with a warm greeting using their name.
  Do NOT ask for project details yet. Instead ask: "Would you like to start a new requirements interview now?"
- When the user confirms they want to start (or they describe the project), then ask them to describe the project in simple terms.
- Ask one question at a time.
- Clarify vague statements by asking follow-up questions.
- Adapt vocabulary to the role guidance.
- When the user says they are done, produce a categorized summary and end politely.
""".strip()


def build_system_prompt(user: User) -> str:
    guidance = ROLE_STYLE.get(user.role, "Use clear, professional language and adapt to the user's domain.")
    return BASE_SYSTEM_PROMPT.format(
        user_name=user.name,
        role_name=user.role.value,
        role_guidance=guidance
    )


# ----------------------------
# Helpers
# ----------------------------
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return User.query.get(uid)


def get_latest_conversation(user: User):
    return (
        Conversation.query
        .filter_by(user_id=user.id)
        .order_by(Conversation.created_at.desc())
        .first()
    )


def ensure_conversation(user: User) -> Conversation:
    """
    Ensure session["conversation_id"] points to a valid conversation for this user.
    If missing, automatically select the user's latest conversation (or create a new one).
    """
    conv_id = session.get("conversation_id")
    conv = Conversation.query.get(conv_id) if conv_id else None

    if conv and conv.user_id == user.id:
        return conv

    latest = get_latest_conversation(user)
    if latest:
        session["conversation_id"] = latest.id
        return latest

    # No conversation exists yet; create one
    conv = Conversation(user_id=user.id, title="Requirements Interview")
    db.session.add(conv)
    db.session.commit()
    session["conversation_id"] = conv.id
    return conv


# ----------------------------
# Routes
# ----------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/auth/me", methods=["GET"])
def me():
    user = current_user()
    if not user:
        return jsonify({"ok": True, "user": None})

    # Optional: keep a stable conversation selected for refreshes
    ensure_conversation(user)

    return jsonify({"ok": True, "user": {"name": user.name, "email": user.email, "role": user.role.value}})


@app.route("/auth/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    name = data.get("name", "").strip()
    role = data.get("role", "").strip()
    password = data.get("password", "")

    if not email or not name or not role or not password:
        return jsonify({"error": "Missing fields"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered"}), 409

    try:
        role_enum = Role(role)
    except Exception:
        return jsonify({"error": "Invalid role"}), 400

    u = User(
        email=email,
        name=name,
        role=role_enum,
        password_hash=generate_password_hash(password),
    )
    db.session.add(u)
    db.session.commit()

    session["user_id"] = u.id

    # Create the first conversation so history can load immediately
    conv = Conversation(user_id=u.id, title="Requirements Interview")
    db.session.add(conv)
    db.session.commit()
    session["conversation_id"] = conv.id

    return jsonify({"ok": True, "user": {"name": u.name, "email": u.email, "role": u.role.value}})


@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    u = User.query.filter_by(email=email).first()
    if not u or not check_password_hash(u.password_hash, password):
        return jsonify({"error": "Invalid credentials"}), 401

    session["user_id"] = u.id

    # ✅ KEY CHANGE: select the user's latest conversation so /history returns it right away
    ensure_conversation(u)

    return jsonify({"ok": True, "user": {"name": u.name, "email": u.email, "role": u.role.value}})


@app.route("/auth/logout", methods=["POST"])
def logout():
    # Frontend will clear chat window; backend clears auth session
    session.pop("user_id", None)
    session.pop("conversation_id", None)
    return jsonify({"ok": True})


@app.route("/history", methods=["GET"])
def history():
    user = current_user()
    if not user:
        return jsonify({"messages": []})

    conv = ensure_conversation(user)

    msgs = (
        Message.query.filter_by(conversation_id=conv.id)
        .order_by(Message.created_at.asc())
        .all()
    )

    return jsonify({
        "messages": [{"sender": m.sender, "content": m.content, "at": m.created_at.isoformat()} for m in msgs]
    })


@app.route("/chat", methods=["POST"])
def chat():
    user = current_user()
    if not user:
        return jsonify({"error": "Not authenticated. Please login/register first."}), 401

    user_msg = request.json.get("message", "").strip()
    if not user_msg:
        return jsonify({"error": "Empty message"}), 400

    conv = ensure_conversation(user)

    # save user message
    db.session.add(Message(conversation_id=conv.id, sender="user", content=user_msg))
    db.session.commit()

    # Gemini chat session (keyed by conversation id)
    conv_key = f"conv:{conv.id}"

    if conv_key not in chat_sessions:
        chat_sessions[conv_key] = client.chats.create(model="gemini-2.5-flash")
        chat_sessions[conv_key].send_message(build_system_prompt(user))

        # Replay conversation history from DB (optional)
        past = (
            Message.query.filter_by(conversation_id=conv.id)
            .order_by(Message.created_at.asc())
            .all()
        )
        for m in past[:-1]:
            if m.sender == "user":
                chat_sessions[conv_key].send_message(m.content)
            else:
                chat_sessions[conv_key].send_message(f"(assistant previously said) {m.content}")

    chat_instance = chat_sessions[conv_key]
    response = chat_instance.send_message(user_msg)
    resp_text = response.text.strip()

    # save assistant response
    db.session.add(Message(conversation_id=conv.id, sender="assistant", content=resp_text))
    db.session.commit()

    # Extract structured requirements if present
    lines = [line.strip() for line in resp_text.split("\n") if line.strip()]
    reqs = []
    for line in lines:
        if re.match(r"(?i)^requirement:", line):
            parts = re.split(r"\|\s*category\s*:", line, flags=re.IGNORECASE)
            body = parts[0][len("Requirement:"):].strip()
            cat = parts[1].strip() if len(parts) > 1 else ""
            reqs.append({"text": body, "category": cat})

    if any(p in user_msg.lower() for p in ["done", "that's all", "no more"]):
        summary_response = chat_instance.send_message(
            "Please summarize all gathered requirements categorized into Functional, Non-functional, and User Requirements."
        )
        summary = summary_response.text.strip()
        db.session.add(Message(conversation_id=conv.id, sender="assistant", content=summary))
        db.session.commit()

        return jsonify({"requirements": None, "summary": summary, "error": None})

    return jsonify({"requirements": reqs if reqs else None, "summary": None, "error": None if reqs else resp_text})


@app.route("/reset", methods=["POST"])
def reset():
    user = current_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    conv_id = session.get("conversation_id")
    if conv_id:
        chat_sessions.pop(f"conv:{conv_id}", None)

    # start a NEW conversation on reset (so old chat won't reappear)
    conv = Conversation(user_id=user.id, title="Requirements Interview")
    db.session.add(conv)
    db.session.commit()
    session["conversation_id"] = conv.id

    return jsonify({"message": "Conversation reset for this user."})


if __name__ == "__main__":
    app.run(debug=True)
