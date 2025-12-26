from flask import Flask, request, render_template_string, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import re
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)

# ==========================
# DATABASE CONFIG
# ==========================
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phishing.db'   # SQLite database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ==========================
# DATABASE MODELS
# ==========================
class URLCheck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    result = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class EmailCheck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(300), nullable=False)
    reply_to = db.Column(db.String(300), nullable=True)
    subject = db.Column(db.String(500), nullable=True)
    body = db.Column(db.Text, nullable=True)
    result = db.Column(db.String(300), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# ==========================
# RULE-BASED URL DETECTION
# ==========================
def is_phishing_url(url: str) -> str:
    # Basic normalization
    url = url.strip()
    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
    if ip_pattern.search(url):
        return "⚠️ Phishing Website! (Contains IP address)"
    if not url.lower().startswith("https://"):
        return "⚠️ Phishing Website! (No HTTPS)"
    # suspicious symbols: @, '-' is common though, but keep original rule
    if "@" in url or "//" in url[8:]:
        return "⚠️ Phishing Website! (Suspicious symbols in URL)"
    # too long
    if len(url) > 75:
        return "⚠️ Phishing Website! (URL too long)"
    # suspicious domain like multiple subdomains resembling common brand
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    if hostname.count('.') >= 3 and any(keyword in hostname for keyword in ['login', 'secure', 'account']):
        return "⚠️ Phishing Website! (Suspicious subdomain pattern)"
    return "✅ Legitimate Website!"

# ==========================
# RULE-BASED EMAIL DETECTION
# ==========================
SUSPICIOUS_KEYWORDS = [
    'urgent', 'verify', 'verify your', 'account', 'password', 'reset', 'confirm',
    'click here', 'login', 'limited time', 'immediately', 'suspend', 'security alert',
    'wire transfer', 'bank', 'ssn'
]

def contains_link(text: str) -> bool:
    return bool(re.search(r'https?://', text))

def extract_domain(email_address: str) -> str:
    if not email_address:
        return ""
    parts = email_address.split('@')
    return parts[-1].lower() if len(parts) > 1 else ""

def is_email_phishing(sender: str, reply_to: str, subject: str, body: str) -> str:
    s = (sender or "").strip()
    r = (reply_to or "").strip()
    subj = (subject or "").lower()
    body_text = (body or "").lower()

    # Rule 1: suspicious keyword in subject or body
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in subj or kw in body_text:
            return f"⚠️ Phishing Email! (Found suspicious keyword: '{kw}')"

    # Rule 2: body contains links (unexpected links)
    if contains_link(body_text):
        # if the link domain doesn't match sender domain, suspicious
        link_domains = re.findall(r'https?://([A-Za-z0-9\.-]+)', body_text)
        sender_domain = extract_domain(s)
        if link_domains and sender_domain:
            # check if any link domain differs significantly
            for ld in link_domains:
                ld_clean = ld.lower()
                if sender_domain not in ld_clean and ld_clean not in sender_domain:
                    return "⚠️ Phishing Email! (Contains external link not matching sender domain)"
        else:
            # links but can't confirm domains
            return "⚠️ Phishing Email! (Contains link)"
    # Rule 3: mismatch between sender domain and reply-to domain
    if r:
        sd = extract_domain(s)
        rd = extract_domain(r)
        if sd and rd and sd != rd:
            return "⚠️ Phishing Email! (Sender/Reply-To domain mismatch)"

    # Rule 4: many exclamation marks or urgent tone
    if body_text.count('!') >= 3 or subj.count('!') >= 2:
        return "⚠️ Phishing Email! (Excessive urgency/exclamation marks)"

    # Rule 5: suspicious phrases asking for credentials
    if any(word in body_text for word in ['enter your password', 'provide your password', 'send your password', 'ssn', 'social security']):
        return "⚠️ Phishing Email! (Asks for sensitive information)"

    return "✅ Likely Legitimate Email"

# ==========================
# HTML TEMPLATE
# ==========================
html = """
<!DOCTYPE html>
<html>
<head>
    <title>Phishing Detection System</title>
    <style>
        body { font-family: Arial; text-align: center; margin: 30px; }
        .box { display:inline-block; text-align:left; margin:10px; padding:15px; border:1px solid #ccc; border-radius:6px; }
        table { border-collapse: collapse; margin: auto; }
        td, th { padding: 6px 10px; border: 1px solid #ddd; }
        textarea { width: 400px; height: 120px; }
        input[type="text"] { width: 400px; }
    </style>
</head>
<body>
    <h1>🔒 Phishing Detection System</h1>

    <div class="box">
      <h3>Check a URL</h3>
      <form method="POST" action="{{ url_for('check_url') }}">
        <label>Website URL:</label><br>
        <input type="text" name="url" required placeholder="https://example.com"><br><br>
        <button type="submit">Check URL</button>
      </form>
    </div>

    

    <hr style="margin-top:30px; margin-bottom:30px;">

    <h2>🔎 Last 5 URL Checks</h2>
    <table>
        <tr><th>URL</th><th>Result</th><th>Time</th></tr>
        {% for entry in url_history %}
            <tr>
                <td style="max-width:400px; word-wrap:break-word;">{{ entry.url }}</td>
                <td>{{ entry.result }}</td>
                <td>{{ entry.timestamp.strftime('%Y-%m-%d %H:%M:%S') }}</td>
            </tr>
        {% endfor %}
    </table>

    

</body>
</html>
"""

# ==========================
# ROUTES
# ==========================
@app.route("/", methods=["GET"])
def home():
    url_history = URLCheck.query.order_by(URLCheck.timestamp.desc()).limit(5).all()
    email_history = EmailCheck.query.order_by(EmailCheck.timestamp.desc()).limit(5).all()
    return render_template_string(html, url_history=url_history, email_history=email_history)

@app.route("/check_url", methods=["POST"])
def check_url():
    url = request.form.get("url", "").strip()
    if not url:
        return redirect(url_for('home'))
    result = is_phishing_url(url)
    new_entry = URLCheck(url=url, result=result)
    db.session.add(new_entry)
    db.session.commit()
    return redirect(url_for('home'))

@app.route("/check_email", methods=["POST"])
def check_email():
    sender = request.form.get("sender", "").strip()
    reply_to = request.form.get("reply_to", "").strip()
    subject = request.form.get("subject", "").strip()
    body = request.form.get("body", "").strip()

    if not sender:
        return redirect(url_for('home'))

    result = is_email_phishing(sender, reply_to, subject, body)
    new_entry = EmailCheck(sender=sender, reply_to=reply_to, subject=subject, body=body, result=result)
    db.session.add(new_entry)
    db.session.commit()
    return redirect(url_for('home'))

# ==========================
# MAIN
# ==========================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()   # Create tables if not exist
    app.run(debug=True)
