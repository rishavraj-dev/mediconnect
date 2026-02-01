from flask import Flask, render_template
from flask_mail import Mail
from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "super_secret_key")

# Brevo SMTP Configuration
app.config['MAIL_SERVER'] = 'smtp-relay.brevo.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("BREVO_LOGIN")
app.config['MAIL_PASSWORD'] = os.getenv("BREVO_SMTP_KEY")

mail = Mail(app)

# MongoDB Connection
client = MongoClient(os.getenv("MONGO_URI"))
db = client['mediconnect_db']

# Register Blueprint
from modules.auth import auth_bp
app.register_blueprint(auth_bp)

# --- FIX: ADD THIS ROUTE BACK ---
@app.route('/')
def home():
    try:
        client.admin.command('ping')
        status, color = "Connected", "#28a745"
    except:
        status, color = "Disconnected", "#dc3545"
    return render_template('index.html', status=status, color=color)

if __name__ == '__main__':
    app.run(debug=True, port=5000)