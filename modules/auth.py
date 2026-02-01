from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash
import random

auth_bp = Blueprint('auth', __name__)

# --- PATIENT REGISTER ---
@auth_bp.route('/register/patient', methods=['GET', 'POST'])
def register_patient():
    if request.method == 'POST':
        from app import db 
        
        name = request.form.get('name')
        email = request.form.get('email').lower()
        password = request.form.get('password')

        if db.users.find_one({"email": email}):
            flash("Email already registered!")
            return redirect(url_for('auth.register_patient'))

        # Generate OTP
        otp = str(random.randint(100000, 999999))

        # --- THIS IS THE FIX: PRINT TO LOGS INSTEAD OF EMAILING ---
        print(f"OTP for {email}: {otp}", flush=True) 

        session['temp_user'] = {
            'role': 'patient',
            'name': name,
            'email': email,
            'password': generate_password_hash(password),
            'otp': otp
        }

        return redirect(url_for('auth.verify_otp'))

    return render_template('register_patient.html')

# --- DOCTOR REGISTER ---
@auth_bp.route('/register/doctor', methods=['GET', 'POST'])
def register_doctor():
    if request.method == 'POST':
        from app import db
        
        name = request.form.get('name')
        license_id = request.form.get('license_id')
        specialization = request.form.get('specialization')
        email = request.form.get('email').lower()
        password = request.form.get('password')

        if db.users.find_one({"email": email}):
            flash("Email already registered!")
            return redirect(url_for('auth.register_doctor'))

        otp = str(random.randint(100000, 999999))

        # --- FIX: PRINT TO LOGS ---
        print(f"OTP for Dr. {name}: {otp}", flush=True)

        session['temp_user'] = {
            'role': 'doctor',
            'name': name,
            'license_id': license_id,
            'specialization': specialization,
            'email': email,
            'password': generate_password_hash(password),
            'otp': otp
        }

        return redirect(url_for('auth.verify_otp'))

    return render_template('register_doctor.html')

# --- VERIFY OTP ---
@auth_bp.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'temp_user' not in session:
        return redirect('/')

    if request.method == 'POST':
        from app import db
        user_otp = request.form.get('otp')
        
        if user_otp == session['temp_user']['otp']:
            final_user = session.pop('temp_user')
            final_user.pop('otp')
            db.users.insert_one(final_user)
            return "SUCCESS! ACCOUNT CREATED. (Go to /login to sign in)" 
        else:
            flash("Invalid OTP, check your logs!")

    return render_template('verify_otp.html')