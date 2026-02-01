from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from flask_mail import Message
from werkzeug.security import generate_password_hash, check_password_hash
import random

auth_bp = Blueprint('auth', __name__)

# --- PATIENT ROUTE ---
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

        # Save to Session
        session['temp_user'] = {
            'role': 'patient',
            'name': name,
            'email': email,
            'password': generate_password_hash(password),
            'otp': otp
        }

        # Send Email via Brevo SMTP
        from app import mail
        msg = Message("MediConnect Verification", 
                     sender="MediConnect <aiuser.first@gmail.com>", 
                     recipients=[email])
        msg.body = f"Hello {name},\n\nYour verification code is: {otp}\n\nThank you for choosing MediConnect!"
        mail.send(msg)

        return redirect(url_for('auth.verify_otp'))

    return render_template('register_patient.html')

# --- DOCTOR ROUTE ---
@auth_bp.route('/register/doctor', methods=['GET', 'POST'])
def register_doctor():
    if request.method == 'POST':
        from app import db
        
        name = request.form.get('name')
        license_id = request.form.get('license_id') # Extra Field
        specialization = request.form.get('specialization') # Extra Field
        email = request.form.get('email').lower()
        password = request.form.get('password')

        if db.users.find_one({"email": email}):
            flash("Email already registered!")
            return redirect(url_for('auth.register_doctor'))

        otp = str(random.randint(100000, 999999))

        session['temp_user'] = {
            'role': 'doctor',
            'name': name,
            'license_id': license_id,
            'specialization': specialization,
            'email': email,
            'password': generate_password_hash(password),
            'otp': otp
        }

        # Send Email via Brevo SMTP
        from app import mail
        msg = Message("Doctor Verification - MediConnect", 
                     sender="MediConnect <aiuser.first@gmail.com>", 
                     recipients=[email])
        msg.body = f"Dr. {name},\n\nYour verification code is: {otp}\n\nSpecialization: {specialization}\nLicense ID: {license_id}\n\nWelcome to MediConnect!"
        mail.send(msg)

        return redirect(url_for('auth.verify_otp'))

    return render_template('register_doctor.html')

# --- OTP VERIFICATION (Shared) ---
@auth_bp.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        from app import db
        if request.form.get('otp') == session.get('temp_user', {}).get('otp'):
            # Save User to DB
            user_data = session.pop('temp_user')
            user_data.pop('otp')
            db.users.insert_one(user_data)
            
            # Log the user in automatically
            session['user'] = {
                'email': user_data['email'],
                'name': user_data['name'],
                'role': user_data['role']
            }
            
            # Redirect to appropriate dashboard
            if user_data['role'] == 'patient':
                return redirect(url_for('auth.patient_dashboard'))
            else:
                return redirect(url_for('auth.doctor_dashboard'))
        else:
            flash("Invalid OTP")
            
    return render_template('verify_otp.html')

# --- PATIENT LOGIN ---
@auth_bp.route('/login/patient', methods=['GET', 'POST'])
def login_patient():
    if request.method == 'POST':
        from app import db
        
        email = request.form.get('email').lower()
        password = request.form.get('password')
        
        user = db.users.find_one({"email": email, "role": "patient"})
        
        if user and check_password_hash(user['password'], password):
            session['user'] = {
                'email': user['email'],
                'name': user['name'],
                'role': user['role']
            }
            return redirect(url_for('auth.patient_dashboard'))
        else:
            flash("Invalid email or password!")
            
    return render_template('login_patient.html')

# --- DOCTOR LOGIN ---
@auth_bp.route('/login/doctor', methods=['GET', 'POST'])
def login_doctor():
    if request.method == 'POST':
        from app import db
        
        email = request.form.get('email').lower()
        password = request.form.get('password')
        
        user = db.users.find_one({"email": email, "role": "doctor"})
        
        if user and check_password_hash(user['password'], password):
            session['user'] = {
                'email': user['email'],
                'name': user['name'],
                'role': user['role'],
                'license_id': user.get('license_id'),
                'specialization': user.get('specialization')
            }
            return redirect(url_for('auth.doctor_dashboard'))
        else:
            flash("Invalid email or password!")
            
    return render_template('login_doctor.html')

# --- PATIENT DASHBOARD ---
@auth_bp.route('/dashboard/patient')
def patient_dashboard():
    if 'user' not in session or session['user']['role'] != 'patient':
        flash("Please login to access dashboard")
        return redirect(url_for('auth.login_patient'))
    
    return render_template('patient_dashboard.html', user=session['user'])

# --- DOCTOR DASHBOARD ---
@auth_bp.route('/dashboard/doctor')
def doctor_dashboard():
    if 'user' not in session or session['user']['role'] != 'doctor':
        flash("Please login to access dashboard")
        return redirect(url_for('auth.login_doctor'))
    
    return render_template('doctor_dashboard.html', user=session['user'])

# --- LOGOUT ---
@auth_bp.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out successfully")
    return redirect(url_for('home'))