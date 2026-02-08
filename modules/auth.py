from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from flask_mail import Message
from werkzeug.security import generate_password_hash, check_password_hash
import random
from datetime import datetime, date
from bson.objectid import ObjectId

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

    from app import db

    doctors = list(db.users.find(
        {"role": "doctor"},
        {"password": 0}
    ).sort("name", 1))

    appointments = list(db.appointments.find(
        {"patient_email": session['user']['email']}
    ).sort("created_at", -1))

    for appt in appointments:
        appt["id"] = str(appt["_id"])

    upcoming_count = sum(1 for appt in appointments if appt.get("status") in ["pending", "confirmed"])
    completed_count = sum(1 for appt in appointments if appt.get("status") == "completed")

    return render_template(
        'patient_dashboard.html',
        user=session['user'],
        doctors=doctors,
        appointments=appointments,
        upcoming_count=upcoming_count,
        completed_count=completed_count
    )

# --- DOCTOR DASHBOARD ---
@auth_bp.route('/dashboard/doctor')
def doctor_dashboard():
    if 'user' not in session or session['user']['role'] != 'doctor':
        flash("Please login to access dashboard")
        return redirect(url_for('auth.login_doctor'))

    from app import db
    doctor_email = session['user']['email']

    appointments = list(db.appointments.find(
        {"doctor_email": doctor_email}
    ).sort("created_at", -1))

    for appt in appointments:
        appt["id"] = str(appt["_id"])

    today_str = date.today().isoformat()
    todays_appointments = sum(
        1 for appt in appointments
        if appt.get("status") == "confirmed" and appt.get("date") == today_str
    )

    total_patients = len({appt.get("patient_email") for appt in appointments if appt.get("patient_email")})

    pending_appointments = [appt for appt in appointments if appt.get("status") == "pending"]
    confirmed_appointments = [appt for appt in appointments if appt.get("status") == "confirmed"]

    return render_template(
        'doctor_dashboard.html',
        user=session['user'],
        appointments=appointments,
        pending_appointments=pending_appointments,
        confirmed_appointments=confirmed_appointments,
        todays_appointments=todays_appointments,
        total_patients=total_patients
    )

# --- CREATE APPOINTMENT (PATIENT) ---
@auth_bp.route('/appointments/create', methods=['POST'])
def create_appointment():
    if 'user' not in session or session['user']['role'] != 'patient':
        flash("Please login to book an appointment")
        return redirect(url_for('auth.login_patient'))

    from app import db

    doctor_email = request.form.get('doctor_email')
    date_value = request.form.get('date')
    time_value = request.form.get('time')
    reason = request.form.get('reason')

    if not doctor_email or not date_value or not time_value:
        flash("Please select a doctor, date, and time")
        return redirect(url_for('auth.patient_dashboard'))

    doctor = db.users.find_one({"email": doctor_email, "role": "doctor"})
    if not doctor:
        flash("Selected doctor not found")
        return redirect(url_for('auth.patient_dashboard'))

    appointment = {
        "patient_email": session['user']['email'],
        "patient_name": session['user']['name'],
        "doctor_email": doctor.get('email'),
        "doctor_name": doctor.get('name'),
        "doctor_specialization": doctor.get('specialization'),
        "date": date_value,
        "time": time_value,
        "reason": reason or "",
        "status": "pending",
        "created_at": datetime.utcnow()
    }

    db.appointments.insert_one(appointment)
    flash("Appointment request sent to doctor")
    return redirect(url_for('auth.patient_dashboard'))

# --- UPDATE APPOINTMENT STATUS (DOCTOR) ---
@auth_bp.route('/appointments/<appointment_id>/<action>', methods=['POST'])
def update_appointment_status(appointment_id, action):
    if 'user' not in session or session['user']['role'] != 'doctor':
        flash("Please login to manage appointments")
        return redirect(url_for('auth.login_doctor'))

    if action not in ["accept", "reject"]:
        flash("Invalid action")
        return redirect(url_for('auth.doctor_dashboard'))

    from app import db
    doctor_email = session['user']['email']

    status = "confirmed" if action == "accept" else "rejected"

    try:
        appointment_object_id = ObjectId(appointment_id)
    except Exception:
        flash("Invalid appointment")
        return redirect(url_for('auth.doctor_dashboard'))

    db.appointments.update_one(
        {"_id": appointment_object_id, "doctor_email": doctor_email},
        {"$set": {"status": status, "updated_at": datetime.utcnow()}}
    )

    flash("Appointment updated")
    return redirect(url_for('auth.doctor_dashboard'))

# --- CANCEL APPOINTMENT (PATIENT) ---
@auth_bp.route('/appointments/<appointment_id>/cancel', methods=['POST'])
def cancel_appointment(appointment_id):
    if 'user' not in session or session['user']['role'] != 'patient':
        flash("Please login to manage appointments")
        return redirect(url_for('auth.login_patient'))

    from app import db

    try:
        appointment_object_id = ObjectId(appointment_id)
    except Exception:
        flash("Invalid appointment")
        return redirect(url_for('auth.patient_dashboard'))

    db.appointments.update_one(
        {"_id": appointment_object_id, "patient_email": session['user']['email']},
        {"$set": {"status": "cancelled", "updated_at": datetime.utcnow()}}
    )

    flash("Appointment cancelled")
    return redirect(url_for('auth.patient_dashboard'))

# --- LOGOUT ---
@auth_bp.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out successfully")
    return redirect(url_for('home'))