from flask import Blueprint, render_template, request, redirect, url_for, session, flash, current_app
from flask_socketio import emit, join_room
from flask_mail import Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import random
from datetime import datetime, date, timedelta
from bson.objectid import ObjectId
import os

auth_bp = Blueprint('auth', __name__)

ALLOWED_REPORT_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "doc", "docx"}
DEFAULT_NOTIFY_EMAIL = True
DEFAULT_NOTIFY_SMS = False
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
MAX_CHAT_MESSAGE_LEN = 1000

def is_allowed_report(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_REPORT_EXTENSIONS

def _get_user_settings(db, email, role):
    doc = db.users.find_one({"email": email, "role": role}, {"settings": 1})
    return (doc or {}).get("settings", {})

def _should_send_email(db, email, role):
    settings = _get_user_settings(db, email, role)
    if not settings:
        return DEFAULT_NOTIFY_EMAIL
    return settings.get("notify_email", DEFAULT_NOTIFY_EMAIL)

def _send_email(to_address, subject, body):
    if not to_address:
        return False

    from app import mail
    try:
        msg = Message(subject,
                      sender="MediConnect <aiuser.first@gmail.com>",
                      recipients=[to_address])
        msg.body = body
        mail.send(msg)
        current_app.logger.info("Email sent to %s with subject '%s'", to_address, subject)
        return True
    except Exception:
        current_app.logger.exception("Email send failed to %s with subject '%s'", to_address, subject)
        return False

def _log_audit(db, actor_email, role, action, metadata=None):
    db.audit_logs.insert_one({
        "actor_email": actor_email,
        "role": role,
        "action": action,
        "metadata": metadata or {},
        "created_at": datetime.utcnow()
    })

def _get_availability_rules(db, doctor_email):
    return db.availability_rules.find_one({"doctor_email": doctor_email}) or {}

def _parse_datetime(date_value, time_value):
    return datetime.strptime(f"{date_value} {time_value}", "%Y-%m-%d %H:%M")

def _build_session_user(user_data):
    session_user = {
        'email': user_data.get('email'),
        'name': user_data.get('name'),
        'role': user_data.get('role')
    }
    if user_data.get('role') == 'patient':
        session_user.update({
            'phone': user_data.get('phone'),
            'dob': user_data.get('dob'),
            'gender': user_data.get('gender'),
            'address': user_data.get('address')
        })
    if user_data.get('role') == 'doctor':
        session_user.update({
            'license_id': user_data.get('license_id'),
            'specialization': user_data.get('specialization'),
            'phone': user_data.get('phone'),
            'clinic_address': user_data.get('clinic_address'),
            'years_experience': user_data.get('years_experience')
        })
    return session_user

# --- PATIENT ROUTE ---
@auth_bp.route('/register/patient', methods=['GET', 'POST'])
def register_patient():
    if request.method == 'POST':
        from app import db
        
        name = request.form.get('name')
        phone = request.form.get('phone')
        dob = request.form.get('dob')
        gender = request.form.get('gender')
        address = request.form.get('address')
        email = request.form.get('email').lower()
        password = request.form.get('password')

        if db.users.find_one({"email": email}):
            flash("Email already registered!")
            return redirect(url_for('auth.register_patient'))

        # Generate OTP
        otp = str(random.randint(100000, 999999))

        # Save to Session
        temp_user = {
            'role': 'patient',
            'name': name,
            'phone': phone,
            'dob': dob,
            'gender': gender,
            'address': address,
            'email': email,
            'status': 'active',
            'settings': {
                'notify_email': DEFAULT_NOTIFY_EMAIL,
                'notify_sms': DEFAULT_NOTIFY_SMS
            },
            'otp': otp
        }

        if password:
            temp_user['password'] = generate_password_hash(password)

        session['temp_user'] = temp_user

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
        phone = request.form.get('phone')
        clinic_address = request.form.get('clinic_address')
        years_experience = request.form.get('years_experience')
        email = request.form.get('email').lower()
        password = request.form.get('password')

        if db.users.find_one({"email": email}):
            flash("Email already registered!")
            return redirect(url_for('auth.register_doctor'))

        otp = str(random.randint(100000, 999999))

        temp_user = {
            'role': 'doctor',
            'name': name,
            'license_id': license_id,
            'specialization': specialization,
            'phone': phone,
            'clinic_address': clinic_address,
            'years_experience': years_experience,
            'email': email,
            'status': 'pending',
            'settings': {
                'notify_email': DEFAULT_NOTIFY_EMAIL,
                'notify_sms': DEFAULT_NOTIFY_SMS
            },
            'otp': otp
        }

        if password:
            temp_user['password'] = generate_password_hash(password)

        session['temp_user'] = temp_user

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
        otp_input = request.form.get('otp')
        temp_login = session.get('temp_login')
        if temp_login:
            if otp_input == temp_login.get('otp'):
                user = db.users.find_one({"email": temp_login.get('email'), "role": temp_login.get('role')})
                if not user:
                    flash("Account not found")
                    session.pop('temp_login', None)
                    return redirect(url_for('auth.login_patient'))
                if user.get("role") == "doctor" and user.get("status") != "approved":
                    flash("Your doctor account is pending approval")
                    session.pop('temp_login', None)
                    return redirect(url_for('auth.login_doctor'))
                session['user'] = _build_session_user(user)
                _log_audit(db, user.get("email"), user.get("role"), "login", {"method": "otp"})
                session.pop('temp_login', None)
                if user.get('role') == 'patient':
                    return redirect(url_for('auth.patient_dashboard'))
                return redirect(url_for('auth.doctor_dashboard'))
            flash("Invalid OTP")
            return render_template('verify_otp.html', mode='login')

        if otp_input == session.get('temp_user', {}).get('otp'):
            user_data = session.pop('temp_user')
            user_data.pop('otp', None)
            if user_data.get("role") == "doctor" and not user_data.get("status"):
                user_data["status"] = "pending"
            if user_data.get("role") == "patient" and not user_data.get("status"):
                user_data["status"] = "active"
            db.users.insert_one(user_data)

            _log_audit(db, user_data.get("email"), user_data.get("role"), "register", {
                "status": user_data.get("status")
            })

            session['user'] = _build_session_user(user_data)

            if user_data.get('role') == 'patient':
                return redirect(url_for('auth.patient_dashboard'))
            if user_data.get("status") != "approved":
                flash("Your doctor account is pending approval")
                return redirect(url_for('auth.login_doctor'))
            return redirect(url_for('auth.doctor_dashboard'))
        else:
            flash("Invalid OTP")

    mode = 'login' if session.get('temp_login') else 'register'
    return render_template('verify_otp.html', mode=mode)

# --- RESEND OTP ---
@auth_bp.route('/resend-otp', methods=['POST'])
def resend_otp():
    temp_login = session.get('temp_login')
    if temp_login and temp_login.get('email'):
        otp = str(random.randint(100000, 999999))
        temp_login['otp'] = otp
        session['temp_login'] = temp_login

        subject = "MediConnect Login Code"
        body = f"Hello,\n\nYour login code is: {otp}\n\nIf you did not request this, please ignore this email."
        _send_email(temp_login.get('email'), subject, body)

        flash("A new OTP has been sent to your email")
        return redirect(url_for('auth.verify_otp'))

    temp_user = session.get('temp_user')
    if not temp_user or not temp_user.get('email'):
        flash("Please register first")
        return redirect(url_for('home'))

    otp = str(random.randint(100000, 999999))
    temp_user['otp'] = otp
    session['temp_user'] = temp_user

    from app import mail
    msg = Message(
        "MediConnect Verification",
        sender="MediConnect <aiuser.first@gmail.com>",
        recipients=[temp_user['email']]
    )
    msg.body = f"Hello {temp_user.get('name')},\n\nYour new verification code is: {otp}\n\nThank you for choosing MediConnect!"
    mail.send(msg)

    flash("A new OTP has been sent to your email")
    return redirect(url_for('auth.verify_otp'))

# --- PATIENT LOGIN ---
@auth_bp.route('/login/patient', methods=['GET', 'POST'])
def login_patient():
    if request.method == 'POST':
        from app import db
        email = request.form.get('email', '').lower().strip()
        if not email:
            flash("Please enter your email")
            return redirect(url_for('auth.login_patient'))

        user = db.users.find_one({"email": email, "role": "patient"})
        if not user:
            flash("No patient account found for this email")
            return redirect(url_for('auth.login_patient'))

        otp = str(random.randint(100000, 999999))
        session['temp_login'] = {
            'role': 'patient',
            'email': email,
            'otp': otp
        }

        subject = "MediConnect Login Code"
        body = f"Hello {user.get('name')},\n\nYour login code is: {otp}\n\nIf you did not request this, please ignore this email."
        _send_email(email, subject, body)

        return redirect(url_for('auth.verify_otp'))
            
    return render_template('login_patient.html')

# --- DOCTOR LOGIN ---
@auth_bp.route('/login/doctor', methods=['GET', 'POST'])
def login_doctor():
    if request.method == 'POST':
        from app import db
        email = request.form.get('email', '').lower().strip()
        if not email:
            flash("Please enter your email")
            return redirect(url_for('auth.login_doctor'))

        user = db.users.find_one({"email": email, "role": "doctor"})
        if not user:
            flash("No doctor account found for this email")
            return redirect(url_for('auth.login_doctor'))

        status = user.get("status")
        if status and status != "approved":
            flash("Your doctor account is pending approval")
            return redirect(url_for('auth.login_doctor'))

        otp = str(random.randint(100000, 999999))
        session['temp_login'] = {
            'role': 'doctor',
            'email': email,
            'otp': otp
        }

        subject = "MediConnect Doctor Login Code"
        body = f"Hello Dr. {user.get('name')},\n\nYour login code is: {otp}\n\nIf you did not request this, please ignore this email."
        _send_email(email, subject, body)

        return redirect(url_for('auth.verify_otp'))
            
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

    today_str = date.today().isoformat()
    availability_slots = list(db.availability.find(
        {"date": {"$gte": today_str}}
    ).sort([("date", 1), ("start_time", 1)]).limit(100))
    doctor_emails = list({slot.get("doctor_email") for slot in availability_slots if slot.get("doctor_email")})
    doctor_map = {}
    if doctor_emails:
        doctors_cursor = db.users.find({"email": {"$in": doctor_emails}, "role": "doctor"}, {"password": 0})
        doctor_map = {doc.get("email"): doc for doc in doctors_cursor}
    for slot in availability_slots:
        slot["id"] = str(slot.get("_id"))
        doc = doctor_map.get(slot.get("doctor_email"), {})
        slot["doctor_name"] = doc.get("name")
        slot["doctor_specialization"] = doc.get("specialization")

    now = datetime.now()

    for appt in appointments:
        appt["id"] = str(appt["_id"])
        appt["call_active"] = False
        if appt.get("status") == "confirmed":
            try:
                appointment_time = datetime.strptime(
                    f"{appt.get('date')} {appt.get('time')}",
                    "%Y-%m-%d %H:%M"
                )
                window_start = appointment_time
                window_end = appointment_time + timedelta(minutes=60)
                appt["call_active"] = window_start <= now <= window_end
            except Exception:
                appt["call_active"] = False

    upcoming_count = sum(1 for appt in appointments if appt.get("status") in ["pending", "confirmed"])
    completed_count = sum(1 for appt in appointments if appt.get("status") == "completed")

    return render_template(
        'patient_dashboard.html',
        user=session['user'],
        doctors=doctors,
        appointments=appointments,
        availability_slots=availability_slots,
        upcoming_count=upcoming_count,
        completed_count=completed_count
    )

# --- PATIENT PAGES ---
@auth_bp.route('/patient/appointments')
def patient_appointments():
    if 'user' not in session or session['user']['role'] != 'patient':
        flash("Please login to access appointments")
        return redirect(url_for('auth.login_patient'))

    from app import db
    appointments = list(db.appointments.find(
        {"patient_email": session['user']['email']}
    ).sort("created_at", -1))

    reviews = list(db.reviews.find({"patient_email": session['user']['email']}))
    reviewed_map = {review.get("appointment_id"): True for review in reviews}

    followups = list(db.followups.find({
        "patient_email": session['user']['email']
    }).sort("created_at", -1))
    for item in followups:
        item["id"] = str(item["_id"])

    now = datetime.now()
    for appt in appointments:
        appt["id"] = str(appt["_id"])
        appt["call_active"] = False
        if appt.get("status") == "confirmed":
            try:
                appointment_time = datetime.strptime(
                    f"{appt.get('date')} {appt.get('time')}",
                    "%Y-%m-%d %H:%M"
                )
                window_start = appointment_time
                window_end = appointment_time + timedelta(minutes=60)
                appt["call_active"] = window_start <= now <= window_end
            except Exception:
                appt["call_active"] = False

    return render_template('patient_appointments.html', user=session['user'], appointments=appointments, reviewed_map=reviewed_map, followups=followups)

@auth_bp.route('/patient/records')
def patient_records():
    if 'user' not in session or session['user']['role'] != 'patient':
        flash("Please login to access records")
        return redirect(url_for('auth.login_patient'))

    from app import db
    appointments = list(db.appointments.find(
        {"patient_email": session['user']['email'], "reports": {"$exists": True, "$ne": []}}
    ).sort("created_at", -1))

    for appt in appointments:
        appt["id"] = str(appt["_id"])

    return render_template('patient_records.html', user=session['user'], appointments=appointments)

@auth_bp.route('/patient/doctors')
def patient_doctors():
    if 'user' not in session or session['user']['role'] != 'patient':
        flash("Please login to find doctors")
        return redirect(url_for('auth.login_patient'))

    from app import db
    doctors = list(db.users.find({"role": "doctor"}, {"password": 0}).sort("name", 1))
    return render_template('patient_doctors.html', user=session['user'], doctors=doctors)

@auth_bp.route('/patient/prescriptions')
def patient_prescriptions():
    if 'user' not in session or session['user']['role'] != 'patient':
        flash("Please login to access prescriptions")
        return redirect(url_for('auth.login_patient'))

    from app import db
    prescriptions = list(db.prescriptions.find(
        {"patient_email": session['user']['email']}
    ).sort("created_at", -1))

    for item in prescriptions:
        item["id"] = str(item["_id"])

    return render_template('patient_prescriptions.html', user=session['user'], prescriptions=prescriptions)

@auth_bp.route('/patient/profile', methods=['GET', 'POST'])
def patient_profile():
    if 'user' not in session or session['user']['role'] != 'patient':
        flash("Please login to access profile")
        return redirect(url_for('auth.login_patient'))

    from app import db
    if request.method == 'POST':
        name = request.form.get('name')
        phone = request.form.get('phone')
        dob = request.form.get('dob')
        gender = request.form.get('gender')
        address = request.form.get('address')
        update_data = {}
        if name:
            update_data["name"] = name
            session['user']['name'] = name
        if phone:
            update_data["phone"] = phone
            session['user']['phone'] = phone
        if dob:
            update_data["dob"] = dob
            session['user']['dob'] = dob
        if gender:
            update_data["gender"] = gender
            session['user']['gender'] = gender
        if address:
            update_data["address"] = address
            session['user']['address'] = address
        if update_data:
            update_data["updated_at"] = datetime.utcnow()
            db.users.update_one(
                {"email": session['user']['email'], "role": "patient"},
                {"$set": update_data}
            )
            flash("Profile updated")
        return redirect(url_for('auth.patient_profile'))

    return render_template('patient_profile.html', user=session['user'])

@auth_bp.route('/patient/settings', methods=['GET', 'POST'])
def patient_settings():
    if 'user' not in session or session['user']['role'] != 'patient':
        flash("Please login to access settings")
        return redirect(url_for('auth.login_patient'))

    from app import db
    if request.method == 'POST':
        notify_email = request.form.get('notify_email') == "on"
        notify_sms = request.form.get('notify_sms') == "on"
        db.users.update_one(
            {"email": session['user']['email'], "role": "patient"},
            {"$set": {"settings": {"notify_email": notify_email, "notify_sms": notify_sms}, "updated_at": datetime.utcnow()}}
        )
        flash("Settings saved")
        return redirect(url_for('auth.patient_settings'))

    user_doc = db.users.find_one({"email": session['user']['email'], "role": "patient"}, {"settings": 1})
    settings = (user_doc or {}).get("settings", {})
    return render_template('patient_settings.html', user=session['user'], settings=settings)

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

    now = datetime.now()

    for appt in appointments:
        appt["id"] = str(appt["_id"])
        appt["call_active"] = False
        if appt.get("status") == "confirmed":
            try:
                appointment_time = datetime.strptime(
                    f"{appt.get('date')} {appt.get('time')}",
                    "%Y-%m-%d %H:%M"
                )
                window_start = appointment_time
                window_end = appointment_time + timedelta(minutes=60)
                appt["call_active"] = window_start <= now <= window_end
            except Exception:
                appt["call_active"] = False

    today_str = date.today().isoformat()
    todays_appointments = sum(
        1 for appt in appointments
        if appt.get("status") == "confirmed" and appt.get("date") == today_str
    )

    total_patients = len({appt.get("patient_email") for appt in appointments if appt.get("patient_email")})

    pending_appointments = [appt for appt in appointments if appt.get("status") == "pending"]
    confirmed_appointments = [appt for appt in appointments if appt.get("status") == "confirmed"]

    patients_map = {}
    for appt in appointments:
        patient_email = appt.get("patient_email")
        patient_name = appt.get("patient_name")
        if patient_email and patient_email not in patients_map:
            patients_map[patient_email] = {
                "email": patient_email,
                "name": patient_name or "Patient"
            }

    patients = list(patients_map.values())

    return render_template(
        'doctor_dashboard.html',
        user=session['user'],
        appointments=appointments,
        pending_appointments=pending_appointments,
        confirmed_appointments=confirmed_appointments,
        todays_appointments=todays_appointments,
        total_patients=total_patients,
        patients=patients
    )

# --- DOCTOR PAGES ---
@auth_bp.route('/doctor/appointments')
def doctor_appointments():
    if 'user' not in session or session['user']['role'] != 'doctor':
        flash("Please login to access appointments")
        return redirect(url_for('auth.login_doctor'))

    from app import db
    appointments = list(db.appointments.find(
        {"doctor_email": session['user']['email']}
    ).sort("created_at", -1))

    doctors = list(db.users.find(
        {"role": "doctor", "email": {"$ne": session['user']['email']}},
        {"password": 0}
    ).sort("name", 1))

    now = datetime.now()
    for appt in appointments:
        appt["id"] = str(appt["_id"])
        appt["call_active"] = False
        if appt.get("status") == "confirmed":
            try:
                appointment_time = datetime.strptime(
                    f"{appt.get('date')} {appt.get('time')}",
                    "%Y-%m-%d %H:%M"
                )
                window_start = appointment_time
                window_end = appointment_time + timedelta(minutes=60)
                appt["call_active"] = window_start <= now <= window_end
            except Exception:
                appt["call_active"] = False

    return render_template('doctor_appointments.html', user=session['user'], appointments=appointments, doctors=doctors)

@auth_bp.route('/doctor/patients')
def doctor_patients():
    if 'user' not in session or session['user']['role'] != 'doctor':
        flash("Please login to access patients")
        return redirect(url_for('auth.login_doctor'))

    from app import db
    appointments = list(db.appointments.find({"doctor_email": session['user']['email']}))
    patients_map = {}
    for appt in appointments:
        patient_email = appt.get("patient_email")
        patient_name = appt.get("patient_name")
        if patient_email and patient_email not in patients_map:
            patients_map[patient_email] = {
                "email": patient_email,
                "name": patient_name or "Patient"
            }
    patients = list(patients_map.values())
    patient_emails = [patient["email"] for patient in patients]
    if patient_emails:
        profiles = db.users.find({"email": {"$in": patient_emails}, "role": "patient"}, {"email": 1, "phone": 1})
        profile_map = {profile.get("email"): profile for profile in profiles}
        for patient in patients:
            profile = profile_map.get(patient["email"], {})
            patient["phone"] = profile.get("phone")

    blocked_patients = set()
    blocks = db.blocks.find({"doctor_email": session['user']['email']}, {"patient_email": 1})
    for block in blocks:
        if block.get("patient_email"):
            blocked_patients.add(block.get("patient_email"))
    for patient in patients:
        patient["is_blocked"] = patient.get("email") in blocked_patients
    return render_template('doctor_patients.html', user=session['user'], patients=patients)

@auth_bp.route('/doctor/patients/<patient_email>')
def doctor_patient_detail(patient_email):
    if 'user' not in session or session['user']['role'] != 'doctor':
        flash("Please login to access patient history")
        return redirect(url_for('auth.login_doctor'))

    from app import db
    doctor_email = session['user']['email']
    appointments = list(db.appointments.find({
        "doctor_email": doctor_email,
        "patient_email": patient_email
    }).sort("created_at", -1))

    for appt in appointments:
        appt["id"] = str(appt["_id"])

    prescriptions = list(db.prescriptions.find({
        "doctor_email": doctor_email,
        "patient_email": patient_email
    }).sort("created_at", -1))

    for item in prescriptions:
        item["id"] = str(item["_id"])

    patient_profile = db.users.find_one({"email": patient_email, "role": "patient"}, {"password": 0}) or {}
    patient = {
        "email": patient_email,
        "name": patient_profile.get("name") or (appointments[0].get("patient_name") if appointments else "Patient"),
        "phone": patient_profile.get("phone"),
        "dob": patient_profile.get("dob"),
        "gender": patient_profile.get("gender"),
        "address": patient_profile.get("address")
    }
    patient["is_blocked"] = db.blocks.find_one({"doctor_email": doctor_email, "patient_email": patient_email}) is not None

    return render_template(
        'doctor_patient_detail.html',
        user=session['user'],
        patient=patient,
        appointments=appointments,
        prescriptions=prescriptions
    )

@auth_bp.route('/doctor/schedule', methods=['GET', 'POST'])
def doctor_schedule():
    if 'user' not in session or session['user']['role'] != 'doctor':
        flash("Please login to access schedule")
        return redirect(url_for('auth.login_doctor'))

    from app import db
    if request.method == 'POST':
        form_type = request.form.get('form_type')
        if form_type == "rules":
            allow_weekends = request.form.get('allow_weekends') == "on"
            buffer_minutes = request.form.get('buffer_minutes')
            max_daily_appointments = request.form.get('max_daily_appointments')
            min_notice_hours = request.form.get('min_notice_hours')
            db.availability_rules.update_one(
                {"doctor_email": session['user']['email']},
                {"$set": {
                    "doctor_email": session['user']['email'],
                    "allow_weekends": allow_weekends,
                    "buffer_minutes": int(buffer_minutes) if buffer_minutes else 0,
                    "max_daily_appointments": int(max_daily_appointments) if max_daily_appointments else 0,
                    "min_notice_hours": int(min_notice_hours) if min_notice_hours else 0,
                    "updated_at": datetime.utcnow()
                }},
                upsert=True
            )
            flash("Availability rules updated")
            return redirect(url_for('auth.doctor_schedule'))

        date_value = request.form.get('date')
        start_time = request.form.get('start_time')
        end_time = request.form.get('end_time')
        if date_value and start_time and end_time:
            db.availability.insert_one({
                "doctor_email": session['user']['email'],
                "date": date_value,
                "start_time": start_time,
                "end_time": end_time,
                "created_at": datetime.utcnow()
            })
            flash("Availability added")
        return redirect(url_for('auth.doctor_schedule'))

    slots = list(db.availability.find({"doctor_email": session['user']['email']}).sort("date", 1))
    for slot in slots:
        slot["id"] = str(slot["_id"])
    rules = _get_availability_rules(db, session['user']['email'])
    if not rules:
        rules = {
            "allow_weekends": True,
            "buffer_minutes": 0,
            "max_daily_appointments": 0,
            "min_notice_hours": 0
        }
    return render_template('doctor_schedule.html', user=session['user'], slots=slots, rules=rules)

@auth_bp.route('/doctor/profile', methods=['GET', 'POST'])
def doctor_profile():
    if 'user' not in session or session['user']['role'] != 'doctor':
        flash("Please login to access profile")
        return redirect(url_for('auth.login_doctor'))

    from app import db
    if request.method == 'POST':
        name = request.form.get('name')
        specialization = request.form.get('specialization')
        license_id = request.form.get('license_id')
        phone = request.form.get('phone')
        clinic_address = request.form.get('clinic_address')
        years_experience = request.form.get('years_experience')
        update_data = {}
        if name:
            update_data["name"] = name
            session['user']['name'] = name
        if specialization:
            update_data["specialization"] = specialization
            session['user']['specialization'] = specialization
        if license_id:
            update_data["license_id"] = license_id
            session['user']['license_id'] = license_id
        if phone:
            update_data["phone"] = phone
            session['user']['phone'] = phone
        if clinic_address:
            update_data["clinic_address"] = clinic_address
            session['user']['clinic_address'] = clinic_address
        if years_experience:
            update_data["years_experience"] = years_experience
            session['user']['years_experience'] = years_experience
        if update_data:
            update_data["updated_at"] = datetime.utcnow()
            db.users.update_one(
                {"email": session['user']['email'], "role": "doctor"},
                {"$set": update_data}
            )
            flash("Profile updated")
        return redirect(url_for('auth.doctor_profile'))

    return render_template('doctor_profile.html', user=session['user'])

@auth_bp.route('/doctor/settings', methods=['GET', 'POST'])
def doctor_settings():
    if 'user' not in session or session['user']['role'] != 'doctor':
        flash("Please login to access settings")
        return redirect(url_for('auth.login_doctor'))

    from app import db
    if request.method == 'POST':
        notify_email = request.form.get('notify_email') == "on"
        notify_sms = request.form.get('notify_sms') == "on"
        db.users.update_one(
            {"email": session['user']['email'], "role": "doctor"},
            {"$set": {"settings": {"notify_email": notify_email, "notify_sms": notify_sms}, "updated_at": datetime.utcnow()}}
        )
        flash("Settings saved")
        return redirect(url_for('auth.doctor_settings'))

    user_doc = db.users.find_one({"email": session['user']['email'], "role": "doctor"}, {"settings": 1})
    settings = (user_doc or {}).get("settings", {})
    return render_template('doctor_settings.html', user=session['user'], settings=settings)

@auth_bp.route('/doctor/reviews')
def doctor_reviews():
    if 'user' not in session or session['user']['role'] != 'doctor':
        flash("Please login to access reviews")
        return redirect(url_for('auth.login_doctor'))

    from app import db
    reviews = list(db.reviews.find({"doctor_email": session['user']['email']}).sort("created_at", -1))
    for review in reviews:
        review["id"] = str(review["_id"])
    return render_template('doctor_reviews.html', user=session['user'], reviews=reviews)

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
    issue_category = request.form.get('issue_category')
    issue_detail = request.form.get('issue_detail')
    general_physician = request.form.get('general_physician') == "on"
    symptoms = request.form.get('symptoms')
    allergies = request.form.get('allergies')
    medications = request.form.get('medications')
    conditions = request.form.get('conditions')
    vitals = request.form.get('vitals')

    if not date_value or not time_value or not issue_category:
        flash("Please select an issue, date, and time")
        return redirect(url_for('auth.patient_dashboard'))

    doctor = None
    if doctor_email:
        doctor = db.users.find_one({"email": doctor_email, "role": "doctor"})
    elif general_physician:
        doctor = db.users.find_one({
            "role": "doctor",
            "specialization": {"$regex": "general", "$options": "i"}
        })
        if not doctor:
            doctor = db.users.find_one({"role": "doctor"})
    else:
        flash("Please select a doctor or choose General Physician")
        return redirect(url_for('auth.patient_dashboard'))

    if not doctor:
        flash("No doctor available right now")
        return redirect(url_for('auth.patient_dashboard'))

    if db.blocks.find_one({"doctor_email": doctor.get('email'), "patient_email": session['user']['email']}):
        flash("This doctor is not available for appointments")
        return redirect(url_for('auth.patient_dashboard'))

    rules = _get_availability_rules(db, doctor.get('email'))
    if rules:
        allow_weekends = rules.get("allow_weekends", True)
        min_notice_hours = int(rules.get("min_notice_hours") or 0)
        buffer_minutes = int(rules.get("buffer_minutes") or 0)
        max_daily = int(rules.get("max_daily_appointments") or 0)

        appointment_time = _parse_datetime(date_value, time_value)
        if not allow_weekends and appointment_time.weekday() in [5, 6]:
            flash("This doctor is not available on weekends")
            return redirect(url_for('auth.patient_dashboard'))

        if min_notice_hours:
            min_time = datetime.now() + timedelta(hours=min_notice_hours)
            if appointment_time < min_time:
                flash("Please choose a later time for this doctor")
                return redirect(url_for('auth.patient_dashboard'))

        if max_daily:
            daily_count = db.appointments.count_documents({
                "doctor_email": doctor.get('email'),
                "date": date_value,
                "status": {"$nin": ["cancelled", "rejected"]}
            })
            if daily_count >= max_daily:
                flash("This doctor has reached the daily limit")
                return redirect(url_for('auth.patient_dashboard'))

        if buffer_minutes:
            existing = list(db.appointments.find({
                "doctor_email": doctor.get('email'),
                "date": date_value,
                "status": {"$nin": ["cancelled", "rejected"]}
            }, {"time": 1}))
            for item in existing:
                try:
                    existing_time = _parse_datetime(date_value, item.get("time"))
                except Exception:
                    continue
                diff_minutes = abs(int((appointment_time - existing_time).total_seconds() / 60))
                if diff_minutes < buffer_minutes:
                    flash("This time conflicts with the doctor's buffer window")
                    return redirect(url_for('auth.patient_dashboard'))

    slots = list(db.availability.find({
        "doctor_email": doctor.get('email'),
        "date": date_value
    }))
    if slots:
        appointment_time = _parse_datetime(date_value, time_value)
        in_slot = False
        for slot in slots:
            try:
                start = _parse_datetime(slot.get("date"), slot.get("start_time"))
                end = _parse_datetime(slot.get("date"), slot.get("end_time"))
            except Exception:
                continue
            if start <= appointment_time <= end:
                in_slot = True
                break
        if not in_slot:
            flash("This time is outside the doctor's availability")
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
        "issue_category": issue_category,
        "issue_detail": issue_detail or "",
        "general_physician": general_physician,
        "intake": {
            "symptoms": symptoms or "",
            "allergies": allergies or "",
            "medications": medications or "",
            "conditions": conditions or "",
            "vitals": vitals or ""
        },
        "consultation_notes": "",
        "reports": [],
        "status": "pending",
        "created_at": datetime.utcnow()
    }

    result = db.appointments.insert_one(appointment)
    appointment_id = str(result.inserted_id)

    if _should_send_email(db, doctor.get('email'), "doctor"):
        body = (
            f"Hello Dr. {doctor.get('name')},\n\n"
            f"You have a new appointment request from {session['user']['name']}.\n"
            f"Date: {date_value}\nTime: {time_value}\n"
            f"Issue: {issue_category}\n"
            f"Details: {issue_detail or 'N/A'}\n"
            f"Reason: {reason or 'N/A'}\n\n"
            "Please log in to MediConnect to review the request."
        )
        _send_email(doctor.get('email'), "New Appointment Request", body)

    reports = []
    report_files = request.files.getlist('reports')
    if report_files:
        upload_root = current_app.config.get('UPLOAD_FOLDER', os.path.join(current_app.root_path, 'static', 'uploads'))
        report_dir = os.path.join(upload_root, 'reports', appointment_id)
        os.makedirs(report_dir, exist_ok=True)

        for report in report_files:
            if not report or report.filename == "":
                continue
            if not is_allowed_report(report.filename):
                continue

            original_name = report.filename
            safe_name = secure_filename(report.filename)
            if not safe_name:
                continue

            base, ext = os.path.splitext(safe_name)
            final_name = safe_name
            counter = 1
            while os.path.exists(os.path.join(report_dir, final_name)):
                final_name = f"{base}_{counter}{ext}"
                counter += 1

            report.save(os.path.join(report_dir, final_name))
            reports.append({
                "name": original_name,
                "url": f"uploads/reports/{appointment_id}/{final_name}"
            })

    if reports:
        db.appointments.update_one(
            {"_id": result.inserted_id},
            {"$set": {"reports": reports, "updated_at": datetime.utcnow()}}
        )

    flash("Appointment request sent to doctor")
    _log_audit(db, session['user']['email'], session['user']['role'], "appointment_create", {
        "appointment_id": appointment_id,
        "doctor_email": doctor.get('email')
    })
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

    appointment = db.appointments.find_one({"_id": appointment_object_id})
    if appointment and _should_send_email(db, appointment.get("patient_email"), "patient"):
        body = (
            f"Hello {appointment.get('patient_name')},\n\n"
            f"Your appointment with Dr. {appointment.get('doctor_name')} has been {status}.\n"
            f"Date: {appointment.get('date')}\nTime: {appointment.get('time')}\n"
            f"Issue: {appointment.get('issue_category')}\n\n"
            "Thank you for using MediConnect."
        )
        _send_email(appointment.get("patient_email"), "Appointment Update", body)

    flash("Appointment updated")
    return redirect(url_for('auth.doctor_dashboard'))

# --- COMPLETE APPOINTMENT (DOCTOR) ---
@auth_bp.route('/appointments/<appointment_id>/complete', methods=['POST'])
def complete_appointment(appointment_id):
    if 'user' not in session or session['user']['role'] != 'doctor':
        flash("Please login to manage appointments")
        return redirect(url_for('auth.login_doctor'))

    from app import db
    doctor_email = session['user']['email']

    try:
        appointment_object_id = ObjectId(appointment_id)
    except Exception:
        flash("Invalid appointment")
        return redirect(url_for('auth.doctor_dashboard'))

    db.appointments.update_one(
        {"_id": appointment_object_id, "doctor_email": doctor_email},
        {"$set": {"status": "completed", "updated_at": datetime.utcnow()}}
    )

    appointment = db.appointments.find_one({"_id": appointment_object_id})
    if appointment and _should_send_email(db, appointment.get("patient_email"), "patient"):
        body = (
            f"Hello {appointment.get('patient_name')},\n\n"
            f"Your appointment with Dr. {appointment.get('doctor_name')} is marked completed.\n"
            f"Date: {appointment.get('date')}\nTime: {appointment.get('time')}\n\n"
            "You can review your consultation notes and prescriptions in your dashboard."
        )
        _send_email(appointment.get("patient_email"), "Appointment Completed", body)

    flash("Appointment marked as completed")
    return redirect(url_for('auth.doctor_dashboard'))

# --- ADD PRESCRIPTION (DOCTOR) ---
@auth_bp.route('/appointments/<appointment_id>/prescriptions', methods=['POST'])
def add_prescription(appointment_id):
    if 'user' not in session or session['user']['role'] != 'doctor':
        flash("Please login to add prescriptions")
        return redirect(url_for('auth.login_doctor'))

    from app import db
    try:
        appointment_object_id = ObjectId(appointment_id)
    except Exception:
        flash("Invalid appointment")
        return redirect(url_for('auth.doctor_dashboard'))

    appointment = db.appointments.find_one({"_id": appointment_object_id, "doctor_email": session['user']['email']})
    if not appointment:
        flash("Appointment not found")
        return redirect(url_for('auth.doctor_dashboard'))

    medication = request.form.get('medication')
    dosage = request.form.get('dosage')
    frequency = request.form.get('frequency')
    duration = request.form.get('duration')
    refills = request.form.get('refills')
    instructions = request.form.get('instructions')
    notes = request.form.get('notes')

    if not medication or not dosage:
        flash("Medication and dosage are required")
        return redirect(url_for('auth.doctor_dashboard'))

    result = db.prescriptions.insert_one({
        "appointment_id": str(appointment_object_id),
        "patient_email": appointment.get('patient_email'),
        "patient_name": appointment.get('patient_name'),
        "doctor_email": appointment.get('doctor_email'),
        "doctor_name": appointment.get('doctor_name'),
        "medication": medication,
        "dosage": dosage,
        "frequency": frequency or "",
        "duration": duration or "",
        "refills": int(refills) if refills else 0,
        "instructions": instructions or "",
        "notes": notes or "",
        "created_at": datetime.utcnow()
    })

    flash("Prescription added")
    _log_audit(db, session['user']['email'], session['user']['role'], "prescription_create", {
        "prescription_id": str(result.inserted_id)
    })
    return redirect(url_for('auth.doctor_dashboard'))

# --- ADD REVIEW (PATIENT) ---
@auth_bp.route('/appointments/<appointment_id>/review', methods=['POST'])
def add_review(appointment_id):
    if 'user' not in session or session['user']['role'] != 'patient':
        flash("Please login to add a review")
        return redirect(url_for('auth.login_patient'))

    from app import db
    try:
        appointment_object_id = ObjectId(appointment_id)
    except Exception:
        flash("Invalid appointment")
        return redirect(url_for('auth.patient_appointments'))

    appointment = db.appointments.find_one({
        "_id": appointment_object_id,
        "patient_email": session['user']['email'],
        "status": "completed"
    })
    if not appointment:
        flash("Only completed appointments can be reviewed")
        return redirect(url_for('auth.patient_appointments'))

    rating = request.form.get('rating')
    comment = request.form.get('comment')

    if not rating:
        flash("Please select a rating")
        return redirect(url_for('auth.patient_appointments'))

    db.reviews.update_one(
        {"appointment_id": str(appointment_object_id), "patient_email": session['user']['email']},
        {"$set": {
            "appointment_id": str(appointment_object_id),
            "patient_email": session['user']['email'],
            "patient_name": session['user']['name'],
            "doctor_email": appointment.get('doctor_email'),
            "doctor_name": appointment.get('doctor_name'),
            "rating": int(rating),
            "comment": comment or "",
            "created_at": datetime.utcnow()
        }},
        upsert=True
    )

    flash("Review submitted")
    return redirect(url_for('auth.patient_appointments'))

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

    appointment = db.appointments.find_one({"_id": appointment_object_id})
    if appointment and _should_send_email(db, appointment.get("doctor_email"), "doctor"):
        body = (
            f"Hello Dr. {appointment.get('doctor_name')},\n\n"
            f"The appointment with {appointment.get('patient_name')} has been cancelled by the patient.\n"
            f"Date: {appointment.get('date')}\nTime: {appointment.get('time')}\n"
            f"Issue: {appointment.get('issue_category')}\n"
        )
        _send_email(appointment.get("doctor_email"), "Appointment Cancelled", body)

    flash("Appointment cancelled")
    return redirect(url_for('auth.patient_dashboard'))

# --- UPDATE CONSULTATION NOTES (DOCTOR) ---
@auth_bp.route('/appointments/<appointment_id>/notes', methods=['POST'])
def update_consultation_notes(appointment_id):
    if 'user' not in session or session['user']['role'] != 'doctor':
        flash("Please login to manage appointments")
        return redirect(url_for('auth.login_doctor'))

    notes = request.form.get('consultation_notes', '').strip()

    from app import db
    doctor_email = session['user']['email']

    try:
        appointment_object_id = ObjectId(appointment_id)
    except Exception:
        flash("Invalid appointment")
        return redirect(url_for('auth.doctor_dashboard'))

    db.appointments.update_one(
        {"_id": appointment_object_id, "doctor_email": doctor_email},
        {"$set": {"consultation_notes": notes, "updated_at": datetime.utcnow()}}
    )

    flash("Consultation notes updated")
    return redirect(url_for('auth.doctor_dashboard'))

# --- FOLLOW-UP SCHEDULING ---
@auth_bp.route('/appointments/<appointment_id>/followup', methods=['POST'])
def schedule_followup(appointment_id):
    if 'user' not in session or session['user']['role'] != 'doctor':
        flash("Please login to schedule follow-ups")
        return redirect(url_for('auth.login_doctor'))

    from app import db
    date_value = request.form.get('followup_date')
    time_value = request.form.get('followup_time')
    note = request.form.get('followup_note', '').strip()

    if not date_value or not time_value:
        flash("Please select follow-up date and time")
        return redirect(url_for('auth.doctor_appointments'))

    try:
        appointment_object_id = ObjectId(appointment_id)
    except Exception:
        flash("Invalid appointment")
        return redirect(url_for('auth.doctor_appointments'))

    appointment = db.appointments.find_one({
        "_id": appointment_object_id,
        "doctor_email": session['user']['email']
    })
    if not appointment:
        flash("Appointment not found")
        return redirect(url_for('auth.doctor_appointments'))

    db.followups.insert_one({
        "appointment_id": str(appointment_object_id),
        "doctor_email": appointment.get("doctor_email"),
        "doctor_name": appointment.get("doctor_name"),
        "patient_email": appointment.get("patient_email"),
        "patient_name": appointment.get("patient_name"),
        "date": date_value,
        "time": time_value,
        "note": note,
        "status": "scheduled",
        "created_at": datetime.utcnow()
    })

    if _should_send_email(db, appointment.get("patient_email"), "patient"):
        body = (
            f"Hello {appointment.get('patient_name')},\n\n"
            f"A follow-up visit has been scheduled with Dr. {appointment.get('doctor_name')}.\n"
            f"Date: {date_value}\nTime: {time_value}\n\n"
            "Please log in to MediConnect for details."
        )
        _send_email(appointment.get("patient_email"), "Follow-up Scheduled", body)

    _log_audit(db, session['user']['email'], session['user']['role'], "followup_schedule", {
        "appointment_id": appointment_id
    })

    flash("Follow-up scheduled")
    return redirect(url_for('auth.doctor_appointments'))

@auth_bp.route('/appointments/<appointment_id>/followup/request', methods=['POST'])
def request_followup(appointment_id):
    if 'user' not in session or session['user']['role'] != 'patient':
        flash("Please login to request follow-ups")
        return redirect(url_for('auth.login_patient'))

    from app import db
    note = request.form.get('followup_note', '').strip()

    try:
        appointment_object_id = ObjectId(appointment_id)
    except Exception:
        flash("Invalid appointment")
        return redirect(url_for('auth.patient_appointments'))

    appointment = db.appointments.find_one({
        "_id": appointment_object_id,
        "patient_email": session['user']['email']
    })
    if not appointment:
        flash("Appointment not found")
        return redirect(url_for('auth.patient_appointments'))

    db.followups.insert_one({
        "appointment_id": str(appointment_object_id),
        "doctor_email": appointment.get("doctor_email"),
        "doctor_name": appointment.get("doctor_name"),
        "patient_email": appointment.get("patient_email"),
        "patient_name": appointment.get("patient_name"),
        "note": note,
        "status": "requested",
        "created_at": datetime.utcnow()
    })

    if _should_send_email(db, appointment.get("doctor_email"), "doctor"):
        body = (
            f"Hello Dr. {appointment.get('doctor_name')},\n\n"
            f"{appointment.get('patient_name')} requested a follow-up appointment.\n\n"
            f"Note: {note or 'N/A'}\n"
        )
        _send_email(appointment.get("doctor_email"), "Follow-up Requested", body)

    _log_audit(db, session['user']['email'], session['user']['role'], "followup_request", {
        "appointment_id": appointment_id
    })

    flash("Follow-up request sent")
    return redirect(url_for('auth.patient_appointments'))

# --- APPOINTMENT CHAT ---
@auth_bp.route('/appointments/<appointment_id>/chat')
def appointment_chat(appointment_id):
    if 'user' not in session:
        flash("Please login to access chat")
        return redirect(url_for('home'))

    from app import db
    try:
        appointment_object_id = ObjectId(appointment_id)
    except Exception:
        flash("Invalid appointment")
        return redirect(url_for('home'))

    appointment = db.appointments.find_one({"_id": appointment_object_id})
    if not appointment:
        flash("Appointment not found")
        return redirect(url_for('home'))

    user_email = session['user']['email']
    if session['user']['role'] == 'patient' and appointment.get("patient_email") != user_email:
        flash("Unauthorized")
        return redirect(url_for('home'))
    if session['user']['role'] == 'doctor' and appointment.get("doctor_email") != user_email:
        flash("Unauthorized")
        return redirect(url_for('home'))

    messages = list(db.messages.find(
        {"appointment_id": appointment_id}
    ).sort("created_at", 1))
    for msg in messages:
        msg["id"] = str(msg.get("_id"))

    return render_template(
        'appointment_chat.html',
        user=session['user'],
        appointment=appointment,
        appointment_id=appointment_id,
        messages=messages
    )

# --- E-PRESCRIPTION VIEW ---
@auth_bp.route('/prescriptions/<prescription_id>')
def view_prescription(prescription_id):
    if 'user' not in session:
        flash("Please login to access prescriptions")
        return redirect(url_for('home'))

    from app import db
    try:
        prescription_object_id = ObjectId(prescription_id)
    except Exception:
        flash("Invalid prescription")
        return redirect(url_for('home'))

    prescription = db.prescriptions.find_one({"_id": prescription_object_id})
    if not prescription:
        flash("Prescription not found")
        return redirect(url_for('home'))

    if session['user']['role'] == 'patient' and prescription.get("patient_email") != session['user']['email']:
        flash("Unauthorized")
        return redirect(url_for('home'))
    if session['user']['role'] == 'doctor' and prescription.get("doctor_email") != session['user']['email']:
        flash("Unauthorized")
        return redirect(url_for('home'))

    prescription["id"] = str(prescription.get("_id"))
    return render_template('e_prescription.html', user=session['user'], prescription=prescription)

# --- MEDICAL HISTORY TIMELINE ---
@auth_bp.route('/patient/timeline')
def patient_timeline():
    if 'user' not in session or session['user']['role'] != 'patient':
        flash("Please login to access timeline")
        return redirect(url_for('auth.login_patient'))

    from app import db
    appointments = list(db.appointments.find({
        "patient_email": session['user']['email']
    }))
    prescriptions = list(db.prescriptions.find({
        "patient_email": session['user']['email']
    }))
    followups = list(db.followups.find({
        "patient_email": session['user']['email']
    }))

    timeline = []
    for appt in appointments:
        try:
            timestamp = _parse_datetime(appt.get("date"), appt.get("time"))
        except Exception:
            timestamp = appt.get("created_at") or datetime.utcnow()
        timeline.append({
            "type": "appointment",
            "title": f"Appointment with Dr. {appt.get('doctor_name')}",
            "timestamp": timestamp,
            "details": appt.get("issue_category")
        })
        if appt.get("reports"):
            timeline.append({
                "type": "report",
                "title": "Reports uploaded",
                "timestamp": appt.get("created_at") or timestamp,
                "details": f"{len(appt.get('reports'))} file(s)"
            })

    for rx in prescriptions:
        timeline.append({
            "type": "prescription",
            "title": f"Prescription from Dr. {rx.get('doctor_name')}",
            "timestamp": rx.get("created_at") or datetime.utcnow(),
            "details": rx.get("medication")
        })

    for item in followups:
        try:
            timestamp = _parse_datetime(item.get("date"), item.get("time")) if item.get("date") and item.get("time") else item.get("created_at")
        except Exception:
            timestamp = item.get("created_at") or datetime.utcnow()
        timeline.append({
            "type": "followup",
            "title": f"Follow-up with Dr. {item.get('doctor_name')}",
            "timestamp": timestamp,
            "details": item.get("status")
        })

    timeline.sort(key=lambda x: x.get("timestamp") or datetime.utcnow(), reverse=True)
    return render_template('patient_timeline.html', user=session['user'], timeline=timeline)

# --- ADMIN PANEL ---
@auth_bp.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        from app import db
        email = request.form.get('email').lower()
        password = request.form.get('password')
        user = db.users.find_one({"email": email, "role": "admin"})
        if user and check_password_hash(user['password'], password):
            session['admin'] = {
                'email': user['email'],
                'name': user.get('name') or 'Admin'
            }
            _log_audit(db, user['email'], user['role'], "admin_login", {})
            return redirect(url_for('auth.admin_dashboard'))
        flash("Invalid admin credentials")

    return render_template('admin_login.html')

@auth_bp.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    flash("Logged out")
    return redirect(url_for('auth.admin_login'))

@auth_bp.route('/admin/dashboard')
def admin_dashboard():
    if 'admin' not in session:
        flash("Please login as admin")
        return redirect(url_for('auth.admin_login'))

    from app import db
    pending_doctors = list(db.users.find({
        "role": "doctor",
        "$or": [
            {"status": "pending"},
            {"status": {"$exists": False}},
            {"status": ""}
        ]
    }))
    reports = list(db.reports.find({}).sort("created_at", -1).limit(50))
    audit_logs = list(db.audit_logs.find({}).sort("created_at", -1).limit(100))
    users = list(db.users.find({}, {"password": 0}).sort("created_at", -1).limit(200))

    return render_template(
        'admin_dashboard.html',
        admin=session['admin'],
        pending_doctors=pending_doctors,
        reports=reports,
        audit_logs=audit_logs,
        users=users
    )

@auth_bp.route('/admin/doctors/<doctor_id>/approve', methods=['POST'])
def admin_approve_doctor(doctor_id):
    if 'admin' not in session:
        flash("Please login as admin")
        return redirect(url_for('auth.admin_login'))

    from app import db
    try:
        doctor_object_id = ObjectId(doctor_id)
    except Exception:
        flash("Invalid doctor")
        return redirect(url_for('auth.admin_dashboard'))

    doctor = db.users.find_one({"_id": doctor_object_id, "role": "doctor"})
    if not doctor:
        flash("Doctor not found")
        return redirect(url_for('auth.admin_dashboard'))

    db.users.update_one(
        {"_id": doctor_object_id},
        {"$set": {"status": "approved", "approved_at": datetime.utcnow()}}
    )

    _log_audit(db, session['admin']['email'], "admin", "doctor_approve", {
        "doctor_email": doctor.get("email")
    })

    flash("Doctor approved")
    return redirect(url_for('auth.admin_dashboard'))

@auth_bp.route('/admin/doctors/<doctor_id>/reject', methods=['POST'])
def admin_reject_doctor(doctor_id):
    if 'admin' not in session:
        flash("Please login as admin")
        return redirect(url_for('auth.admin_login'))

    from app import db
    reason = request.form.get('reason', '').strip()
    try:
        doctor_object_id = ObjectId(doctor_id)
    except Exception:
        flash("Invalid doctor")
        return redirect(url_for('auth.admin_dashboard'))

    doctor = db.users.find_one({"_id": doctor_object_id, "role": "doctor"})
    if not doctor:
        flash("Doctor not found")
        return redirect(url_for('auth.admin_dashboard'))

    db.users.update_one(
        {"_id": doctor_object_id},
        {"$set": {"status": "rejected", "rejected_at": datetime.utcnow(), "rejection_reason": reason}}
    )

    _log_audit(db, session['admin']['email'], "admin", "doctor_reject", {
        "doctor_email": doctor.get("email"),
        "reason": reason
    })

    flash("Doctor rejected")
    return redirect(url_for('auth.admin_dashboard'))

@auth_bp.route('/admin/users/<user_id>/role', methods=['POST'])
def admin_update_user_role(user_id):
    if 'admin' not in session:
        flash("Please login as admin")
        return redirect(url_for('auth.admin_login'))

    from app import db
    new_role = request.form.get('role')
    if new_role not in ["admin", "doctor", "patient"]:
        flash("Invalid role")
        return redirect(url_for('auth.admin_dashboard'))

    try:
        user_object_id = ObjectId(user_id)
    except Exception:
        flash("Invalid user")
        return redirect(url_for('auth.admin_dashboard'))

    user = db.users.find_one({"_id": user_object_id})
    if not user:
        flash("User not found")
        return redirect(url_for('auth.admin_dashboard'))

    db.users.update_one({"_id": user_object_id}, {"$set": {"role": new_role}})
    _log_audit(db, session['admin']['email'], "admin", "role_update", {
        "user_email": user.get("email"),
        "role": new_role
    })
    flash("Role updated")
    return redirect(url_for('auth.admin_dashboard'))

# --- SOCKET.IO EVENTS ---
def register_socketio_handlers(socketio):
    @socketio.on('join_appointment')
    def handle_join(data):
        appointment_id = data.get('appointment_id')
        if appointment_id:
            join_room(appointment_id)

    @socketio.on('send_message')
    def handle_message(data):
        appointment_id = data.get('appointment_id')
        sender_email = data.get('sender_email')
        sender_name = data.get('sender_name')
        sender_role = data.get('sender_role')
        text = (data.get('text') or '').strip()

        if not appointment_id or not sender_email or not text:
            return
        if len(text) > MAX_CHAT_MESSAGE_LEN:
            text = text[:MAX_CHAT_MESSAGE_LEN]

        from app import db
        try:
            appointment_object_id = ObjectId(appointment_id)
        except Exception:
            return

        appointment = db.appointments.find_one({"_id": appointment_object_id})
        if not appointment:
            return
        if sender_role == "patient" and appointment.get("patient_email") != sender_email:
            return
        if sender_role == "doctor" and appointment.get("doctor_email") != sender_email:
            return

        message_doc = {
            "appointment_id": appointment_id,
            "sender_email": sender_email,
            "sender_name": sender_name,
            "sender_role": sender_role,
            "text": text,
            "created_at": datetime.utcnow()
        }
        db.messages.insert_one(message_doc)

        emit('new_message', {
            "appointment_id": appointment_id,
            "sender_email": sender_email,
            "sender_name": sender_name,
            "sender_role": sender_role,
            "text": text,
            "created_at": message_doc["created_at"].strftime("%Y-%m-%d %H:%M")
        }, room=appointment_id)

# --- REROUTE APPOINTMENT (DOCTOR) ---
@auth_bp.route('/appointments/<appointment_id>/reroute', methods=['POST'])
def reroute_appointment(appointment_id):
    if 'user' not in session or session['user']['role'] != 'doctor':
        flash("Please login to manage appointments")
        return redirect(url_for('auth.login_doctor'))

    from app import db
    new_doctor_email = request.form.get('new_doctor_email')
    if not new_doctor_email:
        flash("Please select a doctor to reroute")
        return redirect(url_for('auth.doctor_appointments'))

    try:
        appointment_object_id = ObjectId(appointment_id)
    except Exception:
        flash("Invalid appointment")
        return redirect(url_for('auth.doctor_appointments'))

    appointment = db.appointments.find_one({
        "_id": appointment_object_id,
        "doctor_email": session['user']['email']
    })
    if not appointment:
        flash("Appointment not found")
        return redirect(url_for('auth.doctor_appointments'))

    if new_doctor_email == appointment.get("doctor_email"):
        flash("Select a different doctor")
        return redirect(url_for('auth.doctor_appointments'))

    if db.blocks.find_one({"doctor_email": new_doctor_email, "patient_email": appointment.get("patient_email")}):
        flash("This doctor is not available for this patient")
        return redirect(url_for('auth.doctor_appointments'))

    new_doctor = db.users.find_one({"email": new_doctor_email, "role": "doctor"})
    if not new_doctor:
        flash("Selected doctor not found")
        return redirect(url_for('auth.doctor_appointments'))

    db.appointments.update_one(
        {"_id": appointment_object_id},
        {"$set": {
            "doctor_email": new_doctor.get("email"),
            "doctor_name": new_doctor.get("name"),
            "doctor_specialization": new_doctor.get("specialization"),
            "status": "pending",
            "updated_at": datetime.utcnow(),
            "rerouted_from": session['user']['email']
        }}
    )

    if _should_send_email(db, new_doctor.get('email'), "doctor"):
        body = (
            f"Hello Dr. {new_doctor.get('name')},\n\n"
            f"An appointment has been rerouted to you from Dr. {session['user'].get('name')}.\n"
            f"Patient: {appointment.get('patient_name')}\n"
            f"Date: {appointment.get('date')}\nTime: {appointment.get('time')}\n"
            f"Issue: {appointment.get('issue_category')}\n"
            f"Details: {appointment.get('issue_detail') or 'N/A'}\n\n"
            "Please log in to MediConnect to review the request."
        )
        _send_email(new_doctor.get('email'), "Appointment Rerouted", body)

    if _should_send_email(db, appointment.get("patient_email"), "patient"):
        body = (
            f"Hello {appointment.get('patient_name')},\n\n"
            f"Your appointment has been rerouted to Dr. {new_doctor.get('name')}.\n"
            f"Date: {appointment.get('date')}\nTime: {appointment.get('time')}\n"
            f"Specialization: {new_doctor.get('specialization') or 'N/A'}\n\n"
            "Please log in to MediConnect for the latest updates."
        )
        _send_email(appointment.get("patient_email"), "Appointment Rerouted", body)

    flash("Appointment rerouted")
    _log_audit(db, session['user']['email'], session['user']['role'], "appointment_reroute", {
        "appointment_id": appointment_id,
        "new_doctor_email": new_doctor.get('email')
    })
    return redirect(url_for('auth.doctor_appointments'))

# --- BLOCK/REPORT PATIENT (DOCTOR) ---
@auth_bp.route('/doctor/patients/<patient_email>/block', methods=['POST'])
def doctor_block_patient(patient_email):
    if 'user' not in session or session['user']['role'] != 'doctor':
        flash("Please login to manage patients")
        return redirect(url_for('auth.login_doctor'))

    from app import db
    reason = request.form.get('reason', '').strip()
    db.blocks.update_one(
        {"doctor_email": session['user']['email'], "patient_email": patient_email},
        {"$set": {
            "doctor_email": session['user']['email'],
            "patient_email": patient_email,
            "reason": reason,
            "created_at": datetime.utcnow()
        }},
        upsert=True
    )

    flash("Patient blocked")
    _log_audit(db, session['user']['email'], session['user']['role'], "patient_block", {
        "patient_email": patient_email,
        "reason": reason
    })
    return redirect(request.referrer or url_for('auth.doctor_patients'))

@auth_bp.route('/doctor/patients/<patient_email>/unblock', methods=['POST'])
def doctor_unblock_patient(patient_email):
    if 'user' not in session or session['user']['role'] != 'doctor':
        flash("Please login to manage patients")
        return redirect(url_for('auth.login_doctor'))

    from app import db
    db.blocks.delete_one({"doctor_email": session['user']['email'], "patient_email": patient_email})
    flash("Patient unblocked")
    _log_audit(db, session['user']['email'], session['user']['role'], "patient_unblock", {
        "patient_email": patient_email
    })
    return redirect(request.referrer or url_for('auth.doctor_patients'))

@auth_bp.route('/doctor/patients/<patient_email>/report', methods=['POST'])
def doctor_report_patient(patient_email):
    if 'user' not in session or session['user']['role'] != 'doctor':
        flash("Please login to manage patients")
        return redirect(url_for('auth.login_doctor'))

    from app import db
    reason = request.form.get('reason', '').strip()
    details = request.form.get('details', '').strip()

    if not reason:
        flash("Please provide a reason for the report")
        return redirect(request.referrer or url_for('auth.doctor_patients'))

    report_doc = {
        "doctor_email": session['user']['email'],
        "doctor_name": session['user'].get('name'),
        "patient_email": patient_email,
        "reason": reason,
        "details": details,
        "created_at": datetime.utcnow()
    }
    db.reports.insert_one(report_doc)

    if ADMIN_EMAIL:
        body = (
            f"Patient report submitted\n\n"
            f"Doctor: {report_doc.get('doctor_name')} ({report_doc.get('doctor_email')})\n"
            f"Patient: {patient_email}\n"
            f"Reason: {reason}\n\n"
            f"Details:\n{details or 'N/A'}\n"
        )
        _send_email(ADMIN_EMAIL, "MediConnect Patient Report", body)

    flash("Report submitted")
    _log_audit(db, session['user']['email'], session['user']['role'], "patient_report", {
        "patient_email": patient_email,
        "reason": reason
    })
    return redirect(request.referrer or url_for('auth.doctor_patients'))

# --- LOGOUT ---
@auth_bp.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out successfully")
    return redirect(url_for('home'))