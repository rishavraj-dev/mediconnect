MediConnect
===========

Overview
--------
MediConnect is a telemedicine platform that connects patients with verified doctors for appointments, consultations, medical records, and follow-ups. The app uses email-based OTP (one-time password) verification for patient and doctor registration and login, with no passwords required for those roles.

Key Features
------------
- Patient and doctor dashboards for appointments, records, and actions.
- Email OTP registration and login for patients and doctors.
- Doctor approval workflow via the admin dashboard.
- Appointment scheduling with intake notes and document uploads.
- Chat and video consultation links for active visits.
- Prescriptions and follow-up tracking.
- Mobile-first navigation with a consistent bottom bar on dashboards.
- Landing page hamburger menu on mobile screens.

Tech Stack
----------
- Backend: Flask, Flask-SocketIO, Flask-Mail
- Database: MongoDB
- Frontend: HTML, CSS, Font Awesome

Authentication Summary
----------------------
- Patients and doctors sign up with email and profile details.
- OTP is sent to the email address for verification.
- Login uses email OTP only (no password required).
- Doctors must be approved by an admin before accessing the doctor dashboard.
- Admin login uses email and password.

Project Structure
-----------------
- app.py: Flask app entry point and mail setup
- modules/auth.py: Authentication, dashboards, and core routes
- templates/: HTML templates for all views
- static/style.css: Application styles
- requirements.txt: Python dependencies
- userguide.md: End-user walkthrough and feature guide

Environment Variables
---------------------
Create a .env file in the project root with the following values:

SECRET_KEY=your_flask_secret_key
MONGO_URI=your_mongodb_connection_string
BREVO_LOGIN=your_brevo_smtp_login
BREVO_SMTP_KEY=your_brevo_smtp_key
ADMIN_EMAIL=admin_email_for_notifications

Optional email configuration is defined in app.py and can be adjusted if you use a different SMTP provider.

Setup
-----
1) Create and activate a virtual environment.
2) Install dependencies:

	pip install -r requirements.txt

3) Configure the .env file.
4) Start the app:

	python app.py

The app runs at http://localhost:5000.

Core User Flows
---------------

Patient Registration
--------------------
1) Open Patient Registration.
2) Enter profile details and email.
3) Submit the form to receive an OTP.
4) Verify OTP to complete registration and sign in.

Doctor Registration
-------------------
1) Open Doctor Registration.
2) Enter professional details and email.
3) Submit the form to receive an OTP.
4) Verify OTP to complete registration.
5) Wait for admin approval before accessing the dashboard.

Patient and Doctor Login
------------------------
1) Enter registered email.
2) Click Send OTP.
3) Verify the OTP to sign in.

Resend OTP
----------
If the OTP is not received, use the Resend Code action on the OTP page.

Patient Features
----------------
- Dashboard summary for upcoming and completed appointments.
- Book appointments with issue category, doctor, date, and time.
- Add intake details: symptoms, allergies, medications, conditions, vitals, and notes.
- Upload medical reports with appointments.
- View appointment status, chat, and join video calls.
- Access medical records, prescriptions, and timeline history.
- Manage profile and notification preferences.

Doctor Features
---------------
- Dashboard overview for daily appointments and pending requests.
- Accept or reject appointment requests.
- Add consultation notes and prescriptions.
- Mark appointments as completed.
- Manage availability schedule.
- View patients and reviews.
- Manage profile and notification preferences.

Admin Features
--------------
- Admin login with email and password.
- Approve or reject pending doctor registrations.
- Review audit logs and reports.
- Manage user roles when required.

Mobile UX
---------
- Patient bottom navigation: Home, Appointments, Book, Records, Profile.
- Doctor bottom navigation: Home, Appointments, Schedule, Patients, Profile.
- Landing page uses a hamburger menu on small screens.

Supported Report File Types
---------------------------
- pdf, png, jpg, jpeg, doc, docx

Data Model Notes
----------------
MongoDB collections are created automatically when data is inserted. Common collections include:
- users: patient, doctor, and admin records
- appointments: appointment requests and statuses
- availability: doctor availability slots
- prescriptions: medication and dosage instructions
- reviews: patient feedback
- followups: follow-up requests
- audit_logs: login and admin activity

Operational Notes
-----------------
- OTP emails are sent via Brevo SMTP using the credentials in .env.
- Doctors cannot log in until their status is approved.
- Admin login still uses passwords and is not OTP-based.

Troubleshooting
---------------
- OTP not received: check spam/junk folder, then resend.
- Doctor cannot log in: verify approval status in admin dashboard.
- File upload fails: confirm file type is supported and size is reasonable.
- SMTP issues: confirm Brevo credentials and network access.

Security Considerations
-----------------------
- Use strong values for SECRET_KEY.
- Keep SMTP credentials private.
- Restrict admin access to trusted users only.

License
-------
This project is provided as-is for demonstration and learning purposes.
