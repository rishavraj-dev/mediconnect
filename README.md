# MediConnect

MediConnect is a telemedicine platform that connects patients with verified doctors for appointments, consultations, medical records, prescriptions, and follow-ups.

## Contents

- [Features](#features)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [Installation and Local Development](#installation-and-local-development)
- [Authentication](#authentication)
- [Application Routes](#application-routes)
- [User Workflows](#user-workflows)
- [Data and File Storage](#data-and-file-storage)
- [Testing and Verification](#testing-and-verification)
- [Deployment Notes](#deployment-notes)
- [Troubleshooting](#troubleshooting)
- [Security Checklist](#security-checklist)

## Features

- Patient and doctor dashboards for appointments, records, and actions.
- Email OTP registration and login for patients and doctors.
- Admin approval workflow for doctor registrations.
- Appointment requests with issue categories, intake details, dates, and report uploads.
- Doctor availability management and appointment time confirmation.
- Real-time appointment chat and video consultation links.
- Consultation notes, prescriptions, reviews, and follow-up requests.
- Patient and doctor profiles, profile photos, preferences, and account deletion.
- Doctor verification document uploads.
- Mobile dashboard navigation and a responsive landing-page menu.
- Plain-text and HTML email notifications for important account and appointment events.

## Technology Stack

- **Backend:** Python, Flask 3, Flask Blueprints, Flask-SocketIO
- **Database:** MongoDB through PyMongo
- **Email:** Flask-Mail with Brevo SMTP
- **Frontend:** Jinja2 templates, HTML, CSS, and Font Awesome
- **Configuration:** `python-dotenv` and environment variables
- **Production options:** Gunicorn and Eventlet are included in `requirements.txt`

## Project Structure

```text
MediConnect/
├── app.py                  # Flask application, MongoDB, mail, and Socket.IO setup
├── modules/
│   └── auth.py             # Blueprint, authentication, dashboards, and business routes
├── templates/              # Jinja2 pages for public, patient, doctor, and admin views
├── static/
│   ├── style.css           # Shared application styles
│   └── uploads/reports/    # Uploaded appointment reports
├── requirements.txt        # Pinned Python dependencies
├── userguide.md            # End-user walkthrough
└── README.md               # Developer documentation
```

`app.py` creates the Flask application, configures MongoDB, email, uploads, and Socket.IO, registers the `auth` blueprint, and starts the server. Most application behavior currently lives in `modules/auth.py`.

## Prerequisites

- Python 3.10 or newer is recommended.
- A running MongoDB deployment, either local or hosted.
- A Brevo SMTP account, or another SMTP provider configured in `app.py`.
- Git and a terminal capable of activating a Python virtual environment.

## Configuration

Create a `.env` file in the project root:

```dotenv
SECRET_KEY=your_flask_secret_key
MONGO_URI=your_mongodb_connection_string
BREVO_LOGIN=your_brevo_smtp_login
BREVO_SMTP_KEY=your_brevo_smtp_key
ADMIN_EMAIL=admin_email_for_notifications
```

Variable reference:

- `SECRET_KEY` signs Flask sessions. Use a long, random value outside local development.
- `MONGO_URI` is the MongoDB connection string. The application uses the `mediconnect_db` database.
- `BREVO_LOGIN` is the SMTP username or login.
- `BREVO_SMTP_KEY` is the SMTP key or password.
- `ADMIN_EMAIL` is the administrator email used for notifications and admin defaults.

The SMTP host (`smtp-relay.brevo.com`), port (`2525`), and TLS settings are configured in `app.py`. Keep `.env` out of version control and never expose SMTP credentials in templates or client-side code.

## Installation and Local Development

1. Create and activate a virtual environment.

   ```powershell
   python -m venv .venv
   .\\.venv\\Scripts\\Activate.ps1
   ```

   On macOS or Linux, activate it with `source .venv/bin/activate`.

2. Install dependencies.

   ```bash
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

3. Create `.env` using the configuration above and confirm that MongoDB is reachable.

4. Start the development server.

   ```bash
   python app.py
   ```

5. Open <http://localhost:5000>.

The development server runs with Flask-SocketIO and debug mode enabled. Do not use debug mode or the built-in development server for production.

## Authentication

### Patients and Doctors

1. A user submits the patient or doctor registration form.
2. MediConnect generates a six-digit OTP and emails it to the submitted address.
3. The user enters the OTP on `/verify-otp`.
4. Registration data is stored in MongoDB after successful verification.
5. A doctor remains pending until an administrator approves the account.

Patient and doctor login also uses email OTP. A password field may be collected during registration, but it is not used for their login flow.

### Administrator

Administrators sign in at `/admin/login` with an email and password. Admin sessions can approve or reject doctors, manage departments and roles, inspect audit activity, and view verification documents.

## Application Routes

Public pages:

- `/`: landing page and MongoDB connection status.
- `/about`, `/contact`, `/privacy`, `/terms`: informational pages.

Authentication:

- `/register/patient` and `/register/doctor`: registration forms.
- `/login/patient` and `/login/doctor`: request a login OTP.
- `/verify-otp`: shared registration and login verification page.
- `/resend-otp`: resend the current OTP.
- `/logout`: end the active user session.

Patient and doctor areas:

- `/dashboard/patient` and `/dashboard/doctor`: role-specific dashboards.
- `/patient/*`: appointments, doctors, records, prescriptions, timeline, profile, and settings.
- `/doctor/*`: appointments, patients, schedule, reviews, profile, and settings.
- `/appointments/*`: create, update, complete, cancel, review, notes, follow-ups, chat, and rerouting.

Administration:

- `/admin/login`, `/admin/logout`, and `/admin/dashboard`.
- Admin actions include department management, doctor approval or rejection, role management, and access to verification documents.

Most write operations use `POST` routes and require the appropriate session role. Route definitions are in `modules/auth.py`; templates should use Flask `url_for` rather than hard-coded route URLs.

## User Workflows

### Patient Workflow

- Register and verify an email address with an OTP.
- Browse approved doctors or choose General Physician for automatic assignment.
- Book an appointment with an issue category, preferred date, intake details, and optional reports.
- Track pending, accepted, rejected, cancelled, and completed appointments.
- Chat with the doctor, open a video consultation link, and review the visit.
- View medical records, prescriptions, follow-ups, and timeline history.
- Manage profile and notification preferences.

### Doctor Workflow

- Register with professional details and verification documents.
- Wait for administrator approval.
- Configure availability, appointment limits, weekend availability, and minimum notice.
- Accept or reject requests and set the confirmed appointment time.
- Review patient details and uploaded reports.
- Add consultation notes, prescriptions, follow-ups, and completion details.
- Manage profile, reviews, notifications, and patient access controls.

### Admin Workflow

- Sign in with admin credentials.
- Review pending doctor accounts and verification documents.
- Approve or reject doctors and send status notifications.
- Manage departments and user roles.
- Review audit records and administrative activity.

## Data and File Storage

MongoDB collections are created as data is inserted. Common collections include:

- `users`: patient, doctor, and admin records.
- `appointments`: requests, confirmed visits, statuses, notes, and links.
- `availability`: doctor availability slots.
- `availability_rules`: doctor scheduling rules.
- `prescriptions`: medication and dosage instructions.
- `reviews`: patient feedback.
- `followups`: follow-up requests and scheduling details.
- `audit_logs`: login and administrator activity.

Uploaded appointment reports are stored under `static/uploads/reports/`. Supported report extensions are `pdf`, `png`, `jpg`, `jpeg`, `doc`, and `docx`. Avatar uploads support `png`, `jpg`, and `jpeg`.

The application currently relies on MongoDB and the local filesystem; it does not include migrations or a separate object-storage adapter. Back up both the database and uploaded files before moving environments.

## Testing and Verification

There is currently no dedicated automated test suite in the repository. For a local smoke test:

1. Start MongoDB and the Flask application.
2. Open the landing page and verify the displayed database status.
3. Register a test patient and verify the emailed OTP.
4. Register a test doctor, approve it from the admin dashboard, and verify doctor login.
5. Create an appointment, upload a supported report, and test the appointment status flow.
6. Open the appointment chat in two sessions and verify messages are delivered.
7. Confirm that invalid file extensions and unauthorized dashboard access are rejected.

When adding automated tests, isolate email and MongoDB behind test fixtures and use a separate test database.

## Deployment Notes

- Set a unique production `SECRET_KEY` and production MongoDB URI.
- Disable Flask debug mode.
- Use a production WSGI/Socket.IO server such as Gunicorn with the Eventlet worker when appropriate.
- Configure the reverse proxy to support WebSocket upgrades for appointment chat.
- Use HTTPS because the application handles health information, login OTPs, and uploaded documents.
- Store uploaded reports outside the public web root or serve them through authenticated download routes in a production hardening pass.
- Configure database backups, upload backups, log rotation, and monitoring.
- Restrict administrator access and rotate SMTP credentials if they are exposed.

## Troubleshooting

- **OTP not received:** check spam or junk folders, verify SMTP credentials, then use Resend Code.
- **Doctor cannot log in:** confirm that an administrator approved the doctor and that the account is not marked for deletion.
- **Database shows Disconnected:** verify `MONGO_URI`, network access, MongoDB availability, and firewall rules.
- **File upload fails:** confirm the extension is supported and that the upload directory is writable.
- **Chat does not update:** confirm the Socket.IO connection, reverse-proxy WebSocket support, and that both users belong to the appointment.
- **SMTP errors:** confirm Brevo credentials, sender configuration, TLS access, and network connectivity.

## Security Checklist

- Use a strong, random `SECRET_KEY`.
- Keep `.env`, MongoDB credentials, SMTP keys, and uploaded medical documents private.
- Run behind HTTPS in any environment containing real user data.
- Restrict admin credentials and review `audit_logs` regularly.
- Validate upload extensions, file sizes, filenames, and storage permissions.
- Use a non-production database for development and testing.
- Review session, CSRF, rate-limiting, OTP expiry, and access-control behavior before production use.
- Treat this project as a demonstration until it has received a full privacy and security review for real medical data.

## Related Documentation

- [User guide](userguide.md)
- [Dependency list](requirements.txt)

## License

This project is provided as-is for demonstration and learning purposes.
