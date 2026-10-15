# Ecosphere Waste Solutions Authentication Starter

This project connects the landing page to a Flask server, Twilio Verify SMS OTP, Google Identity Services, SQLite account storage, password hashing, and a 5-failed-password-attempt / 1-hour lockout.

## 1. Requirements
- Python 3.10+
- A Twilio account and a Twilio Verify Service
- A Google OAuth Web Client ID from Google Cloud Console
- HTTPS for production

## 2. Install and configure
Windows PowerShell:
```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```
Open `.env` and fill in credentials. Generate a secret key with:
```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```
Put the output in `FLASK_SECRET_KEY`.

## 3. Set up Twilio Verify
1. Sign in to Twilio Console.
2. Create a Verify Service.
3. Copy Account SID, Auth Token, and Verify Service SID into `.env`.
4. Make sure your account/service supports SMS delivery to the destination country. Trial accounts may require verified recipient numbers. Follow local SMS regulations and provider requirements.

Twilio Verify generates and checks OTPs; this application does not expose the OTP in the browser.

## 4. Set up Google sign-in
1. In Google Cloud Console, configure the OAuth consent screen.
2. Create an OAuth Client ID with application type **Web application**.
3. Add your exact local origin to Authorized JavaScript origins, typically `http://localhost:5000`.
4. Put the client ID in `GOOGLE_CLIENT_ID`.
5. For deployment, add your production HTTPS origin and use the same client ID on the server.

## 5. Run
```powershell
python app.py
```
Open `http://127.0.0.1:5000`.

## Security notes
- Never put Twilio credentials in HTML or JavaScript.
- Never commit `.env`.
- Use HTTPS and `COOKIE_SECURE=1` in production.
- Run behind a production WSGI server such as Gunicorn (on a Linux host) or a suitable Windows production host.
- Add reverse-proxy/IP rate limiting and monitoring before public launch. Twilio Verify has its own checks and limits; consider additional per-IP send limits.
- This starter includes CSRF protection, HttpOnly/SameSite cookies, server-side password hashing, OTP verification through Twilio, Google ID-token verification, and per-account password lockout.
- Before production, review account-linking policy, recovery flows, backups, privacy notice, and applicable data-protection/SMS rules.
