# Simple Email Backend for Study Decoder Contact Form
# Flask server to receive contact form submissions and send email via SMTP
# Does NOT interfere with OpenAI or any other APIs

from flask import Flask, request, jsonify
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

app = Flask(__name__)

# --- CONFIGURATION ---
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_USERNAME = 'yazhat42@gmail.com'  # The Gmail address to send from
SMTP_PASSWORD = os.environ.get('STUDYDECODER_EMAIL_PASSWORD')  # Set this as an environment variable for security
TO_EMAIL = 'yazhat42@gmail.com'  # Where to receive contact form messages

@app.route('/api/contact', methods=['POST'])
def contact():
    data = request.json
    name = data.get('name', '')
    email = data.get('email', '')
    subject = data.get('subject', 'Contact Form Submission')
    message = data.get('message', '')

    # Compose email
    msg = MIMEMultipart()
    msg['From'] = SMTP_USERNAME
    msg['To'] = TO_EMAIL
    msg['Subject'] = f"[Study Decoder] {subject}"
    body = f"Name: {name}\nEmail: {email}\n\n{message}"
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SMTP_USERNAME, TO_EMAIL, msg.as_string())
        server.quit()
        return jsonify({'success': True, 'message': 'Message sent successfully.'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
