import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests
import stripe
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')


# Defensive: Use os.getenv and move risky setup into a function
def get_env_var(key, default=None):
    return os.getenv(key, default)

def safe_init_stripe():
    key = get_env_var('STRIPE_SECRET_KEY', 'sk_test_...')
    try:
        import stripe
        stripe.api_key = key
        return stripe
    except Exception as e:
        logging.error(f'Stripe init failed: {e}')
        return None

def safe_get_google_client_id():
    return get_env_var('GOOGLE_CLIENT_ID', '875851537672-mn188te4kip14c0f6th40o9ui9ccuevs.apps.googleusercontent.com')

def safe_get_stripe_webhook_secret():
    return get_env_var('STRIPE_WEBHOOK_SECRET', '')

stripe = safe_init_stripe()
GOOGLE_CLIENT_ID = safe_get_google_client_id()
STRIPE_WEBHOOK_SECRET = safe_get_stripe_webhook_secret()

# In-memory store for first-time user detection (replace with DB for true enterprise)
first_time_users = set()

# Serve static files from the current directory
app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)

@app.route('/api/check_payment', methods=['POST'])
def check_payment():
    data = request.get_json()
    id_token = data.get('id_token')
    if not id_token:
        logging.warning('Missing id_token in request')
        return jsonify({'error': 'Missing id_token'}), 400

    # Verify Google ID token
    google_resp = requests.get(f'https://oauth2.googleapis.com/tokeninfo?id_token={id_token}')
    if google_resp.status_code != 200:
        logging.warning('Invalid Google token')
        return jsonify({'error': 'Invalid Google token'}), 401
    google_data = google_resp.json()
    email = google_data.get('email')
    sub = google_data.get('sub')
    if not email or not sub:
        logging.warning('No email or sub in Google token')
        return jsonify({'error': 'No email in Google token'}), 401

    # First-time user detection (in-memory, for demo)
    is_first_time = sub not in first_time_users
    if is_first_time:
        first_time_users.add(sub)
        logging.info(f'First time user detected: {email} ({sub})')
    else:
        logging.info(f'Returning user: {email} ({sub})')

    # Check Stripe for a successful payment with this email
    if not stripe:
        logging.error('Stripe not initialized')
        return jsonify({'paid': False, 'first_time': is_first_time, 'error': 'Stripe not initialized'}), 500
    try:
        customers = stripe.Customer.list(email=email, limit=1)
        if not customers.data:
            logging.info(f'No Stripe customer found for {email}')
            return jsonify({'paid': False, 'first_time': is_first_time})
        customer_id = customers.data[0].id
        # Check for active subscriptions
        subs = stripe.Subscription.list(customer=customer_id, status='active')
        if subs.data:
            logging.info(f'Active subscription found for {email}')
            return jsonify({'paid': True, 'first_time': is_first_time})
        # Check for successful one-time payment
        charges = stripe.Charge.list(customer=customer_id, paid=True)
        if charges.data:
            logging.info(f'One-time payment found for {email}')
            return jsonify({'paid': True, 'first_time': is_first_time})
        logging.info(f'No payment found for {email}')
        return jsonify({'paid': False, 'first_time': is_first_time})
    except Exception as e:
        logging.error(f'Stripe API error: {e}')
        return jsonify({'paid': False, 'first_time': is_first_time, 'error': 'Stripe API error'}), 500


# Serve index.html at root
@app.route('/')
def root():
    return send_from_directory('.', 'index.html')

# Serve any other static file (css, js, images, etc.)
@app.route('/<path:path>')
def static_proxy(path):
    return send_from_directory('.', path)

# Stripe webhook for real-time payment status (production-grade)
@app.route('/api/stripe_webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    event = None
    if not stripe:
        logging.error('Stripe not initialized for webhook')
        return '', 500
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except Exception as e:
        logging.error(f'Webhook error: {e}')
        return '', 400
    # Log the event
    logging.info(f'Stripe webhook event: {event["type"]}')
    # You can add DB updates or other logic here for true enterprise
    return '', 200

if __name__ == '__main__':
    # Only run the server locally for development. Render/Gunicorn will serve the app in production.
    app.run(host='0.0.0.0', port=5000)
