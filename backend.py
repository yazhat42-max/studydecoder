import os
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import stripe

app = Flask(__name__)
CORS(app)

# Set your Stripe secret key here
STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY', 'sk_test_...')
stripe.api_key = STRIPE_SECRET_KEY

# Your Google client ID
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '875851537672-mn188te4kip14c0f6th40o9ui9ccuevs.apps.googleusercontent.com')

@app.route('/api/check_payment', methods=['POST'])
def check_payment():
    data = request.get_json()
    id_token = data.get('id_token')
    if not id_token:
        return jsonify({'error': 'Missing id_token'}), 400

    # Verify Google ID token
    google_resp = requests.get(f'https://oauth2.googleapis.com/tokeninfo?id_token={id_token}')
    if google_resp.status_code != 200:
        return jsonify({'error': 'Invalid Google token'}), 401
    google_data = google_resp.json()
    email = google_data.get('email')
    if not email:
        return jsonify({'error': 'No email in Google token'}), 401

    # Check Stripe for a successful payment with this email
    customers = stripe.Customer.list(email=email, limit=1)
    if not customers.data:
        return jsonify({'paid': False})
    customer_id = customers.data[0].id
    # Check for active subscriptions
    subs = stripe.Subscription.list(customer=customer_id, status='active')
    if subs.data:
        return jsonify({'paid': True})
    # Check for successful one-time payment
    charges = stripe.Charge.list(customer=customer_id, paid=True)
    if charges.data:
        return jsonify({'paid': True})
    return jsonify({'paid': False})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
