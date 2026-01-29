import os
from flask import Flask, request, session, jsonify, redirect, url_for
from flask_cors import CORS
from functools import wraps
import requests

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret')
CORS(app, supports_credentials=True)

# In-memory user store: { user_id: { email, subscribed, plan } }
users = {}

GOOGLE_CLIENT_ID = '875851537672-mn188te4kip14c0f6th40o9ui9ccuevs.apps.googleusercontent.com'

# --- Helpers ---
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Not logged in'}), 401
        return f(*args, **kwargs)
    return decorated

def verify_google_token(id_token):
    r = requests.get(f'https://oauth2.googleapis.com/tokeninfo?id_token={id_token}')
    if r.status_code != 200:
        return None
    data = r.json()
    if data.get('aud') != GOOGLE_CLIENT_ID:
        return None
    return {'email': data['email'], 'user_id': data['sub']}

# --- Auth Endpoints ---
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    id_token = data.get('idToken')
    email = data.get('email')
    password = data.get('password')
    user = None
    if id_token:
        verified = verify_google_token(id_token)
        if not verified:
            return jsonify({'error': 'Invalid Google token'}), 401
        user_id = verified['user_id']
        user = users.get(user_id) or {'email': verified['email'], 'user_id': user_id, 'subscribed': False, 'plan': None}
        users[user_id] = user
        session['user_id'] = user_id
    elif email and password:
        user_id = 'email:' + email
        user = users.get(user_id) or {'email': email, 'user_id': user_id, 'subscribed': False, 'plan': None}
        users[user_id] = user
        session['user_id'] = user_id
    else:
        return jsonify({'error': 'Missing credentials'}), 400
    return jsonify({'email': user['email'], 'subscribed': user['subscribed'], 'plan': user['plan']})

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'ok': True})

@app.route('/api/subscription', methods=['GET'])
@login_required
def subscription():
    user = users[session['user_id']]
    return jsonify({'subscribed': user['subscribed'], 'plan': user['plan'], 'email': user['email']})

@app.route('/api/subscribe', methods=['POST'])
@login_required
def subscribe():
    plan = request.json.get('plan')
    user = users[session['user_id']]
    user['subscribed'] = True
    user['plan'] = plan
    return jsonify({'ok': True})

@app.route('/api/cancel', methods=['POST'])
@login_required
def cancel():
    user = users[session['user_id']]
    user['subscribed'] = False
    user['plan'] = None
    return jsonify({'ok': True})

if __name__ == '__main__':
    app.run(port=4242, debug=True)
