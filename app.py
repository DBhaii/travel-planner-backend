import os
import json
import requests
import jwt
import datetime
from functools import wraps
from flask import Flask, jsonify, request
from flask_cors import CORS
from dotenv import load_dotenv
import google.generativeai as genai
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
CORS(app)

# --- Add a Secret Key for Signing Tokens ---
app.config['SECRET_KEY'] = 'your-super-secret-key-please-change-this'

# --- Database Configuration ---
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")
DB_HOST = "localhost"
DB_PORT = "5432"

app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- AI Configuration ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-pro')

# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Trip(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    items = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# app.py
import os
import json
# ... (all other imports are the same)

# ... (app, CORS, DB Config, AI Config are all the same) ...
db = SQLAlchemy(app)

# --- Database Models (no changes) ---
class User(db.Model):
    # ... (no changes)
class Trip(db.Model):
    # ... (no changes)

# --- NEW: A command to create the database tables ---
@app.cli.command("create-db")
def create_db():
    """Creates the database tables."""
    db.create_all()
    print("Database tables created!")

# --- The rest of your app.py file is EXACTLY the same ---
# ... (get_amadeus_token, all API endpoints, etc.) ...

# --- Token Verification Decorator ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['id'])
        except Exception as e:
            print(e)
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# --- Amadeus Helper Function ---
def get_amadeus_token():
    client_id = os.getenv("AMADEUS_API_KEY")
    client_secret = os.getenv("AMADEUS_API_SECRET")
    token_url = "https://test.api.amadeus.com/v1/security/oauth2/token"
    payload = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret}
    try:
        res = requests.post(token_url, data=payload)
        res.raise_for_status()
        return res.json()['access_token']
    except requests.exceptions.RequestException as e:
        print(f"Error getting Amadeus token: {e}")
        return None

# --- User Authentication Endpoints ---
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Username and password are required!'}), 400
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Username already exists!'}), 409
    
    new_user = User(username=data['username'])
    new_user.set_password(data['password'])
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'New user created!'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    auth = request.get_json()
    if not auth or not auth.get('username') or not auth.get('password'):
        return jsonify({'message': 'Could not verify'}), 401
    
    user = User.query.filter_by(username=auth['username']).first()
    if not user or not user.check_password(auth['password']):
        return jsonify({'message': 'Could not verify'}), 401
    
    token = jwt.encode({
        'id': user.id,
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm="HS256")
    
    return jsonify({'token': token})

# --- Search Endpoints ---
@app.route("/api/search-flights")
def search_flights():
    # ... (code is complete and correct)
    return #...

@app.route("/api/search-hotels")
def search_hotels():
    # ... (code is complete and correct)
    return #...

# --- UPDATED: Trip Endpoints to be User-Specific ---
@app.route("/api/trip", methods=['POST'])
@token_required
def save_trip(current_user):
    trip_items = request.json.get('tripData')
    if trip_items is None:
        return jsonify({"error": "No trip data provided"}), 400
    
    user_trip = Trip.query.filter_by(user_id=current_user.id).first()
    if not user_trip:
        user_trip = Trip(user_id=current_user.id, items=json.dumps(trip_items))
        db.session.add(user_trip)
    else:
        user_trip.items = json.dumps(trip_items)
        
    db.session.commit()
    
    return jsonify({"message": "Trip saved successfully!"})

@app.route("/api/trip", methods=['GET'])
@token_required
def load_trip(current_user):
    trip = Trip.query.filter_by(user_id=current_user.id).first()
    if trip:
        return jsonify({"tripData": json.loads(trip.items)})
    else:
        return jsonify({"tripData": []})

# --- AI Itinerary Endpoint (now requires token) ---
@app.route("/api/generate-itinerary", methods=['POST'])
@token_required
def generate_itinerary(current_user):
    trip_data = request.json.get('tripData')
    if not trip_data:
        return jsonify({"error": "No trip data provided"}), 400

    prompt = f"""
    You are a helpful travel assistant...
    """ # ... (prompt content is the same)
    
    try:
        response = model.generate_content(prompt)
        return jsonify({"itinerary_html": response.text})
    except Exception as e:
        print(f"Error calling Gemini API: {e}")
        return jsonify({"error": "Failed to generate itinerary from AI"}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5000)