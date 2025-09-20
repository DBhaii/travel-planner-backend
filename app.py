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

# Use Render's DATABASE_URL if available, otherwise use local config
if os.getenv("DATABASE_URL"):
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL").replace("postgres://", "postgresql://", 1)
else:
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

# --- A command to create the database tables ---
@app.cli.command("create-db")
def create_db():
    """Creates the database tables."""
    db.create_all()
    print("Database tables created!")

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
    token = get_amadeus_token()
    if not token:
        return jsonify({"error": "Could not authenticate with Amadeus"}), 500
    origin = request.args.get('origin')
    destination = request.args.get('destination')
    departure_date = request.args.get('departureDate')
    if not all([origin, destination, departure_date]):
        return jsonify({"error": "Missing required search parameters"}), 400
    flight_url = "https://test.api.amadeus.com/v2/shopping/flight-offers"
    params = {"originLocationCode": origin, "destinationLocationCode": destination, "departureDate": departure_date, "adults": 1, "nonStop": "true", "max": 5}
    headers = {"Authorization": f"Bearer {token}"}
    try:
        res = requests.get(flight_url, headers=headers, params=params)
        res.raise_for_status()
        return jsonify(res.json())
    except requests.exceptions.HTTPError as e:
        error_details = e.response.json()
        return jsonify({"error": "Amadeus API Error", "details": error_details}), e.response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Network Error", "details": str(e)}), 500

@app.route("/api/search-hotels")
def search_hotels():
    token = get_amadeus_token()
    if not token:
        return jsonify({"error": "Could not authenticate with Amadeus"}), 500
    city_code = request.args.get('cityCode')
    check_in_date = request.args.get('checkInDate')
    check_out_date = request.args.get('checkOutDate')
    if not all([city_code, check_in_date, check_out_date]):
        return jsonify({"error": "Missing required search parameters"}), 400
    hotel_url = "https://test.api.amadeus.com/v1/reference-data/locations/hotels/by-city"
    params = {"cityCode": city_code, "checkInDate": check_in_date, "checkOutDate": check_out_date}
    headers = {"Authorization": f"Bearer {token}"}
    try:
        res = requests.get(hotel_url, headers=headers, params=params)
        res.raise_for_status()
        return jsonify(res.json())
    except requests.exceptions.HTTPError as e:
        error_details = e.response.json()
        return jsonify({"error": "Amadeus API Error", "details": error_details}), e.response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Network Error", "details": str(e)}), 500

# --- User-Specific Trip Endpoints ---
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

@app.route("/api/generate-itinerary", methods=['POST'])
@token_required
def generate_itinerary(current_user):
    trip_data = request.json.get('tripData')
    if not trip_data:
        return jsonify({"error": "No trip data provided"}), 400

    prompt = f"""
    You are a helpful travel assistant. Based on the following travel components:
    {json.dumps(trip_data, indent=2)}

    Please create a suggested, creative, day-by-day itinerary.
    The user has booked these items, so the plan should revolve around them.
    Suggest nearby attractions, local restaurants, and transportation tips.
    Format your entire response as a single block of clean HTML.
    Use headings (h3, h4), paragraphs (p), lists (ul, li), and bold tags (b) to make it readable.
    Do not include `<html>` or `<body>` tags.
    """
    try:
        response = model.generate_content(prompt)
        return jsonify({"itinerary_html": response.text})
    except Exception as e:
        print(f"Error calling Gemini API: {e}")
        return jsonify({"error": "Failed to generate itinerary from AI"}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5000)