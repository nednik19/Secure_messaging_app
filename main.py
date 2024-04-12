import hashlib
from flask import Flask, render_template, request, session, redirect, url_for, g, send_file
from flask_socketio import join_room, leave_room, send, SocketIO
import random
import os
import sqlite3
import bcrypt
import uuid
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import hmac
import string
from functools import wraps
import qrcode
import pyotp
import ssl

app = Flask(__name__)
app.config["SECRET_KEY"] = "hjhjsdahhds"
socketio = SocketIO(app)

# Path to the database file
db_file = "DB/db3.db"

# Add SSL context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("cert.pem", "key.pem")

def generate_unique_code(code_length):
    characters = string.ascii_uppercase + string.digits
    unique_code = ''.join(random.choices(characters, k=code_length))
    return unique_code

# Function to derive encryption key from room code
def derive_key_from_room(room_code):
    # Convert room code to bytes
    room_code_bytes = room_code.encode('utf-8')
    
    # Use a KDF to derive a fixed-length encryption key from the room code
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Length of the key in bytes
        salt=b'',  # Since room code is unique, no need for salt
        iterations=100000,  # Number of iterations
        backend=default_backend()
    )
    
    # Derive the key from the room code
    key_material = kdf.derive(room_code_bytes)
    
    return key_material

def login_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return decorated_function


def encrypt_message(message, key):
    # print("Message to encrypt: ", message)
    # print("Key: ", key)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext)


def decrypt_message(ciphertext, key):
    ciphertext = base64.b64decode(ciphertext)
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    # print("Plaintext: ", plaintext, " key: ", key)
    # print("plaintext Type: ", type(plaintext))
    return plaintext.decode('utf-8')


# Connect to the SQLite database
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(db_file)
    return db

# Create a table if it doesn't exist
def init_users():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            full_name TEXT NOT NULL,
            secret_qrcode_key TEXT NOT NULL
        );
        """)
        db.commit()

def init_messages():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL REFERENCES users(username),
            room_code TEXT NOT NULL REFERENCES rooms(room_code),
            message TEXT,
            hmac TEXT      
        );
        """)
        db.commit()

def init_rooms():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS rooms (
            id TEXT PRIMARY KEY,
            code TEXT NOT NULL UNIQUE,
            secret TEXT NOT NULL,
            users_count NUMBER NOT NULL DEFAULT 0   
        );
        """)
        db.commit()



# Initialize the database on first run
if not os.path.isfile(db_file):
    init_users()
    init_rooms()
    init_messages()
    

# Close the database connection at the end of each request
@app.teardown_appcontext
def teardown_db(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

################################################################

@app.route("/", methods=["POST", "GET"])
@login_required
def home():
    # print("home " + request.method)

    if request.method == "POST":
        username = request.form.get("username")
        code = request.form.get("code")
        join = request.form.get("join", False)
        create = request.form.get("create", False)

        if not username:
            # print("If not username")
            return render_template("home.html", error="Please enter a name.", code=code, username=username)

        if join != False and not code:
            # print("if join != False and not code:")
            return render_template("home.html", error="Please enter a room code.", code=code, username=username)
        
        room = code
        room_encryption_key = derive_key_from_room(room)

        #room_exists = get_room(room)
        if create != False:
            # print("if create != False:")
            room = generate_unique_code(8)
            create_room(room, room_encryption_key, 0)
            # rooms[room] = {"members": 0, "messages": []}
        
        else:
            room_exists = get_room(room)
            if not room_exists:
                # print("elif code not in rooms:")
                return render_template("home.html", error="Room does not exist.", code=code, username=username)
        
        # Derive encryption and authentication keys from the room code
        authentication_key = os.urandom(32)  # Generate a random authentication key for each room

        # Store the keys in the session
        session['encryption_key'] = room_encryption_key
        session['authentication_key'] = authentication_key
        session["room"] = room
        session["username"] = username

        # print("else")
        # print("Here is the encryption key: ", room_encryption_key)
        return redirect(url_for("room"))

    username = session.get("username") 
    # print("HOME GET")
    return render_template("home.html", username=username)

@app.route("/room")
@login_required
# @app.route("/room", methods=['GET', 'POST'])
def room():

    username = session.get("username")
    room = session.get("room")
    
    room_exists = get_room(room)
    if room is None or session.get("username") is None or not room_exists:
        return render_template("home.html", username=username)
        # return redirect(url_for("home"))

    messages = get_messages_in_room(room)
    return render_template("room.html",username=username, code=room, messages=messages, online=room_exists[3])

@app.route('/login', methods=['GET', 'POST'])
def login():
    session.clear()
    error = None  # Initialize error variable
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        session['username'] = username
        
        # Retrieve user from the database
        cursor = get_db().cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if user:
            # Verify the password using bcrypt
            if bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
                # Prompt user to enter OTP
                return redirect(url_for('verify_otp', username=username))
            else:
                error = 'Invalid username or password'  # Set error message
        else:
            error = 'Invalid username or password'  # Set error message
        
    return render_template('login.html', error=error)  # Pass error to the template


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        full_name = request.form['full_name']
        
        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Generate a secret key for the user
        secret_qrcode_key = pyotp.random_base32()
        
        # Encode the secret key into a QR code
        totp = pyotp.TOTP(secret_qrcode_key)
        uri = totp.provisioning_uri(username)
        img = qrcode.make(uri)
        img_path = f"static/QRcodes/{username}_qr.png"
        img.save(img_path)  # Save the QR code image to a static folder

        # Store img_path in the session
        session['img_path'] = img_path

        # Set session variable indicating registration completion
        session['registration_complete'] = True
        
        # Insert new user into the database
        cursor = get_db().cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, email))
        existing_user = cursor.fetchone()
        
        if existing_user:
            error = 'Username or email already exists'
            return render_template('register.html', error=error)

        insert_query = "INSERT INTO users (id, username, password, email, full_name, secret_qrcode_key) VALUES (?, ?, ?, ?, ?, ?)"
        cursor.execute(insert_query, (str(uuid.uuid4()), username, hashed_password.decode('utf-8'), email, full_name, secret_qrcode_key))
        get_db().commit()
        
        return redirect(url_for('register_MFA', username=username))
    
    return render_template('register.html')



@app.route('/register_MFA/<username>', methods=['GET', 'POST'])
def register_MFA(username):

    # Check if registration is complete
    if not session.get('registration_complete'):
        # Redirect to registration page if registration is not complete
        return redirect(url_for('register'))
    
    img_path = session.get('img_path')
    if img_path is None:
        # Handle the case where img_path is not found in the session
        return redirect(url_for('register'))  # Redirect to register route if img_path is not available
    
    if request.method == 'POST':
        otp = request.form.get('otp')
        username = request.form.get('username')

        # Retrieve the secret key for the user from the database
        cursor = get_db().cursor()
        cursor.execute("SELECT secret_qrcode_key FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user:
            secret_key = user[0]
            # Verify the OTP entered by the user
            totp = pyotp.TOTP(secret_key)
            if totp.verify(otp):
                # OTP verification successful, delete the QR code
                img_path = f"static/QRcodes/{username}_qr.png"
                if os.path.exists(img_path):
                    os.remove(img_path)
                
                # Redirect to home or any other route
                return redirect(url_for('home'))
            else:
                # OTP verification failed, display error message
                error = 'Invalid OTP. Please try again.'
                return render_template('register_MFA.html', username=username, error=error)

    # If it's a GET request or OTP verification failed, render the register_MFA.html template
    return render_template('register_MFA.html', username=username, img_path=img_path)


@app.route('/verify_otp', methods=['GET', 'POST'])
@login_required
def verify_otp():
    # Retrieve the username from the session
    username_session = session.get('username')
    
    if request.method == 'POST':
        # Retrieve username and OTP from the session
        username = username_session
        otp = request.form.get('otp')
        
        # Retrieve the secret key for the user from the database
        cursor = get_db().cursor()
        cursor.execute("SELECT secret_qrcode_key FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user:
            secret_key = user[0]
            # Verify the OTP entered by the user
            totp = pyotp.TOTP(secret_key)
            if totp.verify(otp):
                # OTP verification successful, set session variable for the user
                session['username'] = username
                return redirect(url_for('home'))
            else:
                # OTP verification failed, display error message
                error = 'Invalid OTP. Please try again.'
                return render_template('verify_otp.html', username=username, error=error)

    # If it's a GET request or OTP verification failed, render the verify_OTP.html template
    username = username_session
    # Check if the username in the URL parameter matches the username in the session
    if request.args.get('username') != username:
        return redirect(url_for('home'))  # Redirect to home if the usernames don't match

    return render_template('verify_otp.html', username=username)




@app.route('/qr_code/<username>')
def qr_code(username):
    try:
        return send_file(f"static/QRcodes/{username}_qr.png", mimetype='image/png')
    except FileNotFoundError:
        return render_template('qr_error.html'), 404



@socketio.on("message")
def message(data):
    room = session.get("room")
    username = session.get("username")

    room_exists = get_room(room)
    if not room_exists:
        return

    # Retrieve encryption and authentication keys from the session
    room_encryption_key = room_exists[2]
    authentication_key = session.get('authentication_key')

    # Calculate HMAC digest using SHA256
    h = hmac.new(authentication_key, data['data'].encode('utf-8'), hashlib.sha256)
    mac = h.digest()

    # Encrypt the message
    encrypted_message = encrypt_message(data['data'], room_encryption_key)
    
    # Store the message and its HMAC in the database
    cursor = get_db().cursor()
    insert_query = "INSERT INTO messages (id, username, room_code, message, hmac) VALUES (?, ?, ?, ?, ?)"
    cursor.execute(insert_query, (str(uuid.uuid4()), username, room, encrypted_message, mac))
    get_db().commit()

    send({"type": "message", 'username': username, 'message': data['data']}, to=room)
    print(f"{username} said: {data['data']}")

@socketio.on("connect")
def connect(auth):
    room = session.get("room")
    username = session.get("username")
    if not room or not username:
        return
    
    room_exists = get_room(room)
    if not room_exists:
        leave_room(room)
        return

    join_room(room)
    send({"type": "message", "username": username, "message": "has entered the room"}, to=room)
    update_room_users_count(room, 1)
    print(f"{username} joined room {room}")

@socketio.on("disconnect")
def disconnect():
    room = session.get("room")
    username = session.get("username")
    leave_room(room)
    
    send({"type": "message", "username": username, "message": "has left the room"}, to=room)
    update_room_users_count(room, -1)
    print(f"{username} has left the room {room}")

#helpers
def create_room(room_code, room_secret, count):
    
    room_id = uuid.uuid4()
    # room_secret = encrypt_message(room_code, room_id.bytes)

    # Insert room into the database
    cursor = get_db().cursor()
    
    insert_query = "INSERT INTO rooms (id, code, secret, users_count) VALUES (?, ?, ?, ?)"
    cursor.execute(insert_query,( (str(room_id)), room_code, room_secret, count))
    get_db().commit()

def get_room(room_code):
    cursor = get_db().cursor()
    cursor.execute("SELECT * FROM rooms WHERE code = ?", (room_code,))
    room = cursor.fetchone()

    return room

def get_messages_in_room(room_code):
    cursor = get_db().cursor()
    cursor.execute("SELECT * FROM messages WHERE room_code = ?", (room_code,))
    messages = cursor.fetchall()

    decrypted_messages = []
    room = get_room(room_code)
    if not room:
        return decrypted_messages  # Return empty list if room doesn't exist

    for message in messages:
        # Verify the HMAC
        calculated_hmac = hmac.new(session.get('authentication_key'), message[3], hashlib.sha256).digest()
        if calculated_hmac != message[4]:  # If HMAC doesn't match, discard the message
            continue

        # Decrypt the message and append to the list
        message_decoded = decrypt_message(message[3], room[2])  # message[3] contains the encrypted message, room[2] contains the secret key
        decrypted_messages.append({"id": message[0], "username": message[1], "room_code": message[2], "message": message_decoded})

    return decrypted_messages

    # if not messages:
    #     return []

    # room = get_room(room_code)
    # if not room:
    #     return []
    # for message in messages:
    #     message_decoded = decrypt_message(message["message"], room["secret"])
    #     message["message"] = message_decoded

    # return messages

def update_room_users_count(room_code, delta):
    cursor = get_db().cursor()
    cursor.execute("UPDATE rooms SET users_count = users_count + ? WHERE code = ? RETURNING *", (delta, room_code))
    updated_row = cursor.fetchone()
    get_db().commit()
    send({"type": "users_updated", "count": updated_row[3]}, to=room_code)

# Add error handlers for specific HTTP error codes
    
@app.errorhandler(401)
def unauthorized_error(error):
    app.logger.error(f"401 Unauthorized - You are not authorized to access this page. {str(error)}")

    error = "401 Unauthorized - You are not authorized to access this page."
    return render_template('error.html', error=error), 401

@app.errorhandler(403)
def forbidden_error(error):
    app.logger.error(f"403 Forbidden - You don't have permission to access this page. {str(error)}")    

    error = "403 Forbidden - You don't have permission to access this page."
    return render_template('error.html', error=error), 403

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html'), 404

@app.errorhandler(405)
def method_not_allowed_error(error):
    # Log the error
    app.logger.error(f"Method Not Allowed error occurred: {str(error)}")
    
    # Display a user-friendly error message
    error = "The method is not allowed for the requested URL."
    return render_template('error.html', error=error), 405

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Internal Server error. {str(error)}")

    error = "Internal Server Error"
    return render_template('error.html', error=error), 500

@app.errorhandler(sqlite3.Error)
def handle_database_error(error):
    # Log the error for debugging purposes
    app.logger.error(f"Database error occurred: {str(error)}")
    
    # Display a user-friendly error message
    error = "An error occurred while accessing the database. Please try again later."
    return render_template('error.html', error=error), 500

if __name__ == "__main__":
    # Use SSL context for running the app
    socketio.run(app, debug=True, port=8090, ssl_context=context)