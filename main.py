import hashlib
from flask import Flask, render_template, request, session, redirect, url_for, g
from flask_socketio import join_room, leave_room, send, SocketIO
import random
from string import ascii_uppercase
import os
import sqlite3
import bcrypt
import json
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

app = Flask(__name__)
app.config["SECRET_KEY"] = "hjhjsdahhds"
socketio = SocketIO(app)

# rooms = {}

def generate_unique_code(code_length):
    characters = string.ascii_uppercase + string.digits
    unique_code = ''.join(random.choices(characters, k=code_length))
    return unique_code

################################################################

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
    print("Message to encrypt: ", message)
    print("Key: ", key)
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

################################################################
# Path to the database file
db_file = "DB/db2.db"

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
            full_name TEXT NOT NULL
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
            message TEXT      
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
    # print(json.dumps(rooms, indent=4))
    # print(request.method + " room")
    username = session.get("username")
    room = session.get("room")
    # if request.method == 'POST'and room in rooms:
    #     return render_template("room.html",username=username, code=room, messages=rooms[room]["messages"])
    
    room_exists = get_room(room)
    if room is None or session.get("username") is None or not room_exists:
        return render_template("home.html", username=username)
        # return redirect(url_for("home"))

    messages = get_messages_in_room(room)
    return render_template("room.html",username=username, code=room, messages=messages, online=room_exists[3])

@app.route('/login', methods=['GET', 'POST'])
def login():
    session.clear()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Retrieve user from the database
        cursor = get_db().cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if user:
            # Verify the password using bcrypt
            if bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
                session['username'] = username

                
                return redirect(url_for('home'))
            
        return 'Invalid username or password'
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    session.clear()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        full_name = request.form['full_name']
        
        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Insert new user into the database
        cursor = get_db().cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, email))
        existing_user = cursor.fetchone()
        
        if existing_user:
            return 'Username or email already exists'
        
        insert_query = "INSERT INTO users (id, username, password, email, full_name) VALUES (?, ?, ?, ?, ?)"
        cursor.execute(insert_query, (str(uuid.uuid4()), username, hashed_password.decode('utf-8'), email, full_name))
        get_db().commit()
        
        return redirect(url_for('login'))
    
    return render_template('register.html')


@socketio.on("message")
def message(data):
    room = session.get("room")
    username = session.get("username")

    room_exists = get_room(room)
    if not room_exists:
        return
    # if room not in rooms:
    #     return 
    
    # content = {
    #     "username": session.get("username"),
    #     "message": data["data"]
    # }

    # room

    # Retrieve encryption and authentication keys from the session
    # encryption_key = session.get('encryption_key')
    authentication_key = session.get('authentication_key')

    # Encrypt the message
    # print("Room_exists: ", room_exists)
    # print("Here is your secret for room_exists: ", room_exists[2])
    # print("Here is your secret for encryption_key: ", encryption_key)
    encrypted_message = encrypt_message(data['data'], room_exists[2])
    

    # Calculate HMAC digest using SHA256
    h = hmac.new(authentication_key, data['data'].encode('utf-8'), hashlib.sha256)
    mac = h.digest()

    send({"type": "message", 'username': username, 'message': data['data']}, to=room)
    # rooms[room]["messages"].append(content)
    print(f"{username} said: {data['data']}")

    # Insert message into the database
    cursor = get_db().cursor()
    insert_query = "INSERT INTO messages (id, username, room_code, message) VALUES (?, ?, ?, ?)"
    cursor.execute(insert_query, (str(uuid.uuid4()), username, room, encrypted_message))
    get_db().commit()


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
    # if room not in rooms:

    
    join_room(room)
    send({"type": "message", "username": username, "message": "has entered the room"}, to=room)
    # TODO Update room members
    update_room_users_count(room, 1)
    print(f"{username} joined room {room}")

@socketio.on("disconnect")
def disconnect():
    room = session.get("room")
    username = session.get("username")
    leave_room(room)
    

    # if room in rooms:
    #     rooms[room]["members"] -= 1
    #     if rooms[room]["members"] <= 0:
    #         del rooms[room]
    
    send({"username": username, "message": "has left the room"}, to=room) #TODO: look like this is not displaying when user leaving the room
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
        # print("Here is the error of decoding the message", message[3])
        # print("message type", type(message[3]))
        # Decrypt each message and append to the list
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

if __name__ == "__main__":
    socketio.run(app, debug=True, port=8090)