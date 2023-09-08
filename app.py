# app.py
from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///health_data.db'
app.config['UPLOAD_FOLDER'] = 'uploads'  # Folder for storing uploaded files
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Maximum file size (16MB)
db = SQLAlchemy(app)

# Generate or load your own public and private keys
# You should store these keys securely in a production environment
# For this example, we'll generate a new key pair each time the application runs
private_key = Fernet.generate_key()
public_key = Fernet.generate_key()

# Create a Fernet instance for encryption and decryption
fernet = Fernet(private_key)

# Define the User model with health_data encrypted
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

# Define the Module model to store module data and files
class Module(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('modules', lazy=True))
    module_name = db.Column(db.String(100), nullable=False)
    module_data = db.Column(db.LargeBinary)  # Store encrypted module data
    file_path = db.Column(db.String(255))  # Store file path

# Define the Access model to store access requests and approvals
class Access(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    target_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # Status: pending, accepted, or denied

    requester = db.relationship('User', foreign_keys=[requester_id], backref=db.backref('requested_access', lazy=True))
    target = db.relationship('User', foreign_keys=[target_id], backref=db.backref('access_requests', lazy=True))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            # Implement login logic here
            return redirect(url_for('profile', username=user.username)) 
        else:
            return "Login failed. Invalid username or password."
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        
        # Redirect to the user's profile with the username parameter
        return redirect(url_for('profile', username=username))
    return render_template('register.html')

@app.route('/settings')
def settings():
    # Implement settings page logic here
    return render_template('settings.html')

@app.route('/profile/<username>')
def profile(username):
    user = User.query.filter_by(username=username).first()
    if user:
        return render_template('profile.html', user=user)
    else:
        return "User not found."

# Routes for adding and retrieving modules
@app.route('/add_module', methods=['POST'])
def add_module():
    if request.method == 'POST':
        username = request.form['username']
        user = User.query.filter_by(username=username).first()
        if user:
            module_name = request.form['module_name']
            module_data = request.form['module_data']
            
            # Encrypt module data
            encrypted_data = fernet.encrypt(module_data.encode())
            
            # Create a new module
            new_module = Module(user=user, module_name=module_name, module_data=encrypted_data)
            db.session.add(new_module)
            db.session.commit()
            
            return "Module added successfully."
        else:
            return "User not found."
    return redirect(url_for('index'))

# Routes for encryption and decryption
@app.route('/encrypt', methods=['POST'])
def encrypt():
    if request.method == 'POST':
        username = request.form['username']
        user = User.query.filter_by(username=username).first()
        if user:
            health_data = request.form['health_data']
            encrypted_data = fernet.encrypt(health_data.encode())
            user.health_data = encrypted_data
            db.session.commit()
            return "Health data encrypted and stored successfully."
        else:
            return "User not found."
    return redirect(url_for('index'))

@app.route('/decrypt', methods=['GET'])
def decrypt():
    username = request.args.get('username')
    user = User.query.filter_by(username=username).first()
    if user and user.health_data:
        decrypted_data = fernet.decrypt(user.health_data).decode()
        return f"Decrypted Health Data: {decrypted_data}"
    else:
        return "Health data not found."

@app.route('/modules/<username>')
def get_modules(username):
    user = User.query.filter_by(username=username).first()
    if user:
        modules = Module.query.filter_by(user=user).all()
        return render_template('modules.html', modules=modules, user=user)
    else:
        return "User not found."

# Routes for access requests and approvals
@app.route('/access_requests/<username>', methods=['GET', 'POST'])
def access_requests(username):
    user = User.query.filter_by(username=username).first()
    if user:
        if request.method == 'POST':
            requester_username = request.form['requester_username']
            requester = User.query.filter_by(username=requester_username).first()
            if requester:
                new_access = Access(requester=requester, target=user)
                db.session.add(new_access)
                db.session.commit()
                return "Access request sent."
            else:
                return "Requester not found."
        
        access_requests = Access.query.filter_by(target=user, status='pending').all()
        approved_access = Access.query.filter_by(target=user, status='accepted').all()
        
        return render_template('access_requests.html', user=user, access_requests=access_requests, approved_access=approved_access)
    
    return "User not found."

@app.route('/request_access', methods=['POST'])
def request_access():
    if request.method == 'POST':
        target_username = request.form['target_username']
        user = User.query.filter_by(username=target_username).first()

        if user:
            # Check if a request already exists
            existing_request = Access.query.filter_by(requester=current_user, target=user).first()
            if existing_request:
                return "Access request already exists for this user."

            # Create a new access request
            new_access_request = Access(requester=current_user, target=user)
            db.session.add(new_access_request)
            db.session.commit()
            return "Access request sent successfully."
        else:
            return "Target user not found."

    return redirect(url_for('access_requests', username=current_user.username))


@app.route('/approve_access/<access_id>', methods=['POST'])
def approve_access(access_id):
    access = Access.query.get(access_id)
    if access:
        access.status = 'accepted'
        db.session.commit()
        return redirect(url_for('access_requests', username=access.target.username))
    return "Access request not found."

@app.route('/deny_access/<access_id>', methods=['POST'])
def deny_access(access_id):
    access = Access.query.get(access_id)
    if access:
        access.status = 'denied'
        db.session.commit()
        return redirect(url_for('access_requests', username=access.target.username))
    return "Access request not found."

# Create the database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)