from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os, limiter

#Databse Config and connection settings

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this to a random secret key
app.config['UPLOAD_FOLDER'] = 'uploads'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

limiter = Limiter(
    get_remote_address, 
    app = app,
    storage_uri = "memory://"
)

# Placeholder user database
users = {
    'admin': {'password': generate_password_hash('admin123'), 'role': 'admin'},
    'staff': {'password': generate_password_hash('staff123'), 'role': 'staff'},
    'patient': {'password': generate_password_hash('patient123'), 'role': 'patient'}
}


class User(UserMixin):
    pass

@login_manager.user_loader
def load_user(username):
    if username not in users:
        return None
    user = User()
    user.id = username
    return user

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("15/hour;3/minute")
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Validate user credentials
        if username in users:
            stored_password = users[username]['password']
            if check_password_hash(stored_password, password):
                flash('Login successful!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Invalid password. Please try again.', 'danger')
        else:
            flash('User not found. Please try again.', 'danger')

    return render_template('login.html')

@app.route('/logout')
# @login_required
def logout():
    # logout_user()
    return redirect(url_for('home.html'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    return render_template('register.html')

@app.route('/patient_profile', methods=['GET', 'POST'])
def patient_profile():
    return render_template('patient_profile.html')

@app.route('/doctor_upload', methods=['GET', 'POST'])
@login_required
def staff_upload():
    if current_user.id not in users or users[current_user.id]['role'] != 'staff':
        flash('Access denied. Staff only.', 'error')
        return redirect(url_for('home.html'))

    if request.method == 'POST':
        patient_id = request.form['patient_id']
        document_type = request.form['document_type']
        document = request.files['document']
        notes = request.form['notes']

        if document:
            filename = f"{patient_id}_{document_type}_{datetime.now().strftime('%Y%m%d%H%M%S')}.pdf"
            document.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash('Document uploaded successfully.', 'success')
        else:
            flash('No document uploaded.', 'error')

    return render_template('staff_upload.html')

@app.route('/patient_records')
@login_required
def patient_records():
    if current_user.id not in users or users[current_user.id]['role'] not in ['staff', 'patient']:
        flash('Access denied.', 'error')
        return redirect(url_for('home'))

    # Placeholder: Fetch patient records from database
    records = [
        {'date': '2023-05-01', 'document_type': 'Medical Report', 'uploaded_by': 'Dr. Smith', 'view_url': '#', 'download_url': '#'},
        {'date': '2023-04-15', 'document_type': 'X-Ray Scan', 'uploaded_by': 'Dr. Johnson', 'view_url': '#', 'download_url': '#'},
    ]
    return render_template('patient_records.html', records=records)

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.id not in users or users[current_user.id]['role'] != 'admin':
        flash('Access denied. Admin only.', 'error')
        return redirect(url_for('home'))

    # Placeholder: Fetch user accounts and SIEM events from database
    user_accounts = [
        {'username': 'staff1', 'role': 'staff', 'last_login': '2023-05-01 10:30:00'},
        {'username': 'patient1', 'role': 'patient', 'last_login': '2023-04-30 15:45:00'},
    ]
    siem_events = [
        {'timestamp': '2023-05-01 11:00:00', 'type': 'login', 'user': 'staff1', 'details': 'Successful login'},
        {'timestamp': '2023-05-01 11:05:00', 'type': 'upload', 'user': 'staff1', 'details': 'Document uploaded for patient1'},
    ]
    return render_template('admin_dashboard.html', users=user_accounts, siem_events=siem_events)

if __name__ == '__main__':
    # if not os.path.exists(app.config['UPLOAD_FOLDER']):
    #     os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)