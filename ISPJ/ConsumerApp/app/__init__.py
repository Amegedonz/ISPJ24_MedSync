#Flask Dependancies
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

#App dependancies
import os, limiter
from flask import Flask, request, render_template, redirect, url_for, send_from_directory, flash
import os
from hashlib import sha256
import mimetypes
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import io
import json
from config import Config
import requests


#databse Connection
from database import engine, Base, dbSession
from DBcreateTables import User

#WTF
from flask_wtf.csrf import CSRFProtect
from Forms.appForms import LoginForm, RegistrationForm

#initialising app libraries
app = Flask(__name__)
app.config.from_object(Config)
SECRET_KEY = app.config['SECRET_KEY']


#WTF CSRF Tokens
csrf = CSRFProtect(app)

#Security params
bcrypt = Bcrypt(app)

#Recaptcha tools
RECAPTCHA_PUBLIC_KEY = app.config["RECAPTCHA_PUBLIC_KEY"]
RECAPTCHA_PROJECT_ID = app.config["GOOGLE_RC_PROJECT_ID"]
RECAPTCHA_PRIVATE_KEY = app.config["RECAPTCHA_PRIVATE_KEY"]
RECAPTCHA_API_URL = "https://www.google.com/recaptcha/api/siteverify"

#Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

#Rate Limiter
limiter = Limiter(
    get_remote_address, 
    app = app,
    storage_uri = "memory://"
)

@login_manager.user_loader
def load_user(id):
    return dbSession.query(User).filter(User.id == id).first()

@app.route('/')
def home():
    
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        grequest = request.form['g-recaptcha-response'] 
        verify_response = requests.post(url=f'{RECAPTCHA_API_URL}?secret={RECAPTCHA_PRIVATE_KEY}&response={grequest}').json
        print(verify_response())
        try:
            user = dbSession.query(User).filter(User.id == form.id.data).first()
            if isinstance(user, User) and bcrypt.check_password_hash(user.password, form.password.data):
                remember = form.remember.data
                login_user(user, remember=remember)
                return redirect(url_for("home"))
            
            else: 
                flash("Wrong Username/Password.\n Please try again", 'danger')

        except Exception as e:
            flash(f"An error {e} occured. Please try again.", "Warning")

        finally:
            dbSession.close()

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Successfully Logged Out", "Success")
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        grequest = request.form['g-recaptcha-response'] 
        verify_response = requests.post(url=f'{RECAPTCHA_API_URL}?secret={RECAPTCHA_PRIVATE_KEY}&response={grequest}').json
        print(verify_response())
        if verify_response()['success'] == False:
            flash("Invalid reCAPTCHA")
            return render_template('register.html', form=form)

        user = dbSession.query(User).filter(User.id == form.id.data).first()
        if not user:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            new_user = User(id = form.id.data, username = form.name.data, password = hashed_password)
            if form.email.data:
                new_user.email = form.email.data

            if form.phoneNumber.data:
                new_user.phoneNumber = form.phoneNumber.data

            if isinstance(new_user, User):
                dbSession.add(new_user)
                dbSession.commit()
                flash('Registration Successful!', "success")
                return redirect(url_for('login'))
        else:
            flash("Already registered please login instead" , 'success')
            return redirect(url_for('login'))

    dbSession.close()
    return render_template('register.html', form=form)


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

import os
import json
from flask import Flask, request, render_template, redirect, url_for, flash, send_from_directory
from sqlalchemy.orm import sessionmaker
from database import engine, Base, dbSession  # Ensure dbSession and engine are imported
from sqlalchemy.exc import SQLAlchemyError
from hashlib import sha256
from PyPDF2 import PdfReader, PdfWriter
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from DBcreateTables import File
import mimetypes




app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['META_FOLDER'] = 'meta'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['META_FOLDER'], exist_ok=True)

# Routes
@app.route('/upload')
def upload_page():
    return render_template('upload.html')

def get_file_model():
    from DBcreateTables import File  # Import only when needed
    return File

File = get_file_model()

@app.route('/Landing')
def Landing_page():
    return render_template('Landing.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)

    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)

    if file:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)

        # Process metadata
        metadata = {key: request.form[key] for key in request.form}
        metadata_filepath = os.path.join(app.config['META_FOLDER'], f"{file.filename}_metadata.json")
        with open(metadata_filepath, 'w') as metadata_file:
            json.dump(metadata, metadata_file)

        # Add watermark if the file is PDF
        watermark_hash = None
        if file.filename.endswith('.pdf'):
            watermark_text = "Medsync"
            add_watermark(filepath, filepath, watermark_text)
            watermark_hash = compute_hash_from_text(watermark_text)

        # Compute hash of the file
        file_hash = compute_hash(filepath)

        # Store file and metadata in database
        new_file = File(
            filename=file.filename,
            file_path=filepath,
            name=metadata.get('name'),
            license_no=metadata.get('license_no'),
            date=metadata.get('date'),
            time=metadata.get('time'),
            facility=metadata.get('facility'),
            patient_nric=metadata.get('patient_nric'),
            type=metadata.get('type')
        )

        try:
            dbSession.add(new_file)
            dbSession.commit()
        except SQLAlchemyError as e:
            flash(f"Error saving file to database: {e}")
            dbSession.rollback()
        return render_template('upload_success.html', file_hash=file_hash, watermark_hash=watermark_hash, metadata=metadata, filename=file.filename)

@app.route('/files', methods=['GET'])
def list_files():
    all_files = dbSession.query(File).all()  # Fetch all file entries from the DB
    files_data = [
        {"filename": file.filename, "metadata": json.load(open(os.path.join(app.config['META_FOLDER'], f"{file.filename}_metadata.json"))) if os.path.exists(os.path.join(app.config['META_FOLDER'], f"{file.filename}_metadata.json")) else {}, "hash": compute_hash(file.file_path)}
        for file in all_files
    ]
    return render_template('download.html', files=files_data)

@app.route('/download/<filename>')
def download_file(filename):
    file = dbSession.query(File).filter_by(filename=filename).first()
    if file:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    flash("File not found!")
    return redirect(url_for('list_files'))

@app.route('/delete/<filename>', methods=['DELETE'])
def delete_file(filename):
    file = dbSession.query(File).filter_by(filename=filename).first()
    if file:
        try:
            os.remove(file.file_path)  # Delete the file from the filesystem
            dbSession.delete(file)  # Delete the file record from the database
            dbSession.commit()
            return {"success": True}, 200
        except Exception as e:
            return {"success": False, "error": str(e)}, 500
    return {"success": False, "error": "File not found!"}, 404

# Helper Functions
def compute_hash(filepath):
    hasher = sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

def compute_hash_from_text(text):
    return sha256(text.encode('utf-8')).hexdigest()

def add_watermark(input_pdf_path, output_pdf_path, watermark_text):
    packet = BytesIO()
    c = canvas.Canvas(packet, pagesize=letter)
    width, height = letter
    c.setFont("Helvetica", 60)
    text_width = c.stringWidth(watermark_text, "Helvetica", 60)
    c.setFillAlpha(0.3)
    c.setFillColorRGB(0.5, 0.5, 0.5)
    c.drawString((width - text_width) / 2, height / 2, watermark_text)
    c.showPage()
    c.save()
    packet.seek(0)
    new_pdf = PdfReader(packet)
    existing_pdf = PdfReader(input_pdf_path)
    output_pdf = PdfWriter()
    for page in existing_pdf.pages:
        page.merge_page(new_pdf.pages[0])
        output_pdf.add_page(page)
    with open(output_pdf_path, "wb") as output_file:
        output_pdf.write(output_file)

# Ensure tables exist at runtime
Base.metadata.create_all(engine)

if __name__ == '__main__':
    app.run(debug=True, port=5001)
