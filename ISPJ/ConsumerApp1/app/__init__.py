#Flask Dependancies
from flask import Flask, render_template, request, redirect, url_for, flash, abort, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

#App dependancies
import os, limiter, json, requests, mimetypes
from flask import Flask, request, render_template, redirect, url_for, send_from_directory, flash,jsonify
from hashlib import sha256
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from config import Config

#QR
import qrcode, base64, pyotp
from io import BytesIO

#databse Connection
from database import engine, Base, dbSession
from DBcreateTables import User, Twofa, Doctor, PatientAssignment, File, delete_tables, create_tables
from sqlalchemy.exc import SQLAlchemyError

#WTF
from flask_wtf.csrf import CSRFProtect
from Forms.appForms import LoginForm, RegistrationForm, TwoFactorForm

#Wrappers
from functools import wraps

# Monitoring
from prometheus_client import Counter, Gauge, Info, Histogram, Summary, generate_latest
from prometheus_flask_exporter import PrometheusMetrics
from log_config import logger

#Watermarking
from watermark import compute_hash, compute_hash_from_text, add_watermark



#initialising app libraries
app = Flask(__name__)
app.config.from_object(Config)
SECRET_KEY = app.config['SECRET_KEY']
APP_NAME = app.config['APP_NAME']

#WTF CSRF Tokens
csrf = CSRFProtect(app)

#Security params
bcrypt = Bcrypt(app)

#Recaptcha tools
RECAPTCHA_PUBLIC_KEY = app.config["RECAPTCHA_PUBLIC_KEY"]
RECAPTCHA_PROJECT_ID = app.config["GOOGLE_RC_PROJECT_ID"]
RECAPTCHA_PRIVATE_KEY = app.config["RECAPTCHA_PRIVATE_KEY"]
RECAPTCHA_API_URL = "https://www.google.com/recaptcha/api/siteverify"

#RBAC validation
def roles_required(*allowed_roles):
    def decorator(func):
        @wraps(func)
        def wrapped_function(*args, **kwargs):
            if current_user.role not in allowed_roles:
                abort(401)
            return func(*args, **kwargs)
        return wrapped_function
    return decorator

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


# Prometheus Counters
consumer_login_attempts = Counter('consumer_login_attempts_total', 'Total login attempts', ['status'])
consumer_logout_attempts = Counter('consumer_logout_attempts_total', 'Total logout attempts', ['status'])
consumer_register_attempts = Counter('consumer_register_attempts_total', 'Total register attempts', ['status'])
consumer_views = Counter('consumer_page_views_total', 'Page views', ['page'])
consumer_errors = Counter('consumer_errors_total', 'Errors', ['error'])

#Session loader
@login_manager.user_loader
def load_user(id):
    try:
        return dbSession.query(User).filter(User.id == id).first()
    except:
        dbSession.rollback()
        dbSession.close()

#Test Route
@app.route('/generateData')
@login_required
def generate_data():
    print(request.remote_addr)
    print(request.user_agent)

    return render_template('home.html')



#ROUTES
@app.route('/')
def home():
    consumer_views.labels(page='home').inc()
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
# @limiter.limit("3 per minute")
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        grequest = request.form['g-recaptcha-response'] 
        verify_response = requests.post(url=f'{RECAPTCHA_API_URL}?secret={RECAPTCHA_PRIVATE_KEY}&response={grequest}').json
        print(f'reCATCHA response: {verify_response()}')
        
        try:
            user = dbSession.query(User).filter(User.id == form.id.data).first()
            if isinstance(user, User) and bcrypt.check_password_hash(user.password, form.password.data):
                twofaCheck = dbSession.query(Twofa).filter(Twofa.id == user.get_id()).first()
                remember = form.remember.data
                login_user(user, remember=remember)
                if twofaCheck.twofa_enabled:
                    return redirect(url_for('verify2FA'))
                
                elif not twofaCheck.twofa_enabled:
                    return redirect(url_for('setup2FA'))
                
                else:
                    abort(500)
            
            else: 
                # login failure log
                logger.info("Login failed", extra={
                    "ip": request.remote_addr,
                    "user": user.id,
                })
                flash("Wrong Username/Password.\n Please try again", 'danger')

        except Exception as e:
            flash(f"An error {e} occured. Please try again.", "Warning")

        finally:
            dbSession.close()
    consumer_views.labels(page='login').inc()
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Successfully Logged Out", "success")
    consumer_views.labels(page='logout').inc()
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        grequest = request.form['g-recaptcha-response'] 
        verify_response = requests.post(url=f'{RECAPTCHA_API_URL}?secret={RECAPTCHA_PRIVATE_KEY}&response={grequest}').json
        print(verify_response())
        if verify_response()['success'] == False:
            flash("Invalid reCAPTCHA")
            return render_template('login.html', form=form)

        user = dbSession.query(User).filter(User.id == form.id.data).first()
        if not user:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            new_user = User(id = form.id.data, username = form.name.data, password = hashed_password)
            if form.email.data:
                new_user.email = form.email.data

            if form.phoneNumber.data:
                new_user.phoneNumber = form.phoneNumber.data

            if isinstance(new_user, User):
                populateTwoFA = Twofa(id  = new_user.id)
                dbSession.add(new_user)
                dbSession.add(populateTwoFA)
                dbSession.commit()
                flash('Registration Successful!', "success")
                return redirect(url_for('login'))
        else:
            flash("Already registered please login instead" , 'success')
            return redirect(url_for('login'))

    dbSession.close()
    consumer_views.labels(page='register').inc()
    return render_template('register.html', form=form)

@app.route('/patient_profile', methods=['GET', 'POST'])
@roles_required("Patient")
def patient_profile():
    consumer_views.labels(page='patient_profile').inc()
    return render_template('patient_profile.html')


@app.route('/setup2FA')
@login_required
def setup2FA():
    try:
        twofaCheck = dbSession.query(Twofa).filter(Twofa.id == current_user.get_id()).first()
    except Exception as e:
        dbSession.rollback()    
    secret = twofaCheck.user_secret
    uri = f'otpauth://totp/{current_user.get_id()}?secret={secret}&issuer={APP_NAME}'
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    buffered = BytesIO()
    img.save(buffered)
    base64_qr_image = base64.b64encode(buffered.getvalue()).decode("utf-8")
    return render_template("setup2FA.html", secret=secret, qr_image=base64_qr_image)

@app.route('/verify2FA', methods=['GET', 'POST'])
@limiter.limit("3 per minute", key_func = lambda : current_user.id)
@login_required
def verify2FA():
    form = TwoFactorForm(request.form)
    try:
        twofaCheck = dbSession.query(Twofa).filter(Twofa.id == current_user.get_id()).first()
    except Exception as e:
        dbSession.rollback()    
    if form.validate_on_submit():
        totp = pyotp.parse_uri(f'otpauth://totp/{current_user.get_id()}?secret={twofaCheck.user_secret}&issuer={APP_NAME}')
        if totp.verify(form.data['otp']):
            if twofaCheck.twofa_enabled:
                flash("2FA verification successful. You are logged in!", "success")
                logger.info("Login success", extra={
                        "ip": request.remote_addr,
                        "user": current_user.id,
                    })
            else:
                try:
                    twofaCheck.twofa_enabled = True
                    dbSession.commit()
                    flash("2FA setup successful. You are logged in!", "success")
                except Exception:
                    dbSession.rollback()
                    flash("2FA setup failed. Please try again.", "danger")
                    return redirect(url_for('verify2FA'))
                
            if current_user.role == "Doctor":
                return redirect(url_for('landing'))
            else:
                return redirect(url_for('home'))
        else:
            flash("Invalid OTP. Please try again.", "danger")
            return redirect(url_for('verify2FA'))
    else:
        if not twofaCheck.twofa_enabled:
            flash(
                "You have not enabled 2-Factor Authentication. Please enable it first.", "info")
        return render_template("verify2FA.html", form=form)
    

@app.route('/doctor_assignment', methods=['GET', 'POST'])
@roles_required('Doctor')
def doctor_assignment():
    NRIC = request.args.get('NRIC') 

    user = dbSession.query(User).filter(User.id == NRIC).first()

    if user:
        print(user.username)
        return render_template('doctor_assignment.html', user=user)
    else:
        return render_template('doctor_assignment.html', user=None)

@app.route('/confirm_patient/<NRIC>', methods=['GET', 'POST'])
@roles_required('Doctor')
def confirm_patient(NRIC):
    doctor = dbSession.query(Doctor).filter(Doctor.id == current_user.id).first()
    patientAssignment = PatientAssignment(doctor_id = doctor.license_number, patient_id = NRIC)
    if isinstance(patientAssignment, PatientAssignment):
        dbSession.add(patientAssignment)
        dbSession.commit()
        dbSession.close()
        flash("Successfully assigned patient", "success")
        return redirect(url_for('home'))



app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['META_FOLDER'] = 'meta'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['META_FOLDER'], exist_ok=True)

# @app.route('/upload')
# def upload_page():
#     return render_template('upload.html')

def get_file_model():
    from DBcreateTables import File  # Import only when needed
    return File

File = get_file_model()

@app.route('/landing')
@roles_required('Doctor')
def landing():
    return render_template('landing.html')

@app.route('/upload', methods=['GET', 'POST'])
@roles_required('Doctor')
def upload():
    doctor = dbSession.query(Doctor).filter(Doctor.id == current_user.get_id()).first()

    if request.method == 'GET':
        default_values = {
            "license" : doctor.license_number, 
            "clinic" : doctor.facility, 
            "docName" : current_user.username, 
            "date": datetime.now().strftime('%Y-%m-%d'),
            "time": datetime.now().strftime('%H:%M')
        }
        return render_template('upload.html', **default_values)

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

        # Add watermark if the file is a PDF
        watermark_hash = None
        if file.filename.endswith('.pdf'):
            watermark_text = "Medsync"
            add_watermark(filepath, filepath, watermark_text)
            watermark_hash = compute_hash_from_text(watermark_text)

        # Compute hash of the file
        file_hash = compute_hash(filepath)

        # Store file and metadata in the database
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


@app.route('/view/<filename>')
def view_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # If file doesn't exist, return an error
    if not os.path.exists(file_path):
        flash("File not found!")
        return redirect(url_for('list_files'))

    # Determine MIME type
    mimetype, _ = mimetypes.guess_type(file_path)
    is_pdf = mimetype == 'application/pdf'
    content = None

    # Read text file content if applicable
    if mimetype and mimetype.startswith('text'):
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
        except UnicodeDecodeError:
            with open(file_path, 'r', encoding='latin-1') as file:
                content = file.read()

    # Pass the file URL for embedding
    file_url = url_for('serve_uploaded_file', filename=filename)

    return render_template('view.html', 
                           filename=filename, 
                           is_pdf=is_pdf, 
                           file_url=file_url, 
                           content=content)
    
@app.route('/upload/<filename>')
def serve_uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/files', methods=['GET'])
@roles_required('Patient', 'Doctor')
def list_files():
    try:
        if current_user.role == 'Doctor':
            # Get the doctor details
            doctor = dbSession.query(Doctor).filter(Doctor.id == current_user.get_id()).first()

            # Query all files directly by joining with PatientAssignment
            patient_files = dbSession.query(File).join(PatientAssignment, File.patient_nric == PatientAssignment.patient_id).filter(PatientAssignment.doctor_id == doctor.license_number).all()
        
        else:
            patient_files = dbSession.query(File).filter(File.patient_nric == current_user.get_id()).all()

        
        
    except:
        dbSession.rollback()

    finally:
        dbSession.close()

    # Convert files into a dictionary for rendering
    files_data = [
        {
            "id": file.id, 
            "filename": file.filename,
            "patient_nric": file.patient_nric,
            "document_type": file.type,
            "facility": file.facility,
            "file_path": file.file_path,
        }
        for file in patient_files
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
@login_required  # Ensures only logged-in users can delete
@roles_required('Doctor')  # Ensures only doctors can delete
def delete_file(filename):
    file = dbSession.query(File).filter_by(filename=filename).first()

    if not file:
        return jsonify({"error": "File not found"}), 404

    try:
        # Delete the file from the filesystem
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        metadata_path = os.path.join(app.config['META_FOLDER'], f"{filename}_metadata.json")

        if os.path.exists(file_path):
            os.remove(file_path)

        if os.path.exists(metadata_path):
            os.remove(metadata_path)

        # Delete record from database
        dbSession.delete(file)
        dbSession.commit()

        return jsonify({"success": True, "message": "File deleted successfully"}), 200

    except Exception as e:
        dbSession.rollback()
        return jsonify({"success": False, "error": f"Error deleting file: {str(e)}"}), 500

    finally:
        dbSession.close()
@app.route('/metrics')
def metrics():
    return generate_latest()

#Create Users with bcrypt
# @app.route('/createUsers')
# def createDoctor():
#     delete_tables()
#     create_tables()
#     new_user = User(
#         id='T0110907Z',
#         username='Lucian',
#         password=bcrypt.generate_password_hash("P@ssw0rd").decode('utf-8')
#     )
#     userTwoFA = Twofa(id  = new_user.id)

#     doctorUser = User(
#         id='S1234567A',
#         username='Amy',
#         password=bcrypt.generate_password_hash("P@ssw0rd").decode('utf-8')
#     )
#     doctorTwoFA = Twofa(id  = doctorUser.id)

#     doctor = doctorUser.add_doctor(
#         license_number='M04637Z',
#         specialisation='Family Medicine',  
#         facility='Manadr BoonLay'
#     )

#     dbSession.add(new_user)
#     dbSession.add(doctorUser)
#     dbSession.add(doctor)  
#     dbSession.add(userTwoFA)
#     dbSession.add(doctorTwoFA)
#     dbSession.commit()
#     dbSession.close()
#     flash("Doctor Added to DB", "success")
#     return redirect(url_for('home'))


# error handlers
@app.errorhandler(401)
def not_authorised(e):
    consumer_errors.labels(error='401').inc()
    return render_template('error.html', error_code = 401, message = "Please log in to view this page")

@app.errorhandler(403)
def forbidden(e):
    consumer_errors.labels(error='403').inc()
    return render_template('error.html', error_code = 403, message = "You don't have the required permissions to access this page")

@app.errorhandler(404)
def not_found(e):
    consumer_errors.labels(error='404').inc()
    return render_template('error.html', error_code = 404, message = "Page not found. Sorry for the inconvenience caused")

@app.errorhandler(429)
def too_many_requests(e):
    logout_user()
    consumer_errors.labels(error='429').inc()
    return render_template('error.html', error_code = 429, message = "Too many requests. Please try again later")

@app.errorhandler(500)
def internal_error(e):
    consumer_errors.labels(error='500').inc()
    return render_template('error.html', error_code = 500, message = "Internal server error")

@app.errorhandler(502)
def bad_gateway(e):
    consumer_errors.labels(error='502').inc()
    return render_template('error.html', error_code = 502, message = "Bad gateway")

@app.errorhandler(503)
def service_unavailable(e):
    consumer_errors.labels(error='503').inc()
    return render_template('error.html', error_code = 503, message = "Service unavailable")

@app.errorhandler(504)
def gateway_timeout(e):
    consumer_errors.labels(error='504').inc()
    return render_template('error.html', error_code = 504, message = "Gateway timeout")


if __name__ == '__main__':
    Base.metadata.create_all(engine)
    app.run(ssl_context=('cert.pem','key.pem'),debug=True)