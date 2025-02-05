#Flask Dependancies
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

#App dependancies
from prometheus_client import Counter, Gauge, Info, Histogram, Summary, generate_latest
from prometheus_flask_exporter import PrometheusMetrics
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
import os, limiter
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
    consumer_views.labels(page='home').inc()
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
    consumer_views.labels(page='patient_profile').inc()
    return render_template('patient_profile.html')

@app.route('/doctor_upload', methods=['GET', 'POST'])
@login_required
def staff_upload():
    if current_user.id not in users or users[current_user.id]['role'] != 'staff':
        # to add log and alert if there is attempted unauthorised access
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
            # document activity counter upload
            flash('Document uploaded successfully.', 'success')
        else:
            flash('No document uploaded.', 'error')

    consumer_views.labels(page='staff_upload').inc()
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
    consumer_views.labels(page='patient_records').inc()
    return render_template('patient_records.html', records=records)


if __name__ == '__main__':
    # if not os.path.exists(app.config['UPLOAD_FOLDER']):
    #     os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)