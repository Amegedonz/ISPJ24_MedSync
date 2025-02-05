#Flask Dependancies
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

#App dependancies
import os, limiter
from config import Config
import requests


#databse Connection
from database import engine, Base, dbSession
from DBcreateTables import User

#WTF
from flask_wtf.csrf import CSRFProtect
from Forms.appForms import LoginForm, RegistrationForm

# Monitoring
from prometheus_client import Counter, Gauge, Info, Histogram, Summary, generate_latest
from prometheus_flask_exporter import PrometheusMetrics
from log_config import logger
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


# Prometheus Counters
consumer_login_attempts = Counter('consumer_login_attempts_total', 'Total login attempts', ['status'])
consumer_logout_attempts = Counter('consumer_logout_attempts_total', 'Total logout attempts', ['status'])
consumer_register_attempts = Counter('consumer_register_attempts_total', 'Total register attempts', ['status'])
consumer_views = Counter('consumer_page_views_total', 'Page views', ['page'])
consumer_errors = Counter('consumer_errors_total', 'Errors', ['error'])


@login_manager.user_loader
def load_user(id):
    return dbSession.query(User).filter(User.id == id).first()

@app.route('/')
def home():
    consumer_views.labels(page='home').inc()
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
# @limiter.limit("5 per minute")
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
                # login success log
                logger.info("Login success", extra={
                    "ip": request.remote_addr,
                    "user": user.id,
                })
                return redirect(url_for("home"))
            
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
    flash("Successfully Logged Out", "Success")
    consumer_views.labels(page='logout').inc()
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
# @limiter.limit("5 per minute")
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
    consumer_views.labels(page='register').inc()
    return render_template('register.html', form=form)


@app.route('/patient_profile', methods=['GET', 'POST'])
@login_required
def patient_profile():
    consumer_views.labels(page='patient_profile').inc()
    return render_template('patient_profile.html')

# @app.route('/doctor_upload', methods=['GET', 'POST'])
# @login_required
# def staff_upload():
#     if current_user.id not in users or users[current_user.id]['role'] != 'staff':
#         # to add log and alert if there is attempted unauthorised access
#         flash('Access denied. Staff only.', 'error')
#         return redirect(url_for('home.html'))

#     if request.method == 'POST':
#         patient_id = request.form['patient_id']
#         document_type = request.form['document_type']
#         document = request.files['document']
#         notes = request.form['notes']

#         if document:
#             filename = f"{patient_id}_{document_type}_{datetime.now().strftime('%Y%m%d%H%M%S')}.pdf"
#             document.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
#             # document activity counter upload
#             flash('Document uploaded successfully.', 'success')
#         else:
#             flash('No document uploaded.', 'error')

#     consumer_views.labels(page='staff_upload').inc()
#     return render_template('staff_upload.html')

# @app.route('/patient_records')
# @login_required
# def patient_records():
#     if current_user.id not in users or users[current_user.id]['role'] not in ['staff', 'patient']:
#         flash('Access denied.', 'error')
#         return redirect(url_for('home'))

#     # Placeholder: Fetch patient records from database
#     records = [
#         {'date': '2023-05-01', 'document_type': 'Medical Report', 'uploaded_by': 'Dr. Smith', 'view_url': '#', 'download_url': '#'},
#         {'date': '2023-04-15', 'document_type': 'X-Ray Scan', 'uploaded_by': 'Dr. Johnson', 'view_url': '#', 'download_url': '#'},
#     ]
#     consumer_views.labels(page='patient_records').inc()
#     return render_template('patient_records.html', records=records)

@app.route('/metrics')
def metrics():
    return generate_latest()

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
    # if not os.path.exists(app.config['UPLOAD_FOLDER']):
    #     os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)