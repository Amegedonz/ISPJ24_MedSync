#Flask Dependancies
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

#App dependancies
import os, limiter
from config import Config
import requests

#QR
import qrcode, base64, pyotp
from io import BytesIO

#databse Connection
from database import engine, Base, dbSession
from DBcreateTables import User, Twofa, Doctor, PatientAssignment, deleteTables, createTables

#WTF
from flask_wtf.csrf import CSRFProtect
from Forms.appForms import LoginForm, RegistrationForm, TwoFactorForm

#Wrappers
from functools import wraps


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
def roles_required(allowed_roles):
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


#

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
                flash("Wrong Username/Password.\n Please try again", 'danger')

        except Exception as e:
            flash(f"An error {e} occured. Please try again.", "Warning")

        finally:
            dbSession.close()

    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
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
    return render_template('register.html', form=form)

@app.route('/patient_profile', methods=['GET', 'POST'])
@roles_required("Patient")
def patient_profile():
    return render_template('patient_profile.html')

@app.route('/createUsers')
def createDoctor():
    deleteTables()
    createTables()
    new_user = User(
        id='T0110907Z',
        username='Lucian',
        password=bcrypt.generate_password_hash("P@ssw0rd").decode('utf-8')
    )
    userTwoFA = Twofa(id  = new_user.id)

    doctorUser = User(
        id='S1234567A',
        username='Amy',
        password=bcrypt.generate_password_hash("P@ssw0rd").decode('utf-8')
    )
    doctorTwoFA = Twofa(id  = doctorUser.id)

    doctor = doctorUser.add_doctor(
        license_number='M04637Z',
        specialisation='Family Medicine',  
        facility='Manadr BoonLay'
    )

    dbSession.add(new_user)
    dbSession.add(doctorUser)
    dbSession.add(doctor)  
    dbSession.add(userTwoFA)
    dbSession.add(doctorTwoFA)
    dbSession.commit()
    dbSession.close()
    flash("Doctor Added to DB", "success")
    return redirect(url_for('home'))


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
                return redirect(url_for('home'))
            else:
                try:
                    twofaCheck.twofa_enabled = True
                    dbSession.commit()
                    flash("2FA setup successful. You are logged in!", "success")
                    return redirect(url_for('home'))
                except Exception:
                    dbSession.rollback()
                    flash("2FA setup failed. Please try again.", "danger")
                    return redirect(url_for('verify2FA'))
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

    user = dbSession.query(User).filter(User.id == NRIC).first()  # Find the first user with this username

    if user:
        print(user.username)
        return render_template('doctor_assignment.html', user=user)
    else:
        # If no user is found, pass None (or null) to the template
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

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Successfully Logged Out", "success")
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)