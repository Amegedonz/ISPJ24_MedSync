from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from prometheus_client import Counter, Gauge, Info, Histogram, Summary, generate_latest
from prometheus_flask_exporter import PrometheusMetrics
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
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

# Initialize Prometheus metrics
metrics = PrometheusMetrics(app)

# Initialize OpenTelemetry
trace_exporter = OTLPSpanExporter(endpoint="http://localhost:4317")  # Adjust if using remote OpenTelemetry Collector
provider = TracerProvider()
processor = BatchSpanProcessor(trace_exporter)
provider.add_span_processor(processor)

# Instrument Flask app with OpenTelemetry
FlaskInstrumentor().instrument_app(app)

# Prometheus Counters
consumer_login_attempts = Counter('consumer_login_attempts_total', 'Total login attempts', ['status'])
consumer_logout_attempts = Counter('consumer_logout_attempts_total', 'Total logout attempts', ['status'])
consumer_register_attempts = Counter('consumer_register_attempts_total', 'Total register attempts', ['status'])
consumer_views = Counter('consumer_page_views_total', 'Page views', ['page'])


# Add metrics endpoint
@app.route('/metrics')
def metrics():
    return generate_latest()

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
    consumer_views.labels(page='home').inc()
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("15/hour;3/minute")
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Validate user credentials
        if username in users or username == 'admin':
            stored_password = users[username]['password']
            if check_password_hash(stored_password, password) or (username == 'admin' and password == 'admin123'):
                flash('Login successful!', 'success')
                consumer_login_attempts.labels(status='success').inc()
                return redirect(url_for('home'))
            else:
                consumer_login_attempts.labels(status='password_failed').inc()
                flash('Invalid password. Please try again.', 'danger')
        else:
            consumer_login_attempts.labels(status='username_failed').inc()
            flash('User not found. Please try again.', 'danger')

    consumer_views.labels(page='login').inc()
    return render_template('login.html')

@app.route('/logout')
# @login_required
def logout():
    # logout_user()
    consumer_views.labels(page='logout').inc()
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    consumer_views.labels(page='register').inc()
    return render_template('register.html')

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