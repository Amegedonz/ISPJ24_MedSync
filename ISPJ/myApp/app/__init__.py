from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os, csv
import plotly.graph_objs as go
import plotly.io as pio

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this to a random secret key
app.config['UPLOAD_FOLDER'] = 'uploads'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

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
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and check_password_hash(users[username]['password'], password):
            user = User()
            user.id = username
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'error')
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


@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    admin_username = "admin1"
    admin_password = "admin123"
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == admin_username and password == admin_password:
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    return render_template('admin_login.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    # Sample data for User Login Activity
    login_dates = ['2023-10-01', '2023-10-02', '2023-10-03', '2023-10-04', '2023-10-05']
    login_counts = [50, 75, 60, 80, 90]

    # Sample data for Failed Login Attempts
    failed_login_periods = ['Week 1', 'Week 2', 'Week 3', 'Week 4']
    failed_login_counts = [5, 7, 3, 9]
    
    # Sample data for Document Uploads and Downloads
    dates = ['2023-10-01', '2023-10-02', '2023-10-03', '2023-10-04', '2023-10-05']
    uploads = [20, 30, 25, 35, 45]
    downloads = [15, 25, 20, 30, 40]

    # Create Plotly charts
    login_activity_fig = go.Figure(data=[
        go.Scatter(x=login_dates, y=login_counts, mode='lines+markers', name='Logins', line=dict(color='blue'))
    ])
    login_activity_fig.update_layout(title='User Login Activity Over Time', xaxis_title='Date', yaxis_title='Number of Logins')

    failed_logins_fig = go.Figure(data=[
        go.Bar(x=failed_login_periods, y=failed_login_counts, name='Failed Logins', marker=dict(color='red'))
    ])
    failed_logins_fig.update_layout(title='Failed Login Attempts by Week', xaxis_title='Week', yaxis_title='Number of Failed Attempts')

    document_activity_fig = go.Figure(data=[
        go.Scatter(x=dates, y=uploads, fill='tozeroy', mode='none', name='Uploads', fillcolor='rgba(0, 128, 0, 0.5)'),
        go.Scatter(x=dates, y=downloads, fill='tonexty', mode='none', name='Downloads', fillcolor='rgba(0, 0, 255, 0.5)')
    ])
    document_activity_fig.update_layout(title='Document Uploads and Downloads Over Time', xaxis_title='Date', yaxis_title='Number of Documents')

    # Convert charts to HTML
    login_activity_html = pio.to_html(login_activity_fig, full_html=False)
    failed_logins_html = pio.to_html(failed_logins_fig, full_html=False)
    document_activity_html = pio.to_html(document_activity_fig, full_html=False)

    return render_template('admin_dashboard.html',
                           login_activity_html=login_activity_html,
                           failed_logins_html=failed_logins_html,
                           document_activity_html=document_activity_html)

@app.route('/admin_notif')
def admin_notif():
    notifications = []
    try:
        with open('log.csv', 'r', encoding='utf-8') as file:
            csv_reader = csv.DictReader(file)
            for row in csv_reader:
                if row['levelname'] in ['ERROR', 'CRITICAL']:
                    notifications.append({
                        'datetime': row['asctime'],  # Assuming 'asctime' is the first column
                        'description': row['message'],  # Assuming 'message' is the second column
                        'level': row['levelname'],  # Assuming 'levelname' is the third column
                        'user_id': '12'  # Assuming 'user_id' is a field in the CSV
                    })
                print(notifications)
    except FileNotFoundError:
        flash('No logs found', 'warning')
        notifications = []
        

    return render_template('admin_notif.html', notifications=notifications)

@app.route('/restrict_user/<int:user_id>', methods=['POST'])

def restrict_user(user_id):
    return "User restricted"


@app.route('/disable_user/<int:user_id>', methods=['POST'])

def disable_user(user_id):
    return "User disabled"


@app.route('/delete_user/<int:user_id>', methods=['POST'])

def delete_user(user_id):
    return "User deleted"

if __name__ == '__main__':
    # if not os.path.exists(app.config['UPLOAD_FOLDER']):
    #     os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)