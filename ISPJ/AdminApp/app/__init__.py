from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from prometheus_client import Counter, generate_latest
import os, csv
import plotly.graph_objs as go
import plotly.io as pio
#SQLalchemy requirements to build models
from sqlalchemy import Table, Column, Integer, String, Boolean, ForeignKey, Float, DateTime, text
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.sql import func
 

#DB connection
from database import engine, Base, dbSession

#Login lib requirements
from flask_login import UserMixin



app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this to a random secret key
app.config['UPLOAD_FOLDER'] = 'uploads'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User Class
class User(Base, UserMixin):
    __tablename__ = 'users'

    id = Column(String(9), primary_key=True, unique=True)
    username = Column(String(50), nullable=False)
    password = Column(String(255), nullable=False)
    email = Column(String(100), unique=True)
    phoneNumber = Column(Integer(), unique=True)
    role = Column(String(50), nullable=False, default="Patient")
    
    @property
    def is_active(self):
        if self.not_active:
            return False
        return True
    
    def not_active(self):
        self.not_active = True
    
    # def toggle_active(self):
    #     self.active = not self.active
    #     return not self.active

# Define counters for login attempts
login_attempts = Counter('admin_login_attempts_total', 'Total login attempts', ['status'])
admin_views = Counter('admin_views_total', 'Admin page views', ['page'])

@login_manager.user_loader
def load_user(id):
    return dbSession.query(User).filter(User.id == id).first()

@app.route('/')
def home():
    admin_views.labels(page='admin_home').inc()
    return render_template('admin_login.html')


@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    admin_username = "admin1"
    admin_password = "admin123"
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == admin_username:
            password == admin_password
            if password == admin_password:
                # Increment successful login counter
                login_attempts.labels(status='success').inc()
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Invalid username or password.', 'error')
                login_attempts.labels(status='password_failed').inc()
                return redirect(url_for('admin_login'))
        else:
            # Increment failed login counter
            login_attempts.labels(status='username_failed').inc()
            flash('Invalid username or password.', 'error')
    
    # Increment page view counter
    admin_views.labels(page='login').inc()
    return render_template('admin_login.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    admin_views.labels(page='admin_dashboard').inc()
    return render_template('admin_dashboard.html')

@app.route('/user_management')
def user_management():
    users = dbSession.query(User).all()
    admin_views.labels(page='user_management').inc()
    return render_template('user_management.html', users=users)

@app.route('/toggle_user_status/<user_id>', methods=['POST'])
def toggle_user_status(user_id):
    try:
        user = dbSession.query(User).filter_by(id=user_id).first()
        if user:
            # status = user.toggle_active()
            # user.not_active()
            if user.is_active:
                user.not_active()
            else:
                user.is_active 
            dbSession.commit()
            status = "activated" if user.is_active else "deactivated"
            flash(f'User {user.username} has been {status}', 'success')
        else:
            flash('User not found', 'error')
    except Exception as e:
        dbSession.rollback()
        flash(f'Error updating user: {str(e)}', 'error')
    finally:
        dbSession.close()
    return redirect(url_for('user_management'))

# @app.route('/restrict_user/<int:user_id>', methods=['POST'])
# def restrict_user(user_id):
#     return "User restricted"


# @app.route('/disable_user/<int:user_id>', methods=['POST'])
# def disable_user(user_id):
#     return "User disabled"


# @app.route('/delete_user/<int:user_id>', methods=['POST'])
# def delete_user(user_id):
#     return "User deleted"

@app.route('/metrics')
def metrics():
    return generate_latest()

if __name__ == '__main__':
    # if not os.path.exists(app.config['UPLOAD_FOLDER']):
    #     os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True, port=5002)