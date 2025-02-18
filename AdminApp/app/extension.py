from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt

db = SQLAlchemy
login_manager = LoginManager
bcrypt = Bcrypt


def init_extensions(app):
    db.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)