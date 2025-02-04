from DBcreateTables import User, Doctor
from flask_wtf import FlaskForm
from flask_wtf.recaptcha import RecaptchaField
from wtforms import Form, validators, SelectField, RadioField, BooleanField, StringField, PasswordField, IntegerField, EmailField, TextAreaField

class LoginForm(FlaskForm):
    id = StringField("NRIC: ", [validators.InputRequired(), validators.Regexp(r'^[A-Za-z][0-9]{7}[A-Za-z]$', message = "please ensure correct NRIC")])
    password = PasswordField("Password: ",[validators.InputRequired()])
    remember = BooleanField("Remember me:", default= True )
    
class RegistrationForm(FlaskForm):
    name = StringField("* Name (As Per NRIC):  ",[validators.InputRequired()])
    id = StringField("* NRIC: " ,[validators.InputRequired(), validators.Regexp(r'^[A-Za-z][0-9]{7}[A-Za-z]$', message = "please ensure correct NRIC")])
    email = EmailField('Email:', [validators.Email(), validators.Optional()])
    phoneNumber = IntegerField('Phone Number:', [validators.NumberRange(6000000, 99999999), validators.Optional()])
    password = PasswordField('* Password:',[validators.InputRequired(), validators.Regexp(r'\A(?=\S*?\d)(?=\S*?[A-Z])(?=\S*?[a-z])\S{6,}\Z', message="Password must have at least: \n-6 Characters\n-1 Uppercase, \n-1 Number")])
    confirm = PasswordField('* Repeat Password:',[validators.InputRequired(), validators.EqualTo('password', message='Passwords must match')])
