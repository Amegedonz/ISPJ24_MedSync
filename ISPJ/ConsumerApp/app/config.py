import os
from dotenv import load_dotenv

load_dotenv()

basedir = os.path.abspath(os.path.dirname(__file__))



class Config:
    SECRET_KEY = os.getenv("SECRET_KEY")
    UPLOADS_FOLDER = os.getenv("UPLOAD_FOLDER")
    GOOGLE_RC_PROJECT_ID = os.getenv("GOOGLE_RC_PROJECT_ID")

    #reCAPTCHA keys
    RECAPTCHA_PRIVATE_KEY = os.getenv("RECAPTCHA_PRIVATE_KEY")
    RECAPTCHA_PUBLIC_KEY = os.getenv("RECAPTCHA_PUBLIC_KEY")