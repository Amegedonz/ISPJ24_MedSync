import logging
from pythonjsonlogger import jsonlogger
from datetime import datetime
from flask import request
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Create logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# JSON File Handler
json_handler = logging.FileHandler("ISPJ/ConsumerApp/app/logs/app.log")
json_formatter = jsonlogger.JsonFormatter("%(asctime)s %(levelname)s %(message)s")
json_handler.setFormatter(json_formatter)
logger.addHandler(json_handler)

# Email Handler
# email_handler = SMTPHandler(
#     mailhost=(os.getenv('SMTP_SERVER', 'smtp.gmail.com'), 587),
#     fromaddr=os.getenv('SENDER_EMAIL'),
#     toaddrs=[os.getenv('ADMIN_EMAIL')],
#     subject='MedSync Warning/Error Alert',
#     credentials=(
#         os.getenv('SENDER_EMAIL'),
#         os.getenv('SENDER_PASSWORD')
#     ),
#     secure=()
# )

# # Set email handler level to WARNING
# email_handler.setLevel(logging.WARNING)
# email_formatter = logging.Formatter('''
# Time: %(asctime)s
# Level: %(levelname)s
# Message: %(message)s
# ''')
# email_handler.setFormatter(email_formatter)
# logger.addHandler(email_handler)

# # test email
# logger.error("Test email")

