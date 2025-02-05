import logging, os
from pythonjsonlogger import jsonlogger
from datetime import datetime
from flask import request

base_dir = os.path.dirname(os.path.abspath(__file__))
log_dir = os.path.join(base_dir, "logs")
log_file = os.path.join(log_dir, "app.log")

# Ensure the logs directory exists
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# log handler
logger = logging.getLogger()
logHandler = logging.FileHandler(log_file)
formatter = jsonlogger.JsonFormatter("%(asctime)s %(levelname)s %(message)s")
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)
logger.setLevel(logging.INFO)

