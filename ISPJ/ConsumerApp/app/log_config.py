import logging
from pythonjsonlogger import jsonlogger
from datetime import datetime
from flask import request

# log handler
logger = logging.getLogger()
logHandler = logging.FileHandler("ISPJ/ConsumerApp/app/logs/app.log")
formatter = jsonlogger.JsonFormatter("%(asctime)s %(levelname)s %(message)s")
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)
logger.setLevel(logging.INFO)

