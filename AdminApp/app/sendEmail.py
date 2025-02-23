# sendEmail.py

import logging, csv
from logging.handlers import SMTPHandler
import os
from dotenv import load_dotenv

class CsvFileHandler(logging.FileHandler):
    def headerWriter(self, header, logfile):
        # Check if the file already exists and is not empty
        file_exists = False
        try:
            with open(logfile, 'r', newline='') as f:
                file_exists = f.read(1) != ''
        except FileNotFoundError:
            pass

        # Open the file in append mode
        with open(logfile, 'a', newline='') as f:
            writer = csv.writer(f, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            # Write the header only if the file is empty
            if not file_exists:
                writer.writerow(header)

def write_csv_log(logfile, logrecord):
    with open(logfile, 'a', newline='') as f:
        writer = csv.writer(f, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        writer.writerow(logrecord)

# Load environment variables
load_dotenv()

def setup_logger():
    # Create logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    # Configure email handler
    mail_handler = SMTPHandler(
        mailhost=(os.getenv('SMTP_SERVER', 'smtp.gmail.com'), 587),
        fromaddr=os.getenv('SENDER_EMAIL'),
        toaddrs=[os.getenv('ADMIN_EMAIL')],
        subject='MedSync Log Alert',
        credentials=(
            os.getenv('SENDER_EMAIL'),
            os.getenv('SENDER_PASSWORD')
        ),
        secure=()
    )

    # Set email handler level to ERROR
    mail_handler.setLevel(logging.ERROR)
    
    # Create formatter
    formatter = logging.Formatter(
    '%(asctime)s,%(name)s,%(levelname)s,"%(message)s",%(user_id)s'
)
    mail_handler.setFormatter(formatter)
    
    # Add handler to logger
    logger.addHandler(mail_handler)
    
    # Configure CSV file handler
    csv_logfile = 'logging.csv'
    csv_handler = CsvFileHandler(csv_logfile)
    csv_handler.setLevel(logging.ERROR)
    
    # Write header to CSV file
    csv_handler.headerWriter(['asctime', 'name', 'levelname', 'message', 'user_id'], csv_logfile)
    
    # Create formatter for CSV
    csv_formatter = logging.Formatter('%(asctime)s,%(name)s,%(levelname)s,%(message)s,12')
    csv_handler.setFormatter(csv_formatter)
    
    # Add CSV handler to logger
    logger.addHandler(csv_handler)

    log_logfile = 'log.log'
    default_handler = logging.FileHandler(log_logfile)
    default_handler.setLevel(logging.DEBUG)
    logger.addHandler(default_handler)

    return logger

def test_logging():
    logger = setup_logger()
    
    # Sample user IDs
    user_id_debug = '10'
    user_id_error = '12'
    user_id_warning = '15'
    user_id_info = '20'
    user_id_admin = 'admin'

    # These won't trigger emails
    logger.debug('User login successful for user_id: 10', extra={'user_id': user_id_debug})
    logger.info('User accessed patient records for patient_id: 501', extra={'user_id': user_id_info})
    
    # These will trigger emails
    logger.error("'Failed to retrieve documents for user_id: 12 due to database timeout', extra={'user_id': user_id_error}")
    logger.critical(
        'SECURITY BREACH DETECTED - Multiple failed login attempts (10) from IP 192.168.1.100 '
        'attempting to access patient records. User account "doctor_smith" has been temporarily '
        'locked. Possible brute force attack in progress. Session ID: 5f3e9b2d-8c1a-4e8b-9c1a-8c1a4e8b9c1a. '
        'Immediate investigation required.',
        extra={'user_id': user_id_error}
    )
    logger.warning('User_id: 15 attempted unauthorized access to restricted area', extra={'user_id': user_id_warning})
    logger.error('Error processing payment for user_id: 18 due to invalid credit card details', extra={'user_id': '18'})
    logger.critical('System outage detected. All services are currently unavailable. Immediate action required.', extra={'user_id': user_id_admin})

if __name__ == '__main__':
    test_logging()