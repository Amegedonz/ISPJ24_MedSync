from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os, limiter
from flask import Flask, request, render_template, redirect, url_for, send_from_directory, flash
import os
from hashlib import sha256
import mimetypes
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import io
import json

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
@limiter.limit("15/hour;3/minute")
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Validate user credentials
        # Validate user credentials
        if username in users or username == 'admin':
            stored_password = users[username]['password']
            if check_password_hash(stored_password, password) or (username == 'admin' and password == 'admin123'):
                flash('Login successful!', 'success')
                return redirect(url_for('home'))
        else:
            flash('User not found. Please try again.', 'danger')

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

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.id not in users or users[current_user.id]['role'] != 'admin':
        flash('Access denied. Admin only.', 'error')
        return redirect(url_for('home'))

    # Placeholder: Fetch user accounts and SIEM events from database
    user_accounts = [
        {'username': 'staff1', 'role': 'staff', 'last_login': '2023-05-01 10:30:00'},
        {'username': 'patient1', 'role': 'patient', 'last_login': '2023-04-30 15:45:00'},
    ]
    siem_events = [
        {'timestamp': '2023-05-01 11:00:00', 'type': 'login', 'user': 'staff1', 'details': 'Successful login'},
        {'timestamp': '2023-05-01 11:05:00', 'type': 'upload', 'user': 'staff1', 'details': 'Document uploaded for patient1'},
    ]
    return render_template('admin_dashboard.html', users=user_accounts, siem_events=siem_events)


UPLOAD_FOLDER = 'uploads'
HASH_FOLDER = 'hashes'
META_FOLDER = 'meta'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(HASH_FOLDER, exist_ok=True)
os.makedirs(META_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['HASH_FOLDER'] = HASH_FOLDER
app.config['META_FOLDER'] = META_FOLDER

# Home route
@app.route('/')
def landing_page():
    return render_template('landing.html')

# Home route (Upload page)
@app.route('/upload')
def upload_page():
    return render_template('upload.html')



# Upload route
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)

    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)

    if file:
        # Save the file
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)

        # Process metadata
        name = request.form['name']
        license_no = request.form['license_no']
        date = request.form['date']
        time = request.form['time']
        facility = request.form['facility']
        patient_nric = request.form['patient_nric']
        type = request.form['type']

        # Prepare metadata
        metadata = {
            'name': name,
            'license_no': license_no,
            'date': date,
            'time': time,
            'facility': facility,
            'patient_nric': patient_nric,
            'type': type
        }

        # Save metadata in a JSON file
        metadata_filepath = os.path.join(app.config['META_FOLDER'], f"{file.filename}_metadata.json")
        with open(metadata_filepath, 'w') as metadata_file:
            json.dump(metadata, metadata_file)

        # Add watermark if the file is PDF
        if file.filename.endswith('.pdf'):
            watermark_text = "Medsync"
            add_watermark(filepath, filepath,
                          watermark_text)  # Overwrite the original file with the watermarked version

            # Hash the watermark text itself
            watermark_hash = compute_hash_from_text(watermark_text)
            watermark_hash_filepath = os.path.join(app.config['HASH_FOLDER'], f"{file.filename}_watermark.hash")
            with open(watermark_hash_filepath, 'w') as watermark_hash_file:
                watermark_hash_file.write(watermark_hash)

        # Compute hash of the watermarked file
        file_hash = compute_hash(filepath)
        hash_filepath = os.path.join(app.config['HASH_FOLDER'], f"{file.filename}.hash")
        with open(hash_filepath, 'w') as hash_file:
            hash_file.write(file_hash)

        # Pass hash values to the template
        return render_template('upload_success.html',
                               file_hash=file_hash,
                               watermark_hash=watermark_hash,
                               metadata=metadata,
                               filename=file.filename)




def get_files_metadata():
    files_metadata = []
    for filename in os.listdir(UPLOAD_FOLDER):
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        if os.path.isfile(file_path):
            metadata_path = os.path.join(META_FOLDER, f"{filename}_metadata.json")
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
            else:
                metadata = {}
            file_hash = compute_hash(file_path)
            files_metadata.append({
                "filename": filename,
                "metadata": metadata,
                "hash": file_hash
            })
    return files_metadata

# Route to view files with NRIC filter
@app.route('/files', methods=['GET'])
def list_files():
    # Get the NRIC query parameter
    nric_query = request.args.get('nric', '').strip()

    # Get all files metadata
    all_files = get_files_metadata()

    # Filter the files based on NRIC query if provided
    if nric_query:
        filtered_files = [file for file in all_files if file['metadata'].get('patient_nric') == nric_query]
        if not filtered_files:
            flash("NRIC doesn't exist!")
    else:
        filtered_files = all_files

    return render_template('download.html', files=filtered_files)

@app.route('/delete/<filename>', methods=['DELETE'])
def delete_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    metadata_path = os.path.join(app.config['META_FOLDER'], f"{filename}_metadata.json")
    hash_path = os.path.join(app.config['HASH_FOLDER'], f"{filename}.hash")
    watermark_hash_path = os.path.join(app.config['HASH_FOLDER'], f"{filename}_watermark.hash")

    try:
        # Delete the main file
        if os.path.exists(file_path):
            os.remove(file_path)

        # Delete metadata file
        if os.path.exists(metadata_path):
            os.remove(metadata_path)

        # Delete hash file
        if os.path.exists(hash_path):
            os.remove(hash_path)

        # Delete watermark hash file
        if os.path.exists(watermark_hash_path):
            os.remove(watermark_hash_path)

        return {"success": True}, 200
    except Exception as e:
        return {"success": False, "error": str(e)}, 500

# View file route
@app.route('/view/<filename>')
def view_file(filename):
    # Get the full path of the file
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Check if file exists
    if not os.path.exists(filepath):
        flash("File not found!")
        app.logger.error(f"File not found: {filepath}")  # Debugging log
        return redirect(url_for('list_files'))

    # Determine file MIME type
    mimetype, _ = mimetypes.guess_type(filepath)

    # Debugging logs
    app.logger.debug(f"Attempting to view file: {filepath}")
    app.logger.debug(f"Detected MIME type: {mimetype}")

    # If the file is a PDF, render it
    if mimetype == 'application/pdf':
        return render_template('view.html', filename=filename, is_pdf=True)

    # If the file is a text file, try reading its content
    elif mimetype and mimetype.startswith('text'):
        try:
            with open(filepath, 'r', encoding='utf-8') as file:
                content = file.read()
        except UnicodeDecodeError:
            with open(filepath, 'r', encoding='latin-1') as file:
                content = file.read()

        return render_template('view.html', filename=filename, content=content)

    # If the MIME type is None or unsupported
    flash("This file type cannot be previewed. You can download it.")
    return redirect(url_for('list_files'))

# Download route
@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

# Serve uploaded files for preview
@app.route('/uploads/<filename>')
def serve_uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Compute hash function
def compute_hash(filepath):
    """Compute the SHA-256 hash of the file."""
    hasher = sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

# Function to add watermark to PDF
def add_watermark(input_pdf_path, output_pdf_path, watermark_text):
    # Create a temporary PDF with the watermark
    packet = io.BytesIO()
    c = canvas.Canvas(packet, pagesize=letter)

    # Get the size of the letter page (you can adjust it to fit the size of your PDFs)
    width, height = letter

    # Set the font and size for the watermark
    c.setFont("Helvetica", 60)

    # Calculate the position to center the watermark (horizontal and vertical center)
    text_width = c.stringWidth(watermark_text, "Helvetica", 60)
    x_position = (width - text_width) / 2  # Horizontal center
    y_position = height / 2  # Vertical center

    # Set the opacity for the watermark (0 is fully transparent, 1 is fully opaque)
    c.setFillAlpha(0.3)
    c.setFillColorRGB(0.5, 0.5, 0.5)  # Grey color for the watermark

    # Draw the watermark text
    c.drawString(x_position, y_position, watermark_text)
    c.showPage()
    c.save()

    # Move the watermark to the start of the BytesIO object
    packet.seek(0)

    # Create a PDF reader from the original document and the watermark
    new_pdf = PdfReader(packet)
    existing_pdf = PdfReader(input_pdf_path)
    output_pdf = PdfWriter()

    # Apply the watermark on each page
    for page_num in range(len(existing_pdf.pages)):
        page = existing_pdf.pages[page_num]
        page.merge_page(new_pdf.pages[0])  # Merge the watermark on the page
        output_pdf.add_page(page)

    # Save the output PDF with the watermark
    with open(output_pdf_path, "wb") as output_file:
        output_pdf.write(output_file)

# Function to hash watermark text
def compute_hash_from_text(text):
    """Compute the SHA-256 hash of the watermark text."""
    hasher = sha256()
    hasher.update(text.encode('utf-8'))
    return hasher.hexdigest()








if __name__ == '__main__':
    # if not os.path.exists(app.config['UPLOAD_FOLDER']):
    #     os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True , port=5001)