from io import BytesIO
from hashlib import sha256
#File upload
from PyPDF2 import PdfReader, PdfWriter
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


#helper functions
def compute_hash(filepath):
    hasher = sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

def compute_hash_from_text(text):
    return sha256(text.encode('utf-8')).hexdigest()

def add_watermark(input_pdf_path, output_pdf_path, watermark_text):
    packet = BytesIO()
    c = canvas.Canvas(packet, pagesize=letter)
    width, height = letter
    c.setFont("Helvetica", 60)
    text_width = c.stringWidth(watermark_text, "Helvetica", 60)
    c.setFillAlpha(0.3)
    c.setFillColorRGB(0.5, 0.5, 0.5)
    c.drawString((width - text_width) / 2, height / 2, watermark_text)
    c.showPage()
    c.save()
    packet.seek(0)
    new_pdf = PdfReader(packet)
    existing_pdf = PdfReader(input_pdf_path)
    output_pdf = PdfWriter()
    for page in existing_pdf.pages:
        page.merge_page(new_pdf.pages[0])
        output_pdf.add_page(page)
    with open(output_pdf_path, "wb") as output_file:
        output_pdf.write(output_file)