import os
import json
import base64
import hashlib
import secrets
from datetime import datetime, date, timedelta
from functools import wraps
from io import BytesIO

from flask import (Flask, render_template, request, redirect, url_for, flash,
                   session, jsonify, send_file)
import psycopg2
import psycopg2.extras

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# --- Database ---
def get_db():
    db_url = os.environ.get('DATABASE_URL', '')
    if db_url.startswith('postgres://'):
        db_url = db_url.replace('postgres://', 'postgresql://', 1)
    conn = psycopg2.connect(db_url)
    conn.autocommit = True
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        company_name TEXT DEFAULT '',
        company_address TEXT DEFAULT '',
        company_email TEXT DEFAULT '',
        company_phone TEXT DEFAULT '',
        logo_data TEXT DEFAULT '',
        brand_color TEXT DEFAULT '#2563eb',
        currency TEXT DEFAULT 'INR',
        tax_reg_label TEXT DEFAULT 'GSTIN',
        tax_reg_number TEXT DEFAULT '',
        bank_details TEXT DEFAULT '',
        is_superadmin BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS clients (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        name TEXT NOT NULL,
        email TEXT DEFAULT '',
        address TEXT DEFAULT '',
        phone TEXT DEFAULT '',
        contact_person TEXT DEFAULT '',
        tax_id TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT NOW()
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS contracts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        client_id INTEGER REFERENCES clients(id),
        contract_number TEXT DEFAULT '',
        title TEXT NOT NULL,
        contract_type TEXT DEFAULT 'service',
        source TEXT DEFAULT 'manual',
        status TEXT DEFAULT 'draft',
        start_date DATE,
        end_date DATE,
        total_value REAL DEFAULT 0,
        currency TEXT DEFAULT 'INR',
        payment_terms TEXT DEFAULT '',
        scope_of_work TEXT DEFAULT '',
        terms_conditions TEXT DEFAULT '',
        deliverables TEXT DEFAULT '',
        po_number TEXT DEFAULT '',
        po_file_data TEXT DEFAULT '',
        notes TEXT DEFAULT '',
        invoiced_amount REAL DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS contract_milestones (
        id SERIAL PRIMARY KEY,
        contract_id INTEGER REFERENCES contracts(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        description TEXT DEFAULT '',
        amount REAL DEFAULT 0,
        due_date DATE,
        status TEXT DEFAULT 'pending',
        invoice_id TEXT DEFAULT ''
    )''')
    conn.close()

    # Migrations
    conn = get_db()
    cur = conn.cursor()
    migrations = [
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_superadmin BOOLEAN DEFAULT FALSE",
        "UPDATE users SET is_superadmin = TRUE WHERE id = (SELECT MIN(id) FROM users)",
    ]
    for m in migrations:
        try:
            cur.execute(m)
        except Exception:
            pass
    conn.close()

init_db()

# --- Auth ---
def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def get_user():
    if 'user_id' not in session:
        return None
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('SELECT * FROM users WHERE id=%s', (session['user_id'],))
    user = cur.fetchone()
    conn.close()
    return user

CURR_SYMBOLS = {'CAD': 'C$', 'INR': 'Rs.', 'EUR': 'EUR', 'USD': '$', 'GBP': 'GBP'}

def curr_sym(currency):
    return CURR_SYMBOLS.get(currency, '$')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute('SELECT * FROM users WHERE email=%s', (email,))
        user = cur.fetchone()
        conn.close()
        if user and user['password_hash'] == hash_pw(password):
            session['user_id'] = user['id']
            return redirect(url_for('dashboard'))
        flash('Invalid email or password', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        company = request.form.get('company_name', '')
        currency = request.form.get('currency', 'INR')
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
            return render_template('login.html', show_register=True)
        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute('SELECT COUNT(*) FROM users')
            is_first = cur.fetchone()[0] == 0
            cur.execute('''INSERT INTO users (email, password_hash, company_name, currency, is_superadmin)
                          VALUES (%s,%s,%s,%s,%s) RETURNING id''',
                       (email, hash_pw(password), company, currency, is_first))
            user_id = cur.fetchone()[0]
            session['user_id'] = user_id
            conn.close()
            return redirect(url_for('settings'))
        except psycopg2.IntegrityError:
            conn.close()
            flash('Email already registered', 'error')
    return render_template('login.html', show_register=True)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- Dashboard ---
@app.route('/')
@login_required
def dashboard():
    user = get_user()
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # Stats
    cur.execute('''SELECT
        COUNT(*) as total,
        COUNT(CASE WHEN status='active' THEN 1 END) as active,
        COUNT(CASE WHEN status='draft' THEN 1 END) as drafts,
        COUNT(CASE WHEN status='signed' THEN 1 END) as signed,
        COUNT(CASE WHEN status='completed' THEN 1 END) as completed,
        COALESCE(SUM(total_value), 0) as total_value,
        COALESCE(SUM(CASE WHEN status IN ('active','signed') THEN total_value ELSE 0 END), 0) as active_value,
        COALESCE(SUM(invoiced_amount), 0) as total_invoiced
    FROM contracts WHERE user_id=%s''', (user['id'],))
    stats = cur.fetchone()

    # Recent contracts
    cur.execute('''SELECT c.*, cl.name as client_name
                  FROM contracts c LEFT JOIN clients cl ON c.client_id = cl.id
                  WHERE c.user_id=%s ORDER BY c.updated_at DESC LIMIT 20''', (user['id'],))
    contracts = cur.fetchall()

    conn.close()
    cs = curr_sym(user.get('currency', 'INR'))
    return render_template('dashboard.html', user=user, stats=stats, contracts=contracts, cs=cs)

# --- Clients ---
@app.route('/clients')
@login_required
def clients():
    user = get_user()
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('''SELECT cl.*,
                  COUNT(c.id) as contract_count,
                  COALESCE(SUM(c.total_value), 0) as total_value
                  FROM clients cl LEFT JOIN contracts c ON cl.id = c.client_id
                  WHERE cl.user_id=%s GROUP BY cl.id ORDER BY cl.name''', (user['id'],))
    clients_list = cur.fetchall()
    conn.close()
    return render_template('clients.html', user=user, clients=clients_list, cs=curr_sym(user.get('currency', 'INR')))

@app.route('/client/add', methods=['GET', 'POST'])
@login_required
def add_client():
    user = get_user()
    if request.method == 'POST':
        conn = get_db()
        cur = conn.cursor()
        cur.execute('''INSERT INTO clients (user_id, name, email, address, phone, contact_person, tax_id)
                      VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id''',
                   (user['id'], request.form['name'], request.form.get('email', ''),
                    request.form.get('address', ''), request.form.get('phone', ''),
                    request.form.get('contact_person', ''), request.form.get('tax_id', '')))
        conn.close()
        flash('Client added!', 'success')
        return redirect(url_for('clients'))
    return render_template('client_form.html', user=user, client=None)

@app.route('/api/clients')
@login_required
def api_clients():
    user = get_user()
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('SELECT id, name, email, address, phone, contact_person, tax_id FROM clients WHERE user_id=%s ORDER BY name', (user['id'],))
    clients_list = cur.fetchall()
    conn.close()
    return jsonify(clients_list)

# --- Create Contract ---
@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_contract():
    user = get_user()
    if request.method == 'POST':
        conn = get_db()
        cur = conn.cursor()

        # Handle client - existing or new
        client_id = request.form.get('client_id')
        if not client_id and request.form.get('client_name'):
            cur.execute('''INSERT INTO clients (user_id, name, email, address, contact_person)
                          VALUES (%s,%s,%s,%s,%s) RETURNING id''',
                       (user['id'], request.form['client_name'],
                        request.form.get('client_email', ''),
                        request.form.get('client_address', ''),
                        request.form.get('contact_person', '')))
            client_id = cur.fetchone()[0]

        # Contract number
        cur.execute('SELECT COUNT(*) FROM contracts WHERE user_id=%s', (user['id'],))
        count = cur.fetchone()[0] + 1
        prefix = 'CTR'
        contract_number = f"{prefix}-{count:04d}"

        start = request.form.get('start_date') or None
        end = request.form.get('end_date') or None
        total_value = float(request.form.get('total_value', 0) or 0)

        cur.execute('''INSERT INTO contracts (user_id, client_id, contract_number, title,
                      contract_type, status, start_date, end_date, total_value, currency,
                      payment_terms, scope_of_work, terms_conditions, deliverables,
                      po_number, notes)
                      VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id''',
                   (user['id'], client_id, contract_number,
                    request.form.get('title', 'Untitled Contract'),
                    request.form.get('contract_type', 'service'),
                    request.form.get('status', 'draft'),
                    start, end, total_value, user.get('currency', 'INR'),
                    request.form.get('payment_terms', ''),
                    request.form.get('scope_of_work', ''),
                    request.form.get('terms_conditions', ''),
                    request.form.get('deliverables', ''),
                    request.form.get('po_number', ''),
                    request.form.get('notes', '')))
        contract_id = cur.fetchone()[0]

        # Save milestones
        m_titles = request.form.getlist('milestone_title[]')
        m_amounts = request.form.getlist('milestone_amount[]')
        m_dates = request.form.getlist('milestone_date[]')
        for i, mt in enumerate(m_titles):
            if mt.strip():
                amt = float(m_amounts[i]) if i < len(m_amounts) and m_amounts[i] else 0
                md = m_dates[i] if i < len(m_dates) and m_dates[i] else None
                cur.execute('''INSERT INTO contract_milestones (contract_id, title, amount, due_date)
                              VALUES (%s,%s,%s,%s)''', (contract_id, mt.strip(), amt, md))

        conn.close()
        flash(f'Contract {contract_number} created!', 'success')
        return redirect(url_for('view_contract', contract_id=contract_id))

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('SELECT * FROM clients WHERE user_id=%s ORDER BY name', (user['id'],))
    clients_list = cur.fetchall()
    conn.close()
    return render_template('create.html', user=user, clients=clients_list,
                         cs=curr_sym(user.get('currency', 'INR')))

# --- Upload PO ---
@app.route('/upload-po', methods=['GET', 'POST'])
@login_required
def upload_po():
    user = get_user()
    if request.method == 'POST':
        po_file = request.files.get('po_file')
        if not po_file or not po_file.filename:
            flash('Please upload a PO file', 'error')
            return redirect(url_for('upload_po'))

        file_data = po_file.read()
        ext = po_file.filename.rsplit('.', 1)[-1].lower()

        # Try AI extraction
        extracted = {}
        api_key = os.environ.get('ANTHROPIC_API_KEY', '')
        if api_key:
            try:
                import anthropic
                client = anthropic.Anthropic(api_key=api_key)

                if ext == 'pdf':
                    content = [
                        {"type": "document", "source": {"type": "base64", "media_type": "application/pdf",
                         "data": base64.b64encode(file_data).decode()}},
                        {"type": "text", "text": """Extract all information from this Purchase Order. Return JSON:
{
    "po_number": "",
    "vendor_name": "",
    "client_name": "",
    "client_address": "",
    "contact_person": "",
    "issue_date": "",
    "delivery_date": "",
    "total_value": 0,
    "currency": "",
    "payment_terms": "",
    "items": [{"description": "", "quantity": 0, "unit_price": 0, "amount": 0}],
    "notes": "",
    "scope_of_work": ""
}"""}
                    ]
                else:
                    media_type = f"image/{'jpeg' if ext in ('jpg','jpeg') else ext}"
                    content = [
                        {"type": "image", "source": {"type": "base64", "media_type": media_type,
                         "data": base64.b64encode(file_data).decode()}},
                        {"type": "text", "text": """Extract all information from this Purchase Order. Return JSON:
{
    "po_number": "",
    "vendor_name": "",
    "client_name": "",
    "client_address": "",
    "contact_person": "",
    "issue_date": "",
    "delivery_date": "",
    "total_value": 0,
    "currency": "",
    "payment_terms": "",
    "items": [{"description": "", "quantity": 0, "unit_price": 0, "amount": 0}],
    "notes": "",
    "scope_of_work": ""
}"""}
                    ]

                resp = client.messages.create(
                    model="claude-sonnet-4-20250514",
                    max_tokens=2000,
                    messages=[{"role": "user", "content": content}]
                )
                text = resp.content[0].text
                # Extract JSON from response
                if '```json' in text:
                    text = text.split('```json')[1].split('```')[0]
                elif '```' in text:
                    text = text.split('```')[1].split('```')[0]
                extracted = json.loads(text.strip())
            except Exception as e:
                print(f"AI extraction error: {e}")
                flash('Could not auto-extract PO data. Please fill manually.', 'error')

        # Store file as base64
        if ext == 'pdf':
            media_type = 'application/pdf'
        else:
            media_type = f"image/{'jpeg' if ext in ('jpg','jpeg') else ext}"
        po_file_b64 = f"data:{media_type};base64,{base64.b64encode(file_data).decode()}"

        # Build scope from items
        scope = extracted.get('scope_of_work', '')
        if not scope and extracted.get('items'):
            scope = '\n'.join([f"- {it.get('description', '')} (Qty: {it.get('quantity', '')}, Amount: {it.get('amount', '')})"
                             for it in extracted['items'] if it.get('description')])

        return render_template('po_review.html', user=user, extracted=extracted,
                             po_file_data=po_file_b64, cs=curr_sym(user.get('currency', 'INR')))

    return render_template('upload_po.html', user=user)

@app.route('/save-po', methods=['POST'])
@login_required
def save_po():
    user = get_user()
    conn = get_db()
    cur = conn.cursor()

    # Handle client
    client_id = request.form.get('client_id')
    if not client_id and request.form.get('client_name'):
        cur.execute('''INSERT INTO clients (user_id, name, email, address, contact_person)
                      VALUES (%s,%s,%s,%s,%s) RETURNING id''',
                   (user['id'], request.form['client_name'],
                    request.form.get('client_email', ''),
                    request.form.get('client_address', ''),
                    request.form.get('contact_person', '')))
        client_id = cur.fetchone()[0]

    # Contract number
    cur.execute('SELECT COUNT(*) FROM contracts WHERE user_id=%s', (user['id'],))
    count = cur.fetchone()[0] + 1
    contract_number = f"PO-{count:04d}"

    start = request.form.get('start_date') or None
    end = request.form.get('end_date') or None
    total_value = float(request.form.get('total_value', 0) or 0)

    cur.execute('''INSERT INTO contracts (user_id, client_id, contract_number, title,
                  contract_type, source, status, start_date, end_date, total_value, currency,
                  payment_terms, scope_of_work, po_number, po_file_data, notes)
                  VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id''',
               (user['id'], client_id, contract_number,
                request.form.get('title', 'Purchase Order'),
                'purchase_order', 'scanned', 'active',
                start, end, total_value, user.get('currency', 'INR'),
                request.form.get('payment_terms', ''),
                request.form.get('scope_of_work', ''),
                request.form.get('po_number', ''),
                request.form.get('po_file_data', ''),
                request.form.get('notes', '')))
    contract_id = cur.fetchone()[0]
    conn.close()
    flash(f'Purchase Order {contract_number} saved!', 'success')
    return redirect(url_for('view_contract', contract_id=contract_id))

# --- View Contract ---
@app.route('/contract/<int:contract_id>')
@login_required
def view_contract(contract_id):
    user = get_user()
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('''SELECT c.*, cl.name as client_name, cl.email as client_email,
                  cl.address as client_address, cl.contact_person, cl.tax_id as client_tax_id
                  FROM contracts c LEFT JOIN clients cl ON c.client_id = cl.id
                  WHERE c.id=%s AND c.user_id=%s''', (contract_id, user['id']))
    contract = cur.fetchone()
    if not contract:
        flash('Contract not found', 'error')
        return redirect(url_for('dashboard'))

    cur.execute('SELECT * FROM contract_milestones WHERE contract_id=%s ORDER BY due_date', (contract_id,))
    milestones = cur.fetchall()
    conn.close()

    remaining = float(contract.get('total_value', 0) or 0) - float(contract.get('invoiced_amount', 0) or 0)
    cs = curr_sym(contract.get('currency', user.get('currency', 'INR')))
    return render_template('view_contract.html', user=user, contract=contract,
                         milestones=milestones, remaining=remaining, cs=cs)

# --- Update Status ---
@app.route('/contract/<int:contract_id>/status', methods=['POST'])
@login_required
def update_status(contract_id):
    user = get_user()
    new_status = request.form.get('status', 'draft')
    conn = get_db()
    cur = conn.cursor()
    cur.execute('UPDATE contracts SET status=%s, updated_at=NOW() WHERE id=%s AND user_id=%s',
               (new_status, contract_id, user['id']))
    conn.close()
    flash(f'Status updated to {new_status}', 'success')
    return redirect(url_for('view_contract', contract_id=contract_id))

# --- Delete Contract ---
@app.route('/contract/<int:contract_id>/delete', methods=['POST'])
@login_required
def delete_contract(contract_id):
    user = get_user()
    conn = get_db()
    cur = conn.cursor()
    cur.execute('DELETE FROM contract_milestones WHERE contract_id=%s', (contract_id,))
    cur.execute('DELETE FROM contracts WHERE id=%s AND user_id=%s', (contract_id, user['id']))
    conn.close()
    flash('Contract deleted', 'success')
    return redirect(url_for('dashboard'))

# --- Generate Contract PDF ---
@app.route('/contract/<int:contract_id>/pdf')
@login_required
def download_pdf(contract_id):
    user = get_user()
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('''SELECT c.*, cl.name as client_name, cl.email as client_email,
                  cl.address as client_address, cl.contact_person, cl.tax_id as client_tax_id
                  FROM contracts c LEFT JOIN clients cl ON c.client_id = cl.id
                  WHERE c.id=%s AND c.user_id=%s''', (contract_id, user['id']))
    contract = cur.fetchone()
    cur.execute('SELECT * FROM contract_milestones WHERE contract_id=%s ORDER BY due_date', (contract_id,))
    milestones = cur.fetchall()
    conn.close()
    if not contract:
        flash('Contract not found', 'error')
        return redirect(url_for('dashboard'))

    try:
        pdf_buffer = generate_contract_pdf(user, contract, milestones)
        fname = f"{contract['contract_number']}-{contract['title'][:30].replace(' ','-')}.pdf"
        return send_file(pdf_buffer, as_attachment=True, download_name=fname, mimetype='application/pdf')
    except Exception as e:
        import traceback
        traceback.print_exc()
        flash(f'PDF error: {str(e)}', 'error')
        return redirect(url_for('view_contract', contract_id=contract_id))

def generate_contract_pdf(user, contract, milestones):
    from fpdf import FPDF

    brand = user.get('brand_color', '#2563eb') or '#2563eb'
    br = int(brand[1:3], 16)
    bg = int(brand[3:5], 16)
    bb = int(brand[5:7], 16)

    company = user.get('company_name', '') or 'Company'
    cs = curr_sym(contract.get('currency', user.get('currency', 'INR')))
    ctype = contract.get('contract_type', 'service')
    type_labels = {'service': 'SERVICE AGREEMENT', 'retainer': 'RETAINER AGREEMENT',
                   'purchase_order': 'PURCHASE ORDER', 'nda': 'NON-DISCLOSURE AGREEMENT',
                   'sow': 'STATEMENT OF WORK', 'freelance': 'FREELANCER AGREEMENT'}
    type_label = type_labels.get(ctype, 'CONTRACT')

    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=20)

    # Header bar
    pdf.set_fill_color(br, bg, bb)
    pdf.rect(0, 0, 210, 8, 'F')

    # Company
    pdf.set_y(14)
    pdf.set_font('Helvetica', 'B', 18)
    pdf.set_text_color(br, bg, bb)
    pdf.cell(0, 8, company, ln=True)
    pdf.set_font('Helvetica', '', 8)
    pdf.set_text_color(100, 100, 100)
    if user.get('company_address'):
        for line in str(user['company_address']).split('\n'):
            pdf.cell(0, 4, line, ln=True)
    if user.get('company_email'):
        pdf.cell(0, 4, str(user['company_email']), ln=True)
    if user.get('tax_reg_number'):
        pdf.cell(0, 4, f"{user.get('tax_reg_label', 'GSTIN')}: {user['tax_reg_number']}", ln=True)

    # Title
    pdf.set_y(14)
    pdf.set_font('Helvetica', 'B', 14)
    pdf.set_text_color(br, bg, bb)
    pdf.cell(0, 8, type_label, align='R', ln=True)
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(60, 60, 60)
    pdf.cell(0, 5, f"Ref: {contract.get('contract_number', '')}", align='R', ln=True)
    if contract.get('po_number'):
        pdf.cell(0, 5, f"PO#: {contract['po_number']}", align='R', ln=True)

    # Divider
    pdf.set_y(pdf.get_y() + 6)
    pdf.set_draw_color(br, bg, bb)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.set_y(pdf.get_y() + 6)

    # Contract Title
    pdf.set_font('Helvetica', 'B', 14)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 8, str(contract.get('title', '')), ln=True)
    pdf.ln(4)

    # Client info
    pdf.set_font('Helvetica', 'B', 9)
    pdf.set_text_color(br, bg, bb)
    pdf.cell(0, 5, 'CLIENT:', ln=True)
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 5, str(contract.get('client_name', '')), ln=True)
    if contract.get('client_address'):
        for line in str(contract['client_address']).split('\n'):
            pdf.cell(0, 5, line, ln=True)
    if contract.get('contact_person'):
        pdf.cell(0, 5, f"Attn: {contract['contact_person']}", ln=True)
    pdf.ln(4)

    # Key terms grid
    pdf.set_font('Helvetica', 'B', 9)
    pdf.set_text_color(br, bg, bb)
    pdf.cell(0, 5, 'KEY TERMS:', ln=True)
    pdf.set_font('Helvetica', '', 9)
    pdf.set_text_color(60, 60, 60)

    def term_row(label, value):
        pdf.set_font('Helvetica', 'B', 9)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(45, 5, label)
        pdf.set_font('Helvetica', '', 9)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 5, str(value or '-'), ln=True)

    term_row('Contract Value:', f"{cs}{float(contract.get('total_value', 0) or 0):,.2f}")
    term_row('Start Date:', str(contract.get('start_date', '-')))
    term_row('End Date:', str(contract.get('end_date', '-')))
    term_row('Payment Terms:', str(contract.get('payment_terms', '-')))
    pdf.ln(4)

    # Scope of Work
    scope = contract.get('scope_of_work', '')
    if scope:
        pdf.set_font('Helvetica', 'B', 9)
        pdf.set_text_color(br, bg, bb)
        pdf.cell(0, 5, 'SCOPE OF WORK:', ln=True)
        pdf.set_font('Helvetica', '', 9)
        pdf.set_text_color(60, 60, 60)
        pdf.multi_cell(0, 4, str(scope))
        pdf.ln(4)

    # Deliverables
    deliverables = contract.get('deliverables', '')
    if deliverables:
        pdf.set_font('Helvetica', 'B', 9)
        pdf.set_text_color(br, bg, bb)
        pdf.cell(0, 5, 'DELIVERABLES:', ln=True)
        pdf.set_font('Helvetica', '', 9)
        pdf.set_text_color(60, 60, 60)
        pdf.multi_cell(0, 4, str(deliverables))
        pdf.ln(4)

    # Milestones
    if milestones:
        pdf.set_font('Helvetica', 'B', 9)
        pdf.set_text_color(br, bg, bb)
        pdf.cell(0, 5, 'MILESTONES / PAYMENT SCHEDULE:', ln=True)

        pdf.set_fill_color(br, bg, bb)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font('Helvetica', 'B', 8)
        pdf.cell(80, 6, '  Milestone', fill=True)
        pdf.cell(40, 6, 'Due Date', fill=True, align='C')
        pdf.cell(40, 6, 'Amount', fill=True, align='R')
        pdf.ln()

        for i, m in enumerate(milestones):
            if i % 2 == 0:
                pdf.set_fill_color(248, 250, 252)
            else:
                pdf.set_fill_color(255, 255, 255)
            pdf.set_font('Helvetica', '', 8)
            pdf.set_text_color(60, 60, 60)
            pdf.cell(80, 5, f"  {str(m.get('title', ''))[:45]}", fill=True)
            pdf.cell(40, 5, str(m.get('due_date', '-')), fill=True, align='C')
            pdf.set_font('Helvetica', 'B', 8)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(40, 5, f"{cs}{float(m.get('amount', 0) or 0):,.2f}", fill=True, align='R')
            pdf.ln()
        pdf.ln(4)

    # Terms & Conditions
    tc = contract.get('terms_conditions', '')
    if tc:
        pdf.set_font('Helvetica', 'B', 9)
        pdf.set_text_color(br, bg, bb)
        pdf.cell(0, 5, 'TERMS & CONDITIONS:', ln=True)
        pdf.set_font('Helvetica', '', 8)
        pdf.set_text_color(60, 60, 60)
        pdf.multi_cell(0, 4, str(tc))
        pdf.ln(4)

    # Signature lines
    pdf.set_y(pdf.get_y() + 10)
    pdf.set_draw_color(180, 180, 180)
    pdf.set_font('Helvetica', '', 9)
    pdf.set_text_color(100, 100, 100)

    # Left: Company
    y_sig = pdf.get_y()
    pdf.line(15, y_sig + 20, 90, y_sig + 20)
    pdf.set_xy(15, y_sig + 22)
    pdf.cell(75, 5, f"For {company}", align='L')
    pdf.set_xy(15, y_sig + 27)
    pdf.cell(75, 5, "Authorized Signatory", align='L')
    pdf.set_xy(15, y_sig + 32)
    pdf.cell(75, 5, "Date: _______________", align='L')

    # Right: Client
    pdf.line(120, y_sig + 20, 195, y_sig + 20)
    pdf.set_xy(120, y_sig + 22)
    pdf.cell(75, 5, f"For {contract.get('client_name', 'Client')}", align='L')
    pdf.set_xy(120, y_sig + 27)
    pdf.cell(75, 5, "Authorized Signatory", align='L')
    pdf.set_xy(120, y_sig + 32)
    pdf.cell(75, 5, "Date: _______________", align='L')

    # Footer
    if pdf.get_y() < 260:
        pdf.set_y(-12)
        pdf.set_fill_color(br, bg, bb)
        pdf.rect(0, 285, 210, 8, 'F')
        pdf.set_font('Helvetica', '', 7)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(0, 4, f"Generated by ContractSnap  |  {company}", align='C')

    buffer = BytesIO()
    pdf.output(buffer)
    buffer.seek(0)
    return buffer

# --- AI Generate Contract ---
@app.route('/ai-generate', methods=['GET', 'POST'])
@login_required
def ai_generate():
    user = get_user()
    if request.method == 'POST':
        prompt = request.form.get('prompt', '')
        contract_type = request.form.get('contract_type', 'service')
        api_key = os.environ.get('ANTHROPIC_API_KEY', '')
        if not api_key:
            flash('Anthropic API key not configured', 'error')
            return redirect(url_for('ai_generate'))

        try:
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)

            type_prompts = {
                'service': 'service agreement / consulting contract',
                'retainer': 'retainer agreement for ongoing services',
                'nda': 'non-disclosure agreement (NDA)',
                'sow': 'statement of work (SOW)',
                'freelance': 'freelancer / independent contractor agreement',
            }

            resp = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=3000,
                messages=[{"role": "user", "content": f"""Generate a professional {type_prompts.get(contract_type, 'contract')} based on this brief:

{prompt}

Company: {user.get('company_name', 'Company')}

Return JSON with these fields:
{{
    "title": "Contract title",
    "scope_of_work": "Detailed scope",
    "deliverables": "What will be delivered",
    "terms_conditions": "Standard terms and conditions",
    "payment_terms": "Payment schedule/terms",
    "suggested_value": 0,
    "suggested_duration_months": 3
}}"""}]
            )
            text = resp.content[0].text
            if '```json' in text:
                text = text.split('```json')[1].split('```')[0]
            elif '```' in text:
                text = text.split('```')[1].split('```')[0]
            generated = json.loads(text.strip())

            return render_template('ai_review.html', user=user, generated=generated,
                                 contract_type=contract_type, cs=curr_sym(user.get('currency', 'INR')))
        except Exception as e:
            print(f"AI generation error: {e}")
            flash(f'AI generation failed: {str(e)}', 'error')
            return redirect(url_for('ai_generate'))

    return render_template('ai_generate.html', user=user)

# --- Settings ---
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user = get_user()
    if request.method == 'POST':
        conn = get_db()
        cur = conn.cursor()

        logo_data = user.get('logo_data', '')
        brand_color = request.form.get('brand_color', '#2563eb')
        logo_file = request.files.get('logo')
        if logo_file and logo_file.filename:
            img_data = logo_file.read()
            ext = logo_file.filename.rsplit('.', 1)[-1].lower()
            media_type = f"image/{'jpeg' if ext in ('jpg','jpeg') else ext}"
            logo_data = f"data:{media_type};base64,{base64.b64encode(img_data).decode()}"
            extracted = extract_brand_color(img_data)
            if extracted:
                brand_color = extracted

        cur.execute('''UPDATE users SET company_name=%s, company_address=%s, company_email=%s,
                      company_phone=%s, logo_data=%s, brand_color=%s, currency=%s,
                      tax_reg_label=%s, tax_reg_number=%s, bank_details=%s
                      WHERE id=%s''',
                   (request.form.get('company_name', ''),
                    request.form.get('company_address', ''),
                    request.form.get('company_email', ''),
                    request.form.get('company_phone', ''),
                    logo_data, brand_color,
                    request.form.get('currency', 'INR'),
                    request.form.get('tax_reg_label', 'GSTIN'),
                    request.form.get('tax_reg_number', ''),
                    request.form.get('bank_details', ''),
                    user['id']))
        conn.close()
        flash('Settings saved!', 'success')
        return redirect(url_for('settings'))
    return render_template('settings.html', user=user)

# --- Admin ---
@app.route('/admin')
@login_required
def admin_dashboard():
    user = get_user()
    if not user.get('is_superadmin'):
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('''SELECT u.id, u.email, u.company_name, u.created_at,
                  COUNT(c.id) as contract_count,
                  COALESCE(SUM(c.total_value), 0) as total_value
                  FROM users u LEFT JOIN contracts c ON u.id = c.user_id
                  GROUP BY u.id ORDER BY u.created_at DESC''')
    companies = cur.fetchall()
    conn.close()
    return render_template('admin.html', user=user, companies=companies)

# --- API for FinanceSnap ---
@app.route('/api/contracts')
def api_contracts():
    api_key = request.headers.get('X-API-Key')
    if not api_key:
        return jsonify({'error': 'API key required'}), 401
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('SELECT * FROM users WHERE email=%s', (api_key,))
    user = cur.fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'Invalid'}), 401
    cur.execute('''SELECT c.*, cl.name as client_name FROM contracts c
                  LEFT JOIN clients cl ON c.client_id = cl.id
                  WHERE c.user_id=%s ORDER BY c.updated_at DESC''', (user['id'],))
    contracts = cur.fetchall()
    conn.close()
    for c in contracts:
        for k, v in c.items():
            if hasattr(v, 'isoformat'):
                c[k] = v.isoformat()
        c.pop('po_file_data', None)
    return jsonify({'contracts': contracts, 'count': len(contracts)})

# --- Helpers ---
def extract_brand_color(img_bytes):
    try:
        from PIL import Image
        from collections import Counter
        img = Image.open(BytesIO(img_bytes)).convert('RGB')
        img = img.resize((100, 100))
        pixels = list(img.getdata())
        colored = []
        for r, g, b in pixels:
            brightness = (r + g + b) / 3
            saturation = max(r, g, b) - min(r, g, b)
            if brightness > 30 and brightness < 230 and saturation > 30:
                colored.append((r // 16 * 16, g // 16 * 16, b // 16 * 16))
        if not colored:
            return None
        most_common = Counter(colored).most_common(1)[0][0]
        return f"#{most_common[0]:02x}{most_common[1]:02x}{most_common[2]:02x}"
    except Exception:
        return None

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
