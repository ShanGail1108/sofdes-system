from flask import Flask, render_template, request, jsonify, redirect, url_for, session, json
from datetime import datetime, timedelta
from flask_cors import CORS
import mysql.connector
import random
import yagmail
from flask_mail import Mail, Message
import uuid
import os
import hashlib


app = Flask(__name__)
app.secret_key = 'your_secret_key'
CORS(app)

# -------------------- MySQL CONNECTION --------------------
def connect_mysql():
    return mysql.connector.connect(
        host='dhvsuvisyon-dhvsuvisyon.d.aivencloud.com',
        port=21948,
        user='avnadmin',
        password='AVNS_NW3f3UgJbllwOtgGgkT',
        database='defaultdb',
        ssl_disabled=False
    )

# -------------------- OTP + EMAIL --------------------
def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(receiver_email, otp_code, username):
    try:
        verify_link = f"http://127.0.0.1:5000/verify_otp?email={receiver_email}&otp={otp_code}"
        html_content = render_template("email_otp_template.html", otp=str(otp_code), verify_link=verify_link, username=username)

        msg = Message(subject="Your OTP Code",
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[receiver_email],
                      html=html_content)

        mail.send(msg)
        return True
    except Exception as e:
        print("Email error:", e)
        return False

    
# -------------------- ROUTES --------------------
@app.route('/')
def index():
    return redirect(url_for('roleselection'))


@app.route('/visitor-form')
def visitor_form():
    return render_template('visitor_form.html')

@app.route('/login')
def login():
    
    role = session.get('user', {}).get('role')
    
    if role == 'admin':
        return render_template('adminlogin.html')
    elif role == 'guard':
        return render_template('guardlogin.html')
    elif role == 'receiver':
        return render_template('receiverlogin.html')
    else:
        return redirect(url_for('roleselection'))

@app.route('/handle-request', methods=['POST'])
def handle_request():
    action = request.form.get('action')
    username = request.form.get('user')

    conn = connect_mysql()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM account_requests WHERE username = %s AND status = 'pending'", (username,))
    req = cursor.fetchone()

    if not req:
        conn.close()
        return redirect(url_for('dashboard', role='admin'))

    if action == 'approve':
        if req['request_type'] == 'new_account':
            cursor.execute("SELECT * FROM users WHERE username = %s", (req['username'],))
            if cursor.fetchone():
                conn.close()
                return redirect(url_for('dashboard', role='admin'))

            # Insert plaintext password here
            cursor.execute("""
                INSERT INTO users (username, email, password, role)
                VALUES (%s, %s, %s, %s)
            """, (req['username'], req['email'], req['password'], req['role']))

        elif req['request_type'] == 'change_password':
            # Update password directly with plaintext
            cursor.execute("UPDATE users SET password = %s WHERE username = %s", (req['new_password'], req['username']))

        cursor.execute("DELETE FROM account_requests WHERE id = %s", (req['id'],))

    elif action == 'decline':
        cursor.execute("DELETE FROM account_requests WHERE id = %s", (req['id'],))

    conn.commit()
    conn.close()
    return redirect(url_for('dashboard', role='admin'))

@app.route('/roleselection')
def roleselection():
    return render_template('roleselection.html')

@app.route('/settings/account')
def account_settings():
    if 'user' not in session or session['user']['role'] != 'guard':
        return redirect(url_for('login'))
    return render_template('guardrefer.html') 

@app.route('/settings/receiver')
def receiver_account_settings():
    if 'user' not in session or session['user']['role'] != 'receiver':
        return redirect(url_for('login'))
    return render_template('receiverrefer.html')

@app.route('/guard/forgot-password')
def guard_forgot_password():
    return render_template('guardforgetpass.html')

@app.route('/guard/create-account', methods=['GET', 'POST'], endpoint='guard_create_account')
def guard_create_account():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            return render_template('guardcreatenew.html', error="Passwords do not match.")

        try:
            conn = connect_mysql()
            cursor = conn.cursor()
            # Store password as plaintext (not hashed)
            cursor.execute("""
                INSERT INTO account_requests 
                (username, email, password, request_type, role, status, date)
                VALUES (%s, %s, %s, %s, %s, %s, CURDATE())
            """, (username, email, password, 'new_account', 'guard', 'pending'))
            conn.commit()
            conn.close()
            return render_template('guardcreatenew.html', success="Request submitted for approval.")
        except Exception as e:
            print("Guard account request error:", e)
            return render_template('guardcreatenew.html', error="An error occurred.")
    
    return render_template('guardcreatenew.html')

@app.route('/receiver/forgot-password')
def receiver_forgot_password():
    return render_template('receiverforgetpass.html')

@app.route('/receiver/create-account', methods=['GET', 'POST'])
def receiver_create_account():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            return render_template('receivercreatenew.html', error="Passwords do not match.")

        try:
            conn = connect_mysql()
            cursor = conn.cursor()
            # Store password as plaintext (not hashed)
            cursor.execute("""
                INSERT INTO account_requests 
                (username, email, password, request_type, role, status, date)
                VALUES (%s, %s, %s, %s, %s, %s, CURDATE())
            """, (username, email, password, 'new_account', 'receiver', 'pending'))
            conn.commit()
            conn.close()
            return render_template('receivercreatenew.html', success="Request submitted for approval.")
        except Exception as e:
            print("Receiver account request error:", e)
            return render_template('receivercreatenew.html', error="An error occurred.")
    
    return render_template('receivercreatenew.html')


@app.route('/adminlogin')
def admin_login():
    return render_template('adminlogin.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'GET':
        # Get otp and email from query parameters
        otp_from_url = request.args.get('otp', '')
        email_from_url = request.args.get('email', '')

        # Pass these to the template so inputs can be autofilled
        return render_template('verifyotp.html', prefill_otp=otp_from_url, email=email_from_url)

    elif request.method == 'POST':
        # Collect OTP input from form fields
        otp_input = ''.join([
            request.form.get('otp1', ''),
            request.form.get('otp2', ''),
            request.form.get('otp3', ''),
            request.form.get('otp4', ''),
            request.form.get('otp5', ''),
            request.form.get('otp6', ''),
        ])

        if otp_input == session.get('otp'):
            # OTP verified, redirect to dashboard or wherever you want
            return redirect(url_for('dashboard', role=session['user']['role']))
        else:
            # OTP incorrect, reload page with error
            return render_template('verifyotp.html', error="Incorrect OTP.", prefill_otp=otp_input)



@app.route('/resend_otp', methods=['POST'])
def resend_otp():
    if 'user' not in session or 'email' not in session['user']:
        return jsonify({"success": False, "message": "You must be logged in to resend OTP."}), 403

    email = session['user']['email']
    username = session['user']['username']
    new_otp = generate_otp()
    session['otp'] = new_otp

    if send_otp_email(email, new_otp, username):
        return jsonify({"success": True, "message": "A new OTP has been sent to your email."})
    else:
        return jsonify({"success": False, "message": "Failed to send new OTP."}), 500


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')

        # Check if the email exists in the database
        conn = connect_mysql()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        conn.close()

        if not user:
            return render_template('forgot_password.html', error="Email not found.")

        # Generate and send OTP
        otp = generate_otp()
        session['otp'] = otp  # Store OTP in session
        session['reset_email'] = email  # Store email to associate with OTP
        session['reset_user'] = user['username']  # Store username for email personalization

        if send_otp_email(email, otp, user['username']):
            return redirect(url_for('verify_reset_otp'))
        else:
            return render_template('forgot_password.html', error="Failed to send OTP.")
    
    return render_template('forgot_password.html')


@app.route('/verify_reset_otp', methods=['GET', 'POST'])
def verify_reset_otp():
    if request.method == 'POST':
        otp_input = request.form.get('otp')

        if otp_input == session.get('otp'):
            # ✅ ADDED: Set 'user' in session if not present
            session['user'] = session.get('user', {})

            # ✅ ADDED: Save reset-related session flags for change_password access
            session['user']['email'] = session['reset_email']
            session['user']['reset'] = True  # <- THIS enables access to change_password
            return redirect(url_for('change_password'))
        else:
            return render_template('verify_reset_otp.html', error="Incorrect OTP.")
    
    return render_template('verify_reset_otp.html')


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user' not in session or not session['user'].get('reset'):
        return redirect(url_for('login'))  # Not allowed if not from forgot flow

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            return render_template('change_password.html', error="Passwords do not match.")

        # Update the user's password in the database
        conn = connect_mysql()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password = %s WHERE email = %s", (new_password, session['user']['email']))
        conn.commit()
        conn.close()

        # Clear session reset flag
        session.pop('otp', None)
        session['user'].pop('reset', None)

        return redirect(url_for('login'))  # Redirect to login after successful password change

    return render_template('change_password.html')


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    user = session.get('user')
    if user:
        try:
            conn = connect_mysql()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO login_history (username, email, role, action)
                VALUES (%s, %s, %s, 'logout')
            """, (user['username'], user['email'], user['role']))
            conn.commit()
            conn.close()
        except Exception as e:
            print("Logout log error:", e)

    session.clear()
    return redirect(url_for('roleselection'))


@app.route('/request-account', methods=['POST'])
def request_account():
    data = request.form
    conn = connect_mysql()
    cursor = conn.cursor()
    sql = """
        INSERT INTO account_requests (username, email, password, new_password, request_type, role)
        VALUES (%s, %s, %s, %s, %s, %s)
    """
    values = (
        data.get('username'),
        data.get('email'),
        data.get('password'),
        data.get('new_password') if data.get('request_type') == 'change_password' else None,
        data.get('request_type'),
        data.get('role')
    )
    cursor.execute(sql, values)
    conn.commit()
    conn.close()
    return "Request submitted"


@app.route('/dashboard/<role>') 
def dashboard(role):
    if 'user' not in session or session['user']['role'] != role:
        return redirect(url_for('login'))

    conn = connect_mysql()

    visitor_data = []
    user_data = []
    pending_requests = []
    unread_count = 0
    login_logs = []

    if role == 'receiver':
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM visitor_log")
        visitor_data = cursor.fetchall()

        for row in visitor_data:
            row['full_name'] = f"{row.get('first_name', '')} {row.get('last_name', '')}"
            row['place_to_visit'] = row.get('destination', '')
            row['stub_number'] = row.get('badge_number', '')
            row['time_'] = row.get('time_received', '')

        conn.close()
        return render_template('receiver_dashboard.html', allvisitors=visitor_data, user=session.get('user', {}))

    elif role == 'guard':
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT badge_number, first_name, last_name, destination AS place_to_visit,
                   time_in, time_out, status, date, latitude, longitude
            FROM visitor_log
            ORDER BY time_in DESC
        """)
        visitor_data = cursor.fetchall()
        conn.close()
        return render_template('guard_dashboard.html', visitors=visitor_data, user=session.get('user', {}))

    elif role == 'admin':
        tuple_cursor = conn.cursor()
        dict_cursor = conn.cursor(dictionary=True)

        tuple_cursor.execute("SELECT * FROM visitor_log")
        visitor_data = tuple_cursor.fetchall()

        tuple_cursor.execute("SELECT * FROM users")
        user_data = tuple_cursor.fetchall()

        dict_cursor.execute("SELECT * FROM account_requests WHERE status = 'pending'")
        pending_requests = dict_cursor.fetchall()
        unread_count = len(pending_requests)

        # ✅ Fetch login history
        dict_cursor.execute("SELECT * FROM login_history ORDER BY timestamp DESC")
        login_logs = dict_cursor.fetchall()

        conn.close()

        return render_template(
            'admin_dashboard.html',
            visitors=visitor_data,
            users=user_data,
            requests=pending_requests,
            unread_count=unread_count,
            login_logs=login_logs  # pass to template
        )

    else:
        conn.close()
        return redirect(url_for('login'))
   
@app.template_filter('md5')
def md5_filter(s):
    return hashlib.md5(s.strip().lower().encode('utf-8')).hexdigest()

@app.route('/test_guard_data')
def test_guard_data():
    conn = connect_mysql()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM visitor_log")
    data = cursor.fetchall()
    conn.close()

    # Serialize all values to strings for safety
    safe_data = []
    for row in data:
        safe_row = {key: str(value) if value is not None else None for key, value in row.items()}
        safe_data.append(safe_row)

    return jsonify(safe_data)

@app.route('/api/create-user', methods=['POST'])
def create_user():
    data = request.json  # For JSON-based form submission
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')

    if not email or not username or not password or not role:
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400

    try:
        conn = connect_mysql()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, email, password, role) VALUES (%s, %s, %s, %s)",
            (username, email, password, role)
        )
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        print("Error creating user:", e)
        return jsonify({'success': False, 'message': 'Database error'}), 500

@app.route('/api/roleselection', methods=['POST'])
def api_roleselection():
    data = request.json
    role = data.get('role')

    if role not in ['admin', 'guard', 'receiver']:
        return jsonify({"success": False, "message": "Invalid role"}), 400

    # Ensure 'user' exists in session
    session['user'] = session.get('user', {})
    session['user']['role'] = role

    return jsonify({"success": True})

# -------------------- API ENDPOINTS --------------------
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')

    conn = connect_mysql()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=%s AND password=%s", (username, password))
    user = cursor.fetchone()

    if user:
        if user[4] != role:
            conn.close()
            return jsonify({"success": False, "message": "Wrong role selected."}), 403

        otp = generate_otp()
        session['otp'] = otp
        session['user'] = {'username': username, 'email': user[2], 'role': role}

        # ✅ Log login action
        try:
            cursor.execute("""
                INSERT INTO login_history (username, email, role, action)
                VALUES (%s, %s, %s, 'login')
            """, (username, user[2], role))
            conn.commit()
        except Exception as e:
            print("Login log error:", e)

        conn.close()

        if send_otp_email(user[2], otp, username):
            return jsonify({"success": True, "redirect": url_for('verify_otp')})
        else:
            return jsonify({"success": False, "message": "Failed to send OTP."}), 500

    conn.close()
    return jsonify({"success": False, "message": "Invalid credentials."}), 401

@app.route('/api/verify-otp', methods=['POST'])
def api_verify_otp():
    data = request.json
    user_otp = data.get('otp')

    if user_otp == session.get('otp'):
        # OTP correct, clear it from session
        session.pop('otp', None)
        return jsonify({"success": True, "redirect": url_for('dashboard', role=session['user']['role'])})
    else:
        return jsonify({"success": False, "message": "Incorrect OTP."}), 403


@app.route('/api/visitors')
def get_visitors():
    conn = connect_mysql()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM visitor_log")
    rows = cursor.fetchall()

    visitors = []
    for row in rows:
        # Convert time_in to string if it's datetime or timedelta
        time_in = row["time_in"]
        if isinstance(time_in, (datetime, timedelta)):
            time_in = str(time_in)
        time_out = row["time_out"]
        if isinstance(time_out, (datetime, timedelta)):
            time_out = str(time_out)

        
        visitors.append({
            "badgeNumber": row["badge_number"],
            "firstName": row["first_name"],
            "lastName": row["last_name"],
            "purpose": row["destination"],
            "timeIn": time_in,
            "timeOut": time_out,
            "status": row["status"],
            "date": str(row["date"]),  # ⬅️ Make sure this is a string too
            "latitude": str(row["latitude"]),
            "longitude": str(row["longitude"]),
            "time_received": str(row["time_received"]) if row["time_received"] else None
        })
        
    conn.close()
    return jsonify(visitors)


def serialize_visitor(visitor):
    for key, value in visitor.items():
        if isinstance(value, timedelta):
            # Convert timedelta to HH:MM:SS string
            total_seconds = int(value.total_seconds())
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            seconds = total_seconds % 60
            visitor[key] = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    return visitor


@app.route('/api/updateVisitor', methods=['POST'])
def update_visitor():
    data = request.get_json()
    badge_number = data.get('badgeNumber')
    time_out = data.get('timeOut')
    status = data.get('status')

    if not badge_number or not time_out or not status:
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        conn = connect_mysql()
        cursor = conn.cursor(dictionary=True)

        update_query = """
            UPDATE visitor_log
            SET time_out = %s, status = %s
            WHERE badge_number = %s
        """
        cursor.execute(update_query, (time_out, status, badge_number))
        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({'error': 'Visitor not found'}), 404

        select_query = "SELECT * FROM visitor_log WHERE badge_number = %s"
        cursor.execute(select_query, (badge_number,))
        updated_visitor = cursor.fetchone()

        # Serialize timedelta fields
        updated_visitor = serialize_visitor(updated_visitor)

        return jsonify({
            'message': 'Visitor updated successfully',
            'visitor': updated_visitor
        })

    except Exception as e:
        print("MySQL error:", e)
        return jsonify({'error': 'Internal server error'}), 500

    finally:
        cursor.close()
        conn.close()

@app.route('/api/receiveVisitor', methods=['POST'])
def receive_visitor():
    data = request.get_json()
    badge_number = data.get('badgeNumber')
    time_received = data.get('time_received')

    if not badge_number or not time_received:
        return jsonify({'error': 'Missing badge number or time_received'}), 400

    try:
        conn = connect_mysql()
        cursor = conn.cursor(dictionary=True)

        update_query = """
            UPDATE visitor_log
            SET time_received = %s
            WHERE badge_number = %s
        """
        cursor.execute(update_query, (time_received, badge_number))
        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({'error': 'Visitor not found'}), 404

        select_query = "SELECT * FROM visitor_log WHERE badge_number = %s"
        cursor.execute(select_query, (badge_number,))
        updated_visitor = cursor.fetchone()

        updated_visitor = serialize_visitor(updated_visitor)

        return jsonify({
            'message': 'Visitor received successfully',
            'visitor': updated_visitor
        })

    except Exception as e:
        print("MySQL error:", e)
        return jsonify({'error': 'Internal server error'}), 500

    finally:
        cursor.close()
        conn.close()



@app.route('/api/visitors/receive', methods=['POST'])
def mark_as_received():
    stub_number = request.form.get('stub_number')
    now = datetime.now().strftime('%H:%M:%S')
    conn = connect_mysql()
    cursor = conn.cursor()
    cursor.execute("UPDATE visitor_log SET time_received = %s WHERE stub_number = %s", (now, stub_number))
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard', role='receiver'))


# In-memory store: badge_number -> visitor data
visitors = {}

def generate_badge_number():
    return str(uuid.uuid4())[:8]

@app.route('/api/visitor-checkin', methods=['POST'])
def visitor_checkin():
    data = request.form

    required_fields = ['first_name', 'last_name', 'phone', 'purpose', 'contact', 'id_type', 'id_number', 'latitude', 'longitude', 'status','date']
    for field in required_fields:
        if field not in data or not data.get(field).strip():
            return jsonify(success=False, error=f"Missing required field: {field}"), 400

    badge_number = generate_badge_number()
    now = datetime.now()

    visitor_data = {
        'first_name': data.get('first_name'),
        'last_name': data.get('last_name'),
        'phone': data.get('phone'),
        'email': data.get('email', ''),
        'purpose': data.get('purpose'),
        'contact': data.get('contact'),
        'id_type': data.get('id_type'),
        'id_number': data.get('id_number'),
        'notes': data.get('notes', ''),
        'status': 'checked-in',
        'date': data.get('date'),
        'latitude': float(data.get('latitude')),
        'longitude': float(data.get('longitude')),
        'checkin_time': now.isoformat(),
        'location_updates': [],
    }

    try:
        # Save to MySQL
        conn = connect_mysql()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO visitor_log (
                first_name, last_name, phone_number, email, destination,
                contact_person, id_type, id_number, notes,
                latitude, longitude, badge_number, time_in,status,date
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            visitor_data['first_name'],
            visitor_data['last_name'],
            visitor_data['phone'],
            visitor_data['email'],
            visitor_data['purpose'],
            visitor_data['contact'],
            visitor_data['id_type'],
            visitor_data['id_number'],
            visitor_data['notes'],
            visitor_data['latitude'],
            visitor_data['longitude'],
            badge_number,
            now,
            visitor_data['status'],
            visitor_data['date']
        ))

        conn.commit()
        conn.close()

        # Also save in memory for immediate badge use
        visitors[badge_number] = visitor_data

        return jsonify(success=True, badge_number=badge_number)

    except Exception as e:
        print("Database error:", e)
        return jsonify(success=False, error="Database insert failed"), 500


@app.route('/api/update-location', methods=['POST'])
def update_location():
    try:
        data = request.get_json()
        badge_number = data.get('badge_number')
        lat = data.get('latitude')
        lng = data.get('longitude')

        if not badge_number or lat is None or lng is None:
            return jsonify(success=False, error="Missing badge_number or coordinates"), 400

        conn = connect_mysql()
        cursor = conn.cursor()

        # Update visitor's latest location
        cursor.execute("""
            UPDATE visitor_log
            SET latitude = %s,
                longitude = %s,
                last_updated = NOW()
            WHERE badge_number = %s
        """, (lat, lng, badge_number))

        conn.commit()
        conn.close()

        return jsonify(success=True, message="Location updated successfully")

    except Exception as e:
        print("Update location error:", e)
        return jsonify(success=False, error=str(e)), 500

# Configuration for Gmail SMTP
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'dhvsuvisyon@gmail.com'         # Replace with your email
app.config['MAIL_PASSWORD'] = 'unokzjxzvjzhnllm'            # Use app password (not your Gmail password)
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)
@app.route('/send-email', methods=['POST'])
def send_email():
    email = request.form.get('email')
    name = request.form.get('name')
    purpose = request.form.get('purpose')
    contact = request.form.get('contact')
    badge_number = request.form.get('badgeNumber')
    date = request.form.get('date')
    time_in = request.form.get('timeIn')

    if not email:
        return jsonify(success=False, error="Email is required"), 400

    try:
        import os
        badge_path = os.path.join(os.path.dirname(__file__), 'templates', 'visitorbadge.html')
        with open(badge_path, 'r', encoding='utf-8') as file:
            template = file.read()

        # Replace placeholders
        html_content = (template
            .replace('[Name]', name or 'N/A')
            .replace('[Purpose]', purpose or 'N/A')
            .replace('[Contact]', contact or 'N/A')
            .replace('[BadgeNumber]', badge_number or 'N/A')
            .replace('[Date]', date or 'N/A')
            .replace('[TimeIn]', time_in or 'N/A'))

        msg = Message(subject="Your DHVSU VISYON Visitor Badge",
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[email])
        msg.html = html_content

        mail.send(msg)
        return jsonify(success=True, message="Email sent")

    except Exception as e:
        return jsonify(success=False, error=f"Failed to send email: {str(e)}"), 500


@app.route('/get-email-by-badge', methods=['POST'])
def get_email_by_badge():
    data = request.get_json()
    badge_number = data.get('badgeNumber')

    if not badge_number:
        return jsonify(error="Badge number is required"), 400

    try:
        conn = connect_mysql()
        cursor = conn.cursor()
        query = "SELECT email FROM visitor_log WHERE badge_number = %s"
        cursor.execute(query, (badge_number,))
        result = cursor.fetchone()
        cursor.close()

        if result:
            return jsonify(email=result[0])
        else:
            return jsonify(email=None), 404

    except Exception as e:
        return jsonify(error=str(e)), 500
    
if __name__ == '__main__':
    app.run(debug=True)
