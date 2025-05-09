import re
import MySQLdb.cursors
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# MySQL configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'c@lient098'
app.config['MYSQL_DB'] = 'blood_bank_db'

mysql = MySQL(app)

# ---------- ROUTES ----------

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s AND password = %s', (username, password))
        user = cursor.fetchone()
        if user:
            session.update({
                'loggedin': True,
                'id': user['id'],
                'username': user['username'],
                'role': user['role']
            })
            return redirect(url_for('dashboard'))
        else:
            msg = 'Incorrect username/password!'
    return render_template('login.html', msg=msg)

@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form['role']
        email = request.form.get('email')
        name = request.form.get('name')
        address = request.form.get('address')
        dob = request.form.get('dob')
        gender = request.form.get('gender')
        blood_group = request.form.get('blood_group')
        age = request.form.get('age')
        organization_name = request.form.get('organization_name')
        staff_id = request.form.get('staff_id')
        assigned_blood_bank = request.form.get('assigned_blood_bank')

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s OR email = %s', (username, email))
        account = cursor.fetchone()

        if account:
            msg = 'Account already exists!'
        elif password != confirm_password:
            msg = 'Passwords do not match!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not all([username, password, role]):
            msg = 'Please fill out all required fields!'
        else:
            cursor.execute('''INSERT INTO users (name, email, address, dob, gender, role, username, password)
                              VALUES (%s, %s, %s, %s, %s, %s, %s, %s)''', 
                              (name, email, address, dob, gender, role, username, password))
            mysql.connection.commit()

            user_id = cursor.lastrowid
            if role == 'Donor':
                cursor.execute('INSERT INTO donor_details (user_id, blood_group, age) VALUES (%s, %s, %s)',
                               (user_id, blood_group, age))
            elif role == 'Receiver':
                cursor.execute('INSERT INTO receiver_details (user_id, organization_name) VALUES (%s, %s)',
                               (user_id, organization_name))
            elif role == 'Staff':
               cursor.execute('INSERT INTO users (username, password, name, email, address, dob, gender, role) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)', 
               (username, password, name, email, address, dob, gender, role))

            mysql.connection.commit()
            msg = 'You have successfully registered!'
    return render_template('register.html', msg=msg)

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    user = get_user_by_username(session['username'])
    role = user['role']
    user_id = user['id']

    if role == 'Receiver':
        flash(f'Welcome to LifeLine Blood Bank, {user["name"]}!', 'success')
        if request.method == 'POST':
            form = request.form
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('''INSERT INTO blood_requests (user_id, blood_group, quantity, priority, required_by, address)
                              VALUES (%s, %s, %s, %s, %s, %s)''',
                           (user_id, form['blood_group'], form['quantity'], form['priority'], form['required_by'], form['address']))
            mysql.connection.commit()
            flash('Your blood request has been successfully submitted!', 'success')
        pending_requests = get_user_blood_requests(user_id)
        return render_template('receiver_dashboard.html', role=role, pending_requests=pending_requests)

    elif role == 'Donor':
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        if request.method == 'POST':
            form = request.form
            cursor.execute('SELECT * FROM donor_details WHERE user_id = %s', [user_id])
            if cursor.fetchone():
                cursor.execute('''UPDATE donor_details SET weight=%s, blood_group=%s, diseases=%s WHERE user_id=%s''',
                               (form['weight'], form['blood_group'], form['diseases'], user_id))
                flash('Your donor details have been updated successfully!')
            else:
                cursor.execute('''INSERT INTO donor_details (user_id, weight, blood_group, diseases) 
                                  VALUES (%s, %s, %s, %s)''',
                               (user_id, form['weight'], form['blood_group'], form['diseases']))
                flash('Thank you for your contribution! You are awesome.')
            mysql.connection.commit()
        cursor.execute('SELECT * FROM donor_details WHERE user_id = %s', [user_id])
        donor_info = cursor.fetchone()
        cursor.execute('SELECT * FROM campaigns ORDER BY date ASC LIMIT 1')
        campaign = cursor.fetchone()
        return render_template('dashboard.html', role=role, donor_info=donor_info, campaign=campaign)

    elif role == 'Staff':
        return redirect(url_for('staff_dashboard'))

    return render_template('dashboard.html', role=role)

@app.route('/cancel_request/<int:request_id>', methods=['GET', 'POST'])
def cancel_request(request_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM blood_requests WHERE id = %s', [request_id])
    request_data = cursor.fetchone()

    if request_data:
        if request_data['status'] == 'Pending':
            if request.method == 'POST':
                cursor.execute('DELETE FROM blood_requests WHERE id = %s', [request_id])
                mysql.connection.commit()
                flash('Your blood request has been canceled successfully!', 'success')
                return redirect(url_for('dashboard'))
            return render_template('confirm_cancel.html', request=request_data)
        flash('Cannot cancel a completed or fulfilled request!', 'warning')
    else:
        flash('Blood request not found!', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/update_request/<int:request_id>', methods=['GET', 'POST'])
def update_request(request_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM blood_requests WHERE id = %s', [request_id])
    db_request = cursor.fetchone()

    if db_request:
        if request.method == 'POST':
            form = request.form
            required_fields = ['blood_group', 'quantity', 'priority', 'required_by', 'address']
            if not all(form.get(f) for f in required_fields):
                flash('Please fill out all required fields!', 'danger')
                return render_template('update_request.html', request=db_request)

            cursor.execute('''UPDATE blood_requests SET blood_group=%s, quantity=%s, priority=%s, 
                              required_by=%s, address=%s WHERE id=%s''',
                           (form['blood_group'], form['quantity'], form['priority'], form['required_by'], form['address'], request_id))
            mysql.connection.commit()
            flash('Your blood request has been updated successfully!', 'success')
            return redirect(url_for('dashboard'))
        return render_template('update_request.html', request=db_request)

    flash('Blood request not found!', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/staff_dashboard')
def staff_dashboard():
    if not session.get('loggedin') or session['role'] != 'Staff':
        return redirect(url_for('login'))
    return render_template('staff_dashboard.html',
                           blood_inventory=blood_inventory(),
                           pending_requests=fetch_pending_blood_requests(),
                           campaigns=campaigns())

@app.route('/approve_request/<int:request_id>')
def approve_request(request_id):
    if session.get('role') != 'Staff':
        return redirect(url_for('login'))
    update_request_status(request_id, "Confirmed")
    return redirect(url_for('staff_dashboard'))

@app.route('/reject_request/<int:request_id>')
def reject_request(request_id):
    if session.get('role') != 'Staff':
        return redirect(url_for('login'))
    update_request_status(request_id, "Rejected")
    return redirect(url_for('staff_dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/view_requests')
def view_requests():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM blood_requests ORDER BY required_by ASC')
    return render_template('view_requests.html', requests=cursor.fetchall())

# ---------- HELPERS ----------

def get_user_by_username(username):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM users WHERE username = %s', [username])
    return cursor.fetchone()

def get_user_blood_requests(user_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM blood_requests WHERE user_id = %s ORDER BY required_by ASC', [user_id])
    return cursor.fetchall()

def fetch_pending_blood_requests():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM blood_requests WHERE status = "Pending"')
    return cursor.fetchall()

def update_request_status(request_id, status):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('UPDATE blood_requests SET status = %s WHERE id = %s', (status, request_id))
    mysql.connection.commit()

@app.route('/blood_inventory')
def blood_inventory():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM blood_inventory')
    inventory = cursor.fetchall()
    return render_template('blood_inventory.html', inventory=inventory)

@app.route('/campaigns')
def campaigns():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM campaigns')
    campaigns = cursor.fetchall()
    return render_template('campaigns.html', campaigns=campaigns)


# ---------- ENTRY POINT ----------

if __name__ == '__main__':
    app.run(debug=True)
