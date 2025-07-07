from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
import re
from werkzeug.security import check_password_hash, generate_password_hash
import MySQLdb

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

@app.route('/why-donate')
def why_donate():
    return render_template('why_donate.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        cursor = mysql.connection.cursor()
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()

        if user:
            print(f"User data: {user}")  # Debugging user data
            if check_password_hash(user[2], password):  # password at index 2
                session['loggedin'] = True
                session['user_id'] = user[0]  # Changed to 'user_id' for consistency
                session['username'] = user[1]
                session['role'] = user[6]  # Corrected role index to 6 (role is at index 6)

                print(f"Logged in as: {session['role']}")  # Debugging role in session

                if session['role'] == 'Donor':
                    return redirect(url_for('donor_dashboard'))
                elif session['role'] == 'Receiver':  # Ensure 'Receiver' role check matches the session value
                    return redirect(url_for('receiver_dashboard'))
                elif session['role'] == 'Staff':
                    return redirect(url_for('staff_dashboard'))
                else:
                    flash('Invalid user role.', 'danger')
                    return redirect(url_for('login'))
            else:
                msg = 'Incorrect username/password!'
        else:
            msg = 'No user found!'
    
    return render_template('login.html', msg=msg)



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        role = request.form.get('role')
        if role == 'Donor':
            return redirect(url_for('donor_register'))
        elif role == 'Receiver':
            return redirect(url_for('receiver_register'))
        elif role == 'Staff':
            return redirect(url_for('staff_register'))
        else:
            flash('Please select a valid role', 'danger')
    return render_template('register.html')


@app.route('/donor_register', methods=['GET', 'POST'])
def donor_register():
    msg = ""  # Initialize the message variable
    if request.method == 'POST':
        # Extract form data
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email']
        address = request.form['address']
        
        # Donor-specific fields
        name = request.form['name']
        dob = request.form['dob']
        gender = request.form['gender']

        cursor = mysql.connection.cursor()
        try:
            # Check if the username or email already exists
            cursor.execute('SELECT * FROM users WHERE username = %s OR email = %s', (username, email))
            account = cursor.fetchone()

            if account:
                msg = 'Account already exists with this username or email!'
                flash(msg, 'danger')
            elif password != confirm_password:
                msg = 'Passwords do not match!'
                flash(msg, 'danger')
            elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                msg = 'Invalid email address!'
                flash(msg, 'danger')
            elif not all([username, password, email, address, name, dob, gender]):
                msg = 'Please fill out all required fields!'
                flash(msg, 'warning')
            else:
                # Hash the password
                hashed_password = generate_password_hash(password)

                # Insert into users table
                cursor.execute(''' 
                    INSERT INTO users (username, password, email, address, role) 
                    VALUES (%s, %s, %s, %s, %s)
                ''', (username, hashed_password, email, address, 'Donor'))
                mysql.connection.commit()

                # Get the user_id of the newly created user
                user_id = cursor.lastrowid

                # Insert into donors table (excluding blood_group, medical_history, and last_donation)
                cursor.execute(''' 
                    INSERT INTO donors (user_id, name, dob, gender)
                    VALUES (%s, %s, %s, %s)
                ''', (user_id, name, dob, gender))
                mysql.connection.commit()

                msg = 'You have successfully registered as a donor!'
                flash(msg, 'success')
                return redirect(url_for('login'))

        except Exception as e:
            msg = f"An error occurred: {e}"
            flash(msg, 'danger')

            app.logger.error(f"Error occurred: {e}")
        finally:
            cursor.close()

    return render_template('donor_register.html', msg=msg)


@app.route('/receiver-register', methods=['GET', 'POST'])
def receiver_register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form.get('email')
        address = request.form.get('address')
        organization_name = request.form.get('organization_name')
        type_of_receiver = request.form.get('type_of_receiver')
        contact_number = request.form.get('contact_number')
        license_number = request.form.get('license_number')

        cursor = mysql.connection.cursor()
        cursor.execute('SELECT * FROM users WHERE username = %s OR email = %s', (username, email))
        account = cursor.fetchone()

        if account:
            flash('Account already exists!', 'danger')
        elif password != confirm_password:
            flash('Passwords do not match!', 'danger')
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Invalid email address!', 'danger')
        elif not all([username, password, email, address, organization_name, type_of_receiver, contact_number, license_number]):
            flash('Please fill out all required fields!', 'warning')
        else:
            # Insert into users table
            cursor.execute('''INSERT INTO users (username, password, email, address, role)
                              VALUES (%s, %s, %s, %s, %s)''',
                           (username, generate_password_hash(password), email, address, 'Receiver'))
            user_id = cursor.lastrowid

            # Insert into receiver table
            cursor.execute('''INSERT INTO receiver (user_id, organization_name, type_of_receiver, contact_number, license_number)
                              VALUES (%s, %s, %s, %s, %s)''',
                           (user_id, organization_name, type_of_receiver, contact_number, license_number))
            mysql.connection.commit()

            flash('You have successfully registered as a receiver!', 'success')
            return redirect(url_for('login'))

    return render_template('receiver_register.html')

from uuid import uuid4  # at the top of your file

@app.route('/staff-register', methods=['GET', 'POST'])
def staff_register():
    if request.method == 'POST':
        # Shared user fields
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form.get('email')

        # Staff-specific fields
        full_name = request.form.get('full_name')
        contact_number = request.form.get('contact_number')
        shift = request.form.get('shift')

        # Generate staff ID internally
        staff_id = "STF" + uuid4().hex[:6].upper()

        cursor = mysql.connection.cursor()
        cursor.execute('SELECT * FROM users WHERE username = %s OR email = %s', (username, email))
        account = cursor.fetchone()

        if account:
            flash('Account already exists!', 'danger')
        elif password != confirm_password:
            flash('Passwords do not match!', 'danger')
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Invalid email address!', 'danger')
        elif not all([username, password, email, full_name, contact_number, shift]):
            flash('Please fill out all required fields!', 'warning')
        else:
            # Insert into users table
            cursor.execute('''INSERT INTO users (username, password, email, address, role)
                              VALUES (%s, %s, %s, %s, %s)''',
                           (username, generate_password_hash(password), email, "", 'Staff'))
            user_id = cursor.lastrowid

            # Insert into staff table
            cursor.execute('''INSERT INTO staff (user_id, full_name, staff_id, contact_number, shift)
                              VALUES (%s, %s, %s, %s, %s)''',
                           (user_id, full_name, staff_id, contact_number, shift))
            mysql.connection.commit()

            flash('You have successfully registered as a staff member!', 'success')
            return redirect(url_for('login'))

    return render_template('staff_register.html')


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

    elif role == 'Staff':
        return redirect(url_for('staff_dashboard'))

    return render_template('dashboard.html', role=role)

@app.route('/donor_dashboard', methods=['GET', 'POST'])
def donor_dashboard():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    # Get user information based on the session username
    username = session['username']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
    user = cursor.fetchone()

    if user:
        role = user['role']
        user_id = user['id']

        if role == 'Donor':
            cursor.execute('SELECT * FROM donor_details WHERE user_id = %s', [user_id])
            donor_info = cursor.fetchone()
            cursor.execute('SELECT * FROM campaigns ORDER BY date ASC LIMIT 1')
            campaign = cursor.fetchone()

            if request.method == 'POST':
                form = request.form
                if donor_info:
                    cursor.execute('''UPDATE donor_details SET weight=%s, blood_group=%s, diseases=%s WHERE user_id=%s''',
                                   (form['weight'], form['blood_group'], form['diseases'], user_id))
                    flash('Your donor details have been updated successfully!')
                else:
                    cursor.execute('''INSERT INTO donor_details (user_id, weight, blood_group, diseases) 
                                      VALUES (%s, %s, %s, %s)''',
                                   (user_id, form['weight'], form['blood_group'], form['diseases']))
                    flash('Thank you for your contribution! You are awesome.')
                mysql.connection.commit()

            return render_template('donor_dashboard.html', role=role, donor_info=donor_info, campaign=campaign)
        else:
            flash('You are not a donor.')
            return redirect(url_for('dashboard'))
    else:
        flash('User not found. Please log in again.')
        return redirect(url_for('login'))


@app.route('/receiver_dashboard', methods=['GET', 'POST'])
def receiver_dashboard():
    if 'user_id' not in session or session.get('role', '').lower() != 'receiver':
        flash('You must be logged in as a Receiver to view this page.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']

    if request.method == 'POST':
        blood_group = request.form.get('blood_group')
        priority = request.form.get('priority')
        required_by = request.form.get('required_by')
        address = request.form.get('address')

        try:
            quantity = int(request.form.get('quantity'))
        except (ValueError, TypeError):
            flash("Invalid quantity value.", "danger")
            return redirect(url_for('receiver_dashboard'))

        cursor = mysql.connection.cursor()
        cursor.execute("""
            INSERT INTO blood_requests (user_id, blood_group, quantity, priority, required_by, address, status, staff_approval)
            VALUES (%s, %s, %s, %s, %s, %s, 'Pending', 'Pending')
        """, (user_id, blood_group, quantity, priority, required_by, address))
        mysql.connection.commit()
        cursor.close()

        flash("Blood request submitted successfully.", "success")
        return redirect(url_for('receiver_dashboard'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM blood_requests WHERE user_id = %s AND status = 'Pending'", (user_id,))
    pending_requests = cursor.fetchall()
    cursor.close()

    return render_template('receiver_dashboard.html', pending_requests=pending_requests)


@app.route('/cancel_request/<int:request_id>', methods=['GET', 'POST'])
def cancel_request(request_id):
    if 'user_id' not in session or session.get('role', '').lower() != 'receiver':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM blood_requests WHERE id = %s AND user_id = %s', (request_id, user_id))
    request_data = cursor.fetchone()

    if request_data:
        if request_data['status'] == 'Pending':
            if request.method == 'POST':
                cursor.execute('DELETE FROM blood_requests WHERE id = %s', (request_id,))
                mysql.connection.commit()
                flash('Your blood request has been canceled successfully!', 'success')
                cursor.close()
                return redirect(url_for('receiver_dashboard'))
            cursor.close()
            return render_template('cancel_request.html', request=request_data)
        else:
            flash('Cannot cancel a completed or fulfilled request!', 'warning')
    else:
        flash('Blood request not found or unauthorized access!', 'danger')

    cursor.close()
    return redirect(url_for('receiver_dashboard'))


@app.route('/update_request/<int:request_id>', methods=['GET', 'POST'])
def update_request(request_id):
    if 'user_id' not in session or session.get('role', '').lower() != 'receiver':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM blood_requests WHERE id = %s AND user_id = %s', (request_id, user_id))
    db_request = cursor.fetchone()

    if db_request:
        if request.method == 'POST':
            form = request.form
            blood_group = form.get('blood_group')
            priority = form.get('priority')
            required_by = form.get('required_by')
            address = form.get('address')

            try:
                quantity = int(form.get('quantity'))
            except (ValueError, TypeError):
                flash("Invalid quantity value.", "danger")
                cursor.close()
                return render_template('update_request.html', request=db_request)

            cursor.execute('''
                UPDATE blood_requests
                SET blood_group=%s, quantity=%s, priority=%s, required_by=%s, address=%s
                WHERE id=%s
            ''', (
                blood_group,
                quantity,
                priority,
                required_by,
                address,
                request_id
            ))
            mysql.connection.commit()
            cursor.close()
            flash('Your blood request has been updated successfully!', 'success')
            return redirect(url_for('receiver_dashboard'))

        cursor.close()
        return render_template('update_request.html', request=db_request)

    flash('Blood request not found or unauthorized access!', 'danger')
    cursor.close()
    return redirect(url_for('receiver_dashboard'))


@app.route('/staff_dashboard')
def staff_dashboard():
    if not session.get('loggedin') or session['role'] != 'Staff':
        return redirect(url_for('login'))
    
    # Fetch blood inventory, pending requests, and campaigns as needed
    inventory = fetch_blood_inventory()
    pending_requests = fetch_pending_blood_requests()
    campaigns = fetch_campaigns()

    return render_template('staff_dashboard.html', 
                           blood_inventory=inventory,
                           pending_requests=pending_requests,
                           campaigns=campaigns)

@app.route('/view_requests')
def view_requests():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    
    # Fetch all blood requests from the database
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM blood_requests ORDER BY required_by ASC')
    requests = cursor.fetchall()
    
    return render_template('view_requests.html', requests=requests)

@app.route('/approve_request/<int:request_id>')
def approve_request(request_id):
    if session.get('role') != 'Staff':
        return redirect(url_for('login'))
    
    # Update request status to 'Approved'
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('UPDATE blood_requests SET staff_approval = "Approved" WHERE id = %s', (request_id,))
    mysql.connection.commit()
    
    flash("Request Approved Successfully!", "success")
    return redirect(url_for('view_requests'))

@app.route('/reject_request/<int:request_id>')
def reject_request(request_id):
    if session.get('role') != 'Staff':
        return redirect(url_for('login'))
    
    # Update request status to 'Rejected'
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('UPDATE blood_requests SET staff_approval = "Rejected" WHERE id = %s', (request_id,))
    mysql.connection.commit()
    
    flash("Request Rejected Successfully!", "danger")
    return redirect(url_for('view_requests'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ---------- HELPERS ----------

def fetch_blood_inventory():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM blood_inventory')
    inventory = cursor.fetchall()
    return inventory

def fetch_pending_blood_requests():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM blood_requests WHERE status = "Pending"')
    return cursor.fetchall()

def fetch_campaigns():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM campaigns')
    campaigns = cursor.fetchall()
    return campaigns

def update_request_status(request_id, status):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('UPDATE blood_requests SET status = %s WHERE id = %s', (status, request_id))
    mysql.connection.commit()

from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, flash
from datetime import datetime, timedelta
import MySQLdb.cursors

@app.route('/blood_inventory', methods=['GET', 'POST'])
def blood_inventory():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    blood_group = request.form.get('blood_group', '')
    amount = request.form.get('amount', '')

    query = 'SELECT * FROM blood_inventory WHERE 1=1'
    params = []

    if blood_group:
        query += ' AND blood_group = %s'
        params.append(blood_group)

    if amount:
        query += ' AND available_units >= %s'
        params.append(amount)

    cursor.execute(query, params)
    inventory = cursor.fetchall()

    # For expiry row highlighting
    current_date = datetime.today().date()

    cursor.execute('SELECT DISTINCT blood_group FROM blood_inventory')
    blood_groups = cursor.fetchall()

    return render_template('blood_inventory.html',
                           inventory=inventory,
                           blood_groups=blood_groups,
                           current_date=current_date)


@app.route('/add_inventory', methods=['POST'])
def add_inventory():
    cursor = mysql.connection.cursor()

    blood_group = request.form['blood_group']
    available_units = int(request.form['amount'])
    collection_date = request.form['collection_date']
    product_type = request.form['product_type']

    # Determine shelf life and storage conditions based on product type
    if product_type == 'PRBC':
        shelf_life = 42
        storage_condition = 'Store at 2-6°C'
    elif product_type == 'Platelets':
        shelf_life = 5
        storage_condition = 'Store at room temperature'
    elif product_type == 'FFP':
        shelf_life = 365
        storage_condition = 'Store at -18°C or colder'    
    elif product_type not in ['PRBC', 'Platelets', 'FFP']:
        flash('Invalid product type selected.', 'danger')
    return redirect(url_for('blood_inventory'))

    # Calculate expiry date
    collection_date_obj = datetime.strptime(collection_date, "%Y-%m-%d")
    expiry_date = collection_date_obj + timedelta(days=shelf_life)

    query = """
        INSERT INTO blood_inventory (
            blood_group, available_units, last_updated, expiry_date,
            product_type, storage_conditions, shelf_life
        )
        VALUES (%s, %s, NOW(), %s, %s, %s, %s)
    """
    values = (
        blood_group,
        available_units,
        expiry_date.strftime("%Y-%m-%d"),
        product_type,
        storage_condition,
        shelf_life
    )

    cursor.execute(query, values)
    mysql.connection.commit()

    flash('Blood inventory added successfully!', 'success')
    return redirect(url_for('blood_inventory'))


@app.route('/edit_inventory/<int:id>', methods=['GET', 'POST'])
def edit_inventory(id):
    # Create cursor to interact with the database
    cur = mysql.connection.cursor()

    # Handle GET request (fetch current data)
    if request.method == 'GET':
        # Fetch inventory data for the given id
        cur.execute("SELECT * FROM blood_inventory WHERE id = %s", [id])
        item = cur.fetchone()

        # If no item found, return 404
        if not item:
            flash("Inventory item not found!", "danger")
            return redirect(url_for('blood_inventory'))

        # Render the edit page with the item data
        return render_template('edit_inventory.html', item=item)

    # Handle POST request (update data)
    if request.method == 'POST':
        # Get the new available_units value from the form
        available_units = request.form['amount']
        
        # Update the inventory item in the database
        try:
            # Update the record for the given id
            cur.execute("""
                UPDATE blood_inventory
                SET available_units = %s, last_updated = NOW()
                WHERE id = %s
            """, [available_units, id])

            # Commit the changes to the database
            mysql.connection.commit()

            # Show success message
            flash("Inventory updated successfully!", "success")
        except Exception as e:
            # If an error occurs, show error message
            flash(f"An error occurred while updating the inventory: {e}", "danger")
        finally:
            # Close the cursor
            cur.close()

        # Redirect to the blood inventory list page
        return redirect(url_for('blood_inventory'))


@app.route('/delete_inventory/<int:id>', methods=['POST'])
def delete_inventory(id):
    if session.get('role') != 'Staff':
        flash("Unauthorized access!", "danger")
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor()
    try:
        # Execute deletion
        cursor.execute("DELETE FROM blood_inventory WHERE id = %s", (id,))
        mysql.connection.commit()
        flash("Inventory item deleted successfully!", "success")
    except Exception as e:
        flash(f"Error deleting inventory item: {str(e)}", "danger")
    finally:
        cursor.close()

    return redirect(url_for('blood_inventory'))



@app.route('/view_campaigns')
def view_campaigns():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM campaigns ORDER BY date ASC")
    campaigns = cursor.fetchall()
    cursor.close()
    return render_template('view_campaigns.html', campaigns=campaigns)


# ---------- ENTRY POINT ----------
if __name__ == '__main__':
    app.run(debug=True)
