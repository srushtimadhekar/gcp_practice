import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from uuid import uuid4
from datetime import datetime, timedelta

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = 'your_secret_key'

# ----------------- IN-MEMORY (DUMMY) STORAGE -----------------
# users: username -> user dict
# user dict fields: id, username, password (hashed), role, name, email, address
users = {
    'donor_demo': {'id': 1, 'username': 'donor_demo', 'password': generate_password_hash('1234'), 'role': 'Donor', 'name': 'Demo Donor', 'email': 'donor@example.com', 'address': 'Demo Address'},
    'receiver_demo': {'id': 2, 'username': 'receiver_demo', 'password': generate_password_hash('1234'), 'role': 'Receiver', 'name': 'Demo Receiver', 'email': 'receiver@example.com', 'address': 'Demo Address'},
    'staff_demo': {'id': 3, 'username': 'staff_demo', 'password': generate_password_hash('1234'), 'role': 'Staff', 'name': 'Demo Staff', 'email': 'staff@example.com', 'address': ''}
}
_next_user_id = max(u['id'] for u in users.values()) + 1

# donors details keyed by user_id
donor_details = {
    1: {'weight': 60, 'blood_group': 'A+', 'diseases': 'None', 'name': 'Demo Donor'}
}

# blood requests list (dicts)
# fields: id, user_id, blood_group, quantity, priority, required_by, address, status, staff_approval
blood_requests = [
    {'id': 1, 'user_id': 2, 'blood_group': 'A+', 'quantity': 2, 'priority': 'High', 'required_by': '2025-09-10', 'address': 'Demo Address', 'status': 'Pending', 'staff_approval': 'Pending'}
]
_next_request_id = max((r['id'] for r in blood_requests), default=0) + 1

# blood inventory list
# fields: id, blood_group, available_units, last_updated, expiry_date, product_type, storage_conditions, shelf_life
blood_inventory = [
    {'id': 1, 'blood_group': 'A+', 'available_units': 5, 'last_updated': '2025-09-01', 'expiry_date': '2025-10-01', 'product_type': 'PRBC', 'storage_conditions': 'Store at 2-6°C', 'shelf_life': 42}
]
_next_inventory_id = max((i['id'] for i in blood_inventory), default=0) + 1

# campaigns list
campaigns = [
    {'id': 1, 'title': 'Demo Campaign', 'date': '2025-09-07'}
]

# ----------------- HELPERS -----------------
def get_user_by_username(username):
    return users.get(username)

def get_user_by_id(uid):
    for u in users.values():
        if u['id'] == uid:
            return u
    return None

def get_user_blood_requests(user_id):
    return [r for r in blood_requests if r['user_id'] == user_id]

def fetch_blood_inventory():
    return blood_inventory

def fetch_pending_blood_requests():
    return [r for r in blood_requests if r['status'] == 'Pending']

def fetch_campaigns():
    return campaigns

def update_request_status(request_id, status):
    for r in blood_requests:
        if r['id'] == request_id:
            r['status'] = status
            return True
    return False

def find_request_by_id(rid):
    for r in blood_requests:
        if r['id'] == rid:
            return r
    return None

def find_inventory_item_by_id(iid):
    for i in blood_inventory:
        if i['id'] == iid:
            return i
    return None

# ----------------- ROUTES -----------------
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
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = get_user_by_username(username)
        if user and check_password_hash(user['password'], password):
            session['loggedin'] = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']

            if user['role'] == 'Donor':
                return redirect(url_for('donor_dashboard'))
            elif user['role'] == 'Receiver':
                return redirect(url_for('receiver_dashboard'))
            elif user['role'] == 'Staff':
                return redirect(url_for('staff_dashboard'))
        else:
            msg = 'Invalid username or password!'
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
    global _next_user_id
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        email = request.form.get('email', '').strip()
        address = request.form.get('address', '').strip()
        name = request.form.get('name', '').strip()
        dob = request.form.get('dob', '').strip()
        gender = request.form.get('gender', '').strip()

        if username in users:
            flash('Account already exists with this username!', 'danger')
            return redirect(url_for('donor_register'))
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('donor_register'))
        if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Invalid email address!', 'danger')
            return redirect(url_for('donor_register'))
        # create user
        user = {
            'id': _next_user_id,
            'username': username,
            'password': generate_password_hash(password),
            'role': 'Donor',
            'name': name or username,
            'email': email,
            'address': address
        }
        users[username] = user
        donor_details[_next_user_id] = {'weight': '', 'blood_group': '', 'diseases': '', 'name': name}
        _next_user_id += 1

        flash('You have successfully registered as a donor!', 'success')
        return redirect(url_for('login'))

    return render_template('donor_register.html')


@app.route('/receiver-register', methods=['GET', 'POST'])
def receiver_register():
    global _next_user_id
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        email = request.form.get('email', '').strip()
        address = request.form.get('address', '').strip()
        organization_name = request.form.get('organization_name', '').strip()
        type_of_receiver = request.form.get('type_of_receiver', '').strip()
        contact_number = request.form.get('contact_number', '').strip()
        license_number = request.form.get('license_number', '').strip()

        if username in users:
            flash('Account already exists!', 'danger')
        elif password != confirm_password:
            flash('Passwords do not match!', 'danger')
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Invalid email address!', 'danger')
        else:
            user = {
                'id': _next_user_id,
                'username': username,
                'password': generate_password_hash(password),
                'role': 'Receiver',
                'name': organization_name or username,
                'email': email,
                'address': address
            }
            users[username] = user
            _next_user_id += 1
            flash('You have successfully registered as a receiver!', 'success')
            return redirect(url_for('login'))

    return render_template('receiver_register.html')


@app.route('/staff-register', methods=['GET', 'POST'])
def staff_register():
    global _next_user_id
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        email = request.form.get('email', '').strip()
        full_name = request.form.get('full_name', '').strip()
        contact_number = request.form.get('contact_number', '').strip()
        shift = request.form.get('shift', '').strip()

        staff_id_gen = "STF" + uuid4().hex[:6].upper()

        if username in users:
            flash('Account already exists!', 'danger')
        elif password != confirm_password:
            flash('Passwords do not match!', 'danger')
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Invalid email address!', 'danger')
        else:
            user = {
                'id': _next_user_id,
                'username': username,
                'password': generate_password_hash(password),
                'role': 'Staff',
                'name': full_name or username,
                'email': email,
                'address': ''
            }
            users[username] = user
            _next_user_id += 1
            flash('You have successfully registered as a staff member!', 'success')
            return redirect(url_for('login'))

    return render_template('staff_register.html')


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    user = get_user_by_username(session['username'])
    if not user:
        flash('User not found. Please log in again.')
        return redirect(url_for('login'))

    role = user['role']
    user_id = user['id']

    if role == 'Receiver':
        flash(f'Welcome to LifeLine Blood Bank, {user.get("name", "")}!', 'success')
        if request.method == 'POST':
            form = request.form
            # simulate inserting a blood request
            global _next_request_id
            new_request = {
                'id': _next_request_id,
                'user_id': user_id,
                'blood_group': form.get('blood_group'),
                'quantity': int(form.get('quantity', 0)),
                'priority': form.get('priority'),
                'required_by': form.get('required_by'),
                'address': form.get('address'),
                'status': 'Pending',
                'staff_approval': 'Pending'
            }
            blood_requests.append(new_request)
            _next_request_id += 1
            flash('Your blood request has been successfully submitted!', 'success')

        pending_requests = get_user_blood_requests(user_id)
        return render_template('receiver_dashboard.html', role=role, pending_requests=pending_requests)

    elif role == 'Staff':
        return redirect(url_for('staff_dashboard'))

    return render_template('dashboard.html', role=role)


@app.route('/donor_dashboard', methods=['GET', 'POST'])
def donor_dashboard():
    if 'loggedin' not in session or session.get('role') != 'Donor':
        return redirect(url_for('login'))

    username = session['username']
    user = get_user_by_username(username)
    if not user:
        flash('User not found. Please log in again.')
        return redirect(url_for('login'))

    user_id = user['id']
    role = user['role']

    donor_info = donor_details.get(user_id, {'weight': '', 'blood_group': '', 'diseases': '', 'name': user.get('name', '')})
    campaign = campaigns[0] if campaigns else {'title': 'Sample Campaign', 'date': '2025-09-07'}

    if request.method == 'POST':
        form = request.form
        donor_details[user_id] = {
            'weight': form.get('weight', donor_info.get('weight', '')),
            'blood_group': form.get('blood_group', donor_info.get('blood_group', '')),
            'diseases': form.get('diseases', donor_info.get('diseases', '')),
            'name': user.get('name', '')
        }
        flash('Your donor details have been updated successfully!')

    return render_template('donor_dashboard.html', role=role, donor_info=donor_info, campaign=campaign)


@app.route('/receiver_dashboard', methods=['GET', 'POST'])
def receiver_dashboard_public():
    # this route name intentionally mirrors earlier usage; session role is enforced
    if 'loggedin' not in session or session.get('role') != 'Receiver':
        flash('You must be logged in as a Receiver to view this page.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']

    if request.method == 'POST':
        try:
            quantity = int(request.form.get('quantity', 0))
        except (ValueError, TypeError):
            flash("Invalid quantity value.", "danger")
            return redirect(url_for('receiver_dashboard'))

        global _next_request_id
        new_request = {
            'id': _next_request_id,
            'user_id': user_id,
            'blood_group': request.form.get('blood_group'),
            'quantity': quantity,
            'priority': request.form.get('priority'),
            'required_by': request.form.get('required_by'),
            'address': request.form.get('address'),
            'status': 'Pending',
            'staff_approval': 'Pending'
        }
        blood_requests.append(new_request)
        _next_request_id += 1
        flash("Blood request submitted successfully.", "success")
        return redirect(url_for('receiver_dashboard'))

    pending_requests = [r for r in blood_requests if r['user_id'] == user_id and r['status'] == 'Pending']
    return render_template('receiver_dashboard.html', pending_requests=pending_requests)


@app.route('/cancel_request/<int:request_id>', methods=['GET', 'POST'])
def cancel_request(request_id):
    if 'user_id' not in session or session.get('role') != 'Receiver':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    req = find_request_by_id(request_id)

    if not req or req.get('user_id') != user_id:
        flash('Blood request not found or unauthorized access!', 'danger')
        return redirect(url_for('receiver_dashboard'))

    if req.get('status') != 'Pending':
        flash('Cannot cancel a completed or fulfilled request!', 'warning')
        return redirect(url_for('receiver_dashboard'))

    if request.method == 'POST':
        # remove request
        blood_requests.remove(req)
        flash('Your blood request has been canceled successfully!', 'success')
        return redirect(url_for('receiver_dashboard'))

    return render_template('cancel_request.html', request=req)


@app.route('/update_request/<int:request_id>', methods=['GET', 'POST'])
def update_request(request_id):
    if 'user_id' not in session or session.get('role') != 'Receiver':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    req = find_request_by_id(request_id)

    if not req or req.get('user_id') != user_id:
        flash('Blood request not found or unauthorized access!', 'danger')
        return redirect(url_for('receiver_dashboard'))

    if request.method == 'POST':
        try:
            quantity = int(request.form.get('quantity', req.get('quantity', 0)))
        except (ValueError, TypeError):
            flash("Invalid quantity value.", "danger")
            return render_template('update_request.html', request=req)

        req['blood_group'] = request.form.get('blood_group', req.get('blood_group'))
        req['quantity'] = quantity
        req['priority'] = request.form.get('priority', req.get('priority'))
        req['required_by'] = request.form.get('required_by', req.get('required_by'))
        req['address'] = request.form.get('address', req.get('address'))
        flash('Your blood request has been updated successfully!', 'success')
        return redirect(url_for('receiver_dashboard'))

    return render_template('update_request.html', request=req)


@app.route('/staff_dashboard')
def staff_dashboard():
    if 'loggedin' not in session or session.get('role') != 'Staff':
        return redirect(url_for('login'))

    inventory = fetch_blood_inventory()
    pending_requests = fetch_pending_blood_requests()
    cps = fetch_campaigns()
    return render_template('staff_dashboard.html', blood_inventory=inventory, pending_requests=pending_requests, campaigns=cps)


@app.route('/view_requests')
def view_requests():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    return render_template('view_requests.html', requests=blood_requests)


@app.route('/approve_request/<int:request_id>')
def approve_request(request_id):
    if session.get('role') != 'Staff':
        return redirect(url_for('login'))

    req = find_request_by_id(request_id)
    if not req:
        flash('Request not found.', 'danger')
        return redirect(url_for('view_requests'))

    req['staff_approval'] = 'Approved'
    req['status'] = 'Approved'
    flash("Request Approved Successfully!", "success")
    return redirect(url_for('view_requests'))


@app.route('/reject_request/<int:request_id>')
def reject_request(request_id):
    if session.get('role') != 'Staff':
        return redirect(url_for('login'))

    req = find_request_by_id(request_id)
    if not req:
        flash('Request not found.', 'danger')
        return redirect(url_for('view_requests'))

    req['staff_approval'] = 'Rejected'
    req['status'] = 'Rejected'
    flash("Request Rejected Successfully!", "danger")
    return redirect(url_for('view_requests'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/view_campaigns')
def view_campaigns():
    return render_template('view_campaigns.html', campaigns=campaigns)


# ----------------- Inventory routes -----------------
@app.route('/blood_inventory', methods=['GET', 'POST'])
def blood_inventory_view():
    # Filter inventory by optional form values
    blood_group = request.form.get('blood_group', '') if request.method == 'POST' else request.args.get('blood_group', '')
    amount = request.form.get('amount', '') if request.method == 'POST' else request.args.get('amount', '')

    results = blood_inventory
    if blood_group:
        results = [i for i in results if i.get('blood_group') == blood_group]
    if amount:
        try:
            amt = int(amount)
            results = [i for i in results if int(i.get('available_units', 0)) >= amt]
        except:
            pass

    # For expiry highlighting in templates
    current_date = datetime.today().date()
    # build a list of distinct blood groups
    blood_groups = sorted(list({i['blood_group'] for i in blood_inventory}))

    return render_template('blood_inventory.html', inventory=results, blood_groups=blood_groups, current_date=current_date)


@app.route('/add_inventory', methods=['POST'])
def add_inventory():
    global _next_inventory_id
    blood_group = request.form.get('blood_group')
    try:
        available_units = int(request.form.get('amount', 0))
    except:
        available_units = 0
    collection_date = request.form.get('collection_date')
    product_type = request.form.get('product_type')

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
    else:
        flash('Invalid product type selected.', 'danger')
        return redirect(url_for('blood_inventory'))

    # parse collection date and compute expiry
    try:
        collection_date_obj = datetime.strptime(collection_date, "%Y-%m-%d")
    except:
        collection_date_obj = datetime.today()
    expiry_date = (collection_date_obj + timedelta(days=shelf_life)).strftime("%Y-%m-%d")
    last_updated = datetime.today().strftime("%Y-%m-%d")

    item = {
        'id': _next_inventory_id,
        'blood_group': blood_group,
        'available_units': available_units,
        'last_updated': last_updated,
        'expiry_date': expiry_date,
        'product_type': product_type,
        'storage_conditions': storage_condition,
        'shelf_life': shelf_life
    }
    blood_inventory.append(item)
    _next_inventory_id += 1

    flash('Blood inventory added successfully!', 'success')
    return redirect(url_for('blood_inventory'))


@app.route('/edit_inventory/<int:id>', methods=['GET', 'POST'])
def edit_inventory(id):
    item = find_inventory_item_by_id(id)
    if not item:
        flash("Inventory item not found!", "danger")
        return redirect(url_for('blood_inventory'))

    if request.method == 'GET':
        return render_template('edit_inventory.html', item=item)

    # POST update
    try:
        available_units = int(request.form.get('amount', item.get('available_units', 0)))
    except:
        available_units = item.get('available_units', 0)
    item['available_units'] = available_units
    item['last_updated'] = datetime.today().strftime("%Y-%m-%d")
    flash("Inventory updated successfully!", "success")
    return redirect(url_for('blood_inventory'))


@app.route('/delete_inventory/<int:id>', methods=['POST'])
def delete_inventory(id):
    if session.get('role') != 'Staff':
        flash("Unauthorized access!", 'danger')
        return redirect(url_for('login'))

    item = find_inventory_item_by_id(id)
    if not item:
        flash("Inventory item not found!", "danger")
        return redirect(url_for('blood_inventory'))

    blood_inventory.remove(item)
    flash("Inventory item deleted successfully!", "success")
    return redirect(url_for('blood_inventory'))


# ----------------- Misc helpers used earlier (kept safe) -----------------
@app.route('/view_requests_public')
def view_requests_public():
    return render_template('view_requests.html', requests=blood_requests)


# ----------------- ENTRY POINT -----------------
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8080))
    # Bind to 0.0.0.0 for Cloud Run
    app.run(host="0.0.0.0", port=port, debug=True)
