from flask import Flask, request, jsonify, render_template, redirect, url_for, abort, send_from_directory, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os

# Flask app setup
app = Flask(__name__)

# Use DATABASE_URL from Render (or fallback to local)
database_url = os.getenv('DATABASE_URL', 'postgresql://yeems:supersecure@localhost:5432/maintenance_db')
# Render uses postgres:// but SQLAlchemy needs postgresql://
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

# Create uploads directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt', 'png', 'jpg', 'jpeg', 'gif', 'xlsx', 'xls'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

db = SQLAlchemy(app)
scheduler = BackgroundScheduler()

# ---------------- Models ----------------
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='technician')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Location(db.Model):
    __tablename__ = 'locations'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    tasks = db.relationship('MaintenanceTask', backref='location', lazy=True)

class FunctionalLocation(db.Model):
    __tablename__ = 'functional_locations'
    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=True)
    parent_id   = db.Column(db.Integer, db.ForeignKey('functional_locations.id'), nullable=True)
    parent      = db.relationship('FunctionalLocation', remote_side=[id], backref='children')
    tasks       = db.relationship('MaintenanceTask', backref='func_loc', lazy=True)

class MaintenanceTask(db.Model):
    __tablename__ = 'maintenance_tasks'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    frequency_days = db.Column(db.Integer, nullable=False)
    next_run = db.Column(db.DateTime, nullable=False)
    location_id = db.Column(db.Integer, db.ForeignKey('locations.id'), nullable=False)
    part_name = db.Column(db.String(150))
    vendor = db.Column(db.String(100))
    vendor_part_number = db.Column(db.String(100))
    lead_time_days = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    func_loc_id = db.Column(db.Integer, db.ForeignKey('functional_locations.id'))
    attachments = db.relationship('TaskAttachment', backref='task', lazy=True, cascade='all, delete-orphan')

    def schedule_notifications(self):
        scheduler.add_job(
            func=run_maintenance_task,
            trigger='date',
            run_date=self.next_run,
            args=[self.id]
        )

class TaskAttachment(db.Model):
    __tablename__ = 'task_attachments'
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('maintenance_tasks.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

# ------------- Auth Decorators -------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'unauthorized', 'message': 'Please login'}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'unauthorized', 'message': 'Please login'}), 401
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            return jsonify({'error': 'forbidden', 'message': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

# ------------- Helpers -------------
def is_descendant(node_id, possible_ancestor_id):
    if not node_id or not possible_ancestor_id:
        return False
    stack = [possible_ancestor_id]
    while stack:
        current = stack.pop()
        if current == node_id:
            return True
        for child in FunctionalLocation.query.filter_by(parent_id=current):
            stack.append(child.id)
    return False

def run_maintenance_task(task_id):
    with app.app_context():
        task = MaintenanceTask.query.get(task_id)
        print(f"Task due: '{task.name}' at location '{task.location.name}'")
        task.next_run += timedelta(days=task.frequency_days)
        db.session.commit()
        task.schedule_notifications()

# ---------------- Auth Routes ----------------
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Missing required fields'}), 400
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 400
    
    user_count = User.query.count()
    role = 'admin' if user_count == 0 else data.get('role', 'technician')
    
    user = User(
        username=data['username'],
        email=data['email'],
        role=role
    )
    user.set_password(data['password'])
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'role': user.role
    }), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Missing username or password'}), 400
    
    user = User.query.filter_by(username=data['username']).first()
    
    if not user or not user.check_password(data['password']):
        return jsonify({'error': 'Invalid username or password'}), 401
    
    if not user.is_active:
        return jsonify({'error': 'Account is disabled'}), 403
    
    session['user_id'] = user.id
    session['username'] = user.username
    session['role'] = user.role
    
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'role': user.role
    }), 200

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/api/auth/me', methods=['GET'])
@login_required
def get_current_user():
    user = User.query.get(session['user_id'])
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'role': user.role
    }), 200

@app.route('/api/users', methods=['GET'])
@admin_required
def get_users():
    users = User.query.all()
    return jsonify([{
        'id': u.id,
        'username': u.username,
        'email': u.email,
        'role': u.role,
        'is_active': u.is_active,
        'created_at': u.created_at.isoformat()
    } for u in users])

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@admin_required
def update_user(user_id):
    data = request.get_json()
    user = User.query.get_or_404(user_id)
    
    if 'role' in data:
        user.role = data['role']
    if 'is_active' in data:
        user.is_active = data['is_active']
    
    db.session.commit()
    return jsonify({'message': 'User updated'}), 200

# ---------------- Routes ----------------
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('maintenance_ui.html')

@app.route('/login.html')
def login_page():
    return render_template('login.html')

@app.route('/locations', methods=['GET','POST'])
@login_required
def handle_locations():
    if request.method == 'POST':
        data = request.get_json() or request.form
        loc = Location(name=data.get('name'))
        db.session.add(loc); db.session.commit()
        return jsonify({'id': loc.id, 'name': loc.name}), 201
    locs = Location.query.order_by(Location.name).all()
    return jsonify([{'id': l.id, 'name': l.name} for l in locs])

@app.route('/tasks', methods=['GET','POST'])
@login_required
def handle_tasks():
    if request.method == 'POST':
        data = request.get_json() or request.form
        task = MaintenanceTask(
            name=data['name'],
            frequency_days=int(data['frequency_days']),
            next_run=datetime.fromisoformat(data['next_run']),
            location_id=int(data['location_id']),
            part_name=data.get('part_name'),
            vendor=data.get('vendor'),
            vendor_part_number=data.get('vendor_part_number'),
            func_loc_id=int(data.get('func_loc_id')) if data.get('func_loc_id') else None,
            lead_time_days=int(data.get('lead_time_days', 0))
        )
        db.session.add(task); db.session.commit()
        task.schedule_notifications()
        if request.form:
            return redirect(url_for('index'))
        return jsonify({'id': task.id}), 201

    tasks = MaintenanceTask.query.order_by(MaintenanceTask.next_run).all()
    return jsonify([{
        'id': t.id,
        'name': t.name,
        'frequency_days': t.frequency_days,
        'next_run': t.next_run.isoformat(),
        'location': t.location.name,
        'part_name': t.part_name,
        'vendor': t.vendor,
        'vendor_part_number': t.vendor_part_number,
        'func_loc_id': t.func_loc_id,
        'lead_time_days': t.lead_time_days,
        'attachments': [{
            'id': a.id,
            'filename': a.filename,
            'original_filename': a.original_filename,
            'file_type': a.file_type,
            'uploaded_at': a.uploaded_at.isoformat()
        } for a in t.attachments]
    } for t in tasks])

@app.route('/tasks/<int:task_id>', methods=['PUT'])
@login_required
def update_task(task_id):
    data = request.get_json() or abort(400, "JSON body required")
    task = MaintenanceTask.query.get_or_404(task_id)
    task.name = data['name']
    task.frequency_days = int(data['frequency_days'])
    task.next_run = datetime.fromisoformat(data['next_run'])
    task.location_id = int(data['location_id'])
    task.part_name = data.get('part_name')
    task.vendor = data.get('vendor')
    task.vendor_part_number = data.get('vendor_part_number')
    task.lead_time_days = int(data.get('lead_time_days', 0))
    task.func_loc_id = int(data.get('func_loc_id')) if data.get('func_loc_id') else None
    db.session.commit()
    return jsonify({'status': 'ok'})

@app.route('/tasks/<int:task_id>', methods=['DELETE'])
@login_required
def delete_task(task_id):
    task = MaintenanceTask.query.get_or_404(task_id)
    for attachment in task.attachments:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], attachment.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
    db.session.delete(task); db.session.commit()
    return '', 204

# ---------- File Upload Routes ----------
@app.route('/tasks/<int:task_id>/attachments', methods=['POST'])
@login_required
def upload_attachment(task_id):
    task = MaintenanceTask.query.get_or_404(task_id)
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400
    
    original_filename = secure_filename(file.filename)
    filename = f"{task_id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{original_filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    
    attachment = TaskAttachment(
        task_id=task_id,
        filename=filename,
        original_filename=original_filename,
        file_type=original_filename.rsplit('.', 1)[1].lower()
    )
    db.session.add(attachment)
    db.session.commit()
    
    return jsonify({
        'id': attachment.id,
        'filename': attachment.filename,
        'original_filename': attachment.original_filename,
        'file_type': attachment.file_type,
        'uploaded_at': attachment.uploaded_at.isoformat()
    }), 201

@app.route('/attachments/<int:attachment_id>', methods=['DELETE'])
@login_required
def delete_attachment(attachment_id):
    attachment = TaskAttachment.query.get_or_404(attachment_id)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], attachment.filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    db.session.delete(attachment)
    db.session.commit()
    return '', 204

@app.route('/attachments/<int:attachment_id>/download')
@login_required
def download_attachment(attachment_id):
    attachment = TaskAttachment.query.get_or_404(attachment_id)
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        attachment.filename,
        as_attachment=True,
        download_name=attachment.original_filename
    )

# ---------- Functional Locations ----------
@app.route('/funclocations', methods=['GET','POST'])
@login_required
def handle_funclocs():
    if request.method == 'POST':
        data = request.get_json() or request.form
        fl = FunctionalLocation(
            name=data['name'],
            description=data.get('description'),
            parent_id=data.get('parent_id')
        )
        db.session.add(fl); db.session.commit()
        return jsonify({'id': fl.id, 'name': fl.name, 'description': fl.description, 'parent_id': fl.parent_id}), 201

    fls = FunctionalLocation.query.order_by(FunctionalLocation.name).all()
    return jsonify([
        {'id': f.id, 'name': f.name, 'description': f.description, 'parent_id': f.parent_id}
        for f in fls
    ])

@app.route('/funclocations/<int:fl_id>', methods=['PUT','PATCH'])
@login_required
def update_funcloc(fl_id):
    data = request.get_json() or abort(400, "JSON body required")
    fl = FunctionalLocation.query.get_or_404(fl_id)

    if 'name' in data and data['name'] != fl.name:
        if FunctionalLocation.query.filter_by(name=data['name']).first():
            return jsonify({'error': 'name_not_unique', 'message': 'Functional Location name must be unique.'}), 400
        fl.name = data['name']

    if 'parent_id' in data:
        pid = data['parent_id']
        pid = int(pid) if (pid not in (None, '', 'null', 'None')) else None
        if pid == fl.id:
            return jsonify({'error': 'invalid_parent', 'message': 'Cannot set a node as its own parent.'}), 400
        if pid and is_descendant(pid, fl.id):
            return jsonify({'error': 'cycle', 'message': 'Cannot reparent under its own descendant.'}), 400
        fl.parent_id = pid

    if 'description' in data:
        fl.description = data['description']

    db.session.commit()
    return jsonify({'status': 'ok', 'id': fl.id, 'name': fl.name, 'description': fl.description, 'parent_id': fl.parent_id})

@app.route('/funclocations/<int:fl_id>', methods=['DELETE'])
@login_required
def delete_funcloc(fl_id):
    fl = FunctionalLocation.query.get_or_404(fl_id)
    if fl.children and len(fl.children) > 0:
        return jsonify({'error': 'has_children', 'message': 'Delete or reparent children first.'}), 400
    if fl.tasks and len(fl.tasks) > 0:
        return jsonify({'error': 'has_tasks', 'message': 'Move or delete tasks referencing this functional location first.'}), 400
    db.session.delete(fl); db.session.commit()
    return '', 204

# ---------------- Initialize ----------------
with app.app_context():
    db.create_all()
    
    # Create default admin if no users exist
    if User.query.count() == 0:
        admin = User(username='admin', email='admin@example.com', role='admin')
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print("Created default admin user: admin / admin123")
    
    # Schedule existing tasks
    for task in MaintenanceTask.query.all():
        task.schedule_notifications()

scheduler.start()

if __name__ == '__main__':
    app.run(debug=False)