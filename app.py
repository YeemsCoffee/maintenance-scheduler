from flask import Flask, request, jsonify, render_template, redirect, url_for, send_from_directory, session, g
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy import desc
import os
import secrets
import sys

# Validate critical environment variables
secret_key = os.getenv('SECRET_KEY')
if not secret_key:
    if os.getenv('RENDER'):  # Check if running on Render
        print("ERROR: SECRET_KEY environment variable must be set in production!")
        print("Please set it in your Render dashboard under Environment Variables")
        sys.exit(1)
    # Random per-process key: safe, but sessions won't survive a restart
    print("WARNING: SECRET_KEY not set. Using a random key; users will be logged out on restart.")
    secret_key = secrets.token_hex(32)

database_url = os.getenv('DATABASE_URL')
if not database_url:
    print("ERROR: DATABASE_URL environment variable is required!")
    sys.exit(1)
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,  # Test connections before using them
    'pool_recycle': 300,    # Recycle connections after 5 minutes
    'pool_size': 10,        # Maximum number of connections
    'max_overflow': 5,      # Allow 5 extra connections if needed
    'connect_args': {
        'connect_timeout': 10,
        'keepalives': 1,
        'keepalives_idle': 30,
        'keepalives_interval': 10,
        'keepalives_count': 5,
    }
}
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['SECRET_KEY'] = secret_key
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = bool(os.getenv('RENDER'))  # Render serves over HTTPS
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt', 'png', 'jpg', 'jpeg', 'gif', 'xlsx', 'xls'}
ROLES = ('admin', 'technician', 'viewer')
EDITOR_ROLES = ('admin', 'technician')
MIN_PASSWORD_LENGTH = 8

def file_extension(filename):
    return filename.rsplit('.', 1)[1].lower() if '.' in filename else ''

db = SQLAlchemy(app)
scheduler = BackgroundScheduler()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='technician')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    notification_days_ahead = db.Column(db.Integer, default=3)

    assigned_tasks = db.relationship('MaintenanceTask', backref='assignee', lazy=True)
    completed_tasks = db.relationship('TaskCompletion', backref='completed_by_user', lazy=True)
    notifications = db.relationship('Notification', backref='user', lazy=True, cascade='all, delete-orphan')

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
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    parent_id = db.Column(db.Integer, db.ForeignKey('functional_locations.id'), nullable=True)
    parent = db.relationship('FunctionalLocation', remote_side=[id], backref='children')
    tasks = db.relationship('MaintenanceTask', backref='func_loc', lazy=True)

    # Name must be unique within the same parent
    __table_args__ = (
        db.UniqueConstraint('name', 'parent_id', name='uix_name_parent'),
    )

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
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    status = db.Column(db.String(20), default='pending')
    last_completed = db.Column(db.DateTime, nullable=True)

    attachments = db.relationship('TaskAttachment', backref='task', lazy=True, cascade='all, delete-orphan')
    completions = db.relationship('TaskCompletion', backref='task', lazy=True, cascade='all, delete-orphan')

    def update_status(self):
        """Overdue is derived from next_run; 'in_progress' is kept until then"""
        if self.next_run < datetime.utcnow():
            self.status = 'overdue'
        elif self.status != 'in_progress':
            self.status = 'pending'

    def advance_schedule(self):
        """Move next_run forward by whole intervals until it is in the future"""
        step = timedelta(days=self.frequency_days)
        self.next_run += step
        now = datetime.utcnow()
        if self.next_run < now:
            self.next_run += step * ((now - self.next_run) // step + 1)

class TaskCompletion(db.Model):
    __tablename__ = 'task_completions'
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('maintenance_tasks.id'), nullable=False)
    completed_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)
    scheduled_date = db.Column(db.DateTime, nullable=False)
    actual_date = db.Column(db.DateTime, nullable=False)
    notes = db.Column(db.Text)
    duration_minutes = db.Column(db.Integer)
    parts_used = db.Column(db.Text)
    labor_hours = db.Column(db.Float)
    status = db.Column(db.String(20), default='completed')

class TaskAttachment(db.Model):
    __tablename__ = 'task_attachments'
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('maintenance_tasks.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey('maintenance_tasks.id'), nullable=True)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(50))
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

def error(code, message, status=400):
    return jsonify({'error': code, 'message': message}), status

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = db.session.get(User, session['user_id']) if 'user_id' in session else None
        # Disabled or deleted users lose access immediately, not when their cookie expires
        if not user or not user.is_active:
            session.clear()
            return error('unauthorized', 'Please login', 401)
        g.user = user
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if g.user.role not in roles:
                return error('forbidden', 'You do not have permission to do this', 403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

admin_required = role_required('admin')
editor_required = role_required(*EDITOR_ROLES)  # Viewers are read-only

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'same-origin'
    return response

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

def validate_password(password):
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return f'Password must be at least {MIN_PASSWORD_LENGTH} characters'
    return None

def get_default_location():
    """Tasks are organised by functional location; the physical location
    column is still required, so fall back to a single default one"""
    loc = Location.query.order_by(Location.id).first()
    if not loc:
        loc = Location(name='Default Location')
        db.session.add(loc)
        db.session.flush()
    return loc

def parse_int(value, field, minimum=None, required=False):
    """Returns (int_or_None, error_message)"""
    if value in (None, ''):
        return None, (f'{field} is required' if required else None)
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None, f'{field} must be a whole number'
    if minimum is not None and number < minimum:
        return None, f'{field} must be at least {minimum}'
    return number, None

def apply_task_fields(task, data):
    """Validate a task payload and copy it onto task. Returns an error message or None."""
    text = lambda key: str(data.get(key) or '').strip()
    name = text('name')
    if not name:
        return 'Task name is required'
    if len(name) > 150:
        return 'Task name is too long'

    frequency_days, err = parse_int(data.get('frequency_days'), 'Frequency', minimum=1, required=True)
    if err:
        return err

    try:
        next_run = datetime.fromisoformat(text('next_run'))
    except ValueError:
        return 'Next run date is invalid'

    lead_time_days, err = parse_int(data.get('lead_time_days'), 'Lead time', minimum=0)
    if err:
        return err

    func_loc_id, err = parse_int(data.get('func_loc_id'), 'Functional location')
    if err:
        return err
    if func_loc_id and not db.session.get(FunctionalLocation, func_loc_id):
        return 'Functional location not found'

    assigned_to, err = parse_int(data.get('assigned_to'), 'Assignee')
    if err:
        return err
    if assigned_to and not db.session.get(User, assigned_to):
        return 'Assignee not found'

    location_id, err = parse_int(data.get('location_id'), 'Location')
    if err:
        return err
    if location_id and not db.session.get(Location, location_id):
        return 'Location not found'

    task.name = name
    task.frequency_days = frequency_days
    task.next_run = next_run
    task.lead_time_days = lead_time_days or 0
    task.func_loc_id = func_loc_id
    task.assigned_to = assigned_to
    task.location_id = location_id or task.location_id or get_default_location().id
    task.part_name = text('part_name')[:150]
    task.vendor = text('vendor')[:100]
    task.vendor_part_number = text('vendor_part_number')[:100]
    return None

def create_notification(user_id, task_id, title, message, notif_type):
    """Create in-app notification"""
    notification = Notification(
        user_id=user_id,
        task_id=task_id,
        title=title,
        message=message,
        type=notif_type
    )
    db.session.add(notification)
    db.session.commit()

def check_overdue_tasks():
    """Flag tasks that have passed their due date and notify the assignee once per due date"""
    with app.app_context():
        now = datetime.utcnow()
        for task in MaintenanceTask.query.filter(MaintenanceTask.next_run < now).all():
            task.status = 'overdue'
            if not task.assigned_to:
                continue
            already_notified = Notification.query.filter(
                Notification.task_id == task.id,
                Notification.type == 'overdue',
                Notification.created_at >= task.next_run
            ).first()
            if not already_notified:
                create_notification(
                    task.assigned_to,
                    task.id,
                    f"Task Overdue: {task.name}",
                    f"The maintenance task '{task.name}' at {task.location.name} is now overdue.",
                    'overdue'
                )
        db.session.commit()

def check_upcoming_tasks():
    """Check for tasks due soon and send notifications"""
    with app.app_context():
        users = User.query.filter_by(is_active=True).all()

        for user in users:
            days_ahead = user.notification_days_ahead or 3
            cutoff_date = datetime.utcnow() + timedelta(days=days_ahead)

            # Get tasks assigned to user that are due soon
            upcoming_tasks = MaintenanceTask.query.filter(
                MaintenanceTask.assigned_to == user.id,
                MaintenanceTask.next_run <= cutoff_date,
                MaintenanceTask.next_run > datetime.utcnow(),
                MaintenanceTask.status.in_(['pending', 'in_progress'])
            ).all()

            for task in upcoming_tasks:
                # Check if we already notified about this task
                existing = Notification.query.filter_by(
                    user_id=user.id,
                    task_id=task.id,
                    type='due_soon'
                ).filter(
                    Notification.created_at > datetime.utcnow() - timedelta(days=1)
                ).first()

                if not existing:
                    days_until = (task.next_run - datetime.utcnow()).days
                    create_notification(
                        user.id,
                        task.id,
                        f"Task Due Soon: {task.name}",
                        f"The maintenance task '{task.name}' at {task.location.name} is due in {days_until} day(s).",
                        'due_soon'
                    )

# Authentication routes
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}

    if not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Missing username or password'}), 400

    user = User.query.filter_by(username=data['username']).first()

    if not user or not user.check_password(data['password']):
        return jsonify({'error': 'Invalid username or password'}), 401

    if not user.is_active:
        return jsonify({'error': 'Account is disabled'}), 403

    # Start a fresh session so a pre-login cookie can't be reused
    session.clear()
    session.permanent = True
    session['user_id'] = user.id

    return jsonify({'id': user.id, 'username': user.username, 'email': user.email, 'role': user.role}), 200

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/api/auth/me', methods=['GET'])
@login_required
def get_current_user():
    user = g.user
    unread_count = Notification.query.filter_by(user_id=user.id, is_read=False).count()
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'role': user.role,
        'unread_notifications': unread_count
    }), 200

# User management routes
@app.route('/api/users', methods=['GET'])
@login_required
def get_users():
    users = User.query.order_by(User.username).all()
    return jsonify([{
        'id': u.id,
        'username': u.username,
        'email': u.email,
        'role': u.role,
        'is_active': u.is_active,
        'created_at': u.created_at.isoformat(),
        'notification_days_ahead': u.notification_days_ahead
    } for u in users])

@app.route('/api/users', methods=['POST'])
@admin_required
def create_user():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    email = (data.get('email') or '').strip()
    password = data.get('password') or ''
    role = data.get('role', 'technician')

    if not username or not email or not password:
        return error('missing_fields', 'Username, email and password are required')
    if len(username) > 80 or len(email) > 120:
        return error('too_long', 'Username or email is too long')
    if role not in ROLES:
        return error('invalid_role', 'Invalid role')
    password_error = validate_password(password)
    if password_error:
        return error('weak_password', password_error)
    if User.query.filter_by(username=username).first():
        return error('username_taken', 'Username already exists')
    if User.query.filter_by(email=email).first():
        return error('email_taken', 'Email already exists')

    user = User(username=username, email=email, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({'id': user.id, 'username': user.username, 'email': user.email, 'role': user.role}), 201

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    data = request.get_json(silent=True) or {}
    user = db.get_or_404(User, user_id)
    is_admin = g.user.role == 'admin'
    is_self = user.id == g.user.id

    if not is_admin and not is_self:
        return error('forbidden', 'You can only update your own settings', 403)

    # Only admins can change roles, status and passwords. Admins can't
    # demote or disable themselves, so there is always an active admin.
    if is_admin:
        if 'role' in data and data['role'] != user.role:
            if data['role'] not in ROLES:
                return error('invalid_role', 'Invalid role')
            if is_self:
                return error('forbidden', "You can't change your own role")
            user.role = data['role']
        if 'is_active' in data:
            if is_self and not data['is_active']:
                return error('forbidden', "You can't disable your own account")
            user.is_active = bool(data['is_active'])
        if data.get('password'):
            password_error = validate_password(data['password'])
            if password_error:
                return error('weak_password', password_error)
            user.set_password(data['password'])

    if 'notification_days_ahead' in data:
        days, err = parse_int(data['notification_days_ahead'], 'Notification days', minimum=1)
        if err:
            return error('invalid_value', err)
        user.notification_days_ahead = min(days, 30)

    db.session.commit()
    return jsonify({'message': 'User updated'}), 200

# Notification routes
@app.route('/api/notifications', methods=['GET'])
@login_required
def get_notifications():
    limit = min(request.args.get('limit', 50, type=int), 100)
    notifications = Notification.query.filter_by(
        user_id=g.user.id
    ).order_by(desc(Notification.created_at)).limit(limit).all()

    return jsonify([{
        'id': n.id,
        'task_id': n.task_id,
        'title': n.title,
        'message': n.message,
        'type': n.type,
        'is_read': n.is_read,
        'created_at': n.created_at.isoformat()
    } for n in notifications])

@app.route('/api/notifications/<int:notif_id>/read', methods=['PUT'])
@login_required
def mark_notification_read(notif_id):
    notification = db.get_or_404(Notification, notif_id)
    if notification.user_id != g.user.id:
        return error('forbidden', 'Not your notification', 403)

    notification.is_read = True
    db.session.commit()
    return jsonify({'status': 'ok'})

@app.route('/api/notifications/mark-all-read', methods=['PUT'])
@login_required
def mark_all_notifications_read():
    Notification.query.filter_by(
        user_id=g.user.id,
        is_read=False
    ).update({'is_read': True})
    db.session.commit()
    return jsonify({'status': 'ok'})

# Page routes
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('maintenance_ui.html')

@app.route('/login.html')
def login_page():
    return render_template('login.html')

# Task routes
@app.route('/locations', methods=['GET'])
@login_required
def get_locations():
    locs = Location.query.order_by(Location.name).all()
    return jsonify([{'id': l.id, 'name': l.name} for l in locs])

@app.route('/tasks', methods=['GET', 'POST'])
@login_required
def handle_tasks():
    if request.method == 'POST':
        if g.user.role not in EDITOR_ROLES:
            return error('forbidden', 'You do not have permission to do this', 403)
        data = request.get_json(silent=True) or {}
        task = MaintenanceTask()
        err = apply_task_fields(task, data)
        if err:
            return error('invalid_task', err)
        task.update_status()
        db.session.add(task)
        db.session.commit()

        # Notify assigned user
        if task.assigned_to:
            create_notification(
                task.assigned_to,
                task.id,
                f"New Task Assigned: {task.name}",
                f"You have been assigned the maintenance task '{task.name}' at {task.location.name}. Due: {task.next_run.strftime('%Y-%m-%d')}",
                'assigned'
            )

        return jsonify({'id': task.id}), 201

    # Update all task statuses before returning
    tasks = MaintenanceTask.query.order_by(MaintenanceTask.next_run).all()
    for task in tasks:
        task.update_status()
    db.session.commit()

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
        'assigned_to': t.assigned_to,
        'assignee_name': t.assignee.username if t.assignee else None,
        'status': t.status,
        'last_completed': t.last_completed.isoformat() if t.last_completed else None,
        'completion_count': len(t.completions),
        'attachments': [{
            'id': a.id,
            'original_filename': a.original_filename,
            'file_type': a.file_type,
            'uploaded_at': a.uploaded_at.isoformat()
        } for a in t.attachments]
    } for t in tasks])

@app.route('/tasks/<int:task_id>', methods=['PUT'])
@editor_required
def update_task(task_id):
    data = request.get_json(silent=True) or {}
    task = db.get_or_404(MaintenanceTask, task_id)

    old_assigned_to = task.assigned_to
    err = apply_task_fields(task, data)
    if err:
        db.session.rollback()
        return error('invalid_task', err)

    # 'overdue' is computed from the date; only 'in_progress' can be set by hand
    task.status = 'in_progress' if data.get('status') == 'in_progress' else 'pending'
    task.update_status()

    # Notify if assignee changed
    if task.assigned_to and task.assigned_to != old_assigned_to:
        create_notification(
            task.assigned_to,
            task.id,
            f"Task Assigned: {task.name}",
            f"You have been assigned the maintenance task '{task.name}' at {task.location.name}. Due: {task.next_run.strftime('%Y-%m-%d')}",
            'assigned'
        )

    db.session.commit()
    return jsonify({'status': 'ok'})

@app.route('/tasks/<int:task_id>', methods=['DELETE'])
@admin_required
def delete_task(task_id):
    task = db.get_or_404(MaintenanceTask, task_id)
    for attachment in task.attachments:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], attachment.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
    Notification.query.filter_by(task_id=task.id).delete()
    db.session.delete(task)
    db.session.commit()
    return '', 204

# Task completion routes
@app.route('/tasks/<int:task_id>/complete', methods=['POST'])
@editor_required
def complete_task(task_id):
    data = request.get_json(silent=True) or {}
    task = db.get_or_404(MaintenanceTask, task_id)

    status = data.get('status', 'completed')
    if status not in ('completed', 'skipped'):
        return error('invalid_status', 'Status must be completed or skipped')
    duration_minutes, err = parse_int(data.get('duration_minutes'), 'Duration', minimum=0)
    if err:
        return error('invalid_value', err)
    try:
        labor_hours = float(data['labor_hours']) if data.get('labor_hours') not in (None, '') else None
    except (TypeError, ValueError):
        return error('invalid_value', 'Labor hours must be a number')

    now = datetime.utcnow()
    completion = TaskCompletion(
        task_id=task.id,
        completed_by=g.user.id,
        scheduled_date=task.next_run,
        actual_date=now,
        notes=data.get('notes'),
        duration_minutes=duration_minutes,
        parts_used=data.get('parts_used'),
        labor_hours=labor_hours,
        status=status
    )
    db.session.add(completion)

    # Completed and skipped tasks both move on to their next occurrence
    task.last_completed = now
    task.advance_schedule()
    task.status = 'pending'
    task.update_status()

    db.session.commit()

    return jsonify({
        'id': completion.id,
        'task_id': task.id,
        'next_run': task.next_run.isoformat(),
        'status': task.status
    }), 201

@app.route('/tasks/<int:task_id>/completions', methods=['GET'])
@login_required
def get_task_completions(task_id):
    completions = TaskCompletion.query.filter_by(task_id=task_id).order_by(
        desc(TaskCompletion.completed_at)
    ).all()

    return jsonify([{
        'id': c.id,
        'completed_by': c.completed_by_user.username,
        'completed_at': c.completed_at.isoformat(),
        'scheduled_date': c.scheduled_date.isoformat(),
        'actual_date': c.actual_date.isoformat(),
        'notes': c.notes,
        'duration_minutes': c.duration_minutes,
        'parts_used': c.parts_used,
        'labor_hours': c.labor_hours,
        'status': c.status
    } for c in completions])

@app.route('/api/completions', methods=['GET'])
@login_required
def get_all_completions():
    """All completion records in one request, for the CSV export"""
    completions = TaskCompletion.query.order_by(desc(TaskCompletion.completed_at)).all()
    return jsonify([{
        'task_name': c.task.name,
        'task_location': c.task.location.name,
        'completed_by': c.completed_by_user.username,
        'completed_at': c.completed_at.isoformat(),
        'scheduled_date': c.scheduled_date.isoformat(),
        'status': c.status,
        'duration_minutes': c.duration_minutes,
        'labor_hours': c.labor_hours,
        'parts_used': c.parts_used,
        'notes': c.notes
    } for c in completions])

# Attachment routes
@app.route('/tasks/<int:task_id>/attachments', methods=['POST'])
@editor_required
def upload_attachment(task_id):
    db.get_or_404(MaintenanceTask, task_id)

    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    ext = file_extension(file.filename)
    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({'error': 'File type not allowed'}), 400

    # secure_filename can strip a name down to nothing (e.g. non-Latin names)
    original_filename = secure_filename(file.filename)
    if file_extension(original_filename) != ext:
        original_filename = f"attachment.{ext}"
    filename = f"{task_id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(4)}_{original_filename}"
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    attachment = TaskAttachment(
        task_id=task_id,
        filename=filename,
        original_filename=original_filename,
        file_type=ext
    )
    db.session.add(attachment)
    db.session.commit()

    return jsonify({
        'id': attachment.id,
        'original_filename': attachment.original_filename,
        'file_type': attachment.file_type,
        'uploaded_at': attachment.uploaded_at.isoformat()
    }), 201

@app.route('/attachments/<int:attachment_id>', methods=['DELETE'])
@editor_required
def delete_attachment(attachment_id):
    attachment = db.get_or_404(TaskAttachment, attachment_id)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], attachment.filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    db.session.delete(attachment)
    db.session.commit()
    return '', 204

@app.route('/attachments/<int:attachment_id>/download')
@login_required
def download_attachment(attachment_id):
    attachment = db.get_or_404(TaskAttachment, attachment_id)
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        attachment.filename,
        as_attachment=True,
        download_name=attachment.original_filename
    )

# Functional location routes
def funcloc_json(fl):
    return {'id': fl.id, 'name': fl.name, 'description': fl.description, 'parent_id': fl.parent_id}

def validate_funcloc(name, parent_id, fl_id=None):
    """Returns an error message, or None if name/parent are valid"""
    if not name:
        return 'Name is required'
    if len(name) > 100:
        return 'Name is too long'
    parent = None
    if parent_id:
        parent = db.session.get(FunctionalLocation, parent_id)
        if not parent:
            return 'Parent location not found'
        if fl_id and (parent_id == fl_id or is_descendant(parent_id, fl_id)):
            return 'A location cannot be moved under itself or one of its sub-locations'
    # Same name is allowed under different parents, e.g. "Floor 1" in two buildings
    duplicate = FunctionalLocation.query.filter_by(name=name, parent_id=parent_id or None)
    if fl_id:
        duplicate = duplicate.filter(FunctionalLocation.id != fl_id)
    if duplicate.first():
        where = f'under {parent.name}' if parent else 'at the top level'
        return f'A location named "{name}" already exists {where}'
    return None

@app.route('/funclocations', methods=['GET'])
@login_required
def get_funclocs():
    fls = FunctionalLocation.query.order_by(FunctionalLocation.name).all()
    return jsonify([funcloc_json(f) for f in fls])

@app.route('/funclocations', methods=['POST'])
@editor_required
def create_funcloc():
    data = request.get_json(silent=True) or {}
    name = str(data.get('name') or '').strip()
    parent_id, err = parse_int(data.get('parent_id'), 'Parent location')
    err = err or validate_funcloc(name, parent_id)
    if err:
        return error('invalid_location', err)

    fl = FunctionalLocation(name=name, description=data.get('description'), parent_id=parent_id)
    db.session.add(fl)
    db.session.commit()
    return jsonify(funcloc_json(fl)), 201

@app.route('/funclocations/<int:fl_id>', methods=['PUT', 'PATCH'])
@editor_required
def update_funcloc(fl_id):
    data = request.get_json(silent=True) or {}
    fl = db.get_or_404(FunctionalLocation, fl_id)

    name = str(data['name'] or '').strip() if 'name' in data else fl.name
    if 'parent_id' in data:
        parent_id, err = parse_int(data['parent_id'], 'Parent location')
        if err:
            return error('invalid_location', err)
    else:
        parent_id = fl.parent_id

    err = validate_funcloc(name, parent_id, fl_id=fl.id)
    if err:
        return error('invalid_location', err)

    fl.name = name
    fl.parent_id = parent_id
    if 'description' in data:
        fl.description = data['description']

    db.session.commit()
    return jsonify({'status': 'ok', **funcloc_json(fl)})

@app.route('/funclocations/<int:fl_id>', methods=['DELETE'])
@admin_required
def delete_funcloc(fl_id):
    fl = db.get_or_404(FunctionalLocation, fl_id)
    if fl.children:
        return error('has_children', 'Delete or move its sub-locations first.')
    if fl.tasks:
        return error('has_tasks', 'Move or delete the tasks in this location first.')
    db.session.delete(fl)
    db.session.commit()
    return '', 204

# Dashboard/analytics routes
@app.route('/api/dashboard/stats', methods=['GET'])
@login_required
def get_dashboard_stats():
    # Task counts are computed in the browser from /tasks; this only
    # supplies what the task list doesn't include
    month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    completions_this_month = TaskCompletion.query.filter(
        TaskCompletion.completed_at >= month_start,
        TaskCompletion.status == 'completed'
    ).count()
    return jsonify({'completed_this_month': completions_this_month})

@app.route('/api/workload', methods=['GET'])
@login_required
def get_workload():
    """Get workload for all users"""
    users = User.query.filter_by(is_active=True).order_by(User.username).all()
    tasks = MaintenanceTask.query.filter(MaintenanceTask.assigned_to.isnot(None)).all()
    for task in tasks:
        task.update_status()
    db.session.commit()

    week_ahead = datetime.utcnow() + timedelta(days=7)
    workload = []
    for user in users:
        user_tasks = [t for t in tasks if t.assigned_to == user.id]
        workload.append({
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'total_tasks': len(user_tasks),
            'overdue': len([t for t in user_tasks if t.status == 'overdue']),
            'due_this_week': len([t for t in user_tasks if t.next_run <= week_ahead and t.status != 'overdue'])
        })

    return jsonify(workload)

# Initialize database and scheduler
with app.app_context():
    db.create_all()

    if User.query.count() == 0:
        initial_password = os.getenv('ADMIN_PASSWORD') or secrets.token_urlsafe(12)
        admin = User(username='admin', email='admin@example.com', role='admin')
        admin.set_password(initial_password)
        db.session.add(admin)
        db.session.commit()
        if os.getenv('ADMIN_PASSWORD'):
            print("Created initial admin user 'admin' with the password from ADMIN_PASSWORD")
        else:
            print(f"Created initial admin user 'admin' with password: {initial_password}")
            print("Log in and change it from Manage Users > Reset Password.")
    else:
        default_admin = User.query.filter_by(username='admin').first()
        if default_admin and default_admin.check_password('admin123'):
            print("WARNING: the 'admin' account still uses the default password 'admin123'. "
                  "Change it from Manage Users > Reset Password.")

# Recurring jobs: flag overdue tasks hourly, remind assignees of upcoming tasks
scheduler.add_job(
    func=check_overdue_tasks,
    trigger='interval',
    hours=1,
    id='check_overdue_tasks',
    next_run_time=datetime.now()
)
scheduler.add_job(
    func=check_upcoming_tasks,
    trigger='interval',
    hours=6,  # Check every 6 hours
    id='check_upcoming_tasks'
)

scheduler.start()

if __name__ == '__main__':
    app.run(debug=False)  # CRITICAL: Never run debug=True in production
