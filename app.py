from flask import Flask, request, jsonify, render_template, redirect, url_for, abort, send_from_directory, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import sys
from sqlalchemy import desc

# Validate critical environment variables
if not os.getenv('SECRET_KEY') or os.getenv('SECRET_KEY') == 'dev-secret-key-change-in-production':
    if os.getenv('RENDER'):  # Check if running on Render
        print("ERROR: SECRET_KEY environment variable must be set in production!")
        print("Please set it in your Render dashboard under Environment Variables")
        sys.exit(1)
    else:
        print("WARNING: Using default SECRET_KEY. This is NOT secure for production!")

if not os.getenv('DATABASE_URL'):
    print("ERROR: DATABASE_URL environment variable is required!")
    sys.exit(1)

print("✓ Environment variables validated")

app = Flask(__name__)

database_url = os.getenv('DATABASE_URL', 'postgresql://yeems:supersecure@localhost:5432/maintenance_db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

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
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt', 'png', 'jpg', 'jpeg', 'gif', 'xlsx', 'xls'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=True)
    parent_id = db.Column(db.Integer, db.ForeignKey('functional_locations.id'), nullable=True)
    parent = db.relationship('FunctionalLocation', remote_side=[id], backref='children')
    tasks = db.relationship('MaintenanceTask', backref='func_loc', lazy=True)

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

    def schedule_notifications(self):
        scheduler.add_job(
            func=run_maintenance_task,
            trigger='date',
            run_date=self.next_run,
            args=[self.id]
        )
    
    def update_status(self):
        """Update task status based on next_run date"""
        now = datetime.utcnow()
        if self.next_run < now:
            self.status = 'overdue'
        elif self.next_run <= now + timedelta(days=3):
            if self.status != 'in_progress':
                self.status = 'pending'
        else:
            if self.status != 'in_progress':
                self.status = 'pending'

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

def run_maintenance_task(task_id):
    with app.app_context():
        task = MaintenanceTask.query.get(task_id)
        if task:
            print(f"Task due: '{task.name}' at location '{task.location.name}'")
            task.status = 'overdue'
            db.session.commit()
            
            # Notify assigned user
            if task.assigned_to:
                create_notification(
                    task.assigned_to,
                    task.id,
                    f"Task Overdue: {task.name}",
                    f"The maintenance task '{task.name}' at {task.location.name} is now overdue.",
                    'overdue'
                )

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
    
    user = User(username=data['username'], email=data['email'], role=role)
    user.set_password(data['password'])
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'id': user.id, 'username': user.username, 'email': user.email, 'role': user.role}), 201

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
    
    return jsonify({'id': user.id, 'username': user.username, 'email': user.email, 'role': user.role}), 200

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/api/auth/me', methods=['GET'])
@login_required
def get_current_user():
    user = User.query.get(session['user_id'])
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
    users = User.query.all()
    return jsonify([{
        'id': u.id,
        'username': u.username,
        'email': u.email,
        'role': u.role,
        'is_active': u.is_active,
        'created_at': u.created_at.isoformat(),
        'notification_days_ahead': u.notification_days_ahead
    } for u in users])

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    data = request.get_json()
    user = User.query.get_or_404(user_id)
    
    # Only admins can change roles and status
    current_user = User.query.get(session['user_id'])
    if current_user.role == 'admin':
        if 'role' in data:
            user.role = data['role']
        if 'is_active' in data:
            user.is_active = data['is_active']
    
    # Users can update their own notification preferences
    if user_id == session['user_id'] or current_user.role == 'admin':
        if 'notification_days_ahead' in data:
            user.notification_days_ahead = data['notification_days_ahead']
    
    db.session.commit()
    return jsonify({'message': 'User updated'}), 200

# Notification routes
@app.route('/api/notifications', methods=['GET'])
@login_required
def get_notifications():
    limit = request.args.get('limit', 50, type=int)
    notifications = Notification.query.filter_by(
        user_id=session['user_id']
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
    notification = Notification.query.get_or_404(notif_id)
    if notification.user_id != session['user_id']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    notification.is_read = True
    db.session.commit()
    return jsonify({'status': 'ok'})

@app.route('/api/notifications/mark-all-read', methods=['PUT'])
@login_required
def mark_all_notifications_read():
    Notification.query.filter_by(
        user_id=session['user_id'],
        is_read=False
    ).update({'is_read': True})
    db.session.commit()
    return jsonify({'status': 'ok'})

# Task routes
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('maintenance_ui.html')

@app.route('/login.html')
def login_page():
    return render_template('login.html')

@app.route('/locations', methods=['GET', 'POST'])
@login_required
def handle_locations():
    if request.method == 'POST':
        data = request.get_json() or request.form
        loc = Location(name=data.get('name'))
        db.session.add(loc)
        db.session.commit()
        return jsonify({'id': loc.id, 'name': loc.name}), 201
    locs = Location.query.order_by(Location.name).all()
    return jsonify([{'id': l.id, 'name': l.name} for l in locs])

@app.route('/tasks', methods=['GET', 'POST'])
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
            lead_time_days=int(data.get('lead_time_days', 0)),
            assigned_to=int(data.get('assigned_to')) if data.get('assigned_to') else None
        )
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
        
        task.schedule_notifications()
        if request.form:
            return redirect(url_for('index'))
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
    
    old_assigned_to = task.assigned_to
    
    task.name = data['name']
    task.frequency_days = int(data['frequency_days'])
    task.next_run = datetime.fromisoformat(data['next_run'])
    task.location_id = int(data['location_id'])
    task.part_name = data.get('part_name')
    task.vendor = data.get('vendor')
    task.vendor_part_number = data.get('vendor_part_number')
    task.lead_time_days = int(data.get('lead_time_days', 0))
    task.func_loc_id = int(data.get('func_loc_id')) if data.get('func_loc_id') else None
    task.assigned_to = int(data.get('assigned_to')) if data.get('assigned_to') else None
    
    if 'status' in data:
        task.status = data['status']
    else:
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
@login_required
def delete_task(task_id):
    task = MaintenanceTask.query.get_or_404(task_id)
    for attachment in task.attachments:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], attachment.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
    db.session.delete(task)
    db.session.commit()
    return '', 204

# Task completion routes
@app.route('/tasks/<int:task_id>/complete', methods=['POST'])
@login_required
def complete_task(task_id):
    data = request.get_json()
    task = MaintenanceTask.query.get_or_404(task_id)
    
    # Create completion record
    completion = TaskCompletion(
        task_id=task.id,
        completed_by=session['user_id'],
        scheduled_date=task.next_run,
        actual_date=datetime.utcnow(),
        notes=data.get('notes'),
        duration_minutes=data.get('duration_minutes'),
        parts_used=data.get('parts_used'),
        labor_hours=data.get('labor_hours'),
        status=data.get('status', 'completed')
    )
    db.session.add(completion)
    
    # Update task
    task.last_completed = datetime.utcnow()
    
    if completion.status == 'completed':
        # Reschedule to next occurrence
        task.next_run = task.next_run + timedelta(days=task.frequency_days)
        task.status = 'pending'
    elif completion.status == 'skipped':
        # Still reschedule but mark as skipped
        task.next_run = task.next_run + timedelta(days=task.frequency_days)
        task.status = 'pending'
    
    task.update_status()
    task.schedule_notifications()
    
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

# Attachment routes
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

# Functional location routes
@app.route('/funclocations', methods=['GET', 'POST'])
@login_required
def handle_funclocs():
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            # Validate required fields
            if not data or not data.get('name'):
                return jsonify({'error': 'Name is required'}), 400
            
            # Check for duplicate name
            existing = FunctionalLocation.query.filter_by(name=data['name']).first()
            if existing:
                return jsonify({'error': 'A location with this name already exists'}), 400
            
            # Validate parent_id if provided
            parent_id = data.get('parent_id')
            if parent_id:
                parent = FunctionalLocation.query.get(parent_id)
                if not parent:
                    return jsonify({'error': 'Parent location not found'}), 404
            
            # Create new functional location
            fl = FunctionalLocation(
                name=data['name'],
                description=data.get('description'),
                parent_id=parent_id
            )
            db.session.add(fl)
            db.session.commit()
            
            return jsonify({
                'id': fl.id, 
                'name': fl.name, 
                'description': fl.description, 
                'parent_id': fl.parent_id
            }), 201
            
        except Exception as e:
            db.session.rollback()
            print(f"Error creating functional location: {e}")
            return jsonify({'error': 'Failed to create location', 'message': str(e)}), 500

    # GET request
    try:
        fls = FunctionalLocation.query.order_by(FunctionalLocation.name).all()
        return jsonify([{
            'id': f.id, 
            'name': f.name, 
            'description': f.description, 
            'parent_id': f.parent_id
        } for f in fls])
    except Exception as e:
        print(f"Error fetching functional locations: {e}")
        return jsonify({'error': 'Failed to fetch locations', 'message': str(e)}), 500

@app.route('/funclocations/<int:fl_id>', methods=['PUT', 'PATCH'])
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
    db.session.delete(fl)
    db.session.commit()
    return '', 204

# Dashboard/analytics routes
@app.route('/api/dashboard/stats', methods=['GET'])
@login_required
def get_dashboard_stats():
    user_id = session['user_id']
    user = User.query.get(user_id)
    
    # Get tasks assigned to current user
    my_tasks = MaintenanceTask.query.filter_by(assigned_to=user_id).all()
    
    # Update statuses
    for task in my_tasks:
        task.update_status()
    db.session.commit()
    
    # Calculate stats
    total_tasks = len(my_tasks)
    overdue_tasks = len([t for t in my_tasks if t.status == 'overdue'])
    due_this_week = len([t for t in my_tasks if t.next_run <= datetime.utcnow() + timedelta(days=7) and t.status != 'overdue'])
    in_progress = len([t for t in my_tasks if t.status == 'in_progress'])
    
    # Completion stats for this month
    month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    completions_this_month = TaskCompletion.query.filter(
        TaskCompletion.completed_by == user_id,
        TaskCompletion.completed_at >= month_start,
        TaskCompletion.status == 'completed'
    ).count()
    
    # All tasks stats (for admins)
    all_stats = None
    if user.role == 'admin':
        all_tasks = MaintenanceTask.query.all()
        for task in all_tasks:
            task.update_status()
        db.session.commit()
        
        all_stats = {
            'total_tasks': len(all_tasks),
            'overdue_tasks': len([t for t in all_tasks if t.status == 'overdue']),
            'due_this_week': len([t for t in all_tasks if t.next_run <= datetime.utcnow() + timedelta(days=7) and t.status != 'overdue']),
            'unassigned_tasks': len([t for t in all_tasks if not t.assigned_to])
        }
    
    return jsonify({
        'my_tasks': {
            'total': total_tasks,
            'overdue': overdue_tasks,
            'due_this_week': due_this_week,
            'in_progress': in_progress,
            'completed_this_month': completions_this_month
        },
        'all_tasks': all_stats
    })

@app.route('/api/workload', methods=['GET'])
@login_required
def get_workload():
    """Get workload for all users"""
    users = User.query.filter_by(is_active=True).all()
    workload = []
    
    for user in users:
        tasks = MaintenanceTask.query.filter_by(assigned_to=user.id).all()
        
        # Update statuses
        for task in tasks:
            task.update_status()
        db.session.commit()
        
        overdue = len([t for t in tasks if t.status == 'overdue'])
        due_soon = len([t for t in tasks if t.next_run <= datetime.utcnow() + timedelta(days=7) and t.status != 'overdue'])
        
        workload.append({
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'total_tasks': len(tasks),
            'overdue': overdue,
            'due_this_week': due_soon
        })
    
    return jsonify(workload)

# Initialize database and scheduler
with app.app_context():
    db.create_all()
    
    if User.query.count() == 0:
        admin = User(username='admin', email='admin@example.com', role='admin')
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print("Created default admin user: admin / admin123")
    
    for task in MaintenanceTask.query.all():
        task.schedule_notifications()

# Schedule recurring jobs
scheduler.add_job(
    func=check_upcoming_tasks,
    trigger='interval',
    hours=6,  # Check every 6 hours
    id='check_upcoming_tasks'
)

scheduler.start()

if __name__ == '__main__':
    app.run(debug=False)  # CRITICAL: Never run debug=True in production