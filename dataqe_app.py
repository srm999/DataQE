from flask import Flask, render_template, redirect, url_for, flash, request, session, jsonify,send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import json
from datetime import datetime
import uuid
from flask_mail import Mail, Message
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import func
from integration.dataqe_bridge import DataQEBridge


app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-key-for-testing'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dataqe.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SQL_FOLDER'] = os.path.join('static', 'sql_files')
app.config['DEBUG'] = True

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Change to your SMTP server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'  # Change to your email
app.config['MAIL_PASSWORD'] = 'your-app-password'  # Use app-specific password
app.config['MAIL_DEFAULT_SENDER'] = 'DataQE Suite <your-email@gmail.com>'

mail = Mail(app)
dataqa_bridge = DataQEBridge(app)

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['SQL_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Initialize scheduler
scheduler = BackgroundScheduler()
scheduler.start()

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'))
    is_admin = db.Column(db.Boolean, default=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(200))
    folder_path = db.Column(db.String(500), nullable=False)
    teams = db.relationship('Team', backref='project', lazy=True)
    connections = db.relationship('Connection', backref='project', lazy=True)

class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    users = db.relationship('User', backref='team', lazy=True)
    test_cases = db.relationship('TestCase', backref='team', lazy=True)

class Connection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    server = db.Column(db.String(100), nullable=False)
    database = db.Column(db.String(100), nullable=False)
    warehouse = db.Column(db.String(100))  # For Snowflake
    role = db.Column(db.String(100))  # For Snowflake
    is_excel = db.Column(db.Boolean, default=False)

class TestCase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tcid = db.Column(db.String(100), nullable=False)
    table_name = db.Column(db.String(100), nullable=False)
    test_type = db.Column(db.String(50), nullable=False)
    tc_name = db.Column(db.String(100), nullable=False)
    test_yn = db.Column(db.String(1), default='N')
    src_data_file = db.Column(db.String(200))
    src_connection_id = db.Column(db.Integer, db.ForeignKey('connection.id'))
    tgt_data_file = db.Column(db.String(200))
    tgt_connection_id = db.Column(db.Integer, db.ForeignKey('connection.id'))
    filters = db.Column(db.Text)
    delimiter = db.Column(db.String(10))
    pk_columns = db.Column(db.Text)  # Stored as JSON
    date_fields = db.Column(db.Text)  # Stored as JSON
    percentage_fields = db.Column(db.Text)  # Stored as JSON
    threshold_percentage = db.Column(db.Float, default=0)
    src_sheet_name = db.Column(db.String(100))
    tgt_sheet_name = db.Column(db.String(100))
    header_columns = db.Column(db.Text)  # Stored as JSON
    skip_rows = db.Column(db.Text)  # Stored as JSON
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'), nullable=False)
    
    src_connection = db.relationship('Connection', foreign_keys=[src_connection_id])
    tgt_connection = db.relationship('Connection', foreign_keys=[tgt_connection_id])
    creator = db.relationship('User', backref='test_cases')

class TestExecution(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_case_id = db.Column(db.Integer, db.ForeignKey('test_case.id'), nullable=False)
    execution_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    status = db.Column(db.String(20))  # PENDING, RUNNING, PASSED, FAILED, ERROR
    duration = db.Column(db.Float)  # seconds
    records_compared = db.Column(db.Integer)
    mismatches_found = db.Column(db.Integer)
    error_message = db.Column(db.Text)
    log_file = db.Column(db.String(200))
    executed_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    test_case = db.relationship('TestCase', backref='executions')
    executor = db.relationship('User', backref='test_executions')

class TestMismatch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    execution_id = db.Column(db.Integer, db.ForeignKey('test_execution.id'), nullable=False)
    row_identifier = db.Column(db.String(500))  # Primary key value or row number
    column_name = db.Column(db.String(100))
    source_value = db.Column(db.Text)
    target_value = db.Column(db.Text)
    mismatch_type = db.Column(db.String(50))  # VALUE_MISMATCH, MISSING_IN_SOURCE, MISSING_IN_TARGET
    
    execution = db.relationship('TestExecution', backref='mismatches')

class ScheduledTest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_case_id = db.Column(db.Integer, db.ForeignKey('test_case.id'), nullable=False)
    schedule_type = db.Column(db.String(20))  # DAILY, WEEKLY, CUSTOM
    schedule_time = db.Column(db.String(10))  # HH:MM format
    schedule_days = db.Column(db.String(50))  # For weekly: 0-6 (Mon-Sun)
    cron_expression = db.Column(db.String(100))  # For custom schedules
    is_active = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    test_case = db.relationship('TestCase', backref='schedules')
    creator = db.relationship('User', foreign_keys=[created_by])

# Notification functions
def send_test_failure_notification(test_execution, recipients):
    """Send email notification for test failure"""
    try:
        test_case = test_execution.test_case
        
        msg = Message(
            f'DataQE Alert: Test Case {test_case.tcid} Failed',
            recipients=recipients
        )
        
        # Create HTML email body
        html_body = f"""
        <h2>Test Case Failure Notification</h2>
        <p>Test Case: <strong>{test_case.tcid} - {test_case.tc_name}</strong></p>
        <p>Table: {test_case.table_name}</p>
        <p>Type: {test_case.test_type}</p>
        <p>Status: <span style="color: red;">{test_execution.status}</span></p>
        <p>Execution Time: {test_execution.execution_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Duration: {test_execution.duration:.2f} seconds</p>
        <p>Records Compared: {test_execution.records_compared}</p>
        <p>Mismatches Found: {test_execution.mismatches_found}</p>
        
        {f'<p>Error Message: <code>{test_execution.error_message}</code></p>' if test_execution.error_message else ''}
        
        <p><a href="{url_for('execution_detail', execution_id=test_execution.id, _external=True)}">View Details</a></p>
        """
        
        msg.html = html_body
        mail.send(msg)
        
    except Exception as e:
        app.logger.error(f"Failed to send email notification: {str(e)}")

def read_file_with_multiple_encodings(file_path, encodings=None):
    """Try reading a file with multiple encodings until successful."""
    if encodings is None:
        encodings = ['utf-8', 'latin-1', 'windows-1252', 'ISO-8859-1']
    
    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                return f.read()
        except UnicodeDecodeError:
            continue
    
    # If all encodings fail, try binary mode and replace invalid chars
    with open(file_path, 'rb') as f:
        content = f.read()
        return content.decode('utf-8', errors='replace')
def is_binary_file(file_path):
    """Check if a file is binary or text."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            f.read(1024)  # Try to read as text
        return False  # If no error, it's a text file
    except UnicodeDecodeError:
        return True  # If decode error, it's likely a binary file

def safe_excel_preview(file_path, max_rows=5):
    """Generate a safe preview of Excel files with robust error handling"""
    # Get just the filename without path
    filename = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)
    
    # First try with direct binary reading to create a small preview table manually
    try:
        with open(file_path, 'rb') as f:
            # Check for Excel file signatures
            header = f.read(8)
            
            # Try our own simplified Excel reader
            import io
            import tempfile
            import subprocess
            
            # Try to convert to CSV using external tools if available
            try:
                with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as temp_file:
                    temp_csv_path = temp_file.name
                
                # Try using ssconvert (part of Gnumeric)
                try:
                    result = subprocess.run(['ssconvert', file_path, temp_csv_path], 
                                           capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        import pandas as pd
                        df = pd.read_csv(temp_csv_path, nrows=max_rows)
                        os.unlink(temp_csv_path)  # Delete temp file
                        return f"Excel file: {filename}\n\nPreview (first {max_rows} rows):\n{df.to_string()}"
                except (subprocess.SubprocessError, FileNotFoundError):
                    # ssconvert not available or failed
                    pass
                
                # If we reach here, try pandas with explicit engines
                try:
                    import pandas as pd
                    
                    # Try with automatic engine
                    df = pd.read_excel(file_path, nrows=max_rows, engine=None)
                    return f"Excel file: {filename}\n\nPreview (first {max_rows} rows):\n{df.to_string()}"
                except Exception as e1:
                    # Create a preview table with basic info
                    return f"""Excel file: {filename}
                            Size: {file_size} bytes
                            Format: {"XLSX (Office 2007+)" if filename.endswith('.xlsx') else "XLS (Office 97-2003)"}

                            This Excel file cannot be previewed directly. You can download and open it in Excel.
                            Error details: {str(e1)}"""
            except Exception as e:
                # Fall back to basic info
                return f"Excel file: {filename}\nSize: {file_size} bytes\nCould not generate preview. Try downloading the file."
    except Exception as e:
        # Last resort
        return f"Excel file: {filename}\nSize: {file_size} bytes\nCould not generate preview: {str(e)}"     


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

# Basic routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# Replace your existing logout and login routes with these updated versions

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user is None or not user.check_password(password):
            flash('Invalid username or password', 'error')
            return redirect(url_for('login'))
        
        login_user(user)
        flash(f'Welcome back, {user.username}!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    # Clear all flash messages on logout
    session.pop('_flashes', None)
    return redirect(url_for('index'))


from sqlalchemy import func

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin:
        # Admin dashboard
        projects = Project.query.all()
        users = User.query.all()
        recent_test_cases = TestCase.query.order_by(TestCase.created_at.desc()).limit(10).all()
        recent_executions = TestExecution.query.order_by(TestExecution.execution_time.desc()).limit(10).all()
        
        # Calculate overall statistics
        total_teams = Team.query.count()
        total_test_cases = TestCase.query.count()
        total_active_test_cases = TestCase.query.filter_by(test_yn='Y').count()
        
        # Get project test case counts using a single query
        project_test_counts = db.session.query(
            Project.id,
            func.count(TestCase.id).label('test_count')
        ).join(Team, Project.id == Team.project_id, isouter=True)\
         .join(TestCase, Team.id == TestCase.team_id, isouter=True)\
         .group_by(Project.id)\
         .all()
        
        # Convert to dictionary for easy access in template
        project_stats = {p.id: p.test_count for p in project_test_counts}
        
        return render_template('admin_dashboard.html', 
                            projects=projects, 
                            users=users, 
                            recent_test_cases=recent_test_cases,
                            recent_executions=recent_executions,
                            total_teams=total_teams,
                            total_active_test_cases=total_active_test_cases,
                            total_test_cases=total_test_cases,
                            project_stats=project_stats)
    else:
        # User dashboard
        team = current_user.team
        if team:
            test_cases = TestCase.query.filter_by(team_id=team.id).order_by(TestCase.created_at.desc()).all()
            active_test_cases = TestCase.query.filter_by(team_id=team.id, test_yn='Y').count()
            
            # Add execution statistics
            recent_executions = TestExecution.query.join(TestCase).filter(
                TestCase.team_id == team.id
            ).order_by(TestExecution.execution_time.desc()).limit(10).all()
            
            passed_tests = TestExecution.query.join(TestCase).filter(
                TestCase.team_id == team.id,
                TestExecution.status == 'PASSED'
            ).count()
            
            failed_tests = TestExecution.query.join(TestCase).filter(
                TestCase.team_id == team.id,
                TestExecution.status == 'FAILED'
            ).count()
            
            error_tests = TestExecution.query.join(TestCase).filter(
                TestCase.team_id == team.id,
                TestExecution.status == 'ERROR'
            ).count()
            
            return render_template('user_dashboard.html', 
                                team=team, 
                                test_cases=test_cases,
                                active_test_cases=active_test_cases,
                                recent_executions=recent_executions,
                                passed_tests=passed_tests,
                                failed_tests=failed_tests,
                                error_tests=error_tests)
        else:
            # User not assigned to a team
            flash('You are not assigned to a team yet.', 'warning')
            return render_template('user_dashboard.html', 
                                team=None, 
                                test_cases=[],
                                recent_executions=[],
                                passed_tests=0,
                                failed_tests=0,
                                error_tests=0)

# Project management routes
@app.route('/projects')
@login_required
def projects():
    if not current_user.is_admin:
        flash('Admin access required')
        return redirect(url_for('dashboard'))
    
    projects = Project.query.all()
    return render_template('projects.html', projects=projects)

@app.route('/project/new', methods=['GET', 'POST'])
@login_required
def new_project():
    if not current_user.is_admin:
        flash('Admin access required', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        folder_path = request.form.get('folder_path')
        
        # Validate folder path
        if not folder_path:
            flash('Project folder path is required', 'error')
            return render_template('project_new.html')
        
        # Create project folder structure
        project_folder = os.path.abspath(folder_path)
        input_folder = os.path.join(project_folder, 'input')
        output_folder = os.path.join(project_folder, 'output')
        
        try:
            # Create folders if they don't exist
            os.makedirs(input_folder, exist_ok=True)
            os.makedirs(output_folder, exist_ok=True)
            
            project = Project(
                name=name,
                description=description,
                folder_path=project_folder
            )
            db.session.add(project)
            db.session.commit()
            
            flash('Project created successfully', 'success')
            return redirect(url_for('projects'))
            
        except Exception as e:
            flash(f'Error creating project folders: {str(e)}', 'error')
            return render_template('project_new.html')
    
    return render_template('project_new.html')


@app.route('/project/<int:project_id>')
@login_required
def project_detail(project_id):
    if not current_user.is_admin:
        flash('Admin access required')
        return redirect(url_for('dashboard'))
    
    project = Project.query.get_or_404(project_id)
    teams = Team.query.filter_by(project_id=project_id).all()
    connections = Connection.query.filter_by(project_id=project_id).all()
    
    return render_template('project_detail.html', project=project, teams=teams, connections=connections)

# Team management routes
@app.route('/team/new/<int:project_id>', methods=['GET', 'POST'])
@login_required
def new_team(project_id):
    if not current_user.is_admin:
        flash('Admin access required')
        return redirect(url_for('dashboard'))
    
    project = Project.query.get_or_404(project_id)
    
    if request.method == 'POST':
        name = request.form.get('name')
        
        team = Team(name=name, project_id=project_id)
        db.session.add(team)
        db.session.commit()
        
        flash(f'Team {name} created successfully', 'success')
        return redirect(url_for('project_detail', project_id=project_id))
    
    return render_template('team_new.html', project=project)

# Replace the existing team_detail route with this updated version

@app.route('/team/<int:team_id>')
@login_required
def team_detail(team_id):
    team = Team.query.get_or_404(team_id)
    
    if not current_user.is_admin and current_user.team_id != team_id:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    users = User.query.filter_by(team_id=team_id).all()
    test_cases = TestCase.query.filter_by(team_id=team_id).all()
    
    # Get available users (users without a team or admin users)
    available_users = []
    if current_user.is_admin:
        available_users = User.query.filter(
            (User.team_id == None) | (User.is_admin == True)
        ).all()
    
    return render_template('team_detail.html', 
                          team=team, 
                          users=users, 
                          test_cases=test_cases,
                          available_users=available_users)

# Connection management routes
# Update your connection routes to allow team members to create connections

@app.route('/connection/new/<int:project_id>', methods=['GET', 'POST'])
@login_required
def new_connection(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Allow team members to create connections for their project
    if not current_user.is_admin:
        # Check if user is part of a team in this project
        if not current_user.team or current_user.team.project_id != project_id:
            flash('Access denied. You can only create connections for your team\'s project.', 'error')
            return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        server = request.form.get('server')
        database = request.form.get('database')
        warehouse = request.form.get('warehouse', '')
        role = request.form.get('role', '')
        is_excel = 'is_excel' in request.form
        
        connection = Connection(
            name=name,
            project_id=project_id,
            server=server,
            database=database,
            warehouse=warehouse,
            role=role,
            is_excel=is_excel
        )
        db.session.add(connection)
        db.session.commit()
        
        flash(f'Connection {name} created successfully', 'success')
        
        if current_user.is_admin:
            return redirect(url_for('project_detail', project_id=project_id))
        else:
            return redirect(url_for('team_detail', team_id=current_user.team_id))
    
    return render_template('connection_new.html', project=project)

# Add a route to list connections for team members
@app.route('/team/<int:team_id>/connections')
@login_required
def team_connections(team_id):
    team = Team.query.get_or_404(team_id)
    
    if not current_user.is_admin and current_user.team_id != team_id:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    connections = Connection.query.filter_by(project_id=team.project_id).all()
    
    return render_template('team_connections.html', team=team, connections=connections)

# Test case management routes - the core functionality
@app.route('/testcase/new', methods=['GET', 'POST'])
@login_required
def new_testcase():
    team_id = current_user.team_id
    
    if team_id is None and not current_user.is_admin:
        flash('You are not assigned to a team', 'error')
        return redirect(url_for('dashboard'))
    
    if current_user.is_admin and 'team_id' in request.args:
        team_id = int(request.args.get('team_id'))
    
    if team_id is None:
        flash('Team ID is required', 'error')
        return redirect(url_for('dashboard'))
    
    team = Team.query.get_or_404(team_id)
    project = team.project
    
    # Get connections for the project
    connections = Connection.query.filter_by(project_id=project.id).all()
    
    if request.method == 'POST':
        # Extract form data
        tcid = request.form.get('tcid')
        table_name = request.form.get('table_name')
        test_type = request.form.get('test_type')
        tc_name = request.form.get('tc_name')
        test_yn = request.form.get('test_yn') == 'on'
        src_connection_id = request.form.get('src_connection_id')
        tgt_connection_id = request.form.get('tgt_connection_id')
        
        # Use project input folder for SQL files
        project_input_folder = os.path.join(project.folder_path, 'input')
        
        # Process SQL files or connections
        src_data_file = None
        tgt_data_file = None
        
        if 'src_file' in request.files and request.files['src_file'].filename != '':
            src_file = request.files['src_file']
            src_filename = secure_filename(f"{tcid}_SRC_{src_file.filename}")
            src_filepath = os.path.join(project_input_folder, src_filename)
            src_file.save(src_filepath)
            src_data_file = src_filename
        elif 'src_query' in request.form and request.form.get('src_query', '').strip():
            src_query = request.form.get('src_query')
            src_filename = f"{tcid}_SRC.sql"
            src_filepath = os.path.join(project_input_folder, src_filename)
            with open(src_filepath, 'w') as f:
                f.write(src_query)
            src_data_file = src_filename
            
        if 'tgt_file' in request.files and request.files['tgt_file'].filename != '':
            tgt_file = request.files['tgt_file']
            tgt_filename = secure_filename(f"{tcid}_TGT_{tgt_file.filename}")
            tgt_filepath = os.path.join(project_input_folder, tgt_filename)
            tgt_file.save(tgt_filepath)
            tgt_data_file = tgt_filename
        elif 'tgt_query' in request.form and request.form.get('tgt_query', '').strip():
            tgt_query = request.form.get('tgt_query')
            tgt_filename = f"{tcid}_TGT.sql"
            tgt_filepath = os.path.join(project_input_folder, tgt_filename)
            with open(tgt_filepath, 'w') as f:
                f.write(tgt_query)
            tgt_data_file = tgt_filename
        
        # Handle json fields
        pk_columns = json.dumps(request.form.get('pk_columns', '').split(','))
        date_fields = json.dumps(request.form.get('date_fields', '').split(','))
        percentage_fields = json.dumps(request.form.get('percentage_fields', '').split(','))
        header_columns = json.dumps(request.form.get('header_columns', '').split(','))
        skip_rows = json.dumps(request.form.get('skip_rows', '').split(','))
        
        # Create test case
        test_case = TestCase(
            tcid=tcid,
            table_name=table_name,
            test_type=test_type,
            tc_name=tc_name,
            test_yn='Y' if test_yn else 'N',
            src_data_file=src_data_file,
            src_connection_id=src_connection_id,
            tgt_data_file=tgt_data_file,
            tgt_connection_id=tgt_connection_id,
            filters=request.form.get('filters', ''),
            delimiter=request.form.get('delimiter', ','),
            pk_columns=pk_columns,
            date_fields=date_fields,
            percentage_fields=percentage_fields,
            threshold_percentage=float(request.form.get('threshold_percentage', 0)),
            src_sheet_name=request.form.get('src_sheet_name', ''),
            tgt_sheet_name=request.form.get('tgt_sheet_name', ''),
            header_columns=header_columns,
            skip_rows=skip_rows,
            created_by=current_user.id,
            team_id=team_id
        )
        
        db.session.add(test_case)
        db.session.commit()
        
        flash(f'Test case {tcid} created successfully', 'success')
        
        if current_user.is_admin:
            return redirect(url_for('team_detail', team_id=team_id))
        else:
            return redirect(url_for('dashboard'))
    
    return render_template('testcase_new.html', team=team, connections=connections)


# Fixed testcase_detail route
# Complete fix for both testcase routes

@app.route('/testcase/<int:testcase_id>')
@login_required
def testcase_detail(testcase_id):
    test_case = TestCase.query.get_or_404(testcase_id)
    
    # Check permissions
    if not current_user.is_admin and current_user.team_id != test_case.team_id:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    # Get the team and project
    team = test_case.team
    project = team.project
    
    # Use project input folder if folder_path exists
    if hasattr(project, 'folder_path') and project.folder_path:
        project_input_folder = os.path.join(project.folder_path, 'input')
    else:
        project_input_folder = app.config.get('SQL_FOLDER', os.path.join('static', 'sql_files'))
    
    # Read file content if available
    src_sql = None
    tgt_sql = None
    
    if test_case.src_data_file:
        try:
            file_path = os.path.join(project_input_folder, test_case.src_data_file)
            
            # Check if this is Excel or binary file
            if test_case.src_data_file.endswith(('.xlsx', '.xls', '.xlsm')):
                # For Excel files, use our safe preview function
                src_sql = safe_excel_preview(file_path)
            else:
                # For text files, show content
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    src_sql = f.read()
        except Exception as e:
            src_sql = f"Could not read source file: {str(e)}"
    
    if test_case.tgt_data_file:
        try:
            file_path = os.path.join(project_input_folder, test_case.tgt_data_file)
            
            # Check if this is Excel or binary file
            if test_case.tgt_data_file.endswith(('.xlsx', '.xls', '.xlsm')):
                # For Excel files, use our safe preview function
                tgt_sql = safe_excel_preview(file_path)
            else:
                # For text files, show content
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    tgt_sql = f.read()
        except Exception as e:
            tgt_sql = f"Could not read target file: {str(e)}"
    
    # Sort executions by time (latest first)
    sorted_executions = sorted(
        test_case.executions, 
        key=lambda x: x.execution_time if x.execution_time else datetime.min, 
        reverse=True
    )
    
    # Pass variables to template
    return render_template('testcase_detail.html', 
                          test_case=test_case,
                          team=team,
                          project=project,
                          src_sql=src_sql,
                          tgt_sql=tgt_sql,
                          sorted_executions=sorted_executions[:5])

@app.route('/testcase/edit/<int:testcase_id>', methods=['GET', 'POST'])
@login_required
def edit_testcase(testcase_id):
    test_case = TestCase.query.get_or_404(testcase_id)
    
    if not current_user.is_admin and current_user.team_id != test_case.team_id:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    team = test_case.team
    project = team.project
    connections = Connection.query.filter_by(project_id=project.id).all()
    
    # Use project input folder if folder_path exists
    if hasattr(project, 'folder_path') and project.folder_path:
        project_input_folder = os.path.join(project.folder_path, 'input')
    else:
        project_input_folder = app.config.get('SQL_FOLDER', os.path.join('static', 'sql_files'))
    
    # Read SQL content if available
    src_sql = None
    tgt_sql = None
    
    if test_case.src_data_file:
        try:
            file_path = os.path.join(project_input_folder, test_case.src_data_file)
            src_sql = read_file_with_multiple_encodings(file_path)
        except Exception as e:
            src_sql = ""
    
    if test_case.tgt_data_file:
        try:
            file_path = os.path.join(project_input_folder, test_case.tgt_data_file)
            tgt_sql = read_file_with_multiple_encodings(file_path)
        except Exception as e:
            tgt_sql = ""
    
    if request.method == 'POST':
        try:
            # Update test case
            test_case.tcid = request.form.get('tcid')
            test_case.table_name = request.form.get('table_name')
            test_case.test_type = request.form.get('test_type')
            test_case.tc_name = request.form.get('tc_name')
            test_case.test_yn = 'Y' if request.form.get('test_yn') == 'on' else 'N'
            
            # Update connections
            test_case.src_connection_id = request.form.get('src_connection_id') or None
            test_case.tgt_connection_id = request.form.get('tgt_connection_id') or None
            
            # Process SQL files or queries
            if 'src_file' in request.files and request.files['src_file'].filename != '':
                src_file = request.files['src_file']
                src_filename = secure_filename(f"{test_case.tcid}_SRC_{src_file.filename}")
                src_filepath = os.path.join(project_input_folder, src_filename)
                os.makedirs(os.path.dirname(src_filepath), exist_ok=True)
                src_file.save(src_filepath)
                test_case.src_data_file = src_filename
            elif 'src_query' in request.form and request.form.get('src_query', '').strip():
                src_query = request.form.get('src_query')
                if test_case.src_data_file:
                    src_filepath = os.path.join(project_input_folder, test_case.src_data_file)
                else:
                    src_filename = f"{test_case.tcid}_SRC.sql"
                    src_filepath = os.path.join(project_input_folder, src_filename)
                    test_case.src_data_file = src_filename
                
                os.makedirs(os.path.dirname(src_filepath), exist_ok=True)
                with open(src_filepath, 'w') as f:
                    f.write(src_query)
            
            if 'tgt_file' in request.files and request.files['tgt_file'].filename != '':
                tgt_file = request.files['tgt_file']
                tgt_filename = secure_filename(f"{test_case.tcid}_TGT_{tgt_file.filename}")
                tgt_filepath = os.path.join(project_input_folder, tgt_filename)
                os.makedirs(os.path.dirname(tgt_filepath), exist_ok=True)
                tgt_file.save(tgt_filepath)
                test_case.tgt_data_file = tgt_filename
            elif 'tgt_query' in request.form and request.form.get('tgt_query', '').strip():
                tgt_query = request.form.get('tgt_query')
                if test_case.tgt_data_file:
                    tgt_filepath = os.path.join(project_input_folder, test_case.tgt_data_file)
                else:
                    tgt_filename = f"{test_case.tcid}_TGT.sql"
                    tgt_filepath = os.path.join(project_input_folder, tgt_filename)
                    test_case.tgt_data_file = tgt_filename
                
                os.makedirs(os.path.dirname(tgt_filepath), exist_ok=True)
                with open(tgt_filepath, 'w') as f:
                    f.write(tgt_query)
            
            # Handle json fields - clean empty values
            pk_columns = [x.strip() for x in request.form.get('pk_columns', '').split(',') if x.strip()]
            date_fields = [x.strip() for x in request.form.get('date_fields', '').split(',') if x.strip()]
            percentage_fields = [x.strip() for x in request.form.get('percentage_fields', '').split(',') if x.strip()]
            header_columns = [x.strip() for x in request.form.get('header_columns', '').split(',') if x.strip()]
            skip_rows = [x.strip() for x in request.form.get('skip_rows', '').split(',') if x.strip()]
            
            test_case.pk_columns = json.dumps(pk_columns)
            test_case.date_fields = json.dumps(date_fields)
            test_case.percentage_fields = json.dumps(percentage_fields)
            test_case.header_columns = json.dumps(header_columns)
            test_case.skip_rows = json.dumps(skip_rows)
            
            # Update other fields
            test_case.filters = request.form.get('filters', '')
            test_case.delimiter = request.form.get('delimiter', ',')
            test_case.threshold_percentage = float(request.form.get('threshold_percentage', 0))
            test_case.src_sheet_name = request.form.get('src_sheet_name', '')
            test_case.tgt_sheet_name = request.form.get('tgt_sheet_name', '')
            
            db.session.commit()
            
            flash(f'Test case {test_case.tcid} updated successfully', 'success')
            return redirect(url_for('testcase_detail', testcase_id=testcase_id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating test case: {str(e)}', 'error')
            return redirect(url_for('edit_testcase', testcase_id=testcase_id))
    
    # Make sure to pass all required variables to the template
    return render_template('testcase_edit.html', 
                          test_case=test_case, 
                          team=team,
                          project=project,
                          connections=connections,
                          src_sql=src_sql,
                          tgt_sql=tgt_sql)

@app.route('/download/testcase/<int:testcase_id>/<source_or_target>')
@login_required
def download_testcase_file(testcase_id, source_or_target):
    """Download source or target file for a test case"""
    test_case = TestCase.query.get_or_404(testcase_id)
    
    # Check permissions
    if not current_user.is_admin and current_user.team_id != test_case.team_id:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    # Get the file path
    project = test_case.team.project
    project_input_folder = os.path.join(project.folder_path, 'input')
    
    if source_or_target == 'source':
        file_name = test_case.src_data_file
    elif source_or_target == 'target':
        file_name = test_case.tgt_data_file
    else:
        flash('Invalid file type requested', 'error')
        return redirect(url_for('testcase_detail', testcase_id=test_case.id))
    
    if not file_name:
        flash(f'No {source_or_target} file available', 'error')
        return redirect(url_for('testcase_detail', testcase_id=test_case.id))
    
    file_path = os.path.join(project_input_folder, file_name)
    
    if not os.path.exists(file_path):
        flash(f'{source_or_target.capitalize()} file not found', 'error')
        return redirect(url_for('testcase_detail', testcase_id=test_case.id))
    
    # Determine content type
    mimetype = None
    if file_name.endswith('.xlsx'):
        mimetype = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    elif file_name.endswith('.xls'):
        mimetype = 'application/vnd.ms-excel'
    elif file_name.endswith('.csv'):
        mimetype = 'text/csv'
    elif file_name.endswith('.sql'):
        mimetype = 'application/sql'
    else:
        mimetype = 'application/octet-stream'
    
    return send_file(
        file_path,
        as_attachment=True,
        download_name=file_name,
        mimetype=mimetype
    )

# API for datacompare framework
@app.route('/api/testcases/<int:team_id>')
def api_testcases(team_id):
    team = Team.query.get_or_404(team_id)
    project = team.project
    test_cases = TestCase.query.filter_by(team_id=team_id, test_yn='Y').all()
    
    # Use project folders
    project_input_folder = os.path.join(project.folder_path, 'input')
    project_output_folder = os.path.join(project.folder_path, 'output')
    
    result = []
    for tc in test_cases:
        # Get SQL content
        src_sql = None
        tgt_sql = None
        
        if tc.src_data_file:
            try:
                src_path = os.path.join(project_input_folder, tc.src_data_file)
                with open(src_path, 'r') as f:
                    src_sql = f.read()
            except:
                src_sql = None
        
        if tc.tgt_data_file:
            try:
                tgt_path = os.path.join(project_input_folder, tc.tgt_data_file)
                with open(tgt_path, 'r') as f:
                    tgt_sql = f.read()
            except:
                tgt_sql = None
        
        # Get connection details
        src_conn = None
        tgt_conn = None
        
        if tc.src_connection:
            src_conn = {
                'name': tc.src_connection.name,
                'server': tc.src_connection.server,
                'database': tc.src_connection.database,
                'warehouse': tc.src_connection.warehouse,
                'role': tc.src_connection.role,
                'is_excel': tc.src_connection.is_excel
            }
        
        if tc.tgt_connection:
            tgt_conn = {
                'name': tc.tgt_connection.name,
                'server': tc.tgt_connection.server,
                'database': tc.tgt_connection.database,
                'warehouse': tc.tgt_connection.warehouse,
                'role': tc.tgt_connection.role,
                'is_excel': tc.tgt_connection.is_excel
            }
        
        # Format test case for API
        test_case = {
            'tcid': tc.tcid,
            'table': tc.table_name,
            'test_type': tc.test_type,
            'tc_name': tc.tc_name,
            'src_data': src_sql,
            'src_connection': src_conn,
            'tgt_data': tgt_sql,
            'tgt_connection': tgt_conn,
            'filters': tc.filters,
            'delimiter': tc.delimiter,
            'pk_columns': json.loads(tc.pk_columns) if tc.pk_columns else [],
            'date_fields': json.loads(tc.date_fields) if tc.date_fields else [],
            'percentage_fields': json.loads(tc.percentage_fields) if tc.percentage_fields else [],
            'threshold_percentage': tc.threshold_percentage,
            'src_sheet_name': tc.src_sheet_name,
            'tgt_sheet_name': tc.tgt_sheet_name,
            'header_columns': json.loads(tc.header_columns) if tc.header_columns else [],
            'skip_rows': json.loads(tc.skip_rows) if tc.skip_rows else [],
            'output_folder': project_output_folder  # Add output folder path
        }
        
        result.append(test_case)
    
    return json.dumps(result)

@app.cli.command('init-db')
def init_db_command():
    db.create_all()
    
    # Check if admin user exists
    admin = User.query.filter_by(username='admin').first()
    if admin is None:
        admin = User(username='admin', email='admin@example.com', is_admin=True)
        admin.set_password('admin')  # Change this in production
        db.session.add(admin)
        db.session.commit()
        print('Admin user created')
    
    print('Database initialized')

# Add these routes to your testquerypairs_app.py file

# User Management routes
@app.route('/users')
@login_required
def users():
    if not current_user.is_admin:
        flash('Admin access required')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/user/new', methods=['GET', 'POST'])
@login_required
def new_user():
    if not current_user.is_admin:
        flash('Admin access required')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        team_id = request.form.get('team_id')
        is_admin = 'is_admin' in request.form
        
        # Check if username or email already exists
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or email already exists', 'error')
            return redirect(url_for('new_user'))
        
        user = User(
            username=username,
            email=email,
            team_id=team_id if team_id else None,
            is_admin=is_admin
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash(f'User {username} created successfully')
        return redirect(url_for('users'))
    
    projects = Project.query.all()
    return render_template('user_new.html', projects=projects)

@app.route('/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        flash('Admin access required')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        team_id = request.form.get('team_id')
        is_admin = 'is_admin' in request.form
        
        # Check if username or email already exists (excluding current user)
        existing_user = User.query.filter(
            ((User.username == username) | (User.email == email)) & 
            (User.id != user_id)
        ).first()
        
        if existing_user:
            flash('Username or email already exists', 'error')
            return redirect(url_for('edit_user', user_id=user_id))
        
        user.username = username
        user.email = email
        user.team_id = team_id if team_id else None
        user.is_admin = is_admin
        
        if password:  # Only update password if provided
            user.set_password(password)
        
        db.session.commit()
        
        flash(f'User {username} updated successfully')
        return redirect(url_for('users'))
    
    projects = Project.query.all()
    return render_template('user_edit.html', user=user, projects=projects)

@app.route('/user/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('Admin access required')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    
    # Don't allow deleting yourself
    if user.id == current_user.id:
        flash('You cannot delete your own account', 'error')
        return redirect(url_for('users'))
    
    # Don't allow deleting the last admin
    if user.is_admin:
        admin_count = User.query.filter_by(is_admin=True).count()
        if admin_count <= 1:
            flash('Cannot delete the last admin user', 'error')
            return redirect(url_for('users'))
    
    username = user.username
    db.session.delete(user)
    db.session.commit()
    
    flash(f'User {username} deleted successfully')
    return redirect(url_for('users'))

# Update the team detail route to show team members
@app.route('/team/<int:team_id>/add_member', methods=['POST'])
@login_required
def add_team_member(team_id):
    if not current_user.is_admin:
        flash('Admin access required')
        return redirect(url_for('dashboard'))
    
    team = Team.query.get_or_404(team_id)
    user_id = request.form.get('user_id')
    
    if user_id:
        user = User.query.get(user_id)
        if user:
            user.team_id = team_id
            db.session.commit()
            flash(f'User {user.username} added to team {team.name}')
        else:
            flash('User not found', 'error')
    
    return redirect(url_for('team_detail', team_id=team_id))

@app.route('/team/<int:team_id>/remove_member/<int:user_id>', methods=['POST'])
@login_required
def remove_team_member(team_id, user_id):
    if not current_user.is_admin:
        flash('Admin access required')
        return redirect(url_for('dashboard'))
    
    team = Team.query.get_or_404(team_id)
    user = User.query.get_or_404(user_id)
    
    if user.team_id == team_id:
        user.team_id = None
        db.session.commit()
        flash(f'User {user.username} removed from team {team.name}')
    
    return redirect(url_for('team_detail', team_id=team_id))

@app.route('/testcase/<int:testcase_id>/execute', methods=['GET', 'POST'])
@login_required
def execute_testcase_ui(testcase_id):
    """UI for executing a test case"""
    test_case = TestCase.query.get_or_404(testcase_id)
    
    # Check permissions
    if not current_user.is_admin and current_user.team_id != test_case.team_id:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    # For GET requests, display the execution page
    if request.method == 'GET':
        return render_template('execute_testcase.html', test_case=test_case)
    
    # For POST requests (form submission), redirect to the API endpoint
    # This will avoid page reload issues
    return redirect(url_for('execute_test', test_case_id=testcase_id))


@app.route('/api/execute/<int:test_case_id>', methods=['POST'])
@login_required
def execute_test(test_case_id):
    """Execute a test case and store results"""
    test_case = TestCase.query.get_or_404(test_case_id)
    
    # Check permissions
    if not current_user.is_admin and current_user.team_id != test_case.team_id:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': 'Access denied'}), 403
        else:
            flash('Access denied', 'error')
            return redirect(url_for('dashboard'))
    
    # Get optional overrides from form
    src_sheet_override = request.form.get('src_sheet_override')
    tgt_sheet_override = request.form.get('tgt_sheet_override')
    debug_mode = 'debug_mode' in request.form
    
    # Apply overrides if provided
    if src_sheet_override and test_case.src_sheet_name != src_sheet_override:
        test_case.src_sheet_name = src_sheet_override
    
    if tgt_sheet_override and test_case.tgt_sheet_name != tgt_sheet_override:
        test_case.tgt_sheet_name = tgt_sheet_override
    
    # Create execution record
    execution = TestExecution(
        test_case_id=test_case_id,
        status='PENDING',
        executed_by=current_user.id
    )
    db.session.add(execution)
    db.session.commit()
    
    # Start execution
    try:
        execution.status = 'RUNNING'
        db.session.commit()
        
        # Execute test case using the bridge
        result = dataqa_bridge.execute_test_case(test_case, execution)
        
        # Update execution with results
        execution.end_time = datetime.utcnow()
        execution.duration = (execution.end_time - execution.execution_time).total_seconds()
        execution.status = result.get('status', 'ERROR')
        execution.records_compared = result.get('records_compared', 0)
        execution.mismatches_found = result.get('mismatches_found', 0)
        execution.log_file = result.get('log_file')
        
        if result.get('status') == 'FAILED':
            execution.error_message = result.get('error_message')
            
            # Store mismatches if provided
            if result.get('mismatches'):
                for mismatch in result.get('mismatches', []):
                    mismatch_record = TestMismatch(
                        execution_id=execution.id,
                        row_identifier=mismatch.get('row_id', 'Unknown'),
                        column_name=mismatch.get('column', 'Unknown'),
                        source_value=str(mismatch.get('source_value', '')),
                        target_value=str(mismatch.get('target_value', '')),
                        mismatch_type=mismatch.get('type', 'VALUE_MISMATCH')
                    )
                    db.session.add(mismatch_record)
        
        db.session.commit()
        
        # For AJAX requests, return JSON
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'execution_id': execution.id,
                'status': execution.status,
                'redirect_url': url_for('execution_detail', execution_id=execution.id)
            })
        
        # For regular requests, redirect to execution detail page
        flash(f'Test execution {execution.status.lower()}', 
              'success' if execution.status == 'PASSED' else 'danger')
        return redirect(url_for('execution_detail', execution_id=execution.id))
        
    except Exception as e:
        execution.status = 'ERROR'
        execution.error_message = str(e)
        execution.end_time = datetime.utcnow()
        execution.duration = (execution.end_time - execution.execution_time).total_seconds()
        db.session.commit()
        
        # For AJAX requests, return JSON
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': str(e)}), 500
        
        # For regular requests, redirect with error
        flash(f'Error executing test case: {str(e)}', 'error')
        return redirect(url_for('testcase_detail', testcase_id=test_case_id))


def execute_test_case_logic(test_case, execution):
    """Execute test case using the data validation framework"""
    try:
        # Use the bridge to execute the test
        result = dataqa_bridge.execute_test_case(test_case, execution)
        
        # Process mismatches if any
        if result['status'] == 'FAILED' and result.get('log_file'):
            # Read mismatches from output file
            try:
                mismatch_df = pd.read_excel(result['log_file'], sheet_name='Mismatch Analysis')
                
                # Convert to format expected by DataQE
                mismatches = []
                for idx, row in mismatch_df.iterrows():
                    mismatch = {
                        'row_id': str(idx),
                        'column': row.get('Column', 'Unknown'),
                        'source_value': str(row.get('Source_Value', '')),
                        'target_value': str(row.get('Target_Value', '')),
                        'type': row.get('__mismatch_type', 'VALUE_MISMATCH')
                    }
                    mismatches.append(mismatch)
                
                result['mismatches'] = mismatches[:100]  # Limit to first 100 mismatches
            except Exception as e:
                print(f"Error reading mismatches: {e}")
                result['mismatches'] = []
        
        return result
        
    except Exception as e:
        return {
            'status': 'ERROR',
            'error_message': str(e),
            'records_compared': 0,
            'mismatches_found': 0,
            'mismatches': []
        }

## 4. Results Dashboard Routes

@app.route('/execution/<int:execution_id>')
@login_required
def execution_detail(execution_id):
    """View execution details and mismatches"""
    execution = TestExecution.query.get_or_404(execution_id)
    
    # Check permissions
    if not current_user.is_admin and current_user.team_id != execution.test_case.team_id:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    mismatches = TestMismatch.query.filter_by(execution_id=execution_id).all()
    
    # Check if there's a log file to display
    log_content = None
    if execution.log_file and os.path.exists(execution.log_file):
        try:
            with open(execution.log_file, 'r') as f:
                log_content = f.read()
        except:
            log_content = "Error reading log file"
    
    # Check if there's a debug log
    debug_log = None
    if os.path.exists('debug_log.txt'):
        try:
            with open('debug_log.txt', 'r') as f:
                log_lines = f.readlines()
                # Find the section for this execution
                relevant_lines = []
                collecting = False
                for line in log_lines:
                    if f"Test Case ID: {execution.test_case.tcid}" in line and "New Execution" in line:
                        collecting = True
                        relevant_lines = [line]
                    elif collecting and "--- Execution" in line:
                        relevant_lines.append(line)
                        collecting = False
                    elif collecting:
                        relevant_lines.append(line)
                
                if relevant_lines:
                    debug_log = ''.join(relevant_lines)
        except:
            debug_log = "Error reading debug log"
    
    return render_template('execution_detail.html', 
                         execution=execution, 
                         mismatches=mismatches,
                         log_content=log_content,
                         debug_log=debug_log)


@app.route('/executions')
@login_required
def execution_history():
    """View execution history"""
    page = request.args.get('page', 1, type=int)
    
    if current_user.is_admin:
        executions = TestExecution.query.order_by(TestExecution.execution_time.desc()).paginate(page=page, per_page=20)
    else:
        executions = TestExecution.query.join(TestCase).filter(
            TestCase.team_id == current_user.team_id
        ).order_by(TestExecution.execution_time.desc()).paginate(page=page, per_page=20)
    
    return render_template('execution_history.html', executions=executions)

@app.route('/results-dashboard')
@login_required
def results_dashboard():
    """Results dashboard with summary statistics"""
    if current_user.is_admin:
        total_executions = TestExecution.query.count()
        passed_executions = TestExecution.query.filter_by(status='PASSED').count()
        failed_executions = TestExecution.query.filter_by(status='FAILED').count()
        error_executions = TestExecution.query.filter_by(status='ERROR').count()
        
        recent_executions = TestExecution.query.order_by(
            TestExecution.execution_time.desc()
        ).limit(10).all()
        
        # Get test cases with most failures
        from sqlalchemy import func
        problem_tests = db.session.query(
            TestCase,
            func.count(TestExecution.id).label('failure_count')
        ).join(TestExecution).filter(
            TestExecution.status == 'FAILED'
        ).group_by(TestCase).order_by(
            func.count(TestExecution.id).desc()
        ).limit(5).all()
        
    else:
        # Filter by team for non-admin users
        total_executions = TestExecution.query.join(TestCase).filter(
            TestCase.team_id == current_user.team_id
        ).count()
        
        passed_executions = TestExecution.query.join(TestCase).filter(
            TestCase.team_id == current_user.team_id,
            TestExecution.status == 'PASSED'
        ).count()
        
        failed_executions = TestExecution.query.join(TestCase).filter(
            TestCase.team_id == current_user.team_id,
            TestExecution.status == 'FAILED'
        ).count()
        
        error_executions = TestExecution.query.join(TestCase).filter(
            TestCase.team_id == current_user.team_id,
            TestExecution.status == 'ERROR'
        ).count()
        
        recent_executions = TestExecution.query.join(TestCase).filter(
            TestCase.team_id == current_user.team_id
        ).order_by(TestExecution.execution_time.desc()).limit(10).all()
        
        # Get test cases with most failures for team
        from sqlalchemy import func
        problem_tests = db.session.query(
            TestCase,
            func.count(TestExecution.id).label('failure_count')
        ).join(TestExecution).filter(
            TestCase.team_id == current_user.team_id,
            TestExecution.status == 'FAILED'
        ).group_by(TestCase).order_by(
            func.count(TestExecution.id).desc()
        ).limit(5).all()
    
    return render_template('results_dashboard.html',
                         total_executions=total_executions,
                         passed_executions=passed_executions,
                         failed_executions=failed_executions,
                         error_executions=error_executions,
                         recent_executions=recent_executions,
                         problem_tests=problem_tests)


# Add this route to your dataqe_app.py file

@app.route('/execution/<int:execution_id>/download_log')
@login_required
def download_log(execution_id):
    """Download execution log file"""
    execution = TestExecution.query.get_or_404(execution_id)
    
    # Check permissions
    if not current_user.is_admin and current_user.team_id != execution.test_case.team_id:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    if not execution.log_file or not os.path.exists(execution.log_file):
        flash('Log file not found', 'error')
        return redirect(url_for('execution_detail', execution_id=execution_id))
    
    # Determine the filename for the download
    filename = f"{execution.test_case.tcid}_execution_{execution_id}_{execution.execution_time.strftime('%Y%m%d')}.xlsx"
    
    # Check if it's an Excel file
    if execution.log_file.endswith('.xlsx'):
        return send_file(
            execution.log_file,
            as_attachment=True,
            download_name=filename,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
    else:
        # For text files
        return send_file(
            execution.log_file,
            as_attachment=True,
            download_name=filename.replace('.xlsx', '.txt'),
            mimetype='text/plain'
        )

## 5. Basic Scheduling Functionality


def run_scheduled_test(test_case_id):
    """Run a scheduled test"""
    with app.app_context():
        test_case = TestCase.query.get(test_case_id)
        if test_case and test_case.test_yn == 'Y':
            # Create system user for scheduled executions
            system_user = User.query.filter_by(username='system').first()
            if not system_user:
                system_user = User(username='system', email='system@dataqe.local', is_admin=True)
                system_user.set_password(str(uuid.uuid4()))  # Random password
                db.session.add(system_user)
                db.session.commit()
            
            # Execute test
            execution = TestExecution(
                test_case_id=test_case_id,
                status='PENDING',
                executed_by=system_user.id
            )
            db.session.add(execution)
            db.session.commit()
            
            # Execute test logic (simplified)
            result = execute_test_case_logic(test_case, execution)
            
            # Update execution with results
            execution.end_time = datetime.utcnow()
            execution.duration = (execution.end_time - execution.execution_time).total_seconds()
            execution.status = result['status']
            execution.records_compared = result.get('records_compared', 0)
            execution.mismatches_found = result.get('mismatches_found', 0)
            
            if result['status'] == 'FAILED' and test_case.team:
                recipients = [user.email for user in test_case.team.users if user.email]
                send_test_failure_notification(execution, recipients)
            
            db.session.commit()

@app.route('/schedule/create/<int:test_case_id>', methods=['GET', 'POST'])
@login_required
def create_schedule(test_case_id):
    test_case = TestCase.query.get_or_404(test_case_id)
    
    if not current_user.is_admin and current_user.team_id != test_case.team_id:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        schedule_type = request.form.get('schedule_type')
        schedule_time = request.form.get('schedule_time')
        schedule_days = request.form.get('schedule_days', '')
        
        schedule = ScheduledTest(
            test_case_id=test_case_id,
            schedule_type=schedule_type,
            schedule_time=schedule_time,
            schedule_days=schedule_days,
            created_by=current_user.id
        )
        
        # Create cron expression based on schedule type
        hour, minute = schedule_time.split(':')
        
        if schedule_type == 'DAILY':
            trigger = CronTrigger(hour=int(hour), minute=int(minute))
        elif schedule_type == 'WEEKLY':
            days = schedule_days.split(',')
            trigger = CronTrigger(day_of_week=','.join(days), hour=int(hour), minute=int(minute))
        
        # Add job to scheduler
        job_id = f'test_{test_case_id}_{schedule.id}'
        scheduler.add_job(
            func=run_scheduled_test,
            trigger=trigger,
            args=[test_case_id],
            id=job_id,
            replace_existing=True
        )
        
        db.session.add(schedule)
        db.session.commit()
        
        flash('Schedule created successfully')
        return redirect(url_for('testcase_detail', testcase_id=test_case_id))
    
    return render_template('create_schedule.html', test_case=test_case)

@app.route('/debug/last-execution')
@login_required
def debug_last_execution():
    execution = TestExecution.query.order_by(TestExecution.execution_time.desc()).first()
    if execution:
        return jsonify({
            'id': execution.id,
            'test_case_id': execution.test_case_id,
            'status': execution.status,
            'error_message': execution.error_message,
            'execution_time': execution.execution_time.isoformat() if execution.execution_time else None,
            'end_time': execution.end_time.isoformat() if execution.end_time else None
        })
    return jsonify({'error': 'No executions found'})

# Add to your CLI commands
@app.cli.command('init-db')
def init_db_command():
    """Initialize the database."""
    db.create_all()
    
    # Check if admin user exists
    admin = User.query.filter_by(username='admin').first()
    if admin is None:
        admin = User(username='admin', email='admin@example.com', is_admin=True)
        admin.set_password('admin')  # Change this in production
        db.session.add(admin)
        db.session.commit()
        print('Admin user created')
    
    print('Database initialized')

@app.cli.command('update-db')
def update_db_command():
    """Update database with new tables"""
    db.create_all()
    print('Database updated with new tables')

if __name__ == '__main__':
    app.run(debug=True)