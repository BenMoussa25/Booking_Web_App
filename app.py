from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
import os
from functools import wraps
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from flask import send_file
from io import BytesIO
from openpyxl import Workbook
from flask_migrate import Migrate
from flask_mail import Mail, Message


app = Flask(__name__)


# Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Example with Gmail
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'cyberspherecongress@gmail.com'  # Your email
app.config['MAIL_PASSWORD'] = 'ylvu rngx qwnr awwq'  # Your email password or app password
app.config['MAIL_DEFAULT_SENDER'] = 'cyberspherecongress@gmail.com'
mail = Mail(app)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '8aeff28f748dc1f91c1692db1684d313')
app.config['ADMIN_TOKEN'] = os.environ.get('ADMIN_TOKEN', 'a28d54cd5b19e8af9f072c1879cb73a5')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'cybersphere.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'future': True}
app.config['ADMIN_VERIFY_TIMEOUT'] = 1800



db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

migrate = Migrate(app, db)



# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'))
    is_team_leader = db.Column(db.Boolean, default=False)
    bookings = db.relationship('Booking', backref='user', lazy=True)

class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    members = db.relationship('User', backref='team', lazy=True, foreign_keys='User.team_id')
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'))
    event = db.relationship('Event', backref='teams')
    leader = db.relationship('User', foreign_keys=[created_by])

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(100), nullable=False)
    event_type = db.Column(db.String(20), nullable=False)  # 'workshop' or 'competition'
    max_participants = db.Column(db.Integer, nullable=False, default=20)  # Only for workshops
    max_teams = db.Column(db.Integer, default=0)  # Only for competitions
    team_size = db.Column(db.Integer, default=0)   # Only for competitions
    current_participants = db.Column(db.Integer, default=0)  # Only for workshops
    current_teams = db.Column(db.Integer, default=0)  # Only for competitions
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    bookings = db.relationship('Booking', backref='event', lazy=True)
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.start_time and self.end_time and self.start_time >= self.end_time:
            raise ValueError("End time must be after start time")

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    booking_time = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    status = db.Column(db.String(20), default='pending')
    is_approved = db.Column(db.Boolean, default=False)

def initialize_data():
    with app.app_context():
        db.create_all()
        
        # Create admin if none exists
        if not User.query.filter_by(is_admin=True).first():
            admin = User(
                username='admin',
                email='admin@example.com',
                password=generate_password_hash(os.getenv('ADMIN_PASSWORD', '123')),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            app.logger.info("Admin account created")

# Call this when the app starts
initialize_data()


def has_overlapping_workshop(user_id, new_event):
    """Check if user has any workshops that overlap with the new event"""
    # Get all user's confirmed or pending workshop bookings
    user_bookings = Booking.query.filter(
        Booking.user_id == user_id,
        Booking.status.in_(['confirmed', 'pending']),
        Booking.event.has(event_type='workshop')
    ).all()

    for booking in user_bookings:
        existing_event = booking.event
        # Check if events overlap
        if (new_event.start_time < existing_event.end_time and 
            new_event.end_time > existing_event.start_time):
            return True
    return False

def send_booking_confirmation(user, event):
    try:
        msg = Message(
            subject=f"Booking Confirmation: {event.name}",
            recipients=[user.email],
            html=render_template('email/booking_confirmation.html', user=user, event=event)
        )
        mail.send(msg)
        app.logger.info(f"Confirmation email sent to {user.email}")
    except Exception as e:
        app.logger.error(f"Failed to send confirmation email: {str(e)}")

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Helper functions
def is_admin():
    """Check if current user is admin"""
    if not current_user.is_authenticated:
        return False
    user = db.session.get(User, current_user.id)
    return user and user.is_admin

def admin_required(f):
    """Decorator to require admin access"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_admin():
            flash('Admin access required', 'danger')
            return redirect(url_for('index'))
        if not session.get('admin_verified'):
            return redirect(url_for('admin_verify'))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def check_admin_verification():
    """Check if admin verification has expired"""
    if session.get('admin_verified'):
        if 'admin_verify_time' not in session:
            session['admin_verify_time'] = datetime.now(timezone.utc).timestamp()
        elif datetime.now(timezone.utc).timestamp() - session['admin_verify_time'] > app.config['ADMIN_VERIFY_TIMEOUT']:
            session.pop('admin_verified', None)
            session.pop('admin_verify_time', None)
            flash('Admin verification expired', 'warning')


# Routes
@app.route('/')
def index():
    try:
        events = db.session.query(Event).all()
        return render_template('index.html', events=events)
    except Exception as e:
        app.logger.error(f"Error fetching events: {str(e)}")
        flash('Error loading events', 'error')
        return render_template('index.html', events=[])

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if db.session.query(User).filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        
        if db.session.query(User).filter_by(email=email).first():
            flash('Email already exists', 'error')
            return redirect(url_for('register'))
        
        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password)
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = db.session.query(User).filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            session['is_team_leader'] = user.is_team_leader
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        user = db.session.get(User, current_user.id)
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('logout'))
            
        bookings = db.session.query(Booking).filter_by(user_id=user.id).all()
        return render_template('dashboard.html', user=user, bookings=bookings)
        
    except Exception as e:
        flash('Error accessing dashboard', 'error')
        app.logger.error(f"Dashboard error: {str(e)}")
        return redirect(url_for('index'))

@app.route('/events')
def events():
    event_type = request.args.get('type')
    query = db.session.query(Event)
    
    if event_type in ['workshop', 'competition']:
        events = query.filter_by(event_type=event_type).all()
    else:
        events = query.all()
        
    return render_template('events.html', events=events)

@app.route('/book/<int:event_id>', methods=['POST'])
@login_required
def book_event(event_id):
    try:
        event = db.session.get(Event, event_id)
        if not event:
            flash('Event not found', 'error')
            return redirect(url_for('events'))

        user = db.session.get(User, current_user.id)
        
        # Check for time conflicts only for workshops
        if event.event_type == 'workshop':
            if has_overlapping_workshop(user.id, event):
                flash('You already have a workshop booked at this time', 'error')
                return redirect(url_for('events'))

        # Check for existing booking
        existing_booking = Booking.query.filter_by(
            user_id=user.id, 
            event_id=event.id
        ).first()
        
        if existing_booking:
            if existing_booking.status != 'cancelled':
                flash('You have already booked this event', 'warning')
                return redirect(url_for('events'))
            else:
                existing_booking.status = 'pending'
                existing_booking.booking_time = datetime.now(timezone.utc)
                booking = existing_booking
        else:
            # Create new booking with pending status
            booking = Booking(
                user_id=user.id,
                event_id=event.id,
                status='pending'  # Default status, will be confirmed later by admin
            )
            db.session.add(booking)
        
        # Handle competition events
        if event.event_type == 'competition':
            if not user.team or user.team.event_id != event.id:
                flash('You must join or create a team for this competition first', 'error')
                return redirect(url_for('team_selection', event_id=event.id))
            
            # Check if team already has a confirmed booking
            team_confirmed = Booking.query.filter(
                Booking.event_id == event.id,
                Booking.status == 'confirmed',
                Booking.user.has(team_id=user.team_id)
            ).first()
            
            if team_confirmed:
                flash('Your team is already registered for this competition', 'warning')
                return redirect(url_for('events'))
            
            # Check if team already has a pending booking
            team_pending = Booking.query.filter(
                Booking.event_id == event.id,
                Booking.status == 'pending',
                Booking.user.has(team_id=user.team_id)
            ).first()
            
            if team_pending and team_pending.id != booking.id:
                flash('Your team already has a pending registration for this competition', 'warning')
                return redirect(url_for('events'))
        
        # IMPORTANT: We no longer increment participation/team counts here
        # Those will be handled in the confirm_booking route when status changes to confirmed
        
        db.session.commit()
        flash('Booking submitted successfully! An admin will review your request.', 'success')
        return redirect(url_for('dashboard'))

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in book_event: {str(e)}")
        flash('An error occurred while processing your booking', 'error')
        return redirect(url_for('events'))

@app.route('/cancel_booking/<int:booking_id>')
@login_required
def cancel_booking(booking_id):
    booking = db.session.get(Booking, booking_id)
    event = booking.event
    
    if not booking or booking.user_id != current_user.id:
        flash('Invalid booking', 'error')
        return redirect(url_for('dashboard'))
    
    # Decrease participant count for confirmed bookings
    if booking.status == 'confirmed':
        if event.event_type == 'competition':
            # For competitions, check if we should decrease team count
            team_bookings = Booking.query.filter_by(
                event_id=event.id
            ).join(User).filter(
                User.team_id == current_user.team_id
            ).all()
            
            # Only decrease if this is the last team member canceling
            if len(team_bookings) == 1:
                event.current_teams -= 1
        else:
            event.current_participants -= 1
        
        # Promote next waitlisted booking if available
        waitlisted = Booking.query.filter_by(
            event_id=event.id,
            status='waitlisted'
        ).order_by(Booking.booking_time).first()
        
        if waitlisted:
            waitlisted.status = 'confirmed'
            if event.event_type != 'competition':
                event.current_participants += 1
    
    # Mark as cancelled but don't delete the record
    booking.status = 'cancelled'
    db.session.commit()
    
    flash('Booking cancelled successfully', 'success')
    return redirect(url_for('dashboard'))

# Team routes with password protection
@app.route('/team/select/<int:event_id>')
@login_required
def team_selection(event_id):
    event = db.session.get(Event, event_id)
    if not event or event.event_type != 'competition':
        flash('Invalid competition', 'error')
        return redirect(url_for('events'))
    
    available_teams = db.session.query(Team).filter(
        Team.event_id == event_id,
        db.session.query(User).filter(User.team_id == Team.id).count() < 4
    ).all()
    
    return render_template('team_selection.html', 
                         event=event, 
                         available_teams=available_teams)

@app.route('/team/create', methods=['GET', 'POST'])
@login_required
def create_team():
    if request.method == 'POST':
        try:
            team_name = request.form['team_name']
            event_id = request.form['event_id']
            team_password = request.form['team_password']
            confirm_password = request.form['confirm_password']
            
            if team_password != confirm_password:
                flash('Team passwords do not match', 'error')
                return redirect(url_for('create_team'))
            
            if db.session.query(Team).filter_by(name=team_name).first():
                flash('Team name already exists', 'error')
                return redirect(url_for('create_team'))
            
            event = db.session.get(Event, event_id)
            if not event or event.event_type != 'competition':
                flash('Invalid competition', 'error')
                return redirect(url_for('events'))
            
            new_team = Team(
                name=team_name,
                password=generate_password_hash(team_password),
                created_by=current_user.id,
                event_id=event_id,
                event=event
            )
            db.session.add(new_team)
            db.session.flush()
            
            # Add current user as team leader
            user = db.session.get(User, current_user.id)
            user.team_id = new_team.id
            user.is_team_leader = True
            
            db.session.commit()
            flash('Team created successfully!', 'success')
            return redirect(url_for('team_management', team_id=new_team.id))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error creating team: {str(e)}")
            flash('Error creating team', 'error')
            return redirect(url_for('create_team'))
    
    competitions = db.session.query(Event).filter_by(event_type='competition').all()
    return render_template('create_team.html', 
                         competitions=competitions,
                         username=current_user.username)

@app.route('/team/join', methods=['GET', 'POST'])
@login_required
def join_team():
    if request.method == 'POST':
        team_name = request.form['team_name']
        team_password = request.form['team_password']
        
        team = db.session.query(Team).filter_by(name=team_name).first()
        
        if not team:
            flash('Team not found', 'error')
            return redirect(url_for('join_team'))
        
        if not check_password_hash(team.password, team_password):
            flash('Invalid team password', 'error')
            return redirect(url_for('join_team'))
        
        if len(team.members) >= 4:
            flash('This team is already full', 'error')
            return redirect(url_for('events'))
        
        existing_team = db.session.query(Team).filter(
            Team.members.any(id=current_user.id),
            Team.event_id == team.event_id
        ).first()
        
        if existing_team:
            flash('You are already in a team for this competition', 'error')
            return redirect(url_for('events'))
        
        user = db.session.get(User, current_user.id)
        user.team = team
        db.session.commit()
        
        flash(f'You have joined team {team.name}', 'success')
        return redirect(url_for('team_management', team_id=team.id))
    
    return render_template('join_team.html')

@app.route('/team/manage/<int:team_id>')
@login_required
def team_management(team_id):
    team = db.session.query(Team).options(
        db.joinedload(Team.event),
        db.joinedload(Team.members)
    ).filter_by(id=team_id).first()
    
    if not team:
        flash('Team not found', 'error')
        return redirect(url_for('events'))
    
    if not any(member.id == current_user.id for member in team.members):
        flash('You are not a member of this team', 'error')
        return redirect(url_for('events'))
    
    return render_template('team_management.html', team=team)

@app.route('/team/disband/<int:team_id>', methods=['POST'])
@login_required
def disband_team(team_id):
    team = db.session.get(Team, team_id)
    user = db.session.get(User, current_user.id)
    
    if not user.is_team_leader or user.team_id != team_id:
        flash('Only team leader can disband the team', 'error')
        return redirect(url_for('team_management', team_id=team_id))
    
    for member in team.members:
        member.team_id = None
        member.is_team_leader = False
    
    db.session.delete(team)
    db.session.commit()
    
    flash('Team has been disbanded', 'info')
    return redirect(url_for('dashboard'))

@app.route('/team/leave/<int:team_id>', methods=['POST'])
@login_required
def leave_team(team_id):
    team = db.session.get(Team, team_id)
    user = db.session.get(User, current_user.id)
    
    if user.team_id != team_id:
        flash('You are not a member of this team', 'error')
        return redirect(url_for('dashboard'))
    
    if user.is_team_leader:
        flash('Team leader cannot leave. Please disband the team or transfer leadership.', 'error')
        return redirect(url_for('team_management', team_id=team_id))
    
    user.team_id = None
    db.session.commit()
    
    flash('You have left the team', 'info')
    return redirect(url_for('dashboard'))


# User Management Routes
@app.route('/admin/user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def view_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('admin'))

    if request.method == 'POST':
        try:
            user.username = request.form.get('username', user.username)
            user.email = request.form.get('email', user.email)
            user.is_admin = 'is_admin' in request.form
            user.is_team_leader = 'is_team_leader' in request.form
            
            if request.form.get('password'):
                user.password = generate_password_hash(request.form['password'])
            
            db.session.commit()
            flash('User updated successfully', 'success')
            return redirect(url_for('view_user', user_id=user.id))
        except Exception as e:
            db.session.rollback()
            flash('Error updating user', 'error')
            app.logger.error(f"Error updating user: {str(e)}")

    return render_template('admin_user.html', user=user)

@app.route('/admin/user/delete/<int:user_id>')
@admin_required
def delete_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('admin'))

    try:
        # Handle team leadership if needed
        if user.is_team_leader and user.team:
            flash('Cannot delete team leader. Please reassign leadership first.', 'error')
            return redirect(url_for('view_user', user_id=user.id))

        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting user', 'error')
        app.logger.error(f"Error deleting user: {str(e)}")

    return redirect(url_for('admin'))

# Team Management Routes
@app.route('/admin/team/<int:team_id>', methods=['GET', 'POST'])
@admin_required
def view_team(team_id):
    team = db.session.get(Team, team_id)
    if not team:
        flash('Team not found', 'error')
        return redirect(url_for('admin'))

    if request.method == 'POST':
        try:
            team.name = request.form.get('name', team.name)
            
            # Update team leader if changed
            new_leader_id = request.form.get('leader_id')
            if new_leader_id:
                new_leader = db.session.get(User, new_leader_id)
                if new_leader and new_leader.team_id == team.id:
                    # Remove old leader flag
                    if team.leader:
                        team.leader.is_team_leader = False
                    # Set new leader
                    new_leader.is_team_leader = True
                    team.created_by = new_leader.id
            
            db.session.commit()
            flash('Team updated successfully', 'success')
            return redirect(url_for('view_team', team_id=team.id))
        except Exception as e:
            db.session.rollback()
            flash('Error updating team', 'error')
            app.logger.error(f"Error updating team: {str(e)}")

    return render_template('admin_team.html', team=team)

@app.route('/admin/team/delete/<int:team_id>')
@admin_required
def delete_team(team_id):
    team = db.session.get(Team, team_id)
    if not team:
        flash('Team not found', 'error')
        return redirect(url_for('admin'))

    try:
        # Remove team association from members
        for member in team.members:
            member.team_id = None
            member.is_team_leader = False
        
        db.session.delete(team)
        db.session.commit()
        flash('Team deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting team', 'error')
        app.logger.error(f"Error deleting team: {str(e)}")

    return redirect(url_for('admin'))

# Admin routes
@app.route('/admin/verify', methods=['GET', 'POST'])
def admin_verify():
    if not is_admin():
        flash('Admin access required', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        token = request.form.get('admin_token')
        
        if token == app.config['ADMIN_TOKEN']:
            session['admin_verified'] = True
            session['admin_verify_time'] = datetime.now(timezone.utc).timestamp()
            return redirect(url_for('admin'))
        else:
            flash('Invalid admin token', 'danger')
    
    return render_template('admin_verify.html')

@app.route('/admin')
@admin_required
def admin():
    events = db.session.query(Event).all()
    bookings = db.session.query(Booking).all()
    users = db.session.query(User).all()
    teams = db.session.query(Team).options(
        db.joinedload(Team.members),
        db.joinedload(Team.leader),
        db.joinedload(Team.event)
    ).all()
    
    return render_template('admin.html', events=events, bookings=bookings, users=users,teams=teams)

@app.route('/admin/download_event_participants/<int:event_id>')
@admin_required
def download_event_participants(event_id):
    event = db.session.get(Event, event_id)
    if not event:
        flash('Event not found', 'error')
        return redirect(url_for('admin'))
    
    # Create a workbook
    wb = Workbook()
    ws = wb.active
    ws.title = "Participants"
    
    # Add headers
    headers = ["Name", "Email", "Booking Status", "Booking Time"]
    if event.event_type == 'competition':
        headers.insert(2, "Team Name")
        headers.insert(3, "Team Leader")
    
    ws.append(headers)
    
    # Get all bookings for this event
    bookings = db.session.query(Booking).filter_by(event_id=event.id).all()
    
    for booking in bookings:
        user = db.session.get(User, booking.user_id)
        row_data = [
            user.username,
            user.email,
        ]
        
        if event.event_type == 'competition':
            team_info = ""
            is_leader = "No"
            if user.team:
                team_info = user.team.name
                if user.is_team_leader:
                    is_leader = "Yes"
            row_data.extend([team_info, is_leader])
        
        row_data.extend([
            booking.status,
            booking.booking_time.strftime('%Y-%m-%d %H:%M:%S')
        ])
        
        ws.append(row_data)
    
    # Create a BytesIO buffer and save the workbook
    virtual_workbook = BytesIO()
    wb.save(virtual_workbook)
    virtual_workbook.seek(0)
    
    # Send the file
    filename = f"{event.name.replace(' ', '_')}_participants.xlsx"
    return send_file(
        virtual_workbook,
        as_attachment=True,
        download_name=filename,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )

@app.route('/admin/add_event', methods=['POST'])
@admin_required
def add_event():
    event_type = request.form['event_type']
    new_event = Event(
        name=request.form['name'],
        description=request.form['description'],
        location=request.form['location'],  # Add this line
        event_type=event_type,
        max_participants=int(request.form['max_participants']),
        start_time=datetime.strptime(request.form['start_time'], '%Y-%m-%dT%H:%M'),
        end_time=datetime.strptime(request.form['end_time'], '%Y-%m-%dT%H:%M')
    )
    
    if event_type == 'competition':
        new_event.max_teams = int(request.form['max_teams'])
        new_event.team_size = int(request.form['team_size'])
    
    db.session.add(new_event)
    db.session.commit()
    flash('Event added successfully', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/edit_event/<int:event_id>', methods=['GET', 'POST'])
@admin_required
def edit_event(event_id):
    event = db.session.get(Event, event_id)
    
    if request.method == 'POST':
        event.name = request.form['name']
        event.description = request.form['description']
        event.location = request.form['location']
        event.event_type = request.form['event_type']
        event.start_time = datetime.strptime(request.form['start_time'], '%Y-%m-%dT%H:%M')
        event.end_time = datetime.strptime(request.form['end_time'], '%Y-%m-%dT%H:%M')
        
        if event.event_type == 'workshop':
            event.max_participants = int(request.form['max_participants'])
            event.max_teams = 0
            event.team_size = 0
        else:
            event.max_teams = int(request.form['max_teams'])
            event.team_size = int(request.form['team_size'])
            event.max_participants = 0
        
        db.session.commit()
        flash('Event updated successfully', 'success')
        return redirect(url_for('admin'))
    
    return render_template('edit_event.html', event=event)

@app.route('/admin/delete_event/<int:event_id>')
@admin_required
def delete_event(event_id):
    event = db.session.get(Event, event_id)
    
    try:
        db.session.query(Booking).filter_by(event_id=event.id).delete()
        db.session.delete(event)
        db.session.commit()
        flash('Event deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting event', 'danger')
        app.logger.error(f"Error deleting event: {str(e)}")
    
    return redirect(url_for('admin'))

@app.route('/admin/notify_waitlisted', defaults={'event_id': None})
@app.route('/admin/notify_waitlisted/<int:event_id>')
@admin_required
def notify_waitlisted(event_id):
    if event_id:
        # Notify waitlisted for a specific event
        event = db.session.get(Event, event_id)
        if not event:
            flash('Event not found', 'error')
            return redirect(url_for('admin'))
        
        bookings = Booking.query.filter_by(
            event_id=event.id,
            status='waitlisted'
        ).all()
    else:
        # Notify all waitlisted across all events
        bookings = Booking.query.filter_by(status='waitlisted').all()
    
    emails_sent = 0
    for booking in bookings:
        try:
            msg = Message(
                subject=f"Workshop Full: {booking.event.name}",
                recipients=[booking.user.email],
                html=render_template('email/waitlisted_notification.html', 
                                   user=booking.user, 
                                   event=booking.event)
            )
            mail.send(msg)
            emails_sent += 1
        except Exception as e:
            app.logger.error(f"Failed to send notification to {booking.user.email}: {str(e)}")

    flash(f'Notifications sent to {emails_sent} waitlisted participants', 'success')
    return redirect(url_for('admin'))

# Admin booking management
@app.route('/admin/confirm_booking/<int:booking_id>')
@admin_required
def confirm_booking(booking_id):
    booking = db.session.get(Booking, booking_id)
    if not booking:
        flash('Booking not found', 'error')
        return redirect(url_for('admin'))

    event = booking.event
    user = booking.user
    
    if booking.status == 'confirmed':
        flash('Booking is already confirmed', 'warning')
        return redirect(url_for('admin'))
    
    if booking.status == 'cancelled':
        flash('Cannot confirm a cancelled booking', 'warning')
        return redirect(url_for('admin'))

    if event.event_type == 'competition':
        # Check if team is already confirmed
        team_confirmed = Booking.query.filter(
            Booking.event_id == event.id,
            Booking.status == 'confirmed',
            Booking.user.has(team_id=user.team_id)
        ).first()
        
        if team_confirmed:
            flash('Team already confirmed for this competition', 'warning')
            return redirect(url_for('admin'))
        
        if event.current_teams >= event.max_teams:
            booking.status = 'waitlisted'
            db.session.commit()
            flash('Competition is full. Booking moved to waitlist', 'warning')
            return redirect(url_for('admin'))
        
        event.current_teams += 1  # Only increment when confirming
    else:
        # Workshop logic
        if event.current_participants >= event.max_participants:
            booking.status = 'waitlisted'
            db.session.commit()
            flash('Workshop is full. Booking moved to waitlist', 'warning')
            return redirect(url_for('admin'))
        
        event.current_participants += 1  # Only increment when confirming
    
    booking.status = 'confirmed'
    booking.is_approved = True
    db.session.commit()
    
    try:
        send_booking_confirmation(user, event)
    except Exception as e:
        app.logger.error(f"Failed to send confirmation email: {str(e)}")
        flash('Booking confirmed but email notification failed', 'warning')
    
    flash('Booking confirmed successfully', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/reject_booking/<int:booking_id>')
def reject_booking(booking_id):
    if not is_admin() or not session.get('admin_verified'):
        flash('Admin access required', 'danger')
        return redirect(url_for('index'))
    
    booking = db.session.get(Booking, booking_id)
    
    if booking.status == 'confirmed':
        booking.event.current_participants -= 1
    
    booking.status = 'cancelled'
    db.session.commit()
    
    flash('Booking rejected', 'info')
    return redirect(url_for('admin'))

@app.route('/admin/move_to_waitlist/<int:booking_id>')
def move_to_waitlist(booking_id):
    if not is_admin() or not session.get('admin_verified'):
        flash('Admin access required', 'danger')
        return redirect(url_for('index'))
    
    booking = db.session.get(Booking, booking_id)
    
    if booking.status != 'confirmed':
        flash('Only confirmed bookings can be moved to waitlist', 'warning')
        return redirect(url_for('admin'))
    
    booking.status = 'waitlisted'
    booking.event.current_participants -= 1
    db.session.commit()
    
    # Try to promote next waitlisted booking
    next_booking = db.session.query(Booking).filter(
        Booking.event_id == booking.event_id,
        Booking.status == 'waitlisted'
    ).order_by(Booking.booking_time).first()
    
    if next_booking and booking.event.current_participants < booking.event.max_participants:
        next_booking.status = 'confirmed'
        next_booking.is_approved = True
        booking.event.current_participants += 1
        db.session.commit()
        flash('Booking moved to waitlist and next booking promoted', 'success')
    else:
        flash('Booking moved to waitlist', 'success')
    
    return redirect(url_for('admin'))

@app.route('/admin/cancel_booking/<int:booking_id>')
def admin_cancel_booking(booking_id):
    if not is_admin() or not session.get('admin_verified'):
        flash('Admin access required', 'danger')
        return redirect(url_for('index'))
    
    booking = db.session.get(Booking, booking_id)
    
    if booking.status == 'confirmed':
        booking.event.current_participants -= 1
    
    booking.status = 'cancelled'
    db.session.commit()
    flash('Booking cancelled by admin', 'info')
    return redirect(url_for('admin'))

@app.route('/admin/transfer_booking/<int:booking_id>', methods=['GET', 'POST'])
def transfer_booking(booking_id):
    if not is_admin() or not session.get('admin_verified'):
        flash('Admin access required', 'danger')
        return redirect(url_for('index'))
    
    booking = db.session.get(Booking, booking_id)
    
    if request.method == 'POST':
        new_event_id = request.form.get('new_event_id')
        new_event = db.session.get(Event, new_event_id)
        
        if not new_event:
            flash('Invalid event selected', 'danger')
            return redirect(url_for('transfer_booking', booking_id=booking.id))
        
        if new_event.current_participants >= new_event.max_participants:
            flash('Selected event is full', 'danger')
            return redirect(url_for('transfer_booking', booking_id=booking.id))
        
        # If moving from a confirmed booking, free up space
        if booking.status == 'confirmed':
            booking.event.current_participants -= 1

        if new_event.event_type == 'workshop':
            if has_overlapping_workshop(booking.user_id, new_event):
                flash('User already has a workshop at this time', 'danger')
                return redirect(url_for('transfer_booking', booking_id=booking.id))
        
        booking.event_id = new_event.id
        booking.status = 'confirmed'
        booking.is_approved = True
        new_event.current_participants += 1
        db.session.commit()
        
        flash('Booking transferred successfully', 'success')
        return redirect(url_for('admin'))
    
    # Get all events except the current one
    events = db.session.query(Event).filter(Event.id != booking.event_id).all()
    return render_template('transfer_booking.html', booking=booking, events=events)


if __name__ == '__main__':
    if os.environ.get('FLASK_ENV') == 'development':
        with app.app_context():
            db.create_all()
    app.run()