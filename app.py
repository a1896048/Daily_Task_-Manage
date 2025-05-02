from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import os
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from oauthlib.oauth2 import WebApplicationClient
import requests
import json
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# 配置密钥
app.secret_key = os.urandom(24)

# Google OAuth 配置
GOOGLE_CLIENT_ID = "your-google-client-id"
GOOGLE_CLIENT_SECRET = "your-google-client-secret"
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

# 获取当前文件所在目录的绝对路径
basedir = os.path.abspath(os.path.dirname(__file__))

# 配置数据库路径
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'tasks.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# 设置 Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# OAuth 2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    name = db.Column(db.String(100))
    projects = db.relationship('Project', backref='owner', lazy=True)
    tasks = db.relationship('Task', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_number = db.Column(db.String(20), nullable=False)
    project_info = db.Column(db.Text)
    tasks = db.relationship('Task', backref='project', lazy=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    __table_args__ = (db.UniqueConstraint('project_number', 'user_id', name='unique_project_per_user'),)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    estimated_time = db.Column(db.Integer)  # in hours
    deadline = db.Column(db.DateTime, nullable=False)
    priority = db.Column(db.Integer, default=3)  # 0-5
    is_completed = db.Column(db.Boolean, default=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def update_priority(self):
        if not self.is_completed:
            days_remaining = (self.deadline.date() - datetime.now().date()).days
            if days_remaining <= 2:
                if self.priority != 0:
                    self.priority = 0
                    db.session.commit()
        return self.priority

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

def update_all_priorities():
    tasks = Task.query.filter_by(is_completed=False).all()
    for task in tasks:
        task.update_priority()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')

        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))

        user = User(email=email, name=name)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful! Please login.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        
        flash('Invalid email or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    update_all_priorities()
    
    # 只获取当前用户的任务
    uncompleted_tasks = Task.query.filter_by(
        user_id=current_user.id,
        is_completed=False
    ).order_by(Task.priority, Task.deadline).all()
    
    completed_tasks = Task.query.filter_by(
        user_id=current_user.id,
        is_completed=True
    ).order_by(Task.deadline.desc()).all()
    
    projects = Project.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', 
                         uncompleted_tasks=uncompleted_tasks,
                         completed_tasks=completed_tasks,
                         projects=projects)

@app.route('/project/add', methods=['POST'])
@login_required
def add_project():
    project_number = request.form.get('project_number')
    project_info = request.form.get('project_info')
    
    if Project.query.filter_by(
        project_number=project_number,
        user_id=current_user.id
    ).first():
        return jsonify({'error': 'Project number already exists'}), 400
    
    project = Project(
        project_number=project_number,
        project_info=project_info,
        user_id=current_user.id
    )
    db.session.add(project)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/task/add', methods=['POST'])
@login_required
def add_task():
    name = request.form.get('name')
    estimated_time = request.form.get('estimated_time')
    deadline = datetime.strptime(request.form.get('deadline'), '%Y-%m-%d')
    priority = int(request.form.get('priority'))
    project_id = int(request.form.get('project_id'))
    
    # 验证项目是否属于当前用户
    project = Project.query.filter_by(
        id=project_id,
        user_id=current_user.id
    ).first_or_404()
    
    task = Task(
        name=name,
        estimated_time=estimated_time,
        deadline=deadline,
        priority=priority,
        project_id=project_id,
        user_id=current_user.id
    )
    db.session.add(task)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/task/<int:task_id>/complete', methods=['POST'])
@login_required
def complete_task(task_id):
    task = Task.query.filter_by(
        id=task_id,
        user_id=current_user.id
    ).first_or_404()
    task.is_completed = True
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/task/<int:task_id>/delete', methods=['POST'])
@login_required
def delete_task(task_id):
    task = Task.query.filter_by(
        id=task_id,
        user_id=current_user.id
    ).first_or_404()
    db.session.delete(task)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/task/<int:task_id>/restore', methods=['POST'])
@login_required
def restore_task(task_id):
    task = Task.query.filter_by(
        id=task_id,
        user_id=current_user.id
    ).first_or_404()
    task.is_completed = False
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/daily-tasks')
@login_required
def daily_tasks():
    update_all_priorities()
    selected_date_str = request.args.get('selected_date')
    if selected_date_str:
        selected_date = datetime.strptime(selected_date_str, '%Y-%m-%d').date()
    else:
        selected_date = datetime.now().date()
    
    tasks = Task.query.filter(
        Task.user_id == current_user.id,
        Task.deadline >= selected_date,
        Task.deadline < selected_date + timedelta(days=1),
        Task.is_completed == False
    ).order_by(Task.priority, Task.deadline).all()
    
    return render_template('daily_tasks.html', 
                         tasks=tasks, 
                         selected_date=selected_date.strftime('%Y-%m-%d'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='127.0.0.1', debug=True, port=5000) 