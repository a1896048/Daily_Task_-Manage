from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta, time
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
    deadline = db.Column(db.DateTime, nullable=False)  # Now includes hour
    priority = db.Column(db.Integer, default=3)  # 0-5
    is_completed = db.Column(db.Boolean, default=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    scheduled_start = db.Column(db.DateTime)  # When the task is scheduled to start
    scheduled_end = db.Column(db.DateTime)    # When the task is scheduled to end
    day_of_week = db.Column(db.Integer)       # 0-4 for Monday-Friday

class Schedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    day_of_week = db.Column(db.Integer, nullable=False)  # 0-4 for Monday-Friday
    time_slot = db.Column(db.Time, nullable=False)      # 8:30, 9:30, etc.
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'))
    is_available = db.Column(db.Boolean, default=True)
    date = db.Column(db.Date, nullable=True)  # 新增字段，slot的真实日期

    __table_args__ = (
        db.UniqueConstraint('user_id', 'day_of_week', 'time_slot', name='unique_time_slot'),
    )

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

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
    #session.pop('_flashes', None)  # 清空所有flash消息
    week_offset = int(request.args.get('week_offset', 0))
    today = datetime.now().date()
    # 以周一为一周的开始
    week_start_date = today - timedelta(days=today.weekday()) + timedelta(weeks=week_offset)

    uncompleted_tasks = Task.query.filter_by(
        user_id=current_user.id,
        is_completed=False
    ).order_by(Task.priority, Task.deadline).all()
    completed_tasks = Task.query.filter_by(
        user_id=current_user.id,
        is_completed=True
    ).order_by(Task.deadline.desc()).all()
    projects = Project.query.filter_by(user_id=current_user.id).all()

    # 获取一周日程表（只查当前周）
    schedule = Schedule.query.filter_by(user_id=current_user.id).order_by(
        Schedule.day_of_week,
        Schedule.time_slot
    ).all()
    schedule_by_day = {}
    for slot in schedule:
        if slot.day_of_week not in schedule_by_day:
            schedule_by_day[slot.day_of_week] = []
        schedule_by_day[slot.day_of_week].append(slot)

    return render_template(
        'index.html',
        uncompleted_tasks=uncompleted_tasks,
        completed_tasks=completed_tasks,
        projects=projects,
        schedule_by_day=schedule_by_day,
        Task=Task,
        now=datetime.combine(week_start_date, datetime.min.time()),
        today=datetime.now().date(),
        timedelta=timedelta,
        week_offset=week_offset,
        week_start_date=week_start_date
    )

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
    project_name = request.form.get('project_name')
    name = request.form.get('name')
    estimated_time = int(request.form.get('estimated_time'))
    deadline_str = request.form.get('deadline')
    deadline = datetime.strptime(deadline_str, '%Y-%m-%dT%H:%M')
    priority = int(request.form.get('priority'))

    # 检查当前空闲 slot 是否足够新任务需求（静态插入+先来后到保护）
    slots_needed = estimated_time * 2
    now = datetime.now()
    all_slots = Schedule.query.filter(
        Schedule.user_id == current_user.id,
        Schedule.is_available == True,
        Schedule.date != None
    ).all()
    available_slots = [
        slot for slot in all_slots
        if datetime.combine(slot.date, slot.time_slot) > now and datetime.combine(slot.date, slot.time_slot) <= deadline
    ]
    if len(available_slots) < slots_needed:
        flash(f'Not enough available time slots for this task before deadline. Need {slots_needed}, but only {len(available_slots)} available.', 'warning')
        return redirect(url_for('index'))

    # 自动查找或创建项目
    project = Project.query.filter_by(
        project_number=project_name,
        user_id=current_user.id
    ).first()
    if not project:
        project = Project(
            project_number=project_name,
            project_info='',
            user_id=current_user.id
        )
        db.session.add(project)
        db.session.commit()

    task = Task(
        name=name,
        estimated_time=estimated_time,
        deadline=deadline,
        priority=priority,
        project_id=project.id,
        user_id=current_user.id
    )
    db.session.add(task)
    db.session.commit()

    # 全量重排：所有未完成任务按(deadline, priority)排序，依次分配slot
    schedule_tasks(current_user.id, datetime.now().date())
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

def create_weekly_schedule(user_id):
    """Create empty schedule slots for a user, with half-hour slots, lunch break at 12:00-12:30, ending at 17:00."""
    start_time = datetime.strptime('08:30', '%H:%M').time()
    end_time = datetime.strptime('17:00', '%H:%M').time()
    time_slots = []
    current = datetime.strptime('08:30', '%H:%M')
    end = datetime.strptime('17:00', '%H:%M')
    lunch_start = datetime.strptime('12:00', '%H:%M')
    lunch_end = datetime.strptime('12:30', '%H:%M')
    while current <= end:
        if current.time() == lunch_start.time():
            time_slots.append(current.time())  # Lunch Break slot
            current += timedelta(minutes=30)
            continue
        if lunch_start < current < lunch_end:
            current += timedelta(minutes=30)
            continue  # Skip 12:30 slot (already handled as lunch break)
        time_slots.append(current.time())
        current += timedelta(minutes=30)
    # Clear existing schedule
    Schedule.query.filter_by(user_id=user_id).delete()
    # 只为今天及以后的工作日生成 slot，并写入真实的 date 字段
    today = datetime.now().date()
    for offset in range(0, 5):  # 只生成本周的5天
        slot_date = today + timedelta(days=offset)
        if slot_date.weekday() > 4:  # 只生成周一到周五
            continue
        for slot_time in time_slots:
            is_available = False if slot_time == lunch_start.time() else True
            schedule = Schedule(
                user_id=user_id,
                day_of_week=slot_date.weekday(),
                time_slot=slot_time,
                is_available=is_available,
                date=slot_date
            )
            db.session.add(schedule)
    db.session.commit()

def check_task_feasibility(task, all_slots, week_start_date, now):
    """检查任务是否可以插入而不影响其他任务的完成"""
    slots_needed = task.estimated_time * 2
    available_slots = []
    
    # 收集所有可用的时间槽
    for slot in all_slots:
        slot_datetime = datetime.combine(week_start_date + timedelta(days=slot.day_of_week), slot.time_slot)
        if slot.is_available and slot_datetime >= now and slot_datetime <= task.deadline:
            available_slots.append(slot)
    
    # 如果可用时间槽不足，返回False和原因
    if len(available_slots) < slots_needed:
        return False, f"Not enough time slots available before deadline. Need {slots_needed} slots, but only {len(available_slots)} available."
    
    return True, "Task can be scheduled."

def suggest_deadline_adjustment(task, all_slots, week_start_date, now):
    """为无法完成的任务提供截止时间调整建议"""
    slots_needed = task.estimated_time * 2
    available_slots = []
    
    # 收集所有可用的时间槽
    for slot in all_slots:
        slot_datetime = datetime.combine(week_start_date + timedelta(days=slot.day_of_week), slot.time_slot)
        if slot.is_available and slot_datetime >= now:
            available_slots.append(slot)
    
    if len(available_slots) >= slots_needed:
        # 找到第slots_needed个时间槽的时间作为建议的截止时间
        suggested_slot = available_slots[slots_needed - 1]
        suggested_datetime = datetime.combine(
            week_start_date + timedelta(days=suggested_slot.day_of_week),
            suggested_slot.time_slot
        )
        return True, suggested_datetime
    return False, None

def schedule_tasks(user_id, week_start_date):
    # 强制 week_start_date 为今天，彻底避免 slot_date < today
    now = datetime.now()
    today = now.date()
    week_start_date = today

    # 自动清理所有无效的 task_id
    valid_task_ids = set([t.id for t in Task.query.all()])
    invalid_slots = Schedule.query.filter(
        Schedule.user_id == user_id,
        Schedule.task_id.isnot(None)
    ).all()
    for slot in invalid_slots:
        if slot.task_id not in valid_task_ids:
            slot.task_id = None
            slot.is_available = True
    # 进一步清理所有分配给 project 不存在的任务的 slot
    orphan_tasks = Task.query.filter(~Task.project.has()).all()
    orphan_task_ids = set([t.id for t in orphan_tasks])
    orphan_slots = Schedule.query.filter(
        Schedule.user_id == user_id,
        Schedule.task_id.in_(orphan_task_ids)
    ).all()
    for slot in orphan_slots:
        slot.task_id = None
        slot.is_available = True
    db.session.commit()

    # 获取所有未完成的任务
    tasks = Task.query.filter_by(
        user_id=user_id,
        is_completed=False
    ).all()

    # 重置所有时间槽
    Schedule.query.filter_by(user_id=user_id).update({'task_id': None, 'is_available': True})
    db.session.commit()
    create_weekly_schedule(user_id)

    # 获取所有可用的时间槽
    all_slots = Schedule.query.filter_by(
        user_id=user_id
    ).order_by(Schedule.day_of_week, Schedule.time_slot).all()

    # 将时间槽按天分组
    slots_by_day = {}
    for slot in all_slots:
        if slot.day_of_week not in slots_by_day:
            slots_by_day[slot.day_of_week] = []
        slots_by_day[slot.day_of_week].append(slot)

    # 存储无法完成的任务信息
    unfeasible_tasks = []
    
    # 首先检查所有任务是否都可以完成
    for task in tasks:
        is_feasible, reason = check_task_feasibility(task, all_slots, week_start_date, now)
        if not is_feasible:
            # 尝试提供截止时间调整建议
            can_adjust, suggested_deadline = suggest_deadline_adjustment(task, all_slots, week_start_date, now)
            if can_adjust:
                unfeasible_tasks.append({
                    'task': task,
                    'reason': reason,
                    'suggestion': f"Consider extending deadline to {suggested_deadline.strftime('%Y-%m-%d %I:%M %p')}"
                })
            else:
                unfeasible_tasks.append({
                    'task': task,
                    'reason': reason,
                    'suggestion': "No suitable time slots available in the near future."
                })
            continue

    # 如果有无法完成的任务，可以在这里添加通知逻辑
    if unfeasible_tasks:
        for task_info in unfeasible_tasks:
            task = task_info['task']
            flash(f"Warning: Task '{task.name}' cannot be completed: {task_info['reason']}. {task_info['suggestion']}", 'warning')

    # 按截止时间和优先级排序任务（priority 数字小优先）
    tasks.sort(key=lambda x: (x.deadline, x.priority))

    # 为每个任务分配时间槽
    for task in tasks:
        slots_needed = task.estimated_time * 2
        assigned_slots = []

        # 直接遍历所有 slot，只分配当前时间之后的 slot
        for slot in all_slots:
            if not slot.date:
                continue
            slot_datetime = datetime.combine(slot.date, slot.time_slot)
            if slot_datetime <= now:
                continue
            if slot.is_available and slot_datetime <= task.deadline:
                assigned_slots.append(slot)
            if len(assigned_slots) >= slots_needed:
                break

        # 如果找到足够的时间槽，分配任务
        if len(assigned_slots) == slots_needed:
            for slot in assigned_slots:
                slot.task_id = task.id
                slot.is_available = False
            # 更新任务的开始和结束时间
            task.scheduled_start = datetime.combine(
                assigned_slots[0].date,
                assigned_slots[0].time_slot
            )
            task.scheduled_end = datetime.combine(
                assigned_slots[-1].date,
                assigned_slots[-1].time_slot
            )
            task.day_of_week = assigned_slots[0].date.weekday()

    db.session.commit()

@app.route('/task/<int:task_id>/edit', methods=['POST'])
@login_required
def edit_task(task_id):
    task = Task.query.filter_by(id=task_id, user_id=current_user.id).first_or_404()
    deadline_str = request.form.get('deadline')
    if deadline_str:
        deadline = datetime.strptime(deadline_str, '%Y-%m-%dT%H:%M')
        # 截止时间校验
        if deadline < datetime.now():
            flash('Task deadline is earlier than now. This is not allowed! Please choose a valid deadline.', 'warning')
            return redirect(url_for('index'))
        task.deadline = deadline
    priority = request.form.get('priority')
    if priority is not None:
        task.priority = int(priority)
    estimated_time = request.form.get('estimated_time')
    if estimated_time is not None:
        task.estimated_time = int(estimated_time)
    db.session.commit()
    schedule_tasks(current_user.id, datetime.now().date())
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=8080, debug=True) 