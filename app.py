from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_number = db.Column(db.String(20), unique=True, nullable=False)
    project_info = db.Column(db.Text)
    tasks = db.relationship('Task', backref='project', lazy=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    estimated_time = db.Column(db.Integer)  # in hours
    deadline = db.Column(db.DateTime, nullable=False)
    priority = db.Column(db.Integer, default=3)  # 0-5
    is_completed = db.Column(db.Boolean, default=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)

    def update_priority(self):
        if not self.is_completed:
            days_remaining = (self.deadline.date() - datetime.now().date()).days
            if days_remaining <= 2:
                if self.priority != 0:
                    self.priority = 0
                    db.session.commit()
        return self.priority

def update_all_priorities():
    tasks = Task.query.filter_by(is_completed=False).all()
    for task in tasks:
        task.update_priority()

@app.route('/')
def index():
    update_all_priorities()  # 更新所有任务的优先级
    
    # 获取未完成的任务
    uncompleted_tasks = Task.query.filter_by(is_completed=False).order_by(Task.priority, Task.deadline).all()
    
    # 获取已完成的任务
    completed_tasks = Task.query.filter_by(is_completed=True).order_by(Task.deadline.desc()).all()
    
    projects = Project.query.all()
    return render_template('index.html', 
                         uncompleted_tasks=uncompleted_tasks,
                         completed_tasks=completed_tasks,
                         projects=projects)

@app.route('/project/add', methods=['POST'])
def add_project():
    project_number = request.form.get('project_number')
    project_info = request.form.get('project_info')
    
    if Project.query.filter_by(project_number=project_number).first():
        return jsonify({'error': 'Project number already exists'}), 400
    
    project = Project(project_number=project_number, project_info=project_info)
    db.session.add(project)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/task/add', methods=['POST'])
def add_task():
    name = request.form.get('name')
    estimated_time = request.form.get('estimated_time')
    deadline = datetime.strptime(request.form.get('deadline'), '%Y-%m-%d')
    priority = int(request.form.get('priority'))
    project_id = int(request.form.get('project_id'))
    
    task = Task(
        name=name,
        estimated_time=estimated_time,
        deadline=deadline,
        priority=priority,
        project_id=project_id
    )
    db.session.add(task)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/task/<int:task_id>/complete', methods=['POST'])
def complete_task(task_id):
    task = Task.query.get_or_404(task_id)
    task.is_completed = True
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/task/<int:task_id>/delete', methods=['POST'])
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    db.session.delete(task)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/daily-tasks')
def daily_tasks():
    update_all_priorities()  # 更新所有任务的优先级
    selected_date_str = request.args.get('selected_date')
    if selected_date_str:
        selected_date = datetime.strptime(selected_date_str, '%Y-%m-%d').date()
    else:
        selected_date = datetime.now().date()
    
    tasks = Task.query.filter(
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
    app.run(debug=True, port=5001) 