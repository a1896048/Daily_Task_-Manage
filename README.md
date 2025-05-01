# Daily Task Manager

一个为电气工程师设计的任务管理系统，用于管理多个项目下的任务。

## 功能特点

- 项目管理
  - 添加项目（项目编号和描述）
  - 项目编号唯一性验证

- 任务管理
  - 添加任务（名称、预计时间、截止日期、优先级）
  - 任务优先级自动调整（截止日期≤2天时自动提升为最高优先级）
  - 任务完成标记
  - 任务删除功能

- 任务查看
  - 已完成/未完成任务分类显示
  - 按优先级排序
  - 按日期筛选
  - 优先级颜色标识

## 技术栈

- Flask
- SQLAlchemy
- Bootstrap 5
- Select2
- SQLite

## 安装和运行

1. 安装依赖：
```bash
pip install -r requirements.txt
```

2. 运行应用：
```bash
python app.py
```

3. 访问应用：
打开浏览器访问 http://127.0.0.1:5000

## 项目结构

```
Daily_Task_-Manage/
├── app.py              # 主应用文件
├── requirements.txt    # 项目依赖
├── instance/          # 数据库文件目录
└── templates/         # HTML模板
    ├── base.html     # 基础模板
    ├── index.html    # 主页模板
    └── daily_tasks.html # 每日任务模板
``` 