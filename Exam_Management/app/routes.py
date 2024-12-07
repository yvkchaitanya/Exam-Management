from flask import render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from app import app, db
from app.models import User, Question, Exam,ExamAttempt
from werkzeug.security import generate_password_hash, check_password_hash

@app.route('/')
def home():
    """Home page for the application."""
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register a new user."""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')

        # Input validation
        if not username or not email or not password or not role:
            flash('All fields are required.', 'danger')
            return redirect(url_for('register'))

        if role not in ['student', 'teacher']:
            flash('Invalid role. Choose "student" or "teacher".', 'danger')
            return redirect(url_for('register'))

        # Check for duplicate username or email
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('login'))

        # Create new user
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, email=email, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Log in an existing user."""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Validate login
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard for logged-in users."""
    # If the user is a teacher
    if current_user.role == 'teacher':
        # Fetch all exams and the attempts by students
        exams = Exam.query.all()
        
        # Fetch the attempts for each exam
        exam_attempts = {}
        for exam in exams:
            # Get all attempts for the current exam
            attempts = ExamAttempt.query.filter_by(exam_id=exam.id).all()
            exam_attempts[exam.id] = attempts
        
        # Render the teacher dashboard with all exams and student attempts
        return render_template('dashboard.html', exams=exams, exam_attempts=exam_attempts, is_teacher=True)

    # If the user is a student
    else:
        # Fetch exams available for the student (exams that have questions)
        exams = Exam.query.filter(Exam.questions.any()).all()
        
        # Fetch IDs of exams already attempted by the current user
        attempted_exam_ids = [
            attempt.exam_id for attempt in ExamAttempt.query.filter_by(user_id=current_user.id).all()
        ]
        
        # Fetch the scores for each attempted exam
        exam_attempts = {}
        for attempt in ExamAttempt.query.filter_by(user_id=current_user.id).all():
            exam_attempts[attempt.exam_id] = attempt
        
        # Render the student dashboard with exams, attempted exam IDs, and scores
        return render_template('dashboard.html', exams=exams, attempted_exam_ids=attempted_exam_ids, exam_attempts=exam_attempts, is_teacher=False)

@app.route('/logout')
@login_required
def logout():
    """Log out the current user."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/teacher/create_exam', methods=['GET', 'POST'])
@login_required
def create_exam():
    """Create a new exam (teacher only)."""
    if current_user.role != 'teacher':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form.get('title')
        duration = request.form.get('duration')

        # Validate input
        if not title or not duration.isdigit():
            flash('All fields are required, and duration must be a number.', 'danger')
            return redirect(url_for('create_exam'))

        exam = Exam(title=title, duration=int(duration))
        db.session.add(exam)
        db.session.commit()

        flash(f"Exam '{title}' created successfully!", 'success')
        return redirect(url_for('dashboard'))

    return render_template('create_exam.html')

@app.route('/teacher/add_question/<int:exam_id>', methods=['GET', 'POST'])
@login_required
def add_question(exam_id):
    """Add a question to an exam (teacher only)."""
    if current_user.role != 'teacher':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    exam = Exam.query.get_or_404(exam_id)

    if request.method == 'POST':
        question_text = request.form.get('question_text')
        options = request.form.get('options')  # Options as a comma-separated string
        correct_answer = request.form.get('correct_answer')
        marks = request.form.get('marks')

        # Validate input
        if not question_text or not options or not correct_answer or not marks.isdigit():
            flash('All fields are required, and marks must be a number.', 'danger')
            return redirect(url_for('add_question', exam_id=exam_id))

        options_list = [opt.strip() for opt in options.split(',')]  # Convert to list

        question = Question(
            question_text=question_text,
            options=options_list,
            correct_answer=correct_answer,
            marks=int(marks),
            exam_id=exam.id,
        )
        db.session.add(question)
        db.session.commit()

        flash('Question added successfully!', 'success')
        return redirect(url_for('add_question', exam_id=exam_id))

    return render_template('add_question.html', exam=exam)

@app.route('/student/attempt_exam/<int:exam_id>', methods=['GET', 'POST'])
@login_required
def attempt_exam(exam_id):
    """Attempt an exam (student only)."""
    if current_user.role != 'student':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    exam = Exam.query.get_or_404(exam_id)
    
    # Check if the student has already attempted this exam
    if ExamAttempt.query.filter_by(user_id=current_user.id, exam_id=exam.id).first():
        flash('You have already attempted this exam.', 'info')
        return redirect(url_for('dashboard'))

    if not exam.questions:
        flash('This exam has no questions.', 'danger')
        return redirect(url_for('dashboard'))  # Redirect to student dashboard if no questions

    if request.method == 'POST':
        score = 0
        total_marks = 0

        # Loop through each question to calculate the score
        for question in exam.questions:
            answer = request.form.get(str(question.id))  # Get the selected answer
            total_marks += question.marks
            if answer == question.correct_answer:
                score += question.marks

        # Save the exam attempt
        attempt = ExamAttempt(user_id=current_user.id, exam_id=exam.id, score=score)
        db.session.add(attempt)
        db.session.commit()

        flash(f"You scored {score} out of {total_marks}!", 'success')
        return redirect(url_for('dashboard'))

    return render_template('attempt_exam.html', exam=exam)

@app.route('/student/view_score/<int:exam_id>')
@login_required
def view_score(exam_id):
    """View the score of a previously attempted exam."""
    # Fetch the exam attempt
    attempt = ExamAttempt.query.filter_by(user_id=current_user.id, exam_id=exam_id).first()
    
    if not attempt:
        flash('You have not attempted this exam.', 'danger')
        return redirect(url_for('dashboard'))

    exam = Exam.query.get_or_404(exam_id)
    
    # Calculate the total marks for the exam
    total_marks = sum(question.marks for question in exam.questions)

    # Render the score page
    return render_template('view_score.html', exam=exam, attempt=attempt, total_marks=total_marks)
