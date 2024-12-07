from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.types import Enum
from sqlalchemy.dialects.sqlite import JSON  # Use JSON for SQLite
from datetime import datetime

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(Enum('student', 'teacher', name='role_types'), nullable=False)

    def set_password(self, password):
        """Hashes the password and sets it."""
        self.password = generate_password_hash(password)

    def check_password(self, password):
        """Checks if the given password matches the stored hashed password."""
        return check_password_hash(self.password, password)


# Question model
class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_text = db.Column(db.String(255), nullable=False)
    options = db.Column(JSON, nullable=False)  # JSON field for storing options
    correct_answer = db.Column(db.String(255), nullable=False)
    marks = db.Column(db.Integer, nullable=False)
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id'), nullable=False)
#examattempt table
class ExamAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id'), nullable=False)
    score = db.Column(db.Float, nullable=True)  # Stores the score
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Exam model
class Exam(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    duration = db.Column(db.Integer, nullable=False)  # Duration in minutes
    questions = db.relationship('Question', backref='exam', lazy='dynamic')
 # Many-to-many relationship with dynamic loading

#    def __repr__(self):
 #       return f"<Exam {self.title} - {self.duration} mins>"  # String representation for easier debugging


# Association table for many-to-many relationship between exams and questions
exam_questions = db.Table(
    'exam_questions',
    db.Column('exam_id', db.Integer, db.ForeignKey('exam.id'), primary_key=True),
    db.Column('question_id', db.Integer, db.ForeignKey('question.id'), primary_key=True),
)


# Flask-Login user loader function
@login_manager.user_loader
def load_user(user_id):
    # We expect user_id to be an integer
    return User.query.get(int(user_id))  # Directly converting to integer