from flask import Flask, render_template, url_for, redirect, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, FloatField, TextAreaField, DateField
from wtforms.validators import InputRequired, Length, ValidationError, Email, EqualTo
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
import random
from sqlalchemy import func
import os
import uuid
import io
import pandas as pd
from datetime import datetime
from sqlalchemy import extract
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from flask import send_file
from calendar import monthrange
from werkzeug.utils import secure_filename
from reportlab.lib.pagesizes import letter

from reportlab.pdfgen import canvas

from datetime import datetime

# Initialize Flask App
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:123456@localhost/pytn'
app.config['SECRET_KEY'] = 'thisisasecretkey'

# Flask-Mail Config
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'k.balu.18.me@anits.edu.in'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'auao akiz dxys cgno'         # Replace with your email app password

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

app.config['UPLOAD_FOLDER'] = 'static/profile_pics'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2 MB max size
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# ✅ User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(50), nullable=False, unique=True)
    phone = db.Column(db.String(15), nullable=False)
    location = db.Column(db.String(50), nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    password = db.Column(db.String(80), nullable=False)
    profile_pic = db.Column(db.String(120),nullable=True)
    role = db.Column(db.String(10), nullable=False, default='user')

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(100))
    message = db.Column(db.Text)
    date_submitted = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    # Add this relationship
    user = db.relationship('User', backref='feedbacks')


class FeedbackForm(FlaskForm):
    subject = StringField('Subject', validators=[InputRequired(), Length(max=100)], render_kw={"placeholder": "Subject"})
    message = TextAreaField('Message', validators=[InputRequired()], render_kw={"placeholder": "Write your message here..."})
    submit = SubmitField('Send Feedback')

@app.route('/feedback', methods=['GET', 'POST'])
@login_required
def feedback():
    form = FeedbackForm()
    if form.validate_on_submit():
        new_feedback = Feedback(
            user_id=current_user.id,
            subject=form.subject.data,
            message=form.message.data
        )
        db.session.add(new_feedback)
        db.session.commit()

        # Optionally send email notification to admin
        try:
            admin_email = 'youremail@gmail.com'  # Replace with admin email
            msg = Message(
                f"New Feedback from {current_user.username}: {form.subject.data}",
                sender=app.config['MAIL_USERNAME'],
                recipients=[admin_email]
            )
            msg.body = f"User: {current_user.username} ({current_user.email})\n\nMessage:\n{form.message.data}"
            mail.send(msg)
        except Exception as e:
            flash('Feedback saved but failed to send email notification.', 'warning')
        else:
            flash('Feedback sent successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('feedback.html', form=form)

@app.route('/admin/feedback')
@login_required
def admin_feedback():
    if current_user.role != 'admin':
        flash("Unauthorized access", "danger")
        return redirect(url_for('dashboard'))
    
    feedbacks = Feedback.query.order_by(Feedback.date_submitted.desc()).all()
    return render_template('admin_feedback.html', feedbacks=feedbacks, user=current_user)

@app.route('/admin/feedback/delete/<int:feedback_id>', methods=['POST'])
@login_required
def delete_feedback(feedback_id):
    if current_user.role != 'admin':
        flash("Unauthorized access", "danger")
        return redirect(url_for('admin_feedback'))

    feedback = Feedback.query.get_or_404(feedback_id)
    db.session.delete(feedback)
    db.session.commit()
    flash("Feedback deleted successfully.", "success")
    return redirect(url_for('admin_feedback'))

# Forms
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    email = StringField(validators=[InputRequired(), Email(), Length(max=50)], render_kw={"placeholder": "Email"})
    phone = StringField(validators=[InputRequired(), Length(min=10, max=15)], render_kw={"placeholder": "Phone Number"})
    location = StringField(validators=[InputRequired(), Length(max=50)], render_kw={"placeholder": "Location"})
    gender = SelectField('Gender', choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')], validators=[InputRequired()])
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user = User.query.filter_by(username=username.data).first()
        if existing_user:
            raise ValidationError('That username already exists.')

    def validate_email(self, email):
        existing_email = User.query.filter_by(email=email.data).first()
        if existing_email:
            raise ValidationError('That email is already registered.')


class LoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email()], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired()], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')


class ForgotPasswordForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email()], render_kw={"placeholder": "Enter your email"})
    submit = SubmitField('Send OTP')


class ResetPasswordForm(FlaskForm):
    otp = StringField(validators=[InputRequired()], render_kw={"placeholder": "Enter OTP"})
    new_password = PasswordField(validators=[InputRequired(), Length(min=8)], render_kw={"placeholder": "New Password"})
    confirm_password = PasswordField(validators=[InputRequired(), EqualTo('new_password')], render_kw={"placeholder": "Confirm Password"})
    submit = SubmitField('Reset Password')


# Routes
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash(f"Welcome, {user.username}! You have logged in successfully.", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid email or password", "danger")  # Flash message on failure
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # Hash the password
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        # Handle profile picture upload
        file = request.files.get('profile_pic')
        filename = 'default.jpg'  # your default image in static/profile_pics

        if file and allowed_file(file.filename):
            # Create a unique filename to prevent overwriting
            ext = file.filename.rsplit('.', 1)[1].lower()
            unique_name = f"{uuid.uuid4().hex}.{ext}"
            upload_path = os.path.join(app.root_path, 'static/profile_pics', unique_name)
            file.save(upload_path)
            filename = unique_name

        # Create the new user with profile_pic filename
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            phone=form.phone.data,
            location=form.location.data,
            gender=form.gender.data,
            password=hashed_password,
            profile_pic=filename
        )

        db.session.add(new_user)
        db.session.commit()

        # Send welcome email
        try:
            msg = Message(
                "Welcome to Expense Manager!",
                sender=app.config['MAIL_USERNAME'],  # use your configured email
                recipients=[new_user.email]
            )
            msg.body = f"""
Hi {new_user.username},

Thank you for registering with Expense Management System!

You're all set to start tracking your expenses, setting budgets, and analyzing your spending habits.

Best regards,
Expense Management Team
            """
            mail.send(msg)
        except Exception as e:
            flash("Registration successful, but failed to send welcome email.", "warning")

        flash("Registration successful! Please login.", "success")
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            otp = str(random.randint(100000, 999999))
            session['reset_email'] = user.email
            session['otp'] = otp

            msg = Message("Password Reset OTP", sender="youremail@gmail.com", recipients=[user.email])
            msg.body = f"Your OTP to reset the password is {otp}."
            mail.send(msg)

            flash("OTP sent successfully to your email.", "success")
            return redirect(url_for('reset_password'))
        else:
            flash("Email not found in our system.", "danger")
    return render_template('forgot_password.html', form=form)


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    form = ResetPasswordForm()

    if request.method == 'POST':
        if not form.validate():
            flash("Please fill out all fields correctly.", "danger")
        elif form.new_password.data != form.confirm_password.data:
            flash("New Password and Confirm Password do not match", "danger")
        elif form.otp.data != session.get('otp'):
            flash("Invalid OTP", "danger")
        else:
            user = User.query.filter_by(email=session.get('reset_email')).first()
            if user:
                hashed_pw = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
                user.password = hashed_pw
                db.session.commit()
                session.pop('otp', None)
                session.pop('reset_email', None)
                flash("Password has been reset. Please login.", "success")
                return redirect(url_for('login'))

    return render_template('reset_password.html', form=form)



#PROFILE
@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        current_user.username = request.form['username']
        current_user.phone = request.form['phone']
        current_user.location = request.form['location']

        # 📸 Handle profile picture upload
        file = request.files.get('profile_pic')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            current_user.profile_pic = filename

        db.session.commit()
        flash('Profile updated!', 'success')
        return redirect(url_for('profile'))

    return render_template('edit_profile.html', user=current_user)


#ADMIN PANEL
@app.route('/admin')
@login_required
def admin_panel():
    if current_user.role != 'admin':
        flash("Unauthorized access", "danger")
        return redirect(url_for('dashboard'))
    users = User.query.all()
    return render_template('admin.html', users=users, user=current_user)

@app.route('/delete-user/<int:user_id>')
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash("Unauthorized action", "danger")
        return redirect(url_for('dashboard'))
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash("User deleted successfully", "success")
    return redirect(url_for('admin_panel'))

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=True)
    date = db.Column(db.Date, default=datetime.utcnow)

class ExpenseForm(FlaskForm):
    amount = FloatField('Amount', validators=[InputRequired()])
    category = SelectField('Category', choices=[('Food', 'Food'), ('Travel', 'Travel'),('Shopping', 'Shopping'),('Health', 'Health'),('MakeUp', 'MakeUp'), ('Playing', 'Playing'), ('Others', 'Others')], validators=[InputRequired()])
    description = TextAreaField('Description')
    date = DateField('Date', default=datetime.utcnow, format='%Y-%m-%d')
    submit = SubmitField('Add Expense')

@app.route('/add-expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    form = ExpenseForm()
    if form.validate_on_submit():
        new_expense = Expense(
            user_id=current_user.id,
            amount=form.amount.data,
            category=form.category.data,
            description=form.description.data,
            date=form.date.data
        )
        db.session.add(new_expense)
        db.session.commit()
        flash('Expense added successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_expense.html', form=form, user=current_user)


@app.route('/expense-history')
@login_required
def expense_history():
    user_id = current_user.id
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    category = request.args.get('category')

    query = Expense.query.filter_by(user_id=user_id)

    if start_date:
        query = query.filter(Expense.date >= start_date)
    if end_date:
        query = query.filter(Expense.date <= end_date)
    if category:
        query = query.filter_by(category=category)

    expenses = query.all()

    # Calculate total expenses amount
    total_spent = sum(exp.amount for exp in expenses)

    # Prepare data for charts
    from collections import defaultdict
    cat_data = defaultdict(float)
    for exp in expenses:
        cat_data[exp.category] += exp.amount

    chart_labels = list(cat_data.keys())
    chart_data = list(cat_data.values())

    all_categories = ['Food', 'Travel', 'Shopping', 'Health', 'MakeUp', 'Playing', 'Others']

    # Budget can be set or None if you don't use this feature yet
    budget = None

    return render_template(
        "expense_history.html",
        expenses=expenses,
        total_spent=total_spent,
        budget=budget,
        chart_labels=chart_labels,
        chart_data=chart_data,
        categories=all_categories
    )


@app.route('/upload-expenses-excel', methods=['POST'])
@login_required
def upload_expenses_excel():
    file = request.files.get('excel_file')
    if not file or file.filename == '':
        flash("No file selected", "error")
        return redirect(url_for('expense_history'))

    filename = secure_filename(file.filename)
    df = pd.read_excel(file)

    required_columns = {'date', 'category', 'amount', 'description'}
    if not required_columns.issubset(df.columns):
        flash("Invalid Excel format. Columns should be: date, category, amount, description", "error")
        return redirect(url_for('expense_history'))

    for _, row in df.iterrows():
        try:
            new_expense = Expense(
                user_id=current_user.id,
                date=row['date'],
                category=row['category'],
                amount=float(row['amount']),
                description=row.get('description', '')
            )
            db.session.add(new_expense)
        except Exception as e:
            print("Error inserting row:", e)
            continue

    db.session.commit()
    flash("Expenses uploaded successfully!", "success")
    return redirect(url_for('expense_history'))

@app.route('/download-excel-template')
@login_required
def download_excel_template():
    from io import BytesIO
    from flask import send_file

    df = pd.DataFrame({
        'date': ['2025-05-01'],
        'category': ['Food'],
        'amount': [250.00],
        'description': ['Lunch at cafe']
    })

    output = BytesIO()
    df.to_excel(output, index=False)
    output.seek(0)

    return send_file(
        output,
        download_name="expense_template.xlsx",
        as_attachment=True,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )


@app.route('/delete_expense/<int:expense_id>', methods=['POST'])
@login_required
def delete_expense(expense_id):
    expense = Expense.query.get_or_404(expense_id)
    
    # Ensure user can only delete their own expense (if applicable)
    if expense.user_id != current_user.id and current_user.role != 'admin':
        flash("Unauthorized to delete this expense.", "danger")
        return redirect(url_for('expense_history'))

    db.session.delete(expense)
    db.session.commit()
    flash("Expense deleted successfully.", "success")
    return redirect(url_for('expense_history'))


@app.route('/dashboard')
@login_required
def dashboard():
    selected_year = request.args.get('year', default=datetime.now().year, type=int)

    total = db.session.query(func.sum(Expense.amount))\
                      .filter_by(user_id=current_user.id).scalar() or 0.0

    category_data = db.session.query(
        Expense.category, func.sum(Expense.amount)
    ).filter_by(user_id=current_user.id)\
     .group_by(Expense.category).all()
    category_breakdown = {category: amount for category, amount in category_data}

    recent_expenses = Expense.query\
        .filter_by(user_id=current_user.id)\
        .order_by(Expense.date.desc())\
        .limit(5).all()

    monthly_budget = getattr(current_user, 'monthly_budget', 0)

    monthly_expenses = db.session.query(
        extract('month', Expense.date).label('month'),
        func.sum(Expense.amount)
    ).filter_by(user_id=current_user.id)\
     .filter(extract('year', Expense.date) == selected_year)\
     .group_by('month')\
     .order_by('month').all()

    monthly_expenses_dict = {int(month): amount for month, amount in monthly_expenses}
    chart_labels = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    chart_data = [monthly_expenses_dict.get(i, 0) for i in range(1, 13)]

    years = db.session.query(extract('year', Expense.date).label('year'))\
                      .filter_by(user_id=current_user.id)\
                      .distinct()\
                      .order_by('year').all()
    year_options = [int(y.year) for y in years]

    yearly_total = db.session.query(func.sum(Expense.amount))\
                             .filter_by(user_id=current_user.id)\
                             .filter(extract('year', Expense.date) == selected_year)\
                             .scalar() or 0.0

    return render_template(
        'dashboard.html',
        user=current_user,
        total=total,
        category_breakdown=category_breakdown,
        recent_expenses=recent_expenses,
        monthly_budget=monthly_budget,
        monthly_trends={"labels": chart_labels, "data": chart_data},
        selected_year=selected_year,
        year_options=year_options,
        yearly_total=yearly_total
    )


@app.route('/about')
def about():
    return render_template('about.html', user=current_user)


@app.route('/export_expenses_pdf')
@login_required
def export_expenses_pdf():
    user_id = current_user.id
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    category = request.args.get('category')

    query = Expense.query.filter_by(user_id=user_id)

    if start_date:
        query = query.filter(Expense.date >= start_date)
    if end_date:
        query = query.filter(Expense.date <= end_date)
    if category:
        query = query.filter_by(category=category)

    expenses = query.order_by(Expense.date.desc()).all()

    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    p.drawString(100, 750, "Expense Report")
    y = 720

    for exp in expenses:
        line = f"{exp.date.strftime('%Y-%m-%d')} | {exp.category} | ₹{exp.amount} | {exp.description or '-'}"
        p.drawString(50, y, line)
        y -= 20
        if y < 50:
            p.showPage()
            y = 750

    p.save()
    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name="expense_report.pdf",
        mimetype='application/pdf'
    )

@app.route('/export_expenses_excel')
@login_required
def export_expenses_excel():
    user_id = current_user.id
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    category = request.args.get('category')

    query = Expense.query.filter_by(user_id=user_id)

    if start_date:
        query = query.filter(Expense.date >= start_date)
    if end_date:
        query = query.filter(Expense.date <= end_date)
    if category:
        query = query.filter_by(category=category)

    expenses = query.order_by(Expense.date.desc()).all()

    data = [{
        'Date': exp.date.strftime('%Y-%m-%d'),
        'Category': exp.category,
        'Amount': exp.amount,
        'Description': exp.description or '-'
    } for exp in expenses]

    df = pd.DataFrame(data)

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Expenses')
    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name="expense_report.xlsx",
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )

@app.route('/set-budget', methods=['POST'])
@login_required
def set_budget():
    try:
        budget = float(request.form['budget'])
        current_user.budget = budget
        db.session.commit()
        flash('Budget updated successfully!', 'success')
    except Exception as e:
        flash('Error updating budget.', 'danger')
    return redirect(url_for('dashboard'))

class ReviewForm(FlaskForm):
    response = TextAreaField('Response', validators=[InputRequired()], render_kw={"placeholder": "Write your review response..."})
    submit = SubmitField('Send Review')

@app.route('/admin/review/<int:feedback_id>', methods=['GET', 'POST'])
@login_required
def review_feedback(feedback_id):
    if current_user.role != 'admin':
        flash("Unauthorized access", "danger")
        return redirect(url_for('dashboard'))

    feedback = Feedback.query.get_or_404(feedback_id)
    form = ReviewForm()

    if form.validate_on_submit():
        try:
            msg = Message(
                subject=f"Response to your feedback: {feedback.subject}",
                sender=app.config['MAIL_USERNAME'],
                recipients=[feedback.user.email]
            )
            msg.body = f"""Hi {feedback.user.username},

Thank you for your feedback:

"{feedback.message}"

Here is our response:

"{form.response.data}"

Best regards,
Admin Team
"""
            mail.send(msg)
            flash("Review response sent successfully!", "success")
        except Exception as e:
            flash("Failed to send review response via email.", "danger")

        return redirect(url_for('admin_feedback'))

    return render_template('review_feedback.html', feedback=feedback, form=form, user=current_user)

import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()  # load .env variables
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

from flask import render_template, request
from datetime import datetime
from flask_login import login_required, current_user
import re



@app.route('/chat-ai', methods=['GET', 'POST'])
@login_required
def chat_ai():
    response_text = None
    user_id = current_user.id

    if request.method == 'POST':
        user_message = request.form.get('message', '').lower()
        now = datetime.now()
        year = now.year
        month = now.month

        # Greetings
        if any(greet in user_message for greet in ['hi', 'hello', 'hey']):
            response_text = (
                f"👋 Hello {current_user.username}! I can help you with your expense summary or saving tips. Try asking:\n"
                "• 'summary for March 2024'\n"
                "• 'how to save money'\n"
                "• 'summary for last year'"
            )
            return render_template('chat_ai.html', user=current_user, response=response_text)

        # Month name mapping
        months = {
            'january': 1, 'february': 2, 'march': 3, 'april': 4,
            'may': 5, 'june': 6, 'july': 7, 'august': 8,
            'september': 9, 'october': 10, 'november': 11, 'december': 12
        }

        # Parse year modifiers
        match_year = re.search(r'(\d+)\s+years?\s+ago', user_message)
        if "last year" in user_message:
            year -= 1
        elif match_year:
            year -= int(match_year.group(1))

        explicit_year = re.search(r'\b(20[1-3][0-9])\b', user_message)
        if explicit_year:
            year = int(explicit_year.group(1))

        found_month = next((m for m in months if m in user_message), None)
        if found_month:
            month = months[found_month]
            if not explicit_year and month > now.month and "last" not in user_message:
                year -= 1

        if "last month" in user_message:
            if now.month == 1:
                month = 12
                year -= 1
            else:
                month = now.month - 1

        # Handle "summary" requests
        if "summary" in user_message:
            start_date = datetime(year, month, 1)
            end_date = datetime(year + 1, 1, 1) if month == 12 else datetime(year, month + 1, 1)

            expenses = Expense.query.filter(
                Expense.user_id == user_id,
                Expense.date >= start_date,
                Expense.date < end_date
            ).all()

            total_spent = sum(e.amount for e in expenses)
            category_totals = {}
            for e in expenses:
                category_totals[e.category] = category_totals.get(e.category, 0) + e.amount

            summary_lines = [
                f"📅 **Summary for {start_date.strftime('%B %Y')}**",
                f"💸 Total Spent: ₹{total_spent:.2f}",
                "🧾 **Category Breakdown:**"
            ]
            for cat, amt in category_totals.items():
                summary_lines.append(f"  • {cat}: ₹{amt:.2f}")

            response_text = "\n".join(summary_lines)

        # Handle "save" or "tips" requests
        elif "save" in user_message or "tips" in user_message:
            # Get recent expenses for context
            start_date = datetime(year, month, 1)
            end_date = datetime(year + 1, 1, 1) if month == 12 else datetime(year, month + 1, 1)

            expenses = Expense.query.filter(
                Expense.user_id == user_id,
                Expense.date >= start_date,
                Expense.date < end_date
            ).all()

            category_totals = {}
            for e in expenses:
                category_totals[e.category] = category_totals.get(e.category, 0) + e.amount

            prompt = (
                f"I'm an expense management assistant. Here are the user's monthly expenses by category: "
                f"{category_totals}. Please provide personalized money-saving tips in bullet points."
            )
            model = genai.GenerativeModel("gemini-1.5-flash")
            gemini_response = model.generate_content(prompt)
            response_text = gemini_response.text

        # For any other input, send user input directly to AI model for a generated reply
        else:
            model = genai.GenerativeModel("gemini-1.5-flash")
            gemini_response = model.generate_content(user_message)
            response_text = gemini_response.text

    return render_template('chat_ai.html', user=current_user, response=response_text)

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
