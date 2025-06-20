from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import io
import csv
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import base64

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///finance.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    entries = db.relationship('Entry', backref='user', lazy=True)

class Entry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String(10), nullable=False)
    description = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    type = db.Column(db.String(10), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Home page with chart
@app.route('/')
@login_required
def index():
    entries = Entry.query.filter_by(user_id=current_user.id).all()
    balance = sum(e.amount if e.type == 'income' else -e.amount for e in entries)
    # Pie chart for expenses by category
    expenses = [e for e in entries if e.type == 'expense']
    category_totals = {}
    for e in expenses:
        category_totals[e.category] = category_totals.get(e.category, 0) + e.amount
    chart = None
    if category_totals:
        fig, ax = plt.subplots()
        ax.pie(category_totals.values(), labels=category_totals.keys(), autopct='%1.1f%%')
        ax.set_title('Expenses by Category')
        buf = io.BytesIO()
        plt.savefig(buf, format='png')
        buf.seek(0)
        chart = base64.b64encode(buf.getvalue()).decode()
        plt.close(fig)
    return render_template('index.html', entries=entries, balance=balance, chart=chart)

# Add entry
@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_entry():
    categories = ['Food', 'Rent', 'Utilities', 'Transport', 'Entertainment', 'Other']
    if request.method == 'POST':
        entry = Entry(
            date=request.form['date'],
            description=request.form['description'],
            amount=float(request.form['amount']),
            type=request.form['type'],
            category=request.form['category'],
            user_id=current_user.id
        )
        db.session.add(entry)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('add_entry.html', categories=categories)

# Edit entry
@app.route('/edit/<int:entry_id>', methods=['GET', 'POST'])
@login_required
def edit_entry(entry_id):
    entry = Entry.query.get_or_404(entry_id)
    if entry.user_id != current_user.id:
        flash("You can't edit this entry.")
        return redirect(url_for('index'))
    categories = ['Food', 'Rent', 'Utilities', 'Transport', 'Entertainment', 'Other']
    if request.method == 'POST':
        entry.date = request.form['date']
        entry.description = request.form['description']
        entry.amount = float(request.form['amount'])
        entry.type = request.form['type']
        entry.category = request.form['category']
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('edit_entry.html', entry=entry, categories=categories)

# Delete entry
@app.route('/delete/<int:entry_id>', methods=['POST'])
@login_required
def delete_entry(entry_id):
    entry = Entry.query.get_or_404(entry_id)
    if entry.user_id != current_user.id:
        flash("You can't delete this entry.")
        return redirect(url_for('index'))
    db.session.delete(entry)
    db.session.commit()
    return redirect(url_for('index'))

# Export to CSV
@app.route('/export')
@login_required
def export():
    entries = Entry.query.filter_by(user_id=current_user.id).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Date', 'Description', 'Type', 'Category', 'Amount'])
    for e in entries:
        writer.writerow([e.date, e.description, e.type, e.category, e.amount])
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name='finance_data.csv'
    )

if __name__ == '__main__':
    app.run()
