import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from helpers import calculate_fine
from datetime import datetime, timedelta
from functools import wraps

# 1. App Initialization and Configuration
app = Flask(__name__, instance_relative_config=True)
app.config.from_mapping(
    SECRET_KEY='a-very-secret-key-that-you-should-change',
    DATABASE=os.path.join(app.instance_path, 'library.db'),
)

try:
    os.makedirs(app.instance_path)
except OSError:
    pass

# 2. Database Initialization
from database import init_app, get_db
init_app(app)

# 3. User Class and Flask-Login Setup
class User(UserMixin):
    def __init__(self, id, username, email, password_hash, role):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.role = role
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    user_row = get_db().execute('SELECT * FROM user WHERE id = ?', (user_id,)).fetchone()
    if user_row:
        return User(id=user_row['id'], username=user_row['username'], email=user_row['email'], 
                    password_hash=user_row['password_hash'], role=user_row['role'])
    return None

# 4. Custom Decorator for Admin-Only Pages
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# 5. --- Routes ---

# Authentication and General Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user_row = db.execute('SELECT * FROM user WHERE username = ?', (username,)).fetchone()
        if user_row:
            user = User(id=user_row['id'], username=user_row['username'], email=user_row['email'], 
                        password_hash=user_row['password_hash'], role=user_row['role'])
            if user.check_password(password):
                login_user(user)
                flash('Logged in successfully!', 'success')
                return redirect(url_for('home'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        try:
            db.execute("INSERT INTO user (username, email, password_hash) VALUES (?, ?, ?)",
                       (username, email, generate_password_hash(password)))
            db.commit()
        except db.IntegrityError:
            flash(f"User {username} or email {email} is already registered.", 'warning')
            return redirect(url_for('register'))
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/')
def home():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('member_dashboard'))
    return redirect(url_for('login'))

# Member Routes
@app.route('/dashboard')
@login_required
def member_dashboard():
    db = get_db()
    books = db.execute('SELECT * FROM book WHERE quantity_available > 0 ORDER BY title').fetchall()
    return render_template('member/dashboard.html', books=books)

@app.route('/my-books')
@login_required
def my_books():
    db = get_db()
    transactions = db.execute(
        'SELECT t.*, b.title FROM "transaction" t JOIN book b ON t.book_id = b.id WHERE t.member_id = ? ORDER BY t.issue_date DESC',
        (current_user.id,)
    ).fetchall()
    return render_template('member/my_books.html', transactions=transactions)

@app.route('/request_book/<int:book_id>', methods=['POST'])
@login_required
def request_book(book_id):
    db = get_db()
    existing_request = db.execute('SELECT id FROM book_request WHERE book_id = ? AND member_id = ? AND status = ?',
                                  (book_id, current_user.id, 'pending')).fetchone()
    if existing_request:
        flash('You already have a pending request for this book.', 'warning')
        return redirect(url_for('member_dashboard'))
    active_transaction = db.execute('SELECT id FROM "transaction" WHERE book_id = ? AND member_id = ? AND status = ?',
                                    (book_id, current_user.id, 'issued')).fetchone()
    if active_transaction:
        flash('You have already borrowed this book. Please return it first.', 'warning')
        return redirect(url_for('my_books'))
    try:
        db.execute('INSERT INTO book_request (book_id, member_id) VALUES (?, ?)', (book_id, current_user.id))
        db.commit()
        flash('Your request has been submitted successfully!', 'success')
    except db.Error as e:
        flash(f'An error occurred: {e}', 'danger')
    return redirect(url_for('member_dashboard'))

# Admin Routes
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    db = get_db()
    total_books = db.execute('SELECT COUNT(id) FROM book').fetchone()[0]
    total_members = db.execute("SELECT COUNT(id) FROM user WHERE role = 'member'").fetchone()[0]
    issued_books = db.execute("SELECT COUNT(id) FROM 'transaction' WHERE status = 'issued'").fetchone()[0]
    pending_requests = db.execute("SELECT COUNT(id) FROM book_request WHERE status = 'pending'").fetchone()[0]
    return render_template('admin/dashboard.html', total_books=total_books, total_members=total_members, issued_books=issued_books, pending_requests=pending_requests)

@app.route('/admin/books', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_books():
    db = get_db()
    if request.method == 'POST':
        title = request.form['title']
        author = request.form['author']
        isbn = request.form['isbn']
        quantity = int(request.form['quantity'])
        try:
            db.execute('INSERT INTO book (title, author, isbn, quantity, quantity_available) VALUES (?, ?, ?, ?, ?)',
                       (title, author, isbn, quantity, quantity))
            db.commit()
            flash('Book added successfully!', 'success')
        except db.IntegrityError:
            flash('Book with this ISBN already exists.', 'warning')
        return redirect(url_for('manage_books'))
    books = db.execute('SELECT * FROM book ORDER BY title').fetchall()
    return render_template('admin/manage_books.html', books=books)

@app.route('/admin/books/delete/<int:book_id>', methods=['POST'])
@login_required
@admin_required
def delete_book(book_id):
    db = get_db()
    if db.execute("SELECT 1 FROM 'transaction' WHERE book_id = ? AND status = 'issued'", (book_id,)).fetchone():
        flash('Cannot delete book, it is currently issued to a member.', 'danger')
    else:
        db.execute('DELETE FROM book WHERE id = ?', (book_id,))
        db.commit()
        flash('Book deleted successfully!', 'success')
    return redirect(url_for('manage_books'))

@app.route('/admin/users')
@login_required
@admin_required
def manage_users():
    db = get_db()
    users = db.execute('SELECT id, username, email, role FROM user').fetchall()
    return render_template('admin/manage_users.html', users=users)

@app.route('/admin/requests')
@login_required
@admin_required
def manage_requests():
    db = get_db()
    requests = db.execute("""
        SELECT br.id, br.request_date, u.username, b.title, b.author, b.id as book_id, u.id as user_id
        FROM book_request br JOIN user u ON br.member_id = u.id JOIN book b ON br.book_id = b.id
        WHERE br.status = 'pending' ORDER BY br.request_date ASC
    """).fetchall()
    return render_template('admin/manage_requests.html', requests=requests)

@app.route('/admin/requests/approve/<int:request_id>', methods=['POST'])
@login_required
@admin_required
def approve_request(request_id):
    db = get_db()
    req = db.execute('SELECT * FROM book_request WHERE id = ?', (request_id,)).fetchone()
    if not req:
        flash('Request not found.', 'danger')
        return redirect(url_for('manage_requests'))
    book = db.execute('SELECT * FROM book WHERE id = ?', (req['book_id'],)).fetchone()
    if book and book['quantity_available'] > 0:
        due_date = datetime.utcnow() + timedelta(days=14)
        db.execute('INSERT INTO "transaction" (book_id, member_id, due_date) VALUES (?, ?, ?)',
                   (req['book_id'], req['member_id'], due_date))
        db.execute('UPDATE book SET quantity_available = quantity_available - 1 WHERE id = ?', (req['book_id'],))
        db.execute("UPDATE book_request SET status = 'approved' WHERE id = ?", (request_id,))
        db.commit()
        flash('Request approved and book has been issued.', 'success')
    else:
        flash('Book is out of stock. Cannot approve request.', 'danger')
    return redirect(url_for('manage_requests'))

@app.route('/admin/requests/deny/<int:request_id>', methods=['POST'])
@login_required
@admin_required
def deny_request(request_id):
    db = get_db()
    db.execute("UPDATE book_request SET status = 'denied' WHERE id = ?", (request_id,))
    db.commit()
    flash('Request has been denied.', 'info')
    return redirect(url_for('manage_requests'))

@app.route('/admin/reports')
@login_required
@admin_required
def reports():
    db = get_db()
    transactions = db.execute("""
        SELECT t.*, b.title, u.username FROM "transaction" t 
        JOIN book b ON t.book_id = b.id JOIN user u ON t.member_id = u.id
        ORDER BY t.issue_date DESC
    """).fetchall()
    return render_template('admin/reports.html', transactions=transactions)

@app.route('/admin/return/<int:transaction_id>', methods=['POST'])
@login_required
@admin_required
def return_book(transaction_id):
    db = get_db()
    trans_row = db.execute('SELECT * FROM "transaction" WHERE id = ?', (transaction_id,)).fetchone()
    fine_amount = calculate_fine({'return_date': datetime.utcnow(), 'due_date': trans_row['due_date']})
    db.execute('UPDATE "transaction" SET return_date = ?, status = ?, fine = ? WHERE id = ?',
               (datetime.utcnow(), 'returned', fine_amount, transaction_id))
    db.execute('UPDATE book SET quantity_available = quantity_available + 1 WHERE id = ?', (trans_row['book_id'],))
    db.commit()
    book_title = db.execute('SELECT title FROM book WHERE id = ?', (trans_row['book_id'],)).fetchone()['title']
    flash(f'Book "{book_title}" returned successfully. Fine: ${fine_amount:.2f}', 'success')
    return redirect(url_for('reports'))

# 6. Main Entry Point
if __name__ == '__main__':
    app.run(host="0.0.0.0",port=5000)
