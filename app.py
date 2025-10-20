# We need to import Flask tools along with our other libraries
from flask import Flask, render_template, request, redirect, url_for, session, flash
import psycopg2
import psycopg2.extras
import bcrypt
import re
from datetime import datetime, timedelta

# Create the Flask web app
app = Flask(__name__)

app.secret_key = 'Makisa-10-Secret'

# --- DATABASE SETUP ---
DB_CONFIG = {
    "dbname": "my_app",
    "user": "postgres",
    "password": "Makisa@10",
    "host": "localhost",
    "port": "5432"
}

def connect_db():
    return psycopg2.connect(**DB_CONFIG)

# --- WEB ROUTES ---

# This is the main page (login page)
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = connect_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("SELECT * FROM usuarios WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            session['loggedin'] = True
            session['id'] = user['id']
            session['full_name'] = user['full_name']
            return redirect(url_for('welcome'))
        else:
            flash('Incorrect email or password. Please try again.')

    return render_template('login.html')

# welcome page, only accessible after logging in
@app.route('/welcome')
def welcome():
    if 'loggedin' in session:
        return render_template('welcome.html', full_name=session['full_name'])
    return redirect(url_for('login'))

# The logout route
@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('full_name', None)
    return redirect(url_for('login'))

# The user registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        password = request.form['password']
        
        # Validation logic
        if len(full_name) < 5:
            flash('Error: The full name must have at least 5 characters.', 'error')
            return redirect(url_for('register'))
        
        if len(password) < 8 or not re.search("[a-zA-Z]", password) or not re.search("[0-9]", password):
            flash('Password must be 8+ characters with a letter and a number.', 'error')
            return redirect(url_for('register'))

        # Encrypt the password
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)

        conn = connect_db()
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO usuarios (full_name, email, password_hash) VALUES (%s, %s, %s)",
                (full_name, email, password_hash.decode('utf-8'))
            )
            conn.commit()
            flash('User successfully registered! You can now log in.', 'success')
            return redirect(url_for('login'))
        except psycopg2.IntegrityError:
            flash('That email is already registered.', 'error')
            return redirect(url_for('register'))
        finally:
            cur.close()
            conn.close()

    return render_template('register.html')

# This makes the app run and should be at the VERY END
if __name__ == '__main__':
    app.run(debug=True)