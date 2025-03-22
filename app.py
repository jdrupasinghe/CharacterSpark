from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
import re
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# mongodb connection
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
mongo = PyMongo(app)
bcrypt = Bcrypt(app)

users_collection = mongo.db.users

@app.route('/')
def landing_page():
    if 'user' in session:
        return redirect(url_for('prompt_generation'))
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        re_password = request.form['re_password']

        # Validate username (letters & numbers only)
        if not re.match("^[a-zA-Z0-9]+$", username):
            flash("Username can only contain letters and numbers.", "error")
            return redirect(url_for('signup'))

        # Validate password length
        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "error")
            return redirect(url_for('signup'))

        # Check if passwords match
        if password != re_password:
            flash("Passwords do not match!", "error")
            return redirect(url_for('signup'))

        # Check if username already exists
        existing_user = users_collection.find_one({"username": username})
        if existing_user:
            flash("Username already exists. Please choose a different one.", "error")
            return redirect(url_for('signup'))

        # Hash password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Insert new user to db
        users_collection.insert_one({"username": username, "password": hashed_password})

        # Store user session
        session['user'] = username
        flash("Signup successful!", "success")
        return redirect(url_for('prompt_generation'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session:
        return redirect(url_for('prompt_generation'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if user exists in db
        user = users_collection.find_one({"username": username})

        if user:
            # Verify password
            if bcrypt.check_password_hash(user['password'], password):
                session['user'] = username
                # flash("Login successful!", "success")
                return redirect(url_for('prompt_generation'))
            else:
                flash("Incorrect password. Please try again.", "error")
        else:
            flash("Username does not exist. Please sign up.", "error")

        return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user', None)
    # flash("You have been logged out.", "info")
    return redirect(url_for('landing_page'))


@app.route('/prompt-generation')
def prompt_generation():
    if 'user' not in session:
        return redirect(url_for('signup'))
    return "Prompt Generation Page (Under Development)"


@app.route('/gallery')
def gallery():
    return "Gallery Page (Under Development)"

if __name__ == '__main__':
    app.run(debug=True)
