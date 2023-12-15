import math
import threading
import zipfile
from flask import Flask, Response, flash, jsonify, render_template, send_file, send_from_directory, request, redirect, session, url_for, g
from flask_session import Session
from configparser import ConfigParser
import requests
from werkzeug.utils import secure_filename
import logging
from logging.handlers import RotatingFileHandler
import os
import sqlite3
import re
import sys
import bcrypt
import time
import traceback
from datetime import datetime, timedelta, timezone
import csv
import math
import platform
import cv2
import numpy as np
import pandas as pd
import zwoasi as asi
import pprint
import time
import torch
from queue import Queue
from ultralytics import YOLO
from flask_paginate import Pagination


__author__ = 'Ioannis A. bouhras'
__version__ = '1.0.0 beta'
__license__ = 'AGPL v3'


print('----------------------------------')
print("Application version:", __version__)
print('----------------------------------')

app = Flask(__name__, static_folder='static', template_folder='templates')

# Logging

format = "%(asctime)s: %(message)s"
logging.basicConfig(format=format, level=logging.INFO, datefmt="%H:%M:%S")


def before_first_request():
    log_level = logging.INFO

    for handler in app.logger.handlers:
        app.logger.removeHandler(handler)

    root = os.path.dirname(os.path.abspath(__file__))
    logdir = os.path.join(root, 'logs')
    if not os.path.exists(logdir):
        os.mkdir(logdir)
    log_file = os.path.join(logdir, 'app.log')
    # Rotate every 10 MB and keep up to 5 backups
    handler = RotatingFileHandler(
        log_file, maxBytes=1024*1024*10, backupCount=5)
    handler.setLevel(log_level)
    app.logger.addHandler(handler)

    app.logger.setLevel(log_level)

    defaultFormatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s')
    handler.setFormatter(defaultFormatter)


app.before_request_funcs = [(None, before_first_request())]


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


# Security access
def restrict_access():
    pass


app.before_request_funcs = [(None, restrict_access())]


app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["SECRET_KEY"] = "jsdhfsjd87rewsdjhg78w46sedjfg8346534fsdj347823"
app.config["SESSION_COOKIE_SECURE"] = True
app.config['APP_VERSION'] = 'v 1.0.0 beta'


Session(app)

# folder to upload new models
app.config['UPLOAD_FOLDER'] = 'models'
app.config['ALLOWED_EXTENSIONS'] = {'pt'}

# download reports
app.config['COMMUNITY_UPLOAD_FOLDER'] = 'community'
app.config['COMMUNITY_ALLOWED_EXTENSIONS'] = {'zip'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# Parsing Config file
config_file_path = 'application.conf'

config = ConfigParser(interpolation=None)
config.read(os.path.join(sys.path[0], 'application.conf'))

register_users = config.getboolean("REGISTRATIONS", "register_users")


def get_model_files():
    models_folder = 'models'
    model_files = [file for file in os.listdir(
        models_folder) if file.endswith('.pt')]
    return model_files


def save_selected_model_to_config(selected_model):
    config.read(config_file_path)
    config.set("MODEL", "selected_model", selected_model)
    with open(config_file_path, 'w') as config_file:
        config.write(config_file)


def save_new_model_to_config(selected_model):
    config.read(config_file_path)
    config.set("MODEL_VERSION", "model_version", selected_model)
    with open(config_file_path, 'w') as config_file:
        config.write(config_file)


def load_selected_model_from_config():
    config.read(config_file_path)
    return config.get("MODEL", "selected_model", fallback=None)


# Create and open a CSV file
csv_file_path = 'detections.csv'
fieldnames = ['Date_Time', 'Object', 'Confidence', 'Coordinates']

if not os.path.exists(csv_file_path):
    # Create and open the CSV file
    with open(csv_file_path, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    print(f"CSV file '{csv_file_path}' created.")
else:
    print(f"CSV file '{csv_file_path}' already exists.")

# Create a folder for storing frames with detections
detections_folder = 'detections'
if not os.path.exists(detections_folder):
    os.makedirs(detections_folder)
    

# Create a folder for storing observations
community_folder = 'community'
if not os.path.exists(community_folder):
    os.makedirs(community_folder)

# Create a folder for storing observations
community_folder = 'community'
if not os.path.exists(community_folder):
    os.makedirs(community_folder)


def save_control_values(filename, settings):
    filename += '.txt'
    with open(filename, 'w') as f:
        for k in sorted(settings.keys()):
            f.write('%s: %s\n' % (k, str(settings[k])))
    print('Camera settings saved to %s' % filename)


camera = None


# Database initialization and setup
conn = sqlite3.connect("database/user-database.sqlite")
cursor = conn.cursor()
cursor.execute(
    """CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        login_attempts INTEGER DEFAULT 0,
        last_login_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )"""
)
conn.commit()

MAX_LOGIN_ATTEMPTS = 3  # Maximum number of unsuccessful login attempts
LOCKOUT_TIME = 300  # Lockout duration in seconds (5 minutes)


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect("database/user-database.sqlite")
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(error):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def get_user(username):
    db = get_db()
    cursor = db.execute("SELECT * FROM users WHERE username=?", (username,))
    return cursor.fetchone()


def get_user_id(username):
    db = get_db()
    cursor = db.execute("SELECT id FROM users WHERE username=?", (username,))
    user_row = cursor.fetchone()

    if user_row:
        # Extract the 'id' value from the dictionary
        user_id = user_row['id']
        return user_id
    else:
        return None


def update_login_attempts(username, login_attempts):
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "UPDATE users SET login_attempts=?, last_login_attempt=? WHERE username=?",
        (login_attempts, datetime.now(), username),
    )
    db.commit()


def reset_login_attempts(username):
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "UPDATE users SET login_attempts=0, last_login_attempt=NULL WHERE username=?",
        (username,),
    )
    db.commit()


def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed_password.decode("utf-8")

#################################################################################################################################


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user_ip = request.remote_addr

        user = get_user(username)

        if user is None:
            app.logger.warning(f"Invalid username or password from {user_ip}.")
            return render_template(
                "login.html", error="Invalid username or password."
            )

        # Convert sqlite3.Row to a dictionary-like object
        user_dict = dict(user)

        failed_attempts = user_dict["login_attempts"]
        first_failed_attempt = user_dict.get("first_failed_attempt", None)

        if failed_attempts >= MAX_LOGIN_ATTEMPTS and first_failed_attempt:
            elapsed_time = time.time() - first_failed_attempt
            if elapsed_time < LOCKOUT_TIME:
                remaining_time = int(LOCKOUT_TIME - elapsed_time)
                app.logger.warning(
                    f"Account {username} from IP {user_ip} is locked. Try again after {remaining_time // 60} minutes.")
                return render_template(
                    "login.html",
                    error=f"Your account is locked. Try again after {remaining_time // 60} minutes.",
                )

        hashed_password = user_dict["password"].encode("utf-8")
        if bcrypt.checkpw(password.encode("utf-8"), hashed_password):
            # Successful login, reset login attempts and first_failed_attempt time

            app.logger.info(f"User {username} logged in.")

            reset_login_attempts(username)

            session["username"] = username

            user_id = get_user_id(username)

            session['user_id'] = user_id

            # Update first_failed_attempt to None to indicate a successful login
            db = get_db()
            cursor = db.cursor()
            cursor.execute(
                "UPDATE users SET login_attempts=?, first_failed_attempt=NULL WHERE username=?",
                (0, username),
            )
            db.commit()

            return redirect(url_for("dashboard"))
        else:
            # Increment login attempts and update first failed attempt time if needed
            if failed_attempts == 0:
                db = get_db()
                cursor = db.cursor()
                cursor.execute(
                    "UPDATE users SET login_attempts=?, first_failed_attempt=? WHERE username=?",
                    (1, time.time(), username),
                )
                db.commit()
            else:
                db = get_db()
                cursor = db.cursor()
                cursor.execute(
                    "UPDATE users SET login_attempts=? WHERE username=?",
                    (failed_attempts + 1, username),
                )
                db.commit()

            # If maximum login attempts reached, lock the account
            if failed_attempts + 1 >= MAX_LOGIN_ATTEMPTS:
                app.logger.warning(
                    f"Maximum login attempts reached for {username}. Account is locked for {LOCKOUT_TIME // 60} minutes.")
                return render_template(
                    "login.html",
                    error=f"Maximum login attempts reached. Your account is locked for {LOCKOUT_TIME // 60} minutes.",
                )
            else:
                app.logger.warning(
                    f"Invalid username = {username} or password = {password}. Attempts left: {MAX_LOGIN_ATTEMPTS - failed_attempts - 1}")
                return render_template(
                    "login.html",
                    error=f"Invalid username or password. Attempts left: {MAX_LOGIN_ATTEMPTS - failed_attempts - 1}",
                )

    # if register users is allowed
    register_users = config.getboolean("REGISTRATIONS", "register_users")

    return render_template("login.html", register_users=register_users, error="")

#########################################################################################################################


@app.route("/dashboard", methods=["GET"])
def dashboard():
    if "username" in session:

        # Get list of all photos in the directory
        photo_folder = config.get("DETECTION_DIR", "detection_dir")

        # Only include filenames that start with 'detection'
        photos = [f for f in os.listdir(photo_folder) if f.startswith(
            'detection') and f.endswith(('.jpg', '.png', '.jpeg'))]

        # Get page and page_size from the request parameters (default to 1 and 10 if not provided)
        page = int(request.args.get('page', 1))
        page_size = int(request.args.get('page_size', 12))

        # Calculate start and end indices based on page and page_size
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size

        # Slice the list of photos to get only the ones for the current page
        photos_for_page = photos[start_idx:end_idx]

        # Calculate total number of pages
        num_pages = math.ceil(len(photos) / page_size)

        version = app.config['APP_VERSION']
        
        return render_template(
            "index.html",
            username=session["username"],
            photos=photos_for_page,
            photo_folder=photo_folder,
            page=page,
            page_size=page_size,
            num_pages=num_pages,
            version=version
        )
    else:
        return redirect(url_for("login"))


@app.route('/live')
def live():
    if session['username']:

        # Attempt to initialize the camera
        error_message = initialize_camera()

        while error_message:
            # Camera initialization failed, flash an error message
            flash(error_message, 'danger')
            return render_template('live-dummy.html', username=session.get("username", None))

        if (camera_model):
            CameraModel = camera_model
        else:
            CameraModel = "None detected!"
        # Camera initialized successfully, flash a success message
        flash("Camera " + camera_model + " initialized successfully!", 'success')

        return render_template('live.html', username=session["username"], det_camera=CameraModel)

    return redirect(url_for("login"))


@app.route('/images/<folder>/<filename>')
def serve_image(folder, filename):
    if session['username']:
        return send_from_directory(folder, filename)
    return redirect(url_for("login"))


@app.route('/images/<folder>/<filename>')
def serve_original_image(folder, filename):
    if session['username']:
        return send_from_directory(folder, filename)
    return redirect(url_for("login"))


@app.route('/detections/<filename>')
def serve_detection_image(filename):
    if session['username']:
        detection_folder = config.get("DETECTION_DIR", "detection_dir")
        return send_from_directory(detection_folder, filename)
    return redirect(url_for("login"))


@app.route('/show_photo/<filename>')
def show_photo(filename):
    if session['username']:
        detection_folder = config.get("DETECTION_DIR", "detection_dir")
        original_filename = filename.replace('detection_', 'original_')

        original_path = os.path.join(detection_folder, original_filename)
        detection_path = os.path.join(detection_folder, filename)

        return render_template(
            'photo.html',
            original_path=original_path,
            detection_path=detection_path,
            username=session["username"],
            filename=filename,
            folder=detection_folder,
            original_filename=original_filename
        )
    return redirect(url_for("login"))


@app.route('/delete_photo/<filename>', methods=['POST'])
def delete_photo(filename):
    if session['username']:
        try:
            # Full path to the detection photo
            detection_path = os.path.join(config.get(
                "DETECTION_DIR", "detection_dir"), filename)

            # Assuming your filenames are well-formatted (e.g., 'original_2023-12-06_10-11-28.jpg')
            original_filename = filename.replace('detection_', 'original_')
            original_path = os.path.join(config.get(
                "DETECTION_DIR", "detection_dir"), original_filename)

            # Delete both the detection and original photos
            os.remove(detection_path)
            os.remove(original_path)

            # Delete corresponding row from CSV file
            csv_file_path = 'detections.csv'  # Provide the correct path to your CSV file
            delete_csv_row(csv_file_path, filename)

            flash('Photos deleted successfully', 'success')

            return redirect(url_for('dashboard'))
        except Exception as e:
            traceback.print_exc()  # Print the full traceback to the console for debugging
            return render_template('error.html', error_message=str(e))
    return redirect(url_for("login"))


def delete_csv_row(csv_file_path, filename):
    # Read CSV file into a list of dictionaries
    with open(csv_file_path, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        data = [row for row in reader]

    # Identify and remove the row with the specified filename
    data = [row for row in data if row['Object'] != filename]

    # Write the modified data back to the CSV file
    with open(csv_file_path, 'w', newline='') as csvfile:
        # Replace with your actual field names
        fieldnames = ['Date_Time', 'Object', 'Confidence', 'Coordinates']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)


def initialize_csv(csv_file_path):
    # Check if the CSV file exists, and create it if it doesn't
    if os.path.exists(csv_file_path):
        with open(csv_file_path, 'w', newline='') as csvfile:
            fieldnames = ['Date_Time', 'Object', 'Confidence', 'Coordinates']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()


def delete_all_photos(directory_path):
    try:
        # List all files in the directory
        files = os.listdir(directory_path)

        # Check if there are files to delete
        if not files:
            flash('No photos to delete', 'info')
            return redirect(url_for('dashboard'))

        # Delete all photos
        for file in files:
            file_path = os.path.join(directory_path, file)
            os.remove(file_path)

        # Initialize CSV (assuming this function is responsible for creating detections.csv)
        initialize_csv(csv_file_path)

        flash('All photos deleted successfully', 'success')

        return redirect(url_for('dashboard'))

    except Exception as e:
        print(e)
        traceback.print_exc()
        return render_template('error.html', error_message=str(e))


@app.route('/delete_all_photos', methods=['POST'])
def delete_all_photos_route():
    if session['username']:

        directory_path = config.get("DETECTION_DIR", "detection_dir")

        # Call the function to delete all photos in the directory
        delete_all_photos(directory_path)

        return redirect(url_for('dashboard'))
    return redirect(url_for("login"))


@app.route('/create_observation', methods=['POST'])
def create_observation():
    try:
        if 'username' in session:
            # Get observer
            observer = config.get('OBSERVER', 'name')

            # Directory path for detections
            directory_path = config.get('DETECTION_DIR', 'detection_dir')

            # List all files in the directory
            files = os.listdir(directory_path)

            # Check if there are files to create an observation
            if not files:
                flash('No photos to create an observation', 'info')
                return redirect(url_for('dashboard'))

            # Create a ZIP file with a filename containing the current datetime
            zip_filename = observer + \
                f"_detections_{datetime.now().strftime('%Y%m%d%H%M%S')}.zip"
            zip_filepath = os.path.join('community', zip_filename)

            with zipfile.ZipFile(zip_filepath, 'w') as zipf:
                # Iterate through each file and add it to the ZIP archive
                for file in files:
                    file_path = os.path.join(directory_path, file)
                    zipf.write(file_path, arcname=os.path.basename(file_path))

                # Add the detections.csv file to the ZIP archive
                csv_file_path = os.path.join('detections.csv')
                zipf.write(csv_file_path,
                           arcname=os.path.basename(csv_file_path))

            flash('Observation created successfully', 'success')
            return redirect(url_for('report'))

        else:
            flash('User not authenticated', 'error')
            return redirect(url_for('login'))

    except Exception as e:
        flash(f'Error creating observation: {str(e)}', 'error')
        return redirect(url_for('dashboard'))


@app.route("/logout", methods=["GET"])
def logout():
    if session['username']:
        app.logger.info(f"User {session['username']} logged out.")
        session.pop("username", None)
        return redirect(url_for("login"))
    return redirect(url_for("login"))


@app.errorhandler(Exception)
def handle_error(e):
    return render_template('error.html', error=str(e)), 500


def is_valid_password(password):
    # Check if the password contains at least 8 characters,
    # an uppercase letter, a lowercase letter, and a number.
    if (
        len(password) >= 8
        and re.search(r"[A-Z]", password)
        and re.search(r"[a-z]", password)
        and re.search(r"\d", password)
    ):
        return True
    return False


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        app.logger.info(
            f"New user registration attempt with username =  {username} and password = {password}.")

        if not username or not password or not confirm_password:
            return render_template(
                "register.html", error="Please provide all required fields."
            )

        existing_user = get_user(username)
        if existing_user:
            return render_template(
                "register.html", error="This username is already taken."
            )

        if password != confirm_password:
            return render_template(
                "register.html", error="Passwords do not match. Please try again."
            )

        if not is_valid_password(password):
            return render_template(
                "register.html",
                error="Password must contain at least 8 characters, an uppercase letter, a lowercase letter, and a number.",
            )

        hashed_password = hash_password(password)

        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hashed_password),
        )
        db.commit()

        return redirect(url_for("login"))

    return render_template("register.html", error="")


@app.route('/log')
def log():
    # Check if user is loggedin
    if session['username'] == "admin":
        try:
            logfile = os.path.join(sys.path[0], 'logs/app.log')
            with open(logfile, 'r') as f:
                lines = f.readlines()
                num_lines = len(lines)
                page = request.args.get('page', default=1, type=int)
                page_size = request.args.get('page_size', default=13, type=int)
                num_pages = math.ceil(num_lines / page_size)
                start_index = (page - 1) * page_size
                end_index = min(start_index + page_size, num_lines)
                last_lines = lines[start_index:end_index]
                logs = []

                for line in last_lines:
                    parts = line.strip().split(' ')
                    timestamp = parts[0] + ' ' + parts[1]
                    level = parts[2]
                    module = parts[4].strip(':')
                    message = ' '.join(parts[5:])
                    logs.append({'timestamp': timestamp, 'level': level,
                                'module': module, 'message': message})

            return render_template('log.html', username=session["username"], lines=logs, num_pages=num_pages, current_page=page, page_size=page_size)
        except Exception as ex:
            print(ex)
            flash(
                'There was a problem with your log file, Please clean the file. ', 'warning')
    return redirect(url_for('login'))


@app.route('/clear_log', methods=['POST'])
def clear_log():
    if session['username'] == "admin":
        try:
            with open(os.path.join(sys.path[0], 'logs/app.log'), 'w') as f:
                f.truncate(0)
            logfile = os.path.join(sys.path[0], 'logs/app.log')
            with open(logfile, 'r') as f:
                lines = f.readlines()
                num_lines = len(lines)
                page = request.args.get('page', default=1, type=int)
                page_size = request.args.get('page_size', default=50, type=int)
                num_pages = math.ceil(num_lines / page_size)
                start_index = (page - 1) * page_size
                end_index = min(start_index + page_size, num_lines)
                last_lines = lines[start_index:end_index]
                logs = []
                for line in last_lines:
                    parts = line.strip().split(' ')
                    timestamp = parts[0] + ' ' + parts[1]
                    level = parts[2]
                    module = parts[4].strip(':')
                    message = ' '.join(parts[5:])
                    logs.append({'timestamp': timestamp, 'level': level,
                                'module': module, 'message': message})
                    flash('Log file cleared successfully!', 'success')
            return render_template('log.html', lines=logs, num_pages=num_pages, current_page=page, page_size=page_size, username=session["username"])

        except Exception as e:
            flash('Cannot clear log file', 'danger')
            return render_template('log.html',)
    return redirect(url_for('login'))


def get_user_by_id(user_id):
    db = get_db()
    cursor = db.execute("SELECT * FROM users WHERE id=?", (user_id,))
    return cursor.fetchone()


def check_old_password(user_id, old_password):
    user = get_user_by_id(user_id)

    if user and bcrypt.checkpw(old_password.encode("utf-8"), user["password"].encode("utf-8")):
        return True
    return False


def update_user_password(user_id, new_password):
    hashed_password = hash_password(new_password)

    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "UPDATE users SET password=? WHERE id=?",
        (hashed_password, user_id),
    )
    db.commit()


# Function to get all users
def get_all_users():
    db = get_db()
    cursor = db.execute("SELECT * FROM users")
    users = cursor.fetchall()
    return users


@app.route('/profile', methods=['GET'])
def profile():
    if "user_id" in session:

        users = get_all_users()

        user_id = session["user_id"]
        user = get_user_by_id(user_id)
        return render_template("profile.html", user=user, users=users, username=session['username'])
    else:
        return redirect(url_for("login"))


@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if "user_id" in session:
        user_id = session["user_id"]

        if request.method == "POST":
            # Check the old password and update the password in the database
            old_password = request.form["old_password"]
            new_password = request.form["new_password"]

            if check_old_password(user_id, old_password):
                if not is_valid_password(new_password):
                    flash(
                        "Password must contain at least 8 characters, an uppercase letter, a lowercase letter, and a number.", "warning")
                    # Redirect back to the form with the flash message
                    return redirect(url_for("change_password"))

                update_user_password(user_id, new_password)
                flash("Password updated successfully!", "success")
                return redirect(url_for("profile"))
            else:
                flash("Incorrect old password.", "warning")
                return redirect(url_for("change_password"))

        return render_template("password.html", user_id=user_id, username=session['username'])
    else:
        return redirect(url_for("login"))


# Close the database connection when done
def close_db():
    conn.close()


def insert_user(username, password):
    try:
        db = get_db()
        cursor = db.cursor()
        hash_pwd = hash_password(password)

        if (username, password != ""):
            pass
        else:
            flash('Username/Pasword empty.', 'warning')
            return False

        if not is_valid_password(password):
            return False
        else:
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)", (username, hash_pwd))
            db.commit()
            return True

    except sqlite3.IntegrityError:
        # User with the same username already exists
        flash('Username already exists. Choose a different username.', 'danger')
        return False


# Route for adding a user
@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if session['username']:
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')

            if insert_user(username, password):
                flash('User added successfully!', 'success')
            else:
                flash(
                    'Password must contain at least 8 characters, an uppercase letter, a lowercase letter, and a number.', 'danger')

            return redirect(url_for('profile'))

        return render_template('add_user.html', username=session['username'])
    return redirect(url_for('login'))


def delete_user_from_db(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()

# Route for deleting a user


@app.route('/delete_user/<int:user_id>', methods=['GET', 'POST'])
def delete_user(user_id):
    if session['username']:
        try:
            # Call the function to delete the user from the database
            delete_user_from_db(user_id)

            flash('User deleted successfully!', 'success')
            return redirect(url_for('profile'))
        except Exception as e:
            # Handle any exceptions that may occur during the deletion process
            flash(f'Error deleting user: {str(e)}', 'danger')
            return redirect(url_for('profile'))
    return redirect(url_for('login'))

############################################################################################


def initialize_camera():
    global camera
    global camera_model

    if camera is not None:
        return  # Camera is already initialized

    try:
        if platform.system() == "Windows":
            print("OS Windows - Loading windows driver")
            asi.init(r"drivers\zwo_windows\lib\x64\ASICamera2.dll")
        elif platform.system() == "Linux":
            print("OS Linux - Loading linux driver")
            asi.init(r"drivers/zwo_linux/lib/x64/libASICamera2.so.1.24")
        else:
            print("Unsupported operating system")

        num_cameras = asi.get_num_cameras()
        logging.info(f"Number of cameras: {num_cameras}")

        if num_cameras == 0:
            raise ValueError("No cameras found")

        camera_id = 0  # use the first camera from the list
        cameras_found = asi.list_cameras()

        logging.info(f"List of cameras found: {cameras_found}")
        camera = asi.Camera(camera_id)
        camera_info = camera.get_camera_property()
        logging.debug(
            f"Camera properties :\n{pprint.pformat(camera_info, depth=3)}")

        logging.debug("Is triggercam : {}".format(camera_info["IsTriggerCam"]))
        logging.debug(f"Camera mode : {camera.get_camera_mode()}")

        # Use minimum USB bandwidth permitted
        camera.set_control_value(asi.ASI_BANDWIDTHOVERLOAD, camera.get_controls()[
                                 'BandWidth']['MinValue'])

        camera_info = camera.get_camera_property()

        print('')
        print("Camera detected: " + camera_info['Name'])

        camera_model = camera_info['Name']

        # Get all of the camera controls
        print('')
        print('Camera controls:')
        controls = camera.get_controls()
        for cn in sorted(controls.keys()):
            print('    %s:' % cn)
            for k in sorted(controls[cn].keys()):
                print('        %s: %s' % (k, repr(controls[cn][k])))

        # Set some sensible defaults. They will need adjusting depending upon
        # the sensitivity, lens and lighting conditions used.
        camera.disable_dark_subtract()

        camera.set_control_value(asi.ASI_GAIN, 200)
        camera.set_control_value(asi.ASI_EXPOSURE, 10000)
        camera.set_control_value(asi.ASI_WB_B, 95)
        camera.set_control_value(asi.ASI_WB_R, 52)
        camera.set_control_value(asi.ASI_GAMMA, 0)
        camera.set_control_value(asi.ASI_BRIGHTNESS, 0)
        camera.set_control_value(asi.ASI_FLIP, 0)

        print('Enabling stills mode')
        try:
            # Force any single exposure to be halted
            camera.stop_video_capture()
            camera.stop_exposure()
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            pass

        if camera_info['IsColorCam']:
            camera.set_image_type(asi.ASI_IMG_RGB24)
        else:
            print('Color image not available with this camera')

        if platform.system() == "Linux":
            # Restore all controls to default values except USB bandwidth
            for c in controls:
                if controls[c]['ControlType'] == asi.ASI_BANDWIDTHOVERLOAD:
                    continue
                camera.set_control_value(
                    controls[c]['ControlType'], controls[c]['DefaultValue'])

        # Can autoexposure be used?
        k = 'Exposure'
        if 'Exposure' in controls and controls['Exposure']['IsAutoSupported']:
            print('Enabling auto-exposure mode')
            camera.set_control_value(asi.ASI_EXPOSURE,
                                     controls['Exposure']['DefaultValue'],
                                     auto=True)

            if 'Gain' in controls and controls['Gain']['IsAutoSupported']:
                print('Enabling automatic gain setting')
                camera.set_control_value(asi.ASI_GAIN,
                                         controls['Gain']['DefaultValue'],
                                         auto=True)

            # Keep max gain to the default but allow exposure to be increased to its maximum value if necessary
            camera.set_control_value(
                controls['AutoExpMaxExpMS']['ControlType'], controls['AutoExpMaxExpMS']['MaxValue'])

        # Set the timeout, units are ms
        timeout = (camera.get_control_value(
            asi.ASI_EXPOSURE)[0] / 1000) * 2 + 500
        camera.default_timeout = timeout

        if (platform.system() == 'Linux'):
            save_control_values("camera-settings", camera.get_control_values())

    except Exception as e:
        error_message = f"Error initializing camera: {str(e)}"
        logging.error(error_message)
        camera = None
        return error_message

    return None  # Initialization successful


def resize_without_distortion(img, target_size):
    # Ensure target_size is in (width, height) format
    target_width, target_height = target_size

    # Get the original dimensions
    original_height, original_width = img.shape[:2]

    # Calculate the aspect ratios
    aspect_ratio_original = original_width / original_height
    aspect_ratio_target = target_width / target_height

    # Calculate the new size based on the original aspect ratio
    if aspect_ratio_original > aspect_ratio_target:
        new_width = target_width
        new_height = int(target_width / aspect_ratio_original)
    else:
        new_width = int(target_height * aspect_ratio_original)
        new_height = target_height

    # Resize the image using the INTER_AREA interpolation method
    img_resized = cv2.resize(
        img, (new_width, new_height), interpolation=cv2.INTER_AREA)

    return img_resized


#
#
# MAIN FUNCTION
#
#

def generate_frames():
    # Here is the actual work

    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")

    logging.info("Using: " + str(device))

    selected_model = load_selected_model_from_config()
    logging.info("----> MODEL <----")
    logging.info("loading AI model " + selected_model)
    logging.info("----> MODEL <----")
    model = YOLO("models/" + selected_model)  # Replace with your YOLO model
    classNames = ["Impact", "Satellite", "Shadow"]

    # Retrieve the boolean value from the configuration file
    is_utc_enabled = config.getboolean('UTC', 'utc')
    
    #user defined confidence
    user_dev_confidence = config.getfloat('CONFIDENCE','confidence')

    while True:
        try:
            start = time.time()
            
            img_resized = None  # Reset img_resized on each iteration
            img = None

            max_retries = 5

            for _ in range(max_retries):
                try:

                    img = camera.capture()

                    break
                except asi.ZWO_CaptureError as e:
                    print(f"Capture error: {e}")

            # Ensure the image is in the correct format (BGR)
            # img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
            img = cv2.cvtColor(img, asi.ASI_IMG_RGB24)

            # Print the original size
            original_height, original_width = img.shape[:2]

            # Resize image to match YOLO model input size
            target_size = (640, 640)
            img_resized = resize_without_distortion(img, target_size)

            # Create an empty list to store bounding boxes
            bounding_boxes = []

            # Perform YOLO model inference on the resized image
            results = model(img_resized, stream=True, device=device)
            for r in results:
                boxes = r.boxes

                for box in boxes:
                    # bounding box
                    x1, y1, x2, y2 = map(int, box.xyxy[0])
                    bounding_boxes.append((x1, y1, x2, y2))

                    # confidence
                    confidence = math.ceil((box.conf[0] * 100)) / 100
                    print("Confidence --->", confidence)

                    # class name
                    cls = int(box.cls[0])
                    print("Class name -->", classNames[cls])

                    # object details
                    org = [x1, y1]
                    font = cv2.FONT_HERSHEY_SIMPLEX
                    fontScale = 0.60
                    color = (240, 103, 13)
                    thickness = 2
                    cv2.putText(img_resized, classNames[cls] + " " + str(
                        round(confidence * 100, 2)) + "%", org, font, fontScale, color, thickness)

                    # Get current date and time once
                    date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S_local')

                    # Get current time in UTC
                    date_time_utc = datetime.utcnow().replace(tzinfo=timezone.utc)


                    # Use UTC time for filenames
                    date_time_utc_str = date_time_utc.strftime(
                        '%Y-%m-%d_%H-%M-%S_utc')

                    # Check if UTC is enabled in the configuration
                    if is_utc_enabled:
                        date_time_utc_str = date_time_utc.strftime(
                            '%Y-%m-%d_%H-%M-%S_utc')
                    else:
                        # Use local time
                        date_time_utc_str = date_time
                    

                    # If the detected object is a "Impact," write to CSV and save frame
                    if classNames[cls] == 'Impact' and confidence > user_dev_confidence:
                        # Write to CSV
                        with open(csv_file_path, 'a', newline='') as csvfile:
                            writer = csv.DictWriter(
                                csvfile, fieldnames=fieldnames)
                            writer.writerow({'Date_Time': date_time_utc_str, 'Object': f'detection_{date_time_utc_str.replace(" ", "_").replace(":", "-")}.jpg',
                                            'Confidence': confidence, 'Coordinates': f'({x1},{y1})-({x2},{y2})'})

                        # Save frame without detection
                        frame_filename = os.path.join(
                            detections_folder, f'original_{date_time_utc_str.replace(" ", "_").replace(":", "-")}.jpg')
                        cv2.imwrite(frame_filename,
                                    img)

                        # Draw the new bounding boxes on the image
                        for box in bounding_boxes:
                            x1, y1, x2, y2 = box
                            thickness = 2
                            cv2.rectangle(img_resized, (x1, y1),
                                          (x2, y2), (255, 0, 255), thickness)

                        # Save frame with detection
                        frame_filename = os.path.join(
                            detections_folder, f'detection_{date_time_utc_str.replace(" ", "_").replace(":", "-")}.jpg')
                        cv2.imwrite(frame_filename, resize_without_distortion(
                            img_resized, (original_height, original_width)))

            # Draw the new bounding boxes on the image
            for box in bounding_boxes:
                x1, y1, x2, y2 = box
                thickness = 2
                cv2.rectangle(img_resized, (x1, y1),
                              (x2, y2), (255, 0, 255), thickness)

            # Convert the image to JPEG format for streaming
            ret, jpeg = cv2.imencode('.jpg', img_resized)
            frame_bytes = jpeg.tobytes()
            
            end = time.time()
            # show timing information on YOLO
            print("[INFO] YOLO took {:.6f} seconds".format(end - start))

            # Add headers to disable caching
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n'
                   b'Cache-Control: no-store, no-cache, must-revalidate, max-age=0\r\n\r\n' + frame_bytes + b'\r\n\r\n')

        except asi.ZWO_IOError as e:
            # print(f"Timeout error in camera capture: {e}")
            # Add retry logic or other error handling here
            continue
        except cv2.error as e:
            # Handle OpenCV error related to demosaicing
            print(f"OpenCV error: {e}")
            # Add appropriate error handling or retry logic
            continue


@app.route('/get_camera_controls', methods=['GET'])
def get_camera_controls():
    if session['username']:
        try:
            logging.info("Fetching current camera values")

            if camera is not None:
                # Get current camera controls
                gain = camera.get_control_value(asi.ASI_GAIN)
                exposure = camera.get_control_value(asi.ASI_EXPOSURE)
                wb_b = camera.get_control_value(asi.ASI_WB_B)
                wb_r = camera.get_control_value(asi.ASI_WB_R)
                gamma = camera.get_control_value(asi.ASI_GAMMA)
                brightness = camera.get_control_value(asi.ASI_BRIGHTNESS)
                flip = camera.get_control_value(asi.ASI_FLIP)

                logging.info(
                    f"Camera values: {dict(gain=gain, exposure=exposure, wb_b=wb_b, wb_r=wb_r, gamma=gamma, brightness=brightness, flip=flip)}")

                # Return JSON data
                return jsonify(
                    success=True,
                    gain=gain, exposure=exposure, wb_b=wb_b,
                    wb_r=wb_r, gamma=gamma, brightness=brightness, flip=flip
                )
            else:
                logging.warning('Cannot fetch camera values')
                return jsonify(success=False, error="Camera not available"), 404
        except Exception as e:
            logging.error(f"An error occurred: {e}")
            return jsonify(success=False, error=str(e)), 500
    return redirect(url_for('login'))


@app.route('/set_camera_controls', methods=['POST'])
def set_camera_controls():
    if session['username']:
        try:
            logging.info("Changing camera values")

            if camera is not None:
                # Get form inputs with default values
                gain = int(request.form.get('gain', 0))
                exposure = int(request.form.get('exposure', 0))
                wb_b = int(request.form.get('wb_b', 0))
                wb_r = int(request.form.get('wb_r', 0))
                gamma = int(request.form.get('gamma', 0))
                brightness = int(request.form.get('brightness', 0))
                flip = int(request.form.get('flip', 0))

                # Set camera controls
                camera.set_control_value(asi.ASI_GAIN, gain)
                camera.set_control_value(asi.ASI_EXPOSURE, exposure)
                camera.set_control_value(asi.ASI_WB_B, wb_b)
                camera.set_control_value(asi.ASI_WB_R, wb_r)
                camera.set_control_value(asi.ASI_GAMMA, gamma)
                camera.set_control_value(asi.ASI_BRIGHTNESS, brightness)
                camera.set_control_value(asi.ASI_FLIP, flip)

                logging.info(
                    f"Camera controls set: {dict(gain=gain, exposure=exposure, wb_b=wb_b, wb_r=wb_r, gamma=gamma, brightness=brightness, flip=flip)}")
                if (platform.system() == 'Linux'):
                    save_control_values("camera-settings",
                                        camera.get_control_values())
                # flash('Camera values successfully updated', 'success')
                return jsonify(success=True, message="Camera values updated"), 200
            else:
                # flash('Cannot set camera values', 'warning')
                return jsonify(success=False, error="Camera not available"), 404
        except ValueError as e:
            logging.error(f"Invalid value: {e}")
            return jsonify(success=False, error=f"Invalid value: {e}"), 400
        except KeyError as e:
            logging.error(f"Missing key: {e}")
            return jsonify(success=False, error=f"Missing key: {e}"), 400
        except Exception as e:
            logging.error(f"An error occurred: {e}")
            return jsonify(success=False, error=str(e)), 500
    return redirect(url_for('login'))


@app.route('/video_feed')
def video_feed():
    if session['username']:
        return Response(generate_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')
    return redirect(url_for('login'))


@app.route('/video_feed_dummy')
def video_feed_dummy():
    if session['username']:
        return render_template('live-dummy.html', mimetype='multipart/x-mixed-replace; boundary=frame')
    return redirect(url_for('login'))


@app.route('/detections')
def detections():
    if session['username']:
        # Read data from CSV file using pandas
        df = pd.read_csv('detections.csv')

        # Paginate the data
        page = int(request.args.get('page', 1))
        per_page = 10
        offset = (page - 1) * per_page
        data = df.iloc[offset: offset + per_page].to_dict(orient='records')

        # Set up pagination
        pagination = Pagination(page=page, total=len(
            df), per_page=per_page, css_framework='bootstrap4')

        return render_template('detections.html', columns=df.columns, data=data, pagination=pagination, username=session['username'])
    return redirect(url_for('login'))


@app.route('/jaiid/version')
def version():
    if session['username']:
        appVersion = str(__version__)
        return render_template('about.html', version=appVersion, username=session['username'])
    return redirect(url_for('login'))


@app.route('/process_model', methods=['POST'])
def process_model():
    if session['username']:
        is_utc_enabled = config.getboolean('UTC', 'utc')
        observer = config.get('OBSERVER', 'name')
        impact_confidence = config.get('CONFIDENCE', 'confidence')
        selected_model = request.form['selected_model']
        # Do something with the selected_model, e.g., set it as a session variable
        session['selected_model'] = selected_model
        # Save selected_model to config file
        save_selected_model_to_config(selected_model)
        model_files = get_model_files()
        return render_template('settings.html', model_files=model_files, selected_model=selected_model, is_utc_enabled=is_utc_enabled, observer_name=observer,impact_confidence=impact_confidence,username=session['username'])
    return redirect(url_for('login'))


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if session['username']:
        model_files = get_model_files()
        selected_model = load_selected_model_from_config()
        observer = config.get('OBSERVER', 'name')
        impact_confidence = config.get('CONFIDENCE', 'confidence')

        is_utc_enabled = config.getboolean('UTC', 'utc')

        if request.method == 'POST':
            # Check if the form was submitted for model selection
            if 'selected_model' in request.form:
                selected_model = request.form['selected_model']
                # Do something with the selected_model, e.g., set it as a session variable
                session['selected_model'] = selected_model
                # Save selected_model to config file
                save_selected_model_to_config(selected_model)

            # Check if the form was submitted for file upload
            elif 'file' in request.files:
                file = request.files['file']
                if file and allowed_file(file.filename):
                    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                    filename_with_timestamp = f'jaiid-model-{timestamp}.pt'
                    file.save(os.path.join(
                        app.config['UPLOAD_FOLDER'], filename_with_timestamp))

                    # Update model_files after uploading a new model
                    model_files = get_model_files()

                    flash(
                        f'Model {filename_with_timestamp} uploaded successfully', 'success')
                    return redirect(url_for('settings'))

                flash('Invalid file format. Allowed formats: .pt', 'error')
                return render_template('settings.html', model_files=model_files, selected_model=selected_model,
                                       error='Invalid file format. Allowed formats: .pt, .pth', username=session['username'])

        return render_template('settings.html', model_files=model_files, selected_model=selected_model, username=session['username'], is_utc_enabled=is_utc_enabled, observer_name=observer,impact_confidence=impact_confidence)
    return redirect(url_for('login'))


@app.route('/delete_model', methods=['POST'])
def delete_model():
    if (session['username']):
        model_name_to_delete = request.form['model_name']
        is_utc_enabled = config.getboolean('UTC', 'utc')
        # Ensure that the model name is not empty or None
        if model_name_to_delete:
            # Path to the models folder
            models_folder = "models/"

            # Ensure that the model file exists before attempting to delete
            model_path = os.path.join(models_folder, model_name_to_delete)
            if os.path.exists(model_path):
                # Check if the model to delete is not the currently selected model
                if model_name_to_delete != session.get('selected_model'):
                    try:
                        os.remove(model_path)
                        flash(
                            f'Model {model_name_to_delete} deleted successfully', 'success')
                    except Exception as e:
                        flash(f'Error deleting model: {e}', 'danger')

                    return redirect(url_for('settings', is_utc_enabled=is_utc_enabled))
                else:
                    flash('Cannot delete the currently selected model.', 'danger')
                    return redirect(url_for('settings', is_utc_enabled=is_utc_enabled))

        # If the model name is empty or the file does not exist, flash an error message
        flash('Invalid model name for deletion', 'danger')
        return redirect(url_for('settings'))
    return redirect(url_for('login'))


@app.route('/process_time_option', methods=['POST'])
def process_time_option():
    if (session['username']):
        # Get the selected option from the form
        selected_option = request.form.get('time_option')

        # Update the configuration based on the selected option
        if selected_option == 'utc':
            is_utc_enabled = True
        elif selected_option == 'local':
            is_utc_enabled = False

        # Update the configuration file
        config.set('UTC', 'utc', str(is_utc_enabled))
        with open('application.conf', 'w') as configfile:
            config.write(configfile)
        flash('Option saved successfully!', 'success')
        return redirect(url_for('settings', is_utc_enabled=is_utc_enabled, username=session['username']))
    return redirect(url_for('login'))


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['COMMUNITY_ALLOWED_EXTENSIONS']


@app.route('/report')
def report():
    if (session['username']):
        file_info = get_file_info()
        return render_template('community.html', file_info=file_info, username=session['username'])
    return redirect(url_for('login'))


@app.route('/delete/<filename>')
def delete_file(filename):
    if (session['username']):
        file_path = os.path.join(
            app.config['COMMUNITY_UPLOAD_FOLDER'], filename)
        os.remove(file_path)
        flash(f'{filename} deleted successfully', 'success')
        return redirect(url_for('report'))
    return redirect(url_for('report'))


def get_file_info():
    file_info = []
    for filename in os.listdir(app.config['COMMUNITY_UPLOAD_FOLDER']):
        file_path = os.path.join(
            app.config['COMMUNITY_UPLOAD_FOLDER'], filename)
        stat_info = os.stat(file_path)
        date_created = datetime.fromtimestamp(
            stat_info.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
        size = stat_info.st_size
        file_type = 'ZIP'
        file_info.append({'filename': filename, 'date_created': date_created,
                         'size': size, 'file_type': file_type})
    return file_info


@app.route('/community/<filename>')
def download_file(filename):
    if session['username']:
        detection_folder = "community"
        return send_from_directory(detection_folder, filename)
    return redirect(url_for("login"))


# Process Observer form
@app.route('/process_observer', methods=['POST'])
def process_observer():
    try:
        if 'username' in session:
            new_observer_name = request.form.get('observer_name')

            config.set('OBSERVER', 'name', new_observer_name)

            with open('application.conf', 'w') as config_file:
                config.write(config_file)

            flash('Observer name updated successfully', 'success')
            return redirect(url_for('settings'))

        else:
            flash('User not authenticated', 'error')
            return redirect(url_for('login'))

    except Exception as e:
        flash(f'Error updating observer name: {str(e)}', 'error')
        return redirect(url_for('settings'))


# Process Observer form
@app.route('/process_conficence', methods=['POST'])
def impact_confidence():
    try:
        if 'username' in session:
            new_confidence_value = request.form.get('impact_confidence')

            config.set('CONFIDENCE', 'confidence', new_confidence_value)

            with open('application.conf', 'w') as config_file:
                config.write(config_file)

            flash('Impact confidence updated successfully', 'success')
            return redirect(url_for('settings'))

        else:
            flash('User not authenticated', 'error')
            return redirect(url_for('login'))

    except Exception as e:
        flash(f'Error updating observer name: {str(e)}', 'error')
        return redirect(url_for('settings'))

@app.route('/versioncheck')
def versioncheck():
    if 'username' in session:
        # Create a Queue to communicate the result between threads
        result_queue = Queue()

        # Create a thread to run the check_internet_connection function
        internet_thread = threading.Thread(
            target=check_internet_connection, args=(result_queue,))

        # Start the thread
        internet_thread.start()

        # Optionally, wait for the thread to finish
        internet_thread.join()

        # Retrieve the result from the Queue
        internet_connected = result_queue.get()
        
        
        if internet_connected:
            # Get running version from your config
            config.read(config_file_path)
            running_version = config.get('MODEL_VERSION', 'model_version')

            # Fetch JSON file from the specified URL
            json_url = 'https://raw.githubusercontent.com/ibsoft/ibsoft-updates/main/jaiid/version.json'
            response = requests.get(json_url)

            if response.status_code == 200:
                # Parse JSON content
                versions_data = response.json()
                # Extract the 'community_version' and 'download_link' from the JSON
                community_version = versions_data.get('community_version', '')
                download_link = versions_data.get('download_link', '')

            else:
                # Handle the case when fetching the JSON fails
                community_version = ''
                download_link = ''
                flash('Cannot check for new model version', 'warning')

            # Check if running version matches the community version
            if compare_version_dates(running_version, community_version) < 0:
                is_upgrade_available = True

            else:
                is_upgrade_available = False
        else:
            # No internet connection, set default values
            is_upgrade_available = False
            community_version = ''
            download_link = ''
            config.read(config_file_path)
            running_version = config.get('MODEL_VERSION', 'model_version')
            flash('No internet connection available.', 'warning')

        # Render the template with the variables
        return render_template('version.html', is_upgrade_available=is_upgrade_available, download_link=download_link, version=running_version, username=session['username'])
    return redirect(url_for('login'))


def check_internet_connection(result_queue):
    try:
        # Try to make a request to a known server (e.g., Google's public DNS)
        requests.get("http://www.google.com", timeout=3)
        result_queue.put(True)
    except requests.ConnectionError:
        result_queue.put(False)


def compare_version_dates(local_version, community_version):
    local_date = int(local_version.split('-')[-1].split('.')[0])
    community_date = int(community_version.split('-')[-1].split('.')[0])
    return local_date - community_date


@app.route('/download_model')
def download_model():
    github_url = 'https://raw.githubusercontent.com/ibsoft/ibsoft-updates/main/jaiid/latest.pt'
    response = requests.get(github_url)

    if response.status_code == 200:
        try:
            current_datetime = datetime.now().strftime("%Y%m%d%H%M%S")

            # Create the filename with the desired format
            filename = f"jaiid-model-{current_datetime}.pt"

            # Specify the path to the 'models' folder
            models_folder = 'models'

            # Ensure the 'models' folder exists; create if not
            if not os.path.exists(models_folder):
                os.makedirs(models_folder)

            # Construct the full path to save the updated model
            full_path = os.path.join(models_folder, filename)

            # Save the updated model
            with open(full_path, 'wb') as f:
                f.write(response.content)

            # Flash success message
            flash(
                'Model downloaded successfully! Please go to settings to select it.', 'success')

            save_new_model_to_config(filename)

            # Return the file as a response using Flask's send_file
            return redirect(url_for('versioncheck'))

        except Exception as e:
            # Flash failure message
            flash(f'Error downloading file: {str(e)}', 'danger')
            return redirect(url_for('versioncheck'))
    else:
        # Flash failure message
        flash('Error downloading file. Status code: ' +
              str(response.status_code), 'danger')
        return redirect(url_for('versioncheck'))


if __name__ == "__main__":
    app.run(debug=True)
