#import goodvibes https://open.spotify.com/playlist/37i9dQZF1DXdLK5wjKyhVm?si=18dfdf1af53b484f
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, current_user, login_user, login_required, logout_user
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_container.models import Users, BlogPosts
import hashlib
import os
import re
import datetime



# Class to obtain user specific credentials.
class User(UserMixin):
    def __init__(self, id, role):
        self.id = id
        self.role = role

# Environment variables.
load_dotenv()

# Instance of flask at this root.
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('APP_KEY')

# Instance of login manager for managing user sessions.
login_manager = LoginManager()
login_manager.init_app(app)

# Create an SQLite Engine and print the queries made (remove echo after debugg).
engine = create_engine(f"sqlite:///{os.getenv('DB_LOC')}", echo=True)

# Object Relational Mapping database cursor (essentially).
Session = sessionmaker(bind=engine)
session = Session()

# Load connecting users into user class.
@login_manager.user_loader
def load_user(id):
    user = session.query(Users).get(id)
    if user:
        return User(id=id, role=user.role) # If user is controlled, make an instance.
    return None # Gaurentee's no false authenitication.

# Use form to login users.
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':  # If "submit" is given:
        username = request.form['username'] # Get form credentials.
        input_password = request.form['password']
        hashed_input_password = hashlib.sha3_512(input_password.encode()).hexdigest()  # Hash SHA#-512

        user = session.query(Users).filter_by(username=username).first() # Usernames are unique, grab first intance.

        if user and user.password == hashed_input_password: # If user exist's and the password matches stored password:
            user_obj = User(user.id, user.role) # Create the user object.
            login_user(user_obj) # Flask session for that user object.
            return redirect(url_for('blog')) # Return To Blog
        else:
            flash('Invalid credentials. Please try again.', 'error') # Error message for credentials.
    return render_template('login.html')

# Use form to sign users up.
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password1 = request.form['password1']
        password2 = request.form['password1']
        
        # Order failed states for invalid attempts.
        if len(username) <= 5:                                                                           # Username must be 6 characters minimum
            flash('Username Must Be 6 Characters Minimum.', 'error')
        elif session.query(session.query(Users).filter_by(username=username).exists()).scalar() == True: # Username must not be taken.
            flash('Username Taken.', 'error')
        elif session.query(session.query(Users).filter_by(email=email).exists()).scalar() == True:       # Email must not be taken.
            flash('Email Taken.', 'error')
        elif re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email) is None:               # REGEX email to control it's format.
            flash('Email Has Invalid Format.', 'error')
        elif password1 != password2:                                                                     # Password and Confirm Password must match.
            flash('Password\'s Don\'t Match.', 'error')
        elif len(password1) <= 7:                                                                        # Password must be 8 characters minimum.
            flash(f'Password Must Be 8 Characters Minimum.', 'error')
        elif not any(char.islower() for char in password1):                                              # Password must contain 1 lowercase.
            flash(f'Password Must Have 1 Lowercase Letter.', 'error')
        elif not any(char.isupper() for char in password1):                                              # Password must contain 1 uppercase.
            flash(f'Password Must Have 1 Uppercase Letter.', 'error')
        elif not any(char in '!@#$%^&*()_+[]{}|;:,.<>?/~`"\'\\' for char in password1):                  # Password must contain 1 special character.
            flash(f'Password Must Have 1 Special Character.', 'error')
        else:
            try:
                # INCLUDE SQLI CONTROLLER
                role = "User" # Create a new user (later 2FAC will change this state).
                hashed_password = hashlib.sha3_512(password1.encode()).hexdigest() # SHA3-512 Hash their password.
                new_user = Users(username=username, password=hashed_password, role=role, email=email, company="Demo") # Create a user instance.
                session.add(new_user) # Add a new user to the database.
                session.commit() # Save that user to the database.
                flash('Account created successfully!', 'success') # Success message.
                return redirect(url_for('login')) # Redirect to login.
            except:
                flash(f'Error: If persist\'s, contact X@gmail.com.', 'error')

    return render_template('signup.html')

@app.route('/')
def blog():
    user_status = "logged_out"
    all_posts = session.query(BlogPosts).all()

    if current_user.is_authenticated:
        user_status = "logged_in"

    # Construct a dictionary to store image URLs for each post
    image_urls = {}
    for post in all_posts:
        if post.header_image:
            image_filename = post.header_image
            image_path = os.path.join(app.root_path, 'static', 'blog_images', image_filename)
            image_url = url_for('static', filename=f'blog_images/{image_filename}')
            image_urls[post.id] = image_url

    return render_template('blog.html', user_status=user_status, all_posts=all_posts, image_urls=image_urls)

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if current_user.role.lower() == "admin":
        if request.method == 'POST':
            title = request.form['title']
            content = request.form['paragraph']
            header_image = request.files['image']

            # Ensure the filename is unique by appending a timestamp
            timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            image_filename = f"{timestamp}_{title}.jpg"  # Adjust the file extension if needed

            # Save the image to the static folder
            image_path = os.path.join(app.root_path, 'static', 'blog_images', image_filename)
            header_image.save(image_path)

            new_post = BlogPosts(title=title, content=content, header_image=image_filename)
            session.add(new_post)
            session.commit()

            # Successful image upload and data insertion
            return redirect(url_for('admin'))  # Redirect to the admin page after successful upload
    else:
        return redirect(url_for('blog'))
    return render_template('admin.html')

@app.route('/account')
@login_required
def account_page():
    return render_template('account.html', user_role = current_user.role.lower())

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Error control for directory traversal attack.
# Hidding web status codes related to traversal prevents page discovery.
@app.errorhandler(401) # Unauthorized Access ( Not logged in )
@app.errorhandler(403) # Forbidden Access ( Logged in )
@app.errorhandler(404) # Resource Not Found ( Page Doesn't Exist )
@app.errorhandler(500) # Server Error ( Provides log details about the website. )
def error_handler(e):
    return redirect(url_for('blog'))

if __name__ == '__main__':
    app.run(debug=True)
