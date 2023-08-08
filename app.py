#import goodvibes https://open.spotify.com/playlist/37i9dQZF1DXdLK5wjKyhVm?si=18dfdf1af53b484f
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, current_user, login_user, login_required, logout_user
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_container.models import Users  # Import your Users model from the correct path
import hashlib
import os
import re


load_dotenv() # Load Environment Variables

app = Flask(__name__) # Define the application.
app.config['SECRET_KEY'] = os.getenv('APP_KEY') # Development Key Environment Variable

login_manager = LoginManager()
login_manager.init_app(app)

# Create a SQLAlchemy engine and session
engine = create_engine(f"sqlite:///{os.getenv('DB_LOC')}", echo=True)
Session = sessionmaker(bind=engine)
session = Session()

# Simulating a user database
class User(UserMixin):
    def __init__(self, id, role):
        self.id = id
        self.role = role

@login_manager.user_loader
def load_user(id):
    user = session.query(Users).get(id)
    print(user)
    if user:
        return User(id=id, role=user.role)
    return None

def is_safe_path(basedir, path):
    return os.path.realpath(path).startswith(basedir)

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        input_password = request.form['password']
        hashed_input_password = hashlib.sha3_512(input_password.encode()).hexdigest()  # Hash the input password

        user = session.query(Users).filter_by(username=username).first()

        if user and user.password == hashed_input_password:  # Compare hashed passwords
            user_obj = User(user.id, user.role)  # Create a User object for Flask-Login with id and role
            login_user(user_obj)
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials. Please try again.', 'error')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password1 = request.form['password1']
        password2 = request.form['password1']
        email = request.form['email']
        
        if len(username) <= 5:
            flash('Username Must Be 6 Characters Minimum.', 'error')
        elif session.query(session.query(Users).filter_by(username=username).exists()).scalar() == True:
            flash('Username Taken.', 'error')
        elif session.query(session.query(Users).filter_by(email=email).exists()).scalar() == True:
            flash('Email Taken.', 'error')
        elif re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email) is None:
            flash('Email Has Invalid Format.', 'error')
        elif password1 != password2:
            flash('Password\'s Don\'t Match.', 'error')
        elif len(password1) <= 7:
            flash(f'Password Must Be 8 Characters Minimum.', 'error')
        elif not any(char.islower() for char in password1):
            flash(f'Password Must Have 1 Lowercase Letter.', 'error')
        elif not any(char.isupper() for char in password1):
            flash(f'Password Must Have 1 Uppercase Letter.', 'error')
        elif not any(char in '!@#$%^&*()_+[]{}|;:,.<>?/~`"\'\\' for char in password1):
            flash(f'Password Must Have 1 Special Character.', 'error')
        else:
            try:
                role = "CompanyUser" # Just for now
                hashed_password = hashlib.sha3_512(password1.encode()).hexdigest()
                new_user = Users(username=username, password=hashed_password, role=role, email=email, company="Demo")
                session.add(new_user)
                session.commit()
                flash('Account created successfully!', 'success')
                return redirect(url_for('login'))
            except:
                flash(f'Error: If persist\'s, contact X@gmail.com.', 'error')

    return render_template('signup.html')

@app.route('/admin', methods=['GET'])
@login_required
def admin():
    if current_user.role.lower() != "admin":
        # Redirect non-admin users to a restricted page or show an error message.
        return redirect(url_for('home'))
    # Render the admin page for admin users.
    return render_template('admin.html')

@app.route('/home')
@login_required
def home():
    is_admin = current_user.role.lower() == "admin"  # Check if user is admin
    return render_template('home.html', is_admin=is_admin)

@app.route('/restricted')
@login_required
def restricted():
    return render_template('restricted.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.errorhandler(401)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(500)
def error_handler(e):
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
