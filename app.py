import random, string, requests
import json
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mail import Mail, Message
from flask_session import Session
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import bcrypt

client_id = "291d6289-7fb0-4a47-9aa4-e06d7a1fc17c"
client_secret = "dd8fff64-ca03-4af8-8909-43d89cf2985d"
redirect_uri = "https://restaurantanalytics.azurewebsites.net"
authority_url = 'https://login.microsoftonline.com/common'
pbiusername='info@ngtechuae.com'
pbipassword='Info@Ngtech'


app = Flask(__name__)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key'
app.config['SECURITY_PASSWORD_HASH'] = 'bcrypt'
app.config['SECURITY_PASSWORD_SALT'] = b'$2b$12$wqKlYjmOfXPghx3FuC3Pu.'

Session(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    
    def __init_(self, username, email, password):
        self.username = username
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
    def check_password(self, password):
        pwhash = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
        self.password_hash = pwhash.decode('utf8')
    
with app.app_context():
    db.create_all()
    
admin = Admin(app, name='Admin Panel', template_mode='bootstrap3')
admin.add_view(ModelView(User, db.session))

app.config['MAIL_SERVER'] = 'smtp.your-email-provider.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'your-email@example.com'
app.config['MAIL_PASSWORD'] = 'your-email-password'

# Dummy user data (replace this with a database)
users = {'your_username': 'your_password', 'user@example.com': 'user_password'}
mail = Mail(app)

@app.route('/')
def index():
    authorization_url = (
                f"{authority_url}/oauth2/v2.0/authorize?"
                f"client_id={client_id}"
                f"&redirect_uri={redirect_uri}"
                "&response_type=code"
                "&scope=https://graph.microsoft.com/.default"
                f"{pbiusername}"
                f"{pbipassword}"
            )
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        username = request.form['User']
        password = request.form['Password']

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            # Assuming the user is successfully authenticated, redirect to the Power BI authorization URL
            session['email'] = user.email
            return redirect('/dashboard')
        return render_template('RestaurantDashboard.html')    

        # If authentication fails, render the login page again
    return render_template('RestaurantDashboard.html')
        

@app.route('/dashboard')
def dashboard():
    if session['username']:
        user = User.query.filter_by(email=session['email']).first()
        return render_template('RestaurantDashboard.html', user=user)
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('Logout successful.', 'success')
    return redirect(url_for('index'))

@app.route('/forget_password')
def forget_password():
    if request.method == 'POST':
        email = request.form['Email']
        if email in users[1]:
            temporary_password = ''.join(random.choices(string.ascii_letters+string.digits, k=8))
            users[email] = temporary_password
            send_reset_email(email, temporary_password)
            flash('Password reset link sent to your email.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Email not found. Please check your email address.', 'error')
    return render_template('forget_password.html')

def send_reset_email(email, temp_password):
    message = Message('Password Reset', sender='your-email@example.com', recipients=[email])
    message.body = f'Your temporary password is: {temp_password}. Please login and change your password.'
    mail.send(message)

@app.route('/create_account', methods=['GET', 'POST'])
def create_account():
    if request.method == 'POST':
        username = request.form['Username']
        email = request.form['Email']
        password = request.form['Password']
        
        new_user = User(username=username,email=email,password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('index'))

    return render_template('create_account.html')

if __name__ == '__main__':
    app.run(debug=True)
