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
import pyodbc
from powerbiclient import Report,models

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
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    # Handle login form submission
    username = request.form.get('username')
    password = request.form.get('password')

    # Initialize connection and cursor
    connection = pyodbc.connect("DRIVER={ODBC Driver 17 for SQL SERVER};SERVER=68.178.163.254\\SQLEXPRESS;DATABASE=PBI_Dashboard_DB;UID=sa;PWD=Ngtech@2021")
    cursor = connection.cursor()
    print("Database is connected. here is the connection : ", cursor, sep='\n')

    query = "SELECT * FROM dbo.Users WHERE username = ? AND password = ?"
    result = cursor.execute(query, (username, password)).fetchone()

    if result:
        session['username'] = username
        cursor.close()
        connection.close()
        return redirect(url_for('dashboard'))
    else:
        cursor.close()
        connection.close()
        return render_template('login.html', error="Invalid Details")
        

@app.route('/dashboard')
def dashboard():
    # Check if the user is logged in
    if 'username' in session:
        username = session['username']

        application_id = 'a385e141-b8ab-4b78-b3b6-34c05afede0b'
        tenant_id = '94294eba-fc5c-4c48-a7da-75a76add95ab'
        application_secret = 'dd8fff64-ca03-4af8-8909-43d89cf2985d'
        workspace_id = 'e69c9f15-b04d-47b5-a808-e21e346ff958'
        report_id = 'c1e42270-6277-4fb5-af45-ac7b4c9b5855'

        token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/token'
        token_data = {
            'grant_type': 'client_credentials',
            'client_id': application_id,
            'client_secret': application_secret,
            'resource': 'https://graph.microsoft.com',
        }

        # Debugging: Print the token response
        token_response = requests.post(token_url, data=token_data)
        print("Token Response:", token_response.json())

        access_token = token_response.json().get('access_token')
        try:
            report = Report(report_id, workspace_id, token=access_token)
            embed_token = report.get_embed_token()

            print(username, embed_token, access_token)

            return render_template('RestaurantDashboard.html', username=username, embed_token=embed_token)
        except Exception as ex:
            print("Error: ", str(ex))
            app.logger.exception('Error in dashboard')
            return render_template('Error.html', error_message=str(ex)), 500
    else:
        # Redirect to the login page if not logged in
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
