from flask import Flask, render_template, redirect, url_for, request, flash
import hashlib
from Server import Server

app = Flask(__name__)
app.secret_key = 'your_secret_key'
server = Server()


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not username or not password or not confirm_password:
            error_message = 'All fields are required.'
            return render_template('register.html', error_message=error_message)

        if password != confirm_password:
            error_message = 'Passwords do not match. Please try again.'
            return render_template('register.html', error_message=error_message)

        if len(password) < 6:
            error_message = 'Password must be longer than 6 characters.'
            return render_template('register.html', error_message=error_message)

        if not password.isalnum():
            error_message = 'Password cannot contain special characters.'
            return render_template('register.html', error_message=error_message)
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        otp = server.generate_otp(password)
        server.register_user(username, hashed_password, otp)

        error_message = 'Registration successful'
        return render_template('register.html', error_message=error_message)

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        if server.validate_user(username, hashed_password):
            if server.validate_otp_and_update(username):
                return redirect(url_for('welcome', username=username))
            else:
                error_message = 'OTP validation failed.'
                return render_template('login.html', error_message=error_message)
        else:
            error_message = 'Invalid credentials. Please check your username and password.'
            return render_template('login.html', error_message=error_message)

    return render_template('login.html')



@app.route('/welcome')
def welcome():
    username = request.args.get('username')

    if not username:
        return redirect(url_for('login'))

    return render_template('welcome.html', username=username)

@app.route('/')
def main_screen():
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000, debug=True)
