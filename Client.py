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
            flash('All fields are required.', 'error')
            return render_template('register.html')

        if password != confirm_password:
            flash("Passwords do not match. Please try again.", "error")
            return render_template('register.html')

        if len(password) < 6:
            flash("Password must be longer than 6 characters.", "error")
            return render_template('register.html')

        if not password.isalnum():
            flash("Password cannot contain special characters.", "error")
            return render_template('register.html')
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        otp = server.generate_otp(username)
        server.register_user(username, hashed_password, otp)

        flash('Registration successful', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        if server.validate_user(username, hashed_password):
            if server.validate_otp_and_update(username):
                flash(f'Welcome, {username}!', 'success')
                return redirect(url_for('welcome', username=username))
            else:
                flash('OTP validation failed.', 'error')
        else:
            flash('Invalid credentials. Please check your username and password.', 'error')

    return render_template('login.html')



@app.route('/welcome')
def welcome():
    username = request.args.get('username')

    if not username:
        flash('Unauthorized access. Please log in.', 'error')
        return redirect(url_for('login'))

    return render_template('welcome.html', username=username)

@app.route('/')
def main_screen():
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000, debug=True)
