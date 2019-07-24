from flask import Flask, render_template, request, redirect, session, flash
import re, random, string, hashlib, datetime
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
NONUM_REGEX = re.compile(r'^([^0-9]*)$')
UPNUM_REGEX = re.compile(r'^(?=.*\d)(?=.*[A-Z])')
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key='ThisIsASecret'

mysql = connectToMySQL('friendsdb')


@app.route('/')
def index():
    if 'session_id' in session:
        query = "SELECT session_id, first_name FROM users WHERE session_id = %(session_id)s"
        data = {'session_id': session['session_id']}
        result = mysql.query_db(query, data)
        if result:
            return redirect('/wall')
        else:
            session.clear()
            return render_template('index.html')
    return render_template('index.html')

@app.route('/wall')
def wall():
    if 'session_id' in session:
        query = "SELECT session_id, first_name FROM users WHERE session_id = %(session_id)s"
        data = {'session_id': session['session_id']}
        result = mysql.query_db(query, data)
        if result:
            query_message = "SELECT users.first_name, users.last_name, messages.id, messages.created_at, messages.message FROM messages JOIN users on messages.user_id = users.id ORDER BY messages.created_at DESC;"
            result_message = mysql.query_db(query_message)
            query_comment = "SELECT users.first_name, users.last_name, comments.id, comments.message_id, comments.created_at, comments.comment FROM comments JOIN users on comments.user_id = users.id ORDER BY comments.created_at ASC;"
            result_comment = mysql.query_db(query_comment)
            minutesago30 = datetime.datetime.now() - datetime.timedelta(minutes=30)
            query_ownmessage = "SELECT messages.id FROM messages JOIN users ON messages.user_id = users.id WHERE users.session_id = %(session)s AND messages.created_at > %(minutesago30)s;"
            data_ownmessage = {'session': session['session_id'], 'minutesago30': minutesago30}
            query_owncomment = "SELECT comments.id FROM comments JOIN users ON comments.user_id = users.id WHERE users.session_id = %(session)s AND comments.created_at > %(minutesago30)s;"
            result_ownmessage = mysql.query_db(query_ownmessage, data_ownmessage)
            result_owncomment = mysql.query_db(query_owncomment, data_ownmessage)
            return render_template('wall.html', result_message=result_message, result_comment=result_comment,
                                   result_ownmessage=result_ownmessage, result_owncomment=result_owncomment)
        else:
            session.clear()
            return redirect('/')
    else:
        return redirect('/')


@app.route('/reset', methods=['POST','GET'])
def reset():
    query_session = "UPDATE users SET session_id = NULL WHERE session_id = %(session)s;"
    data_session = {'session': session['session_id']}
    mysql.query_db(query_session, data_session)
    session.clear()
    flash("You successfully logged out",'loginemail')
    return redirect('/')

@app.route('/register', methods=['POST'])
def register():
    trigger = 0
    session['first_name'] = request.form['first_name']
    last_name = request.form['last_name']
    email = request.form['email']
    password = request.form['password']
    confirm_password = request.form['confirm_password']
    salt = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    pw_hash = bcrypt.generate_password_hash(password + salt)

    data = {
        'email': email,
        'first_name': session['first_name'],
        'last_name': last_name,
        'password': pw_hash,
        'salt': salt
    }

    query_match = "SELECT email FROM users WHERE email = %(email)s"
    get_email = mysql.query_db(query_match, data)

    if len(email) < 1:
        trigger = 1
        flash("Please enter Email.", 'email')
    elif not EMAIL_REGEX.match(email):
        trigger = 1
        flash("Invalid Email Address!", 'email')
    elif any(dict['email'] == email for dict in get_email):
        trigger = 1
        flash("Account has been created.", 'firstname')

    if len(session['first_name']) < 2:
        trigger = 1
        flash("Please enter valid First Name.", 'firstname')
    elif not NONUM_REGEX.match(session['first_name']):
        trigger = 1
        flash("You cannot have number(s) in your name.", 'firstname')
    if len(last_name) < 2:
        trigger = 1
        flash("Please enter valid Last Name.", 'lastname')
    elif not NONUM_REGEX.match(last_name):
        trigger = 1
        flash("You cannot have number(s) in your name.", 'lastname')
    if len(password) < 1:
        trigger = 1
        flash("Please enter Password.", 'password')
    elif len(password) < 8:
        trigger = 1
        flash("Password must be 8 characters or longer.", 'password')
    elif not UPNUM_REGEX.match(password):
        trigger = 1
        flash("Password needs to have 1 uppercase letter and 1 number.", 'password')
    elif len(confirm_password) < 1:
        trigger = 1
        flash("Please confirm password.", 'confirmpassword')
    elif password != confirm_password:
        trigger = 1
        flash("Password does not match confirmation! Please confirm password again.", 'confirmpassword')
    if trigger == 1:
        return redirect('/')
    else:
        query = "INSERT INTO users (first_name, last_name, email, password, salt, created_at, updated_at) " \
                "VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s, %(salt)s, NOW(), NOW());"
        mysql.query_db(query, data)
        if mysql.query_db(query_match, data)[0]['email'] == email:
            session['session_id'] = hashlib.md5((salt).encode()).hexdigest()
            query_session = "UPDATE users SET session_id = %(session)s WHERE email = %(email)s;"
            data_session = {'email': email, 'session': session['session_id']}
            mysql.query_db(query_session, data_session)
            flash("Your account has been successfully created.", 'success')
            return redirect('/wall')
        else:
            flash("Your account cannot be created. Please try again at a later time.", 'firstname')
            return redirect('/')

@app.route('/login', methods=['POST'])
def login():
    trigger = 0
    email = request.form['email']
    password = request.form['password']


    if len(email) < 1:
        trigger = 1
        flash("Please enter Email!", 'loginemail')
    elif not EMAIL_REGEX.match(email):
        trigger = 1
        flash("Invalid Email or Password.", 'loginemail')
    if len(password) < 1:
        trigger = 1
        flash("Please enter Password.", 'loginpassword')

    if trigger == 1:
        return redirect('/')
    else:
        query = "SELECT first_name, email, password, salt FROM users WHERE email = %(email)s;"
        data = {'email': email}
        results = mysql.query_db(query, data)
        if results:
            if bcrypt.check_password_hash(results[0]['password'], password+results[0]['salt']):
                justBits = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
                session['session_id'] = hashlib.md5((justBits).encode()).hexdigest()
                query_session = "UPDATE users SET session_id = %(session)s WHERE email = %(email)s;"
                data_session = {'email': email, 'session' : session['session_id']}
                mysql.query_db(query_session, data_session)
                session['first_name'] = results[0]['first_name']
                flash("You are now logged in.", 'success')
                return redirect('/wall')
        flash('Invalid Email or Password.', 'loginemail')
        return redirect('/')

@app.route('/message', methods=['POST'])
def message():
    session['message'] = request.form['message']
    if len(session['message'])<1:
        flash("Please write a message.",'post')
        return redirect('/wall')
    query_message = "INSERT INTO messages (message, created_at, updated_at, user_id) SELECT %(message)s, NOW(), NOW(), users.id FROM users WHERE session_id = %(session)s;"
    data_message = {'session': session['session_id'], 'message' : session['message']}
    mysql.query_db(query_message, data_message)
    return redirect('/wall')

@app.route('/comment', methods=['POST'])
def comment():
    session['comment'] = request.form['comment']
    if len(session['comment'])<1:
        flash("Please write a comment.",'post')
        return redirect('/wall')
    query_message = "INSERT INTO comments (comment, created_at, updated_at, user_id, message_id) SELECT %(comment)s, NOW(), NOW(), users.id, %(message_id)s FROM users WHERE session_id = %(session)s;"
    data_message = {'session': session['session_id'], 'comment' : session['comment'], 'message_id' : request.form['message_id']}
    mysql.query_db(query_message, data_message)
    return redirect('/wall')

@app.route('/removeMessage', methods=['POST'])
def removeMessage():
    data_remove = {'session': session['session_id'], 'message_id': request.form['message_id']}
    minutesago30 = datetime.datetime.now() - datetime.timedelta(minutes=30)
    query_remove30 = "SELECT created_at FROM messages WHERE id = %(message_id)s"
    result_remove30 = mysql.query_db(query_remove30, data_remove)
    if result_remove30[0]['created_at'] > minutesago30:
        query_remove = "DELETE messages FROM messages INNER JOIN users ON messages.user_id = users.id WHERE session_id = %(session)s AND messages.id = %(message_id)s;"
        mysql.query_db(query_remove, data_remove)
        return redirect('/wall')
    else:
        flash("Message cannot be deleted because it was created more than 30 minutes ago.", 'post')
        return redirect('/wall')

@app.route('/removeComment', methods=['POST'])
def removeComment():
    data_remove = {'session': session['session_id'], 'comment_id': request.form['comment_id']}
    minutesago30 = datetime.datetime.now() - datetime.timedelta(minutes=30)
    query_remove30 = "SELECT created_at FROM comments WHERE id = %(comment_id)s"
    result_remove30 = mysql.query_db(query_remove30, data_remove)
    if result_remove30[0]['created_at'] > minutesago30:
        query_remove = "DELETE comments FROM comments INNER JOIN users ON comments.user_id = users.id WHERE session_id = %(session)s AND comments.id = %(comment_id)s;"
        mysql.query_db(query_remove, data_remove)
        return redirect('/wall')
    else:
        flash("Comment cannot be deleted because it was created more than 30 minutes ago.", 'post')
        return redirect('/wall')

if __name__ == "__main__":
    app.run(debug=True)