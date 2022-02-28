from flask import Flask, render_template, flash, url_for
from flask import request, make_response, session
from flask_session import Session
from datetime import datetime
import redis
from redis import StrictRedis
from uuid import uuid4
from dotenv import load_dotenv
from os import getenv
from bcrypt import hashpw, gensalt, checkpw
load_dotenv() 
import re

db = StrictRedis('ec2-54-197-138-125.compute-1.amazonaws.com',port=9899, password='pf0f81485d9f086fce44c1b27fd5731beb0f73cf14b76209a842d68b4d7e2fe90', db=0)
SESSION_TYPE = 'redis'
SESSION_REDIS = db
app = Flask(__name__)
app.config.from_object(__name__)
app.secret_key = getenv('SECRET_KEY')
#ses = Session(app)

@app.route('/')
def index():
    return render_template("home.html")

@app.route('/sender/register', methods=['GET'])
def registerf():
    user = session.get("username")
    if user is not None:
        flash('Jestes już zalogowany')
    return render_template("register.html")

@app.route('/sender/register', methods=['POST'])
def register():
    firstname = request.form.get("firstname")
    lastname = request.form.get("lastname")
    username = request.form.get("login")
    email = request.form.get("e-mail")   
    password = request.form.get("password")
    password2 = request.form.get("password2")
    adress = request.form.get("adress")
    error = False
    PL = 'ĄĆĘŁŃÓŚŹŻ'
    pl = 'ąćęłńóśźż'

    user = session.get("username")
    if user is not None:
        return redirect(url_for('registerf'))

    if not firstname:
        flash("Brak imienia")
        error = True
    elif not re.match(f'[A-Z{PL}][a-z{pl}]+', firstname):
        flash("Błędne imię, musi zaczynać się z dużej litery, a następne z małych")
        error = True

    if not lastname:
        flash("Brak nazwiska")
        error = True
    elif not re.match(f'[A-Z{PL}][a-z{pl}]+', lastname):
        flash("Błędne nazwisko, musi zaczynać się z dużej litery, a następne z małych")
        error = True

    if not username:
        flash("Brak loginu")
        error = True

    if not email:
        flash("Brak e-maila")
        error = True
    elif not re.match(r"^[A-Za-z0-9\.\+_-]+@[A-Za-z0-9\._-]+\.[a-zA-Z]*$", email):
        flash("Błędny e-mail")
        error = True

    if not adress:
        flash("Brak adresu")
        error = True

    if not password:
        flash("Brak hasła")
        error = True
    elif not re.match('[A-Za-z]{8,}', password):
        flash("Błędne hasło, musi składać się z conajmniej 8 znaków")
        error = True

    if password != password2:
        flash("Passwords do not match")
        error = True

    if error:
        return redirect(url_for('registerf'))

    if not is_redis_available():
        flash("Brak połączenia z bazą")
        return redirect(url_for('registerf'))

    if username and firstname and lastname and email and adress and password:
        if is_user(username):
            flash("Nazwa użytkownika już zajęta")
            return redirect(url_for('registerf'))

        success = save_user(firstname, lastname, username, email, password, adress)
        if not success:
            flash("Blad w trakcie zapisywania uzytkownika")
            return redirect(url_for('registerf'))

    

    return redirect(url_for('loginf'))

def redirect(url, status=301):
    response = make_response('', status)
    response.headers['Location'] = url
    return response

def is_redis_available():
    try:
        db.ping()
    except (redis.exceptions.ConnectionError):
        return False
    return True

def save_user(firstname, lastname, username, email, password, adress):
    salt = gensalt(5)
    password = password.encode()
    hashed = hashpw(password, salt)
    db.hset(f"user:{username}","password", hashed)
    db.hset(f"user:{username}","firstname", firstname)
    db.hset(f"user:{username}","lastname", lastname)
    db.hset(f"user:{username}","email", email)
    db.hset(f"user:{username}","address", adress)
    return True

def is_user(username):
    return db.hexists(f"user:{username}", "password")

def verify_user(username, password):
    password = password.encode()
    hashed = db.hget(f"user:{username}","password")
    if not hashed:
        return False
    return checkpw(password,hashed)

@app.route('/sender/login', methods=['GET'])
def loginf():    
    return render_template('login.html')

@app.route('/sender/login', methods=['POST'])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        flash("Brak loginu lub hasła")
        return redirect(url_for('loginf'))

    if not is_redis_available():
        flash("Brak połączenia z bazą")
        return redirect(url_for('loginf'))

    if not verify_user(username,password):
        flash("Zły login lub hasło")
        return redirect(url_for('loginf'))
    
    session["username"] = username
    session["logged-at"] = datetime.now()
    return redirect(url_for('index'))

def is_login_correct(username, password):
    hashed = db.hget(f"user:{username}", "password")
    if not hashed:
        print(f"No password for {username}")
        return False
    
    return checkpw(password.encode(),hashed)

@app.route('/sender/logout')
def sender_logout():
    user = session.get("username")
    [session.pop(key) for key in list(session.keys())]
    session.clear()
    if user is None:
        flash('Nie jestes zalogowany')
        return redirect(url_for('loginf'))
    return render_template('logout.html')

@app.route('/sender/dashboard',  methods = ["GET"])
def dashboardf():
    username = session.get("username")
    if username is None:
        flash('Musisz być zalogowany aby korzystać z tej zakładki')
        return redirect(url_for('loginf'))
    label=[]
    for k in db.scan_iter(f"label:{username}:*"):
        vals = dict()
        vals['sendername'] = db.hget(k, 'sendername').decode()
        vals['identificator'] = db.hget(k, 'identificator').decode()
        vals['size'] = db.hget(k, 'size').decode()
        vals['pid'] = db.hget(k, 'pid').decode()
        label.append(vals)
    return render_template("dashboard.html", toPass=label)
    
@app.route('/sender/dashboard',  methods = ["POST"])
def dashboard():
    sendername = request.form.get("sender_name")
    identificator = request.form.get("identificator")
    size = request.form.get("size")
    username = session.get("username")
    error = False
    pid = str(uuid4())

    if username is None:
        flash('Nie jestes zalogowany')
        return redirect(url_for('loginf'))

    if not sendername:
        flash("Brak adresata")
        error = True

    if not identificator:
        flash("Brak identyfikatora")
        error = True

    if not size:
        flash("Brak rozmiaru")
        error = True

    if error:
        return redirect(url_for('dashboardf'))

    if not is_redis_available():
        flash("Brak połączenia z bazą")
        return redirect(url_for('dashboardf'))

    db.hset(f"label:{username}:{pid}", "sendername", sendername)
    db.hset(f"label:{username}:{pid}", "size", size)
    db.hset(f"label:{username}:{pid}", "identificator", identificator)
    db.hset(f"label:{username}:{pid}", "pid", pid)
    return redirect(url_for('dashboardf'))

@app.route("/sender/delete", methods = ["POST"])
def delete():
    if not is_redis_available():
        flash("Brak połączenia z bazą")
        return redirect(url_for('dashboardf'))
    pid = request.form.get("pid")
    username = session.get("username")
    db.delete(f"label:{username}:{pid}")
    return redirect(url_for("dashboardf"))

if __name__ == '__main__':
    app.run(threaded=True, port=5000)
