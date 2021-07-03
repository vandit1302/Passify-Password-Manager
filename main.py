from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flaskext.mysql import MySQL

import re
import os
import random
import hashlib 
import bcrypt
import json
import requests
import nltk
import pybase64


from base64 import b64encode, b64decode
#from Crypto.Cipher import AES
#from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Hash import SHAKE256
from enyo.enyoencryption import EnyoEncryption
from enyo.enyodecryption import EnyoDecryption

app = Flask(__name__)

port = int(os.environ.get('PORT', 5000))

# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = 'project@cybersec#123'

# Enter your database connection details below
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
app.config['MYSQL_DATABASE_USER'] = 'root'
app.config['MYSQL_DATABASE_PASSWORD	'] = ''
app.config['MYSQL_DATABASE_DB'] = 'cybersec'

# Intialize MySQL
mysql = MySQL(autocommit=True)
mysql.init_app(app)

# Global constants
current_user = ""

@app.route('/')
def index():
	return render_template('index.html')


@app.route('/loginpage')
def loginpage():
    return render_template('login.html')

@app.route('/registerpage')
def registerpage():
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Output message if something goes wrong...
    msg = ''
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        # Check if account exists using MySQL
        cursor = mysql.get_db().cursor()
        cursor.execute('SELECT * FROM users WHERE Username = %s', (username))
        # Fetch one record and return result
        account = cursor.fetchone()
        # If account exists in accounts table in out database
        # if account:
        if bcrypt.checkpw(password.encode('utf-8'), account[2].encode('utf-8')):
            # Create session data, we can access this data in other routes
            #session['loggedin'] = True
            #session['id'] = account[0]
            #session['username'] = account[1]
            #session['api'] = account[8]
            #session['isdoctor'] = 0
            # Redirect to dashboard
            print('Loggedin')
            global current_user
            current_user = username
            return render_template('dashboard.html', msg=msg)
        else:
            # Account doesnt exist or username/password incorrect
            msg = 'Incorrect username/password!'
            print(msg)
            return render_template('login.html')
    # Show the login form with message (if any)
    #return render_template('dashboard.html', msg=msg)


@app.route('/dashboard', methods = ['GET', 'POST'])
def dashboard():
    selection = request.form['selection']
    print(selection)
    if(selection == "0"):
        return render_template('AESpage.html')
    elif(selection == "1"):
        return render_template('DESpage.html')
    else:
        return render_template('dashboard.html')


@app.route('/register', methods = ['GET', 'POST'])
def register():
    # Output message if something goes wrong...
    msg = ''
    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        full_name = request.form['full_name']

        # Check if account exists using MySQL
        cursor = mysql.get_db().cursor()
        cursor.execute('SELECT * FROM users WHERE Username = %s', (username))
        account = cursor.fetchone()
        # If account exists show error and validation checks
        if account:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers!'
        elif not username or not password or not email:
            msg = 'Please fill out the form!'
        else:
            # Account doesnt exists and the form data is valid, now insert new account into users table
            apistr = username
            result = hashlib.md5(apistr.encode()) 
            comb = username+'(~)'+password
            s = comb.encode()
            s1 = pybase64.b64encode(s)
            api=s1.decode('utf-8')
            #print(s1)
            #r=pybase64.b64decode(s)
            #print(r.decode('utf-8'))
            
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            cursor.execute('INSERT INTO users VALUES (NULL, %s, %s, %s, %s)', (username, hashed_password, email, full_name))
            msg = 'You have successfully registered!'
            print(msg)
    elif request.method == 'POST':
        # Form is empty... (no POST data)
        msg = 'Please fill out the form!'
    # Show registration form with message (if any)
    return render_template('login.html', msg=msg)

@app.route('/AES', methods = ['GET', 'POST'])
def AES():
    from Crypto.Cipher import AES
    username = request.form['username']
    cursor = mysql.get_db().cursor()
    cursor.execute('SELECT * FROM users WHERE username = %s', (username))
    # Fetch one record and return result
    account = cursor.fetchone()

    key1 = account[2]
    website = request.form['website']
    password = request.form['password']
    print("website = " + website)
    print("password = " + password)
    print("global key = " + key1)

    data = password
    data = bytes(data, 'utf-8')
    print("data = " + data.decode('utf-8'))

    h = SHAKE256.new( )
    h.update(bytes(key1, 'utf-8'))
    hash = h.read(32)
    key = hash
    print("Hash key = ", end=" ")
    print(key)
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    iv = cipher.iv
    print(ciphertext)
    print(iv)

    # Write to table - password info
    # Passwordid(autoincrement), Username, Website name, Enc_pass, IV, key
    cursor.execute('INSERT INTO passinfo VALUES (NULL, %s, %s, %s, %s, %s, %s)', (username, website, ciphertext, iv, key, "0"))
    print("Added to DB")

    cursor.execute('SELECT * FROM passinfo where username = %s AND website = %s', (username, website))
    pass_details = cursor.fetchone()
    print(pass_details[1])
    print(pass_details[2])
    print(pass_details[3])
    print(pass_details[4])
    print(pass_details[5])

    cipher2 = AES.new(pass_details[5], AES.MODE_CBC, pass_details[4])
    plaintext = unpad(cipher2.decrypt(pass_details[3]), AES.block_size)
    print('Cipher text = ', end = ' ')
    print(ciphertext)
    print('Initialization vector = ', end = ' ')
    print(iv)
    print(pass_details[4])
    print('Plaintext = ', end = ' ')
    print(plaintext)

    return render_template('display.html', encrypted = ciphertext, iv = iv, username = username, website = website, hash = h)

@app.route('/DES', methods = ['GET', 'POST'])
def DES():
    from Crypto.Cipher import DES
    username = request.form['username']
    cursor = mysql.get_db().cursor()
    cursor.execute('SELECT * FROM users WHERE Username = %s', (username))
    # Fetch one record and return result
    account = cursor.fetchone()

    key = account[2]
    website = request.form['website']
    password = request.form['password']
    data = password
    data = bytes(data, 'utf-8')

    h = SHAKE256.new()
    h.update(bytes(key, 'utf-8'))
    hash = h.read(8)
    key = hash
    print("Hash key = ", end=" ")
    print(key)
    cipher = DES.new(key, DES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, DES.block_size))
    iv = cipher.iv
    print(ciphertext)
    print(iv)

    cursor.execute('INSERT INTO passinfo VALUES (NULL, %s, %s, %s, %s, %s, %s)', (username, website, ciphertext, iv, key, "1"))
    print("Added to DB")

    cursor.execute('SELECT * FROM passinfo where username = %s AND website = %s', (username, website))
    pass_details = cursor.fetchone()
    print(pass_details[1])
    print(pass_details[2])
    print(pass_details[3])
    print(pass_details[4])
    print(pass_details[5])


    return render_template('display.html', encrypted = ciphertext, iv = iv, username = username, website = website)


@app.route('/displayAll', methods = ['GET', 'POST'])
def DisplayAll():
    if(current_user == ""):
        username = "vandit"
    else:
        username = current_user
    cursor = mysql.get_db().cursor()
    cursor.execute('SELECT * FROM passinfo WHERE username = %s', (username))
    rows = cursor.fetchall()
    #print(rows[1])
    #print(rows[1][5])

    return render_template('displayall.html', rows = rows)


@app.route('/decrypt', methods = ['GET', 'POST'])
def decrypt():
    from Crypto.Cipher import AES
    from Crypto.Cipher import DES
    username = request.form['username']
    website = request.form['website']
    # ciphertext = request.form['passenc']
    # iv = request.form['iv']
    # key = request.form['key']
    # type = request.form['type']

    cursor = mysql.get_db().cursor()
    cursor.execute('SELECT * FROM passinfo where username = %s AND website = %s', (username, website))
    pass_details = cursor.fetchone()
    print(pass_details[1])
    print(pass_details[2])
    print(pass_details[3])
    print(pass_details[4])
    print(pass_details[5])

    ciphertext = pass_details[3]
    iv = pass_details[4]
    key = pass_details[5]
    type = pass_details[6]


    if(type == '0'):
        print('AES Type...call AES')
        print(username)
        print(website)
        print(ciphertext)
        print(iv)
        print(key)

        cipher2 = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher2.decrypt(ciphertext), AES.block_size)
        print('Cipher text = ', end = ' ')
        print(ciphertext)
        print('Initialization vector = ', end = ' ')
        print(iv)
        print('Plaintext = ', end = ' ')
        print(plaintext.decode('utf-8'))
        
    
    elif(type == '1'):
        print('DES Type...call DES')
        print(username)
        print(website)
        print(ciphertext)
        print(iv)
        print(key)

        cipher2 = DES.new(key, DES.MODE_CBC, iv)
        plaintext = unpad(cipher2.decrypt(ciphertext), DES.block_size)
        print('Cipher text = ', end = ' ')
        print(ciphertext)
        print('Initialization vector = ', end = ' ')
        print(iv)
        print('Plaintext = ', end = ' ')
        print(plaintext)
        print(plaintext.decode('utf-8'))
    

    return render_template('displaypass.html', username = username, website = website, ciphertext = ciphertext, plaintext = plaintext)

@app.route('/dashboard', methods = ['GET', 'POST'])
def dash():
    return render_template("dashboard.html")


if __name__ == '__main__':
	app.run(host='0.0.0.0', port=port, debug=True)