# MODULE IMPORTS

# Flask modules
from cgitb import reset
from flask import Flask, render_template, request, url_for, request, redirect, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_talisman import Talisman
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect

# Other modules
from urllib.parse import urlparse, urljoin
from datetime import datetime
import configparser
import json
import sys
import os, time, random, shutil
import copy
import zipfile
import uuid

# Local imports
from user import User, Anonymous
from message import Message
from note import Note
from email_utility import send_email, send_registration_email, send_message_email
from verification import confirm_token

# File
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
from pathlib import Path

# balance separate db
from tinydb import TinyDB, Query # will not use tinydb as not thread-safe
import pysondb

from flask import Flask, render_template, url_for, request, abort

import stripe

from flask import Flask, request, send_file, make_response

# prod serve
from waitress import serve

# Create app
app = Flask(__name__)

# Configuration
config = configparser.ConfigParser()
config.read('configuration.ini')
default = config['DEFAULT']
app.secret_key = default['SECRET_KEY']
app.config['MONGO_DBNAME'] = default['DATABASE_NAME']
app.config['MONGO_URI'] = default['MONGO_URI']
app.config['PREFERRED_URL_SCHEME'] = "https"


app.config['STRIPE_PUBLIC_KEY'] = 'pk_test_51KRFBJFlFIqZR98TKoXAmdMOfZ47Xf3adag5srBbrWRTnwUfV0PqKvpnOMPcWD7ng5n8tQqrbKyphAU9xHxvzbDi00W0yasWPH'
app.config['STRIPE_SECRET_KEY'] = 'sk_test_51KRFBJFlFIqZR98Tj9MXcjFTV2Hu60soLVpumP9z05MRvrGxQRGV07Z41Te3WbwBHZzS23gTqKBzZD7P3UX3cvXy00u0mwir7q'


stripe.api_key = app.config['STRIPE_SECRET_KEY']

# Create Pymongo
mongo = PyMongo(app)

print(mongo.db.users)

app.db = pysondb.getDb("bal_db.json")

app.tasks_db = pysondb.getDb('tasks_db.json')


### important config
per_word_price = 0.005 # 0.05 sek per word
word_packages = 600 # 100 words in a packages
per_word_time = 0.0085

#print(mongo)
#print(mongo.db)

# Create Bcrypt
bc = Bcrypt(app)

# Create Talisman
csp = {
    'default-src': [
        '\'self\'',
        'https://stackpath.bootstrapcdn.com',
        'https://pro.fontawesome.com',
        'https://code.jquery.com',
        'https://cdnjs.cloudflare.com',
        'https://fonts.googleapis.com',
        'https://www.w3schools.com',
        'https://js.stripe.com',

    ]
}
# talisman = Talisman(app, content_security_policy=csp, content_security_policy_nonce_in=['script-src'])

# Create CSRF protect
csrf = CSRFProtect()
csrf.init_app(app)
# app.config['WTF_CSRF_CHECK_DEFAULT'] = False 

# Create login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.anonymous_user = Anonymous
login_manager.login_view = "login"


# ROUTES

# Index
@app.route('/')
def index():
    return render_template('index.html')


# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        if request.method == 'GET':
            if current_user.is_authenticated:
                # Redirect to index if already authenticated
                return redirect(url_for('index'))
            # Render login page
            return render_template('login.html', error=request.args.get("error"))
        # Retrieve user from database

        users = mongo.db.users
        user_data = users.find_one({'email': request.form['email']}, {'_id': 0})
        if user_data:
            # Check password hash
            
            if bc.check_password_hash(user_data['password'], request.form['pass']):
                # Create user object to login (note password hash not stored in session)
                user = User.make_from_dict(user_data)
                login_user(user)

                # Check for next argument (direct user to protected page they wanted)
                next = request.args.get('next')
                if not is_safe_url(next):
                    return abort(400)

                # Go to profile page after login
                return redirect(next or url_for('profile'))

        # Redirect to login page on error
        return redirect(url_for('login', error=1))
    except Exception as e:
        return str(e)


# Register
@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        # Trim input data
        email = request.form['email'].strip()
        title = request.form['title'].strip()
        first_name = request.form['first_name'].strip()
        last_name = request.form['last_name'].strip()
        password = request.form['pass'].strip()
        org = request.form['org'].strip()
        industry = request.form['industry'].strip()


        users = mongo.db.users
        # Check if email address already exists
        existing_user = users.find_one(
            {'email': email}, {'_id': 0})

        if existing_user is None:
            logout_user()
            # Hash password
            hashpass = bc.generate_password_hash(password).decode('utf-8')
            # Create user object (note password hash not stored in session)
            new_user = User(title, first_name, last_name, email)
            # Create dictionary data to save to database
            user_data_to_save = new_user.dict()
            user_data_to_save['password'] = hashpass

            # Insert user record to database
            if users.insert_one(user_data_to_save):
                login_user(new_user)
                send_registration_email(new_user)
                # update 
                return redirect(url_for('profile'))
            else:
                # Handle database error
                return redirect(url_for('register', error=2))

        # Handle duplicate email
        return redirect(url_for('register', error=1))

    # Return template for registration page if GET request
    return render_template('register.html', error=request.args.get("error"))


# Confirm email
@app.route('/confirm/<token>', methods=['GET'])
def confirm_email(token):
    logout_user()
    try:
        email = confirm_token(token)
        if email:
            if mongo.db.users.update_one({"email": email}, {"$set": {"verified": True}}):
                return render_template('confirm.html', success=True)
    except:
        return render_template('confirm.html', success=False)
    else:
        return render_template('confirm.html', success=False)


# Verification email
@app.route('/verify', methods=['POST'])
@login_required
def send_verification_email():
    if current_user.verified == False:
        send_registration_email(current_user)
        return "Verification email sent"
    else:
        return "Your email address is already verified"
#
# {"user_id": str(current_user.id), "task_path": task_path, "task_status": "uploaded", "download_path": "", #"download_title": tmap, "download_counts": str(num_wavs), "download_date": datetime.now().date().strftime('%m/%d/%Y')#, "cost": per_word_price * tot_words}
#
# Profile
@app.route('/profile', methods=['GET'])
@login_required
def profile():

    notes = []
    tasks = app.tasks_db.getBy({"user_id": str(current_user.id)})
    for task in tasks:
        if task["task_status"] == "completed":
            notes.append({'title': task['download_title'], 'body': f"{task['download_counts']} files", 'id': '1234', 'date_string': task['download_date'], 'download_url': "uploads/" + task['download_path']})
    
    
    id_ = current_user.id
    r = app.db.getBy({'user_id': id_})
    if len(r) == 0:
        app.db.add({'user_id': id_, 'balance': 0})
        pb = 0
    else:
        pb = r[0]['balance']
    print(notes)
    return render_template('profile.html', notes=notes, title=current_user.title, balance = pb)


# Messages
@app.route('/messages', methods=['GET'])
@login_required
def messages():
    all_users = mongo.db.users.find(
        {"id": {"$ne": current_user.id}}, {'_id': 0})
    inbox_messages = mongo.db.messages.find(
        {"to_id": current_user.id, "deleted": False}).sort("timestamp", -1)
    sent_messages = mongo.db.messages.find(
        {"from_id": current_user.id, "deleted": False, "hidden_for_sender": False}).sort("timestamp", -1)

    inbox_messages = list(inbox_messages)
    sent_messages = list(sent_messages)

    User = Query()
    id_ = current_user.id
    r = app.db.getBy({'user_id': id_})
    if len(r) == 0:
        app.db.add({'user_id': id_, 'balance': 0})
        pb = 0
    else:
        pb = r[0]['balance']
    return render_template('messages.html', users=all_users, inbox_messages=inbox_messages, sent_messages=sent_messages,
                           balance = pb)


# Logout
@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


# POST REQUEST ROUTES

# Add note
@app.route('/add_note', methods=['POST'])
@login_required
def add_note():
    title = request.form.get("title")
    body = request.form.get("body")
    user_id = current_user.id
    user_name = current_user.display_name()
    note = Note(title, body, user_id, user_name)
    print(note)
    if mongo.db.notes.insert_one(note.dict()):
        return "Success! Note added: " + title
    else:
        return "Error! Could not add note"


# Delete note
@app.route('/delete_note', methods=['POST'])
@login_required
def delete_note():
    note_id = request.form.get("note_id")
    if mongo.db.notes.update_one({"id": note_id}, {"$set": {"deleted": True}}):
        return "Success! Note deleted"
    else:
        return "Error! Could not delete note"


# Send message
@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    title = request.form.get("title")
    body = request.form.get("body")
    from_id = current_user.id
    from_name = current_user.display_name()
    to_id = request.form.get("user")
    to_user_dict = mongo.db.users.find_one({"id": to_id})
    to_user = User.make_from_dict(to_user_dict)
    to_name = to_user.display_name()
    message = Message(title, body, from_id, from_name, to_id, to_name)
    if mongo.db.messages.insert_one(message.dict()):
        send_message_email(from_user=current_user,
                           to_user=to_user, message=message)
        return "Success! Message sent to " + to_name + ": " + title
    else:
        return "Error! Could not send message"


# Delete message
@app.route('/delete_message', methods=['POST'])
@login_required
def delete_message():
    message_id = request.form.get("message_id")
    if mongo.db.messages.update_one({"id": message_id}, {"$set": {"deleted": True}}):
        return "Success! Message deleted"
    else:
        return "Error! Could not delete message"


# Hide sent message
@app.route('/hide_sent_message', methods=['POST'])
@login_required
def hide_sent_message():
    message_id = request.form.get("message_id")
    if mongo.db.messages.update_one({"id": message_id}, {"$set": {"hidden_for_sender": True}}):
        return "Success! Message hidden from sender"
    else:
        return "Error! Could not hide message"


# Change Name
@app.route('/change_name', methods=['POST'])
@login_required
def change_name():
    title = request.form['title'].strip()
    first_name = request.form['first_name'].strip()
    last_name = request.form['last_name'].strip()

    if mongo.db.users.update_one({"email": current_user.email}, {"$set": {"title": title, "first_name": first_name, "last_name": last_name}}):
        return "User name updated successfully"
    else:
        return "Error! Could not update user name"


# Delete Account
@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user_id = current_user.id

    # Deletion flags
    user_deleted = False
    notes_deleted = False
    messages_deleted = False

    # Delete user details
    if mongo.db.users.delete_one({"id": user_id}):
        user_deleted = True
        logout_user()

    # Delete notes
    if mongo.db.notes.delete_many({"user_id": user_id}):
        notes_deleted = True

    # Delete messages
    if mongo.db.messages.delete_many({"$or": [{"from_id": user_id}, {"to_id": user_id}]}):
        messages_deleted = True

    return redirect(url_for('register'))
    # return {"user_deleted": user_deleted, "notes_deleted": notes_deleted, "messages_deleted": messages_deleted}



def get_file_size_in_bytes_2(file_path):
    """ Get size of file at given path in bytes"""
    # get statistics of the file
    stat_info = os.stat(file_path)
    # get size of file in bytes
    size = stat_info.st_size
    return size


@app.route('/uploader', methods = ['GET', 'POST'])
def uploader():
    if request.method == 'POST':
        try:  
            if 'files[]' not in request.files:
                response = {"success":False,"msg":"No file part in the request"}
                return response         
            files = request.files.getlist("files[]")
            lang = request.form.get("lang")
            # get balance
            id_ = current_user.id
            print("user id_ is: ",id_)
            r = app.db.getBy({'user_id': id_})
                    
            if len(r) == 0:
                app.db.add({'user_id': id_, 'balance': 0})
                user_balance = 0
            else:
                user_balance = r[0]['balance']

            # user_balance = 5000

            # files = request.files.getlist("file")
            # lang = request.form.get("lang")
            # verify
            verify = True
            single_zip = False
            verify_msg = "File upload successful."

            if len(files) == 1:
                p = secure_filename(files[0].filename)
                print("p: ",p)

                    #PS: change "verify" variable when the zip is extracted to confirm balance  avalibility
                if not p.endswith(".zip"):
                    verify = False
                    verify_msg = "Current file format is not supported. There should be equal number of wav and lab/txt files."
                    response = {"success":False,"msg":verify_msg}
                    return response
                else:
                    # single zip file
                    print(files[0])

                    single_zip = True
                    # Extraction 
                    tmp_zip = os.path.join("/tmp", p)
                    tmp_dir = os.path.join("/tmp", str(uuid.uuid4()))
                    files[0].save(tmp_zip)
                        
                    with zipfile.ZipFile(tmp_zip, "r") as zip:
                        os.mkdir(tmp_dir)
                        zip.extractall(tmp_dir)
                    os.remove(tmp_zip)
                    print("seven")
                    files = [ FileStorage(open(os.path.join(tmp_dir, i), "rb")) for i in os.listdir(tmp_dir) if os.path.isfile(i)]
                    # files = [ FileStorage(open(os.path.join(tmp_dir, i), "rb")) for i in os.listdir(tmp_dir)]
                    
                    print("eight")
            
            num_texts = 0
            text_files = []
            num_wavs = 0
            wav_files = []

            tot_words = 0
            for file in files:
                p = secure_filename(file.filename)
                if p.endswith(".wav"):
                    num_wavs += 1
                    wav_files.append(p.replace(".wav", ""))
                elif p.endswith(".txt"):
                    num_texts += 1
                    n_words = len(file.read().decode('utf-8').split())
                    tot_words += n_words
                    text_files.append(p.replace(".txt", ""))
                elif p.endswith(".lab"):
                    num_texts += 1
                    n_words = len(file.read().decode('utf-8').split())
                    tot_words += n_words
                    text_files.append(p.replace(".lab", ""))
                elif p.endswith(".TextGrid"):
                    num_texts += 1
                    # temporarily save this file
                    file.stream.seek(0)
                    file.save("/tmp/dump.TextGrid")
                    textgrid_lines = open("/tmp/dump.TextGrid", encoding="utf-16").readlines()
                    n_words = 0
                    for line in textgrid_lines:
                        line = line.strip()
                        sens = [a.strip() for a in line.split()]
                        if len(sens) >= 3:
                            if sens[0] == "text" and sens[1] == "=" and sens[2] != '""':
                                #print(sens)
                                #print(len(sens))
                                n_words += len(sens) - 2

                    tot_words += n_words
                    text_files.append(p.replace(".TextGrid", ""))
                else:
                    verify = False
                    verify_msg = f"File {p} is not supported. There should be equal number of wav and lab/txt files."
                    response = {"success":False,"msg":verify_msg}
                    return response
                    break

            if sorted(text_files) != sorted(wav_files):
                verify = False
                verify_msg = "The wav filename(s) should exactly match with .txt/.lab label filename(s)."
                response = {"success":False,"msg":verify_msg}
                return response

            if num_texts != num_wavs:
                verify = False
                verify_msg = f"There should be equal number of wav and lab/txt files."
                response = {"success":False,"msg":verify_msg}
                return response


            if verify == False:
                response = {"success":False,"msg":verify_msg}
                return response
                return render_template('messages.html', users=[], inbox_messages=[], sent_messages=[], res=verify_msg, balance = user_balance)

            if single_zip == True: # will add support later
                shutil.rmtree(tmp_dir) # remove tmp extracted file
                response = {"success":True,"msg":verify_msg,"single_zip":True}
                return response
                return render_template('messages.html', users=[], inbox_messages=[], sent_messages=[], res=verify_msg, balance = user_balance)
                
                
            print(user_balance)
            print(per_word_price)
            print(tot_words)
            # return str("groot")
            cost = round(per_word_price * tot_words + 0.05, 2)
            if user_balance < per_word_price * tot_words:
                balance_failed_msg = f"Your balance is too low. For {tot_words} words you need at least {round(per_word_price * tot_words + 0.05, 2)} SEK in balance."
                response = {"success":False,"msg":balance_failed_msg}                
                return response
                return render_template('messages.html', users=[], inbox_messages=[], sent_messages=[], res=balance_failed_msg, balance = user_balance)


            tmap = str(time.time())
            ps = ["uploads", str(current_user.id), tmap]
                    
            Path(os.path.join(*ps)).mkdir(parents=True, exist_ok=True)
            sizes = []
            for file in files:
                p = secure_filename(file.filename)
                paths = ["uploads", str(current_user.id), tmap, p]
                file.stream.seek(0)
                file.save(os.path.join(*paths))

                file_path = os.path.join(*paths)
                size = get_file_size_in_bytes_2(file_path)
                sizes.append(size)
                # print('File size in bytes : ', size)
                size_in_kb = size/1024
                # print('File size in kilobytes : ', size_in_kb)
                if size_in_kb > 150000:                    
                    ps = ["uploads", str(current_user.id), tmap]
                    shutil.rmtree(os.path.join(*ps))
                    verify = False
                    verify_msg = f"File {p} is too large. Max Limit is 150mb"
                    response = {"success":False,"msg":verify_msg} 
                    return response
                    return render_template('messages.html', users=[], inbox_messages=[], sent_messages=[], res=verify_msg, balance = user_balance)                

                #ps_temp = ps + ["file_upload_completed.dsap"]
                #with open(os.path.join(*ps_temp),"a+") as f:
                #    f.write("done")
                #    f.close()

                # schema
                ####
                # {user_id, task_path [main folder], task_status = uploaded / completed, download_path}
                # if task_status is uploaded, run mfa with task_path
                # if task_status is completed, just get the download path in profile to make the download
                ####

                # file just successfully uploaded
                # task_path = os.path.join(str(current_user.id),tmap)

            
            total_size = sum(sizes)
            print('Total size in bytes : ', total_size)
            size_in_kb = total_size/1024
            print('Total size in kilobytes : ', size_in_kb)
            if size_in_kb > 150000:                    
                ps = ["uploads", str(current_user.id), tmap]
                shutil.rmtree(os.path.join(*ps))
                verify = False
                verify_msg = f"Files are too large. Max Limit is 150mb"
                response = {"success":False,"msg":verify_msg} 
                return response
                return render_template('messages.html', users=[], inbox_messages=[], sent_messages=[], res=verify_msg, balance = user_balance)  
            response = {"success":True,"msg":verify_msg,"tmap":tmap,"num_wavs":num_wavs,"per_word_price":per_word_price,"tot_words":tot_words,"lang":lang,"cost":cost} 
            return response
            # return "all good!!"
            task_path = str(current_user.id)+"/"+str(tmap)
            print("current_user.id is: ",current_user.id)
            print("task path is: ",task_path)
            app.tasks_db.add({"user_id": str(current_user.id), "task_path": task_path, "task_status": "uploaded", "download_path": "", "download_title": tmap, "download_counts": str(num_wavs), "download_date": datetime.now().date().strftime('%m/%d/%Y'), "cost": per_word_price * tot_words,"lang":lang})
            print("failed here")

            return render_template('messages.html', users=[], inbox_messages=[], sent_messages=[], res=f"Files uploaded successfully. The processed textgrid files will appear in the downloads section after approximately {round(tot_words * per_word_time, 2)} secs", balance = user_balance)
        except Exception as e:
            print("ISSUEESSS")
            print(e)
            response = {"success":False,"msg":str(e)}
            return response
            return render_template('messages.html', users=[], inbox_messages=[], sent_messages=[], res="File upload failed!", balance = user_balance)



@app.route("/confirm-upload",methods=['POST'])
def confirm_uploads():
    # try:
    if request.method == "POST":
        lang = request.form.get("lang")
        tmap = request.form.get("tmap")
        num_wavs = request.form.get("num_wavs")
        per_word_price = float(request.form.get("per_word_price"))
        tot_words = float(request.form.get("tot_words"))
        print("lang: ",lang)
        print("tmap: ",tmap)
        print("num_wavs: ",num_wavs)
        print("per_word_price: ",per_word_price)
        print("tot_words: ",tot_words)
        # get balance
        id_ = current_user.id
        r = app.db.getBy({'user_id': id_})          
        user_balance = r[0]['balance']

        task_path = str(current_user.id)+"/"+str(tmap)
        cost = per_word_price * tot_words
        print("current_user.id is: ",current_user.id)
        print("task path is: ",task_path)
        app.tasks_db.add({"user_id": str(current_user.id), "task_path": task_path, "task_status": "uploaded", "download_path": "", "download_title": tmap, "download_counts": str(num_wavs), "download_date": datetime.now().date().strftime('%m/%d/%Y'), "cost":cost,"lang":lang})
        # print("failed here")
        req_time = round(float(tot_words) * float(per_word_time), 2)
        msg = "Files uploaded successfully. The processed textgrid files will appear in the downloads section after approximately "+str(req_time)+" secs"
        resp = {"success":True,"msg":msg,"balance":user_balance}
        return resp
        return render_template('messages.html', users=[], inbox_messages=[], sent_messages=[], res=f"Files uploaded successfully. The processed textgrid files will appear in the downloads section after approximately {round(tot_words * per_word_time, 2)} secs", balance = user_balance)

    # except Exception as e:
    #     resp = {"success":False,"msg":str(e)}
    #     return resp


@app.route('/payment')
def payment():
    '''
    session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
            'price': 'price_1GtKWtIdX0gthvYPm4fJgrOr',
            'quantity': 1,
        }],
        mode='payment',
        success_url=url_for('thanks', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
        cancel_url=url_for('index', _external=True),
    )
    '''
    return render_template(
        'payment.html', 
        #checkout_session_id=session['id'], 
        #checkout_public_key=app.config['STRIPE_PUBLIC_KEY']
    )


@app.route('/stripe_pay')
def stripe_pay():
    print(request.args.get('count_w'))
    num_count = request.args.get('count_w')
    try:
        num_count = int(num_count)
    except:
        num_count = 1
    if num_count < 1:
        num_count = 1
        
    session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
            'price': 'price_1Kc4w7FlFIqZR98TYB3dFeQO',
            'quantity': int(num_count),
        }],
        mode='payment',
        success_url=url_for('thanks', _external=True) + '?session_id={CHECKOUT_SESSION_ID}' + f"&sucwords={num_count}",
        cancel_url=url_for('index', _external=True),
    )
    return {
        'checkout_session_id': session['id'], 
        'checkout_public_key': app.config['STRIPE_PUBLIC_KEY']
    }

@app.route('/thanks')
def thanks():
    print(request.args.get('sucwords'))
    num_count = int(request.args.get('sucwords')) * word_packages

    id_ = current_user.id
    r = app.db.getBy({'user_id': id_})
    if len(r) == 0:
        app.db.add({'user_id': id_, 'balance': 0})
    else:
        pb = r[0]['balance']
        db_id = r[0]['id']
        app.db.updateById(db_id, {'balance': pb + num_count})
    return render_template('thanks.html')

@app.route('/fetch-estimated-price', methods=['GET'])
def fetch_estimated_price():
    print("I LOVE YUUUUUUUUUUUUUUU")
    return "Groot"

@app.route('/stripe_webhook', methods=['POST'])
def stripe_webhook():
    print('WEBHOOK CALLED')

    if request.content_length > 1024 * 1024:
        print('REQUEST TOO BIG')
        abort(400)
    payload = request.get_data()
    sig_header = request.environ.get('HTTP_STRIPE_SIGNATURE')
    endpoint_secret = 'YOUR_ENDPOINT_SECRET'
    event = None

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except ValueError as e:
        # Invalid payload
        print('INVALID PAYLOAD')
        return {}, 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        print('INVALID SIGNATURE')
        return {}, 400

    # Handle the checkout.session.completed event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        print(session)
        line_items = stripe.checkout.Session.list_line_items(session['id'], limit=1)
        print(line_items['data'][0]['description'])

    return {}

@app.route('/download', methods=['GET','POST'])
def download():
    import io, zipfile
    FILEPATH = request.args.get("filepath") 
    fileobj = io.BytesIO()
    with zipfile.ZipFile(fileobj, 'w') as zip_file:
        zip_info = zipfile.ZipInfo(FILEPATH)
        zip_info.date_time = time.localtime(time.time())[:6]
        zip_info.compress_type = zipfile.ZIP_DEFLATED
        with open(FILEPATH, 'rb') as fd:
            zip_file.writestr(zip_info, fd.read())
    fileobj.seek(0)

    response = make_response(fileobj.read())
    response.headers.set('Content-Type', 'zip')
    response.headers.set('Content-Disposition', 'attachment', filename='%s.zip' % os.path.basename(FILEPATH))
    return response
# LOGIN MANAGER REQUIREMENTS

# Load user from user ID
@login_manager.user_loader
def load_user(userid):
    # Return user object or none
    users = mongo.db.users
    user = users.find_one({'id': userid}, {'_id': 0})
    if user:
        return User.make_from_dict(user)
    return None


# Safe URL
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
        ref_url.netloc == test_url.netloc



# ENV = "prod"
ENV = "dev"
# Heroku environment
if ENV == "prod":
    serve(app, host='0.0.0.0', port=5000, url_scheme='https')
else:
    app.run(host='0.0.0.0', port=5000, debug=True) #, ssl_context='adhoc'
    # app.run(host='0.0.0.0', port=8080, debug=True) 
