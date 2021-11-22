import logging
import random
import socket
from datetime import datetime, timedelta
from functools import wraps
import jwt
import requests
from faker import Faker
from flask import Blueprint, request, Flask, jsonify, session
from flask_mysqldb import MySQL
from marshmallow import ValidationError, Schema, fields, validate
from werkzeug.security import generate_password_hash, check_password_hash

# Blueprint setup
user = Blueprint("user", __name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'raghu'
mysql = MySQL(app)

# Validations:-
class User_signup(Schema):
    # user_signupid = fields.String(validate=validate.Regexp(r'[A-Za-z0-9]+'))
    username = fields.String(validate=validate.Regexp(r'[A-Za-z]+'))
    email = fields.Email(required=True)
    phone = fields.String(validate=validate.Regexp(r'^(?:(?:\+|0{0,2})91(\s*[\-]\s*)?|[0]?)?[789]\d{9}$'), required=True)
    password = fields.String(validate=validate.Regexp(r'^[A-Za-z0-9@#$%^&+=]{8,32}'))
    ip = fields.String(validate=validate.Regexp(r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|'
                                                r'[01]?[0-9][0-9]?)$'))
    # date = fields.String(validate=validate.Regexp(r'^(19|20)\d\d[- /.](0[1-9]|1[012])[- /.](0[1-9]|[12][0-9]|3[01])$'))

# Signup:-
@user.route('/insert', methods=['POST'])
def usersignup():
    # @wraps()
    # def wrappersUserSignup(*args, **kwargs):
        if 'username' in request.json and 'password' in request.json \
                and 'email' in request.json and 'phone' in request.json:
            request_data = request.json
            # user_signupid = request_data['user_signupid']
            username = request_data['username']
            email = request_data['email']
            phone = request_data['phone']
            password = request_data['password']
            hassedpassword = generate_password_hash(password)
            # userip = request_data['ip']
            ex = Faker()
            ip = ex.ipv4()
            print(ip)
            # date = request_data['date']
            device = socket.gethostname()
            print(device)

            # UserId Pattern for Insert Operation:-
            cursor = mysql.connection.cursor()
            cursor.execute("SELECT USER_ID FROM user_signup")
            last_user_id = cursor.rowcount
            print('----------------------------------')
            print("Last Inserted ID is: " + str(last_user_id))
            pattern = 'US000'  # pattern = ooo
            last_user_id += 1
            # add_value = 00
            # pattern += 1 # pattern incremnting always by 1:-
            user_id = pattern + str(last_user_id)  # pass 'user_id' value in place holder exactly
            # User Id pattern Code End #

            # Cursor:-
            cursor = mysql.connection.cursor()
            cursor.execute('SELECT * FROM user_signup WHERE USER_MAIL_ID = %s OR USER_PHONE_NUMBER = %s', (email, phone))
            account = cursor.fetchone()

            if account and account[3] == email:
                return 'Your Email already exist please enter new Email !', 400

            elif account and account[4] == phone:
                return "Your Phone number is duplicate please enter new number!!!", 400

            # elif account:
            #     return fun(account, args, *kwargs)

            user_schema = User_signup()
            try:
                # Validate request body against schema data types
                user_schema.load(request_data)
                cur = mysql.connection.cursor()
                cur.execute(
                    "insert into user_signup(USER_ID, USER_NAME, USER_MAIL_ID, USER_PHONE_NUMBER, USER_PASSWORD,"
                    "USER_IP, USER_DEVICE) VALUES(%s, %s, %s, %s, %s, %s, %s)",
                    (user_id, username, email, phone, hassedpassword, ip, device))
                mysql.connection.commit()
                logging.info("successfully registered")

                # return fun("successfully inserted", args, *kwargs), 201
                return "Succesfully Inserted", 200
            except ValidationError as e:
                # logTo_database("/user/insert", "user_signup", e, 401)
                return (e.messages), 400
        return "Invalid input", 200
    # return wrappersUserSignup


# def logTo_database(apiUrl, method_Name, e, errorCode):
#     date = datetime.today()
#     cur = mysql.connection.cursor()
#     print(e)
#     cur.execute("insert into api_logs(API_NAME, API_METHOD, TRIGGERED_TIME, ERROR_CODE) values(%s, %s, %s, %s)",
#                 (apiUrl, method_Name, date, errorCode))
#     mysql.connection.commit()


# @user.route('/create', methods=['POST'])
# @usersignup
# def dpttest(test):
#     return test

# Login:-
def logined(func):
    @wraps(func)
    def Wrapperlogin(*args, **kwargs):
        if 'email' in request.json and 'password' in request.json:
            email = request.json["email"]
            #phone = request.json['phonenumber']
            pw = request.json["password"]

            logging.warning('Watch out!')

            cur = mysql.connection.cursor()
            #cur.execute("select USER_PASSWORD from user_signup where USER_MAIL_ID = %s", (email,))
            cur.execute('SELECT * FROM USER_SIGNUP WHERE USER_MAIL_ID = %s',(email,))
            details = cur.fetchone()

            if details is None:
                return'Email not registered', 401
            hashed_password = details[5]
            password_match = check_password_hash(hashed_password, pw)

            if password_match:
                # generate the JWT Token
                data = {
                    'user_mail': email,
                    'password': hashed_password,
                    "user_id": details[1],
                    'exp': datetime.utcnow() + timedelta(minutes=2)}
                token = jwt.encode(data, app.config['SECRET_KEY'], algorithm='HS256')
                data['token'] = token
                return func(data, *args, **kwargs)
            else:
                logging.error("Invalid credentials")
                return "invalid credentials", 401
        return "Insufficient parameters", 400
    return Wrapperlogin


@user.route('/login', methods=["POST"])
@logined
def login_testing(data):
    log_data(data)
    return data['token']


def token_validate(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "x-access-token" in request.headers:
            token = request.headers["x-access-token"]
        if not token:
            return jsonify({"message": "Token is missing !!"}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return jsonify({"message": "Token is invalid"})

        return f(data, *args, **kwargs)

    return decorated


@user.route('/logined', methods=['GET'])
@token_validate
def token_testing(data):
    return data


def log_data(data):
    try:
        date = datetime.today()
        cur = mysql.connection.cursor()
        cur.execute(
            "insert into logins_data(LOGIN_EMAIL_ID, LOGIN_TIME) values(%s, %s)",
            (data['user_mail'], date))
        mysql.connection.commit()
        return "successfully inserted", 200
    except ValidationError as e:
        print(e)
        return e.messages, 400

# Logout:-
@user.route('/logout')
def logout():
    session.pop('username',None)
    # return redirect(url_for('index'))
    cur = mysql.connection.cursor()
    cur.execute('select USER_MAIL_ID from user_signup')
    Email_id = cur.fetchall()
    Login_Email_id = Email_id[-1]
    print(Login_Email_id)
    # date and time object:-
    now = datetime.now()
    logout_time = now.strftime('%Y-%m-%d %H:%M:%S')
    cur = mysql.connection.cursor()
    cur.execute('insert into logins_data(LOGIN_EMAIL_ID, LOGOUT_TIME) values(%s, %s)', (id, logout_time))
    return("User Loggedout Successfully !!!")


# SMS:-
def sms_send(phonenumber,otpmsg):
    url="https://www.fast2sms.com/dev/bulk"
    params={
        "authorization":"m3r7Eu9zhHeLnGMyPk0BXjxVlTag2fRIJF4v6bQDUpNK1ct8ZOoIUdLRsfDE7ZTNMeqc5yHv2uJPazi6",
        "sender_id":"SMSINI",
        "message":otpmsg,
        "language":"english",
        "route":"p",
        "numbers":phonenumber
    }
    requests.get(url, params=params)

# OTP:-
@app.route('/Phone_otp', methods=["POST"])
def otp_generate():
    if 'phonenumber' in request.json:
        phone = request.json['phonenumber']
        OtpGenerated = random.randint(10000, 99999)
        notification = "Your OTP is:" + str(OtpGenerated)
        sms_send(phone,notification)

        inputOtp = input("enter otp:")
        Otp = str(OtpGenerated)
        if inputOtp == Otp:
            return "otp validate"
        logging.info('Admin logged in')
    return 'otp generated',200

# Update in postman by using josnify
@user.route("/update", methods=['POST'])
def update_user_signup():
         user_signup_id = request.json['signupId']
         user_name = request.json['userName']
         user_mail_id = request.json['emailId']
         user_phnum = request.json['phoneNumber']
         cursor = mysql.connection.cursor()
         cursor.execute("""
         UPDATE user_signup set USER_NAME = %s, USER_MAIL_ID = %s, USER_PHONE_NUMBER = %s WHERE USER_SIGNUP_ID =%s
         """,(user_name, user_mail_id, user_phnum, user_signup_id))
         mysql.connection.commit()
         #user_details = cur.fetchall()
         return 'Successfully updated',200

# Delete in postman by using josnify
@user.route("/delete/<USER_ID>", methods=['DELETE'])
def delete_user_signup(USER_ID):
    cursor = mysql.connection.cursor()
    cursor.execute("delete from user_signup where USER_ID =" + USER_ID)
    mysql.connection.commit()
    user_details = cursor.fetchall()
    return jsonify({'user_details':user_details}),200

# Users:-
@user.route("/list")
def users():
    cursor = mysql.connection.cursor()
    cursor.execute("select * from user_signup")
    user_details = cursor.fetchall()
    print(user_details, "User Details")
    return jsonify(user_details), 200