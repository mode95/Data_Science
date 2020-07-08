# Flask library
from flask import Flask, flash, abort, request, jsonify, g
from flask import make_response, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy  import SQLAlchemy
from flask_httpauth import HTTPBasicAuth

# wefotms library
from wtforms import SelectField, StringField, PasswordField, BooleanField
from wtforms.fields import SubmitField
from wtforms.validators import InputRequired, Email, Length, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash

# MongoDB library
import pymongo
from pymongo import MongoClient

# Other library
import jwt
from functools import wraps

# Define Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'very_very_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://///Users/dario/Desktop/Wallet/app/users.db'
app.config['TESTING'] = False
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
bootstrap = Bootstrap(app)

####################
##### DATABASE #####
####################

# DB authentication
auth_db = SQLAlchemy(app)

# login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# mongoDB database for payment methods
client = MongoClient()
mongo_db = client.test_database
collection = mongo_db.test_collection


########################
##### FORM SECTION #####
########################

# LOGIN FORM
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('Remember me')

# SIGN UP FORM
class RegisterForm(FlaskForm):
    def validate_token(form, field):
        if ' ' in field.data:
            raise ValidationError('Il Token non può contenere spazi')
        if collection.count_documents({ 'token': field.data }, limit = 1) != 0:
            raise ValidationError('Il Token inserito è già esistente')

    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    token = StringField('Token',description = "* Inserisci il token con cui condividere le tue informazioni", validators=[InputRequired(), Length(min=4, max=80), validate_token])

# WALLET FORM
# Choose payment method type to create
class ChoseMethod(FlaskForm):
    drop_list = ['Sciegliere un metodo di pagamento', 'IBAN', 'PayPal', 'Satispay']
    dropdown = SelectField('Metodo di pagamento', choices=drop_list, default=0)

# IBAN form
class Method_IBAN(FlaskForm):
    # IBAN
    beneficiario = StringField('Beneficiario', validators=[InputRequired(), Length(min=3)])
    causale = StringField('Causale', validators=[InputRequired(), Length(min=3)])
    IBAN = StringField('IBAN', validators=[InputRequired(), Length(min=3)])

# Paypall form
class Method_PayPal(FlaskForm):
    # Pay Pall
    link = StringField('Link PayPal', validators=[InputRequired(), Length(min = 11)])

# Satispay form
class Method_Satispay(FlaskForm):
    # Satispay
    numero = StringField('Numero cellulare', validators=[InputRequired(), Length(min = 9)])

# SEACH TOKEN FORM
class TokenForm(FlaskForm):
  search = StringField('', validators=[InputRequired()])

####################################
##### USER - SIGN UP - SIGN IN #####
####################################

# API request
# user token user:password
@login_manager.request_loader
def load_user(request):
    token = request.headers.get('Authorization')
    if token is None:
        token = request.args.get('token')

    if token is not None:
        user, password = token.split(":")

        user_entry = User.query.filter_by(user=user).first()
        if user_entry:
            if check_password_hash(user_entry.password, password):
                return user_entry

    return None

# Create User class
class User(UserMixin, auth_db.Model):
    __tablename__ = 'user'

    # define column in db
    id = auth_db.Column(auth_db.Integer, primary_key=True)
    user = auth_db.Column(auth_db.String(15), unique=True)
    email = auth_db.Column(auth_db.String(50), unique=True)
    password = auth_db.Column(auth_db.String(80))
    token = auth_db.Column(auth_db.String(80), unique = True)

# load user in login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#####################
##### HOME PAGE #####
#####################

# home page
@app.route('/', methods=['GET','POST'])
def index():
    form = TokenForm(request.form)
    # user is logged in
    if current_user.is_authenticated:
        # create URL to share
        token = current_user.token
        url = 'http://localhost:5000/' + token
        # validation of seach token form
        if form.validate_on_submit():
            return redirect(url_for('share_token', token = form.search.data))
        return render_template('index_user.html', url = url, form = form, token = token)

    # user is not logged in
    else:
        # validation of seach token form
        if form.validate_on_submit():
            return redirect(url_for('share_token', token = form.search.data))
        return render_template('index.html', form = form)

########################
##### SIGN UP PAGE #####
########################

# User Sign Up
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # Load sign up form
    form = RegisterForm()

    # validate form
    if form.validate_on_submit():
        # hash password
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        # create new user in SQL
        new_user = User(user=form.username.data, email=form.email.data, password=hashed_password, token=form.token.data)
        auth_db.session.add(new_user)
        auth_db.session.commit()

        # create new user in MongoDB
        data_mongo = {'_id': collection.find_one({"$query":{},"$orderby":{"_id":-1}})["_id"] + 1 if collection.find_one() is not None else 1,
                      'user': form.username.data,
                      'token': form.token.data,
                      'metodi': []}
        collection.insert_one(data_mongo)

        # log user
        login_user(new_user)
        return redirect(url_for('index'))

    return render_template('signup.html', form=form)

#######################
##### LOG IN PAGE #####
#######################

# User sign in
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Load sign in form
    form = LoginForm()

    # validate form
    if form.validate_on_submit():
        # search inserted data into SQL
        user = User.query.filter_by(user=form.username.data).first()

        # if user exists
        if user:
            print(check_password_hash(user.password, form.password.data))
            # chech of hashed password
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
            else:
                error = "Le credenziali inserite non sono valide. Riprovare"
                return render_template('login.html', form=form, error = error)

        # if user doesn't exists
        else:
            error = "Le credenziali inserite non sono valide. Riprovare"
            return render_template('login.html', form=form, error = error)

        return redirect(url_for('index'))

    return render_template('login.html', form=form)

# Logout of User
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

#############################
##### WALLET MANAGEMENT #####
#############################

### WALLET PAGE ###
@app.route('/MyWallet', methods = ['GET', 'POST'])
@login_required
def MyWallet():
    # find payment methods of user
    metodi_user = collection.find_one({"user": current_user.user})
    return render_template('MyWallet.html', data = metodi_user)

# Delete of payment method
@app.route('/MyWallet/remove/<method_id>', methods = ['GET', 'POST'])
@login_required
def remove_method(method_id):
    collection.update(
        { 'user': current_user.user},
        { '$pull': { 'metodi': { '_id': int(method_id)}}}
    )
    return redirect(url_for('MyWallet'))

### NEW METHOD PAGE ###
@app.route('/creaMetodo', methods = ['GET', 'POST'])
@login_required
def crea_metodo():
    # load method form
    form = ChoseMethod()

    # validate form
    if(form.dropdown.data):
        # User choosed IBAN
        if(form.dropdown.data == 'IBAN'):
            return redirect(url_for('crea_metodo_type', type = 'IBAN'))
        # User choosed PayPal
        if(form.dropdown.data == 'PayPal'):
            return redirect(url_for('crea_metodo_type', type = 'PayPal'))
        # User choosed Satispay
        if(form.dropdown.data == 'Satispay'):
            return redirect(url_for('crea_metodo_type', type = 'Satispay'))

    return render_template('NewMethod.html', form = form)

# Create form based on payment method choosed
@app.route('/creaMetodo/<type>', methods = ['GET', 'POST'])
@login_required
def crea_metodo_type(type):
    # load payment method
    form = ChoseMethod()

    # User choosed IBAN
    if(type == 'IBAN'):
        # load IBAN form
        form_IBAN = Method_IBAN()
        # validate form
        if(form_IBAN.validate_on_submit()):
            # create method's document
            data = {
                '_id': len(collection.find_one({'user': current_user.user})['metodi']),
                'type': 'IBAN',
                'beneficiario': form_IBAN.beneficiario.data,
                'causale': form_IBAN.causale.data,
                'IBAN': form_IBAN.IBAN.data
            }

            # add method to MongoDB
            collection.update_one({'user': current_user.user},
                                  {'$push': {'metodi': data}})
            return redirect(url_for('index'))
        return render_template('NewMethod.html', form = form, form_IBAN = form_IBAN)

    # User choosed PayPal
    if(type == 'PayPal'):
        # load PayPal form
        form_paypal = Method_PayPal()
        # validate form
        if(form_paypal.validate_on_submit()):
            # create method's document
            data = {
                '_id': len(collection.find_one({'user':current_user.user})['metodi']),
                'type': 'PayPal',
                'link': form_paypal.link.data,
            }
            # add method to MongoDB
            collection.update_one({'user': current_user.user},
                                  {'$push': {'metodi': data}})
            return redirect(url_for('index'))
        return render_template('NewMethod.html', form = form, form_paypal = form_paypal)

    # User choosed Satispay
    if(type == 'Satispay'):
        # load Satispay form
        form_satispay = Method_Satispay()
        # validate form
        if(form_satispay.validate_on_submit()):
            # create method's document
            data = {
                '_id': len(collection.find_one({'user':current_user.user})['metodi']),
                'type': 'Satispay',
                'cellulare': form_satispay.numero.data,
            }
            # add method to MongoDB
            collection.update_one({'user': current_user.user},
                                  {'$push': {'metodi': data}})
            return redirect(url_for('index'))
        return render_template('NewMethod.html', form = form, form_satispay = form_satispay)


###############################
##### SHARE PERSONAL TOKE #####
###############################
@app.route('/<token>', methods = ['GET'])
def share_token(token):
    # seach token in MongoDB
    user_token = collection.find_one({"token": token})
    # User is logged
    if current_user.is_authenticated:
        return render_template('ShareToken_user.html', data = user_token)
    # User is not logged
    else:
        return render_template('ShareToken.html', data = user_token)

# Share a singol payment method
@app.route('/<token>/<method_id>', methods = ['GET'])
def shareMethod(token, method_id):
    # seach singol method in MongoDB
    pipeline = [
        {'$match': {"metodi._id": int(method_id), "token": token}},
        {'$unwind': "$metodi"},
        {'$match': {"metodi._id": int(method_id)}}
    ]
    user = collection.find_one({'token':token})['user']
    data = collection.aggregate(pipeline)
    data = [result['metodi'] for result in data]
    # User is logged
    if current_user.is_authenticated:
        return render_template('shareMethod_user.html', data = data, user = user)
    # User is not logged
    else:
        return render_template('shareMethod.html', data = data, user = user)


######################
##### CREATE API #####
######################
# Get all Tokens
@app.route('/api/all_token', methods = ['GET'])
@login_required
def all_token():
    data_collection = collection.find()
    if collection.find_one() is None:
        abort(404)
    return jsonify([data['token'] for data in collection.find()])

# Get all information of a random user
@app.route('/api/random_user', methods = ['GET'])
@login_required
def random_user():
    data_collection = collection.find()
    if collection.find_one() is None:
        abort(404)
    return jsonify([collection.find_one()])

# Get all payment methodsfor the user with <token>
@app.route('/api/payment_methods/<token>', methods=['GET'])
@login_required
def all_payment_methods(token):
    if collection.find_one() is None:
        abort(404)
    else:
        data = collection.find_one({"token": token})
    return jsonify(data['metodi'])

# Get all payment methods <type> for the user with <token>
@app.route('/api/payment_methods/<token>/<type>', methods=['GET'])
@login_required
def payment_method(token, type):
    if collection.find_one() is None:
        abort(404)
    else:
        pipeline = [
        {'$match': {"metodi.type": type, "token": token}},
        {'$unwind': "$metodi"},
        {'$match': {"metodi.type": type}}
    ]
    data = collection.aggregate(pipeline)
    data = [result['metodi'] for result in data]
    return jsonify(data)

################
##### MAIN #####
################
if __name__ == '__main__':
    auth_db.create_all()
    app.run(debug=True)
