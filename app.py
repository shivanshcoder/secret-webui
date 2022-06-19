# -*- coding: utf-8 -*-

# ! Source of the code
# ! https://developers.google.com/identity/protocols/oauth2/web-server#example

import json
import os
import flask
from markupsafe import Markup
import requests
import io
import string
from flask import render_template, request
import time
import random

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaFileUpload
from googleapiclient.http import MediaIoBaseDownload
import drive_backend
from pymongo import MongoClient

from utils import add_device_code, mfa_exists, upsert_mongo, getUserInfo, verify_device_code, generate_mfa, verify_mfa

# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = "./client_secret.json"

# This OAuth 2.0 access scope allows for full read/write access to the
# authenticated user's account and requires requests to use an SSL connection.
# SCOPES = ['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/drive.appdata']
# SCOPES = ['https://www.googleapis.com/auth/drive.appdata', 'https://www.googleapis.com/auth/userinfo.email']
SCOPES = ['https://www.googleapis.com/auth/drive.appdata', 'openid', 'https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email']
API_SERVICE_NAME = 'drive'
API_VERSION = 'v2'

# callback_uri = "http://localhost:8888/oauth2callback"
app = flask.Flask(__name__)
# Note: A secret key is included in the sample so that it works.
# If you use this code in your application, replace this with a truly secret
# key. See https://flask.palletsprojects.com/quickstart/#sessions.
app.secret_key = 'REPLACE ME - this value is here as a placeholder.'


conn_str = 'mongodb+srv://shivansh:3QNrjnZhgdPqrfbO@cluster0.vueba.mongodb.net/?retryWrites=true&w=majority'
client = MongoClient(conn_str, serverSelectionTimeoutMS=5000)

db = client.flask_db
profiles = db.profiles
device_codes = db.device_codes

if not os.path.exists('tmp'):
    os.mkdir('tmp')

global_secret = {}
with open(CLIENT_SECRETS_FILE, "r") as f:
    global_secret = json.loads(f.read())['web']

def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
    }

def client_cred_dict(credentials, unique_id):
    return {
        'token': credentials['token'],
        'refresh_token': credentials['refresh_token'],
        'token_uri': credentials['token_uri'], 
        'scopes': credentials['scopes'], 
        '_id': unique_id
    }
    
def build_credentials(credentials):
    return {
        'token': credentials['token'],
            'refresh_token': credentials['refresh_token'],
            'token_uri': credentials['token_uri'],
            'client_id': global_secret['client_id'],
            'client_secret': global_secret['client_secret'],
            'scopes': credentials['scopes']
    }
    pass

def get_credentials(session_creds = None):
    if session_creds:
        creds = session_creds
    else:
        creds = flask.session['credentials']
    credentials = google.oauth2.credentials.Credentials(
        **build_credentials(creds))
    return credentials

@app.route('/test')
def test_api_request():
    if 'credentials' not in flask.session:
        return flask.redirect('authorize')

    credentials = google.oauth2.credentials.Credentials(
        **build_credentials(flask.session['credentials']))

    drive = googleapiclient.discovery.build(
        API_SERVICE_NAME, API_VERSION, credentials=credentials)

    files2 = drive.files().list().execute()
    files = {
        "files2": files2
    }
    return flask.jsonify(**files)

# Maybe confirm using MFA code
@app.route('/upload', methods=['POST'])
def config_upload():
    data = json.loads(request.get_data())
    if not verify_mfa(profiles, data['config']['_id'], data['mfa_code']):
        return {"msg": "MFA Failed"}
    credentials = get_credentials(data['config']['google_auth'])

    drive = googleapiclient.discovery.build(
        'drive', 'v3', credentials=credentials)
    
    if request.method == 'POST':
        da = drive_backend.DriveAPI(drive, data['config']['config_filename'])
        return {"msg": "Success", "fileid": da.upload_config(data['config_data'])}

@app.route('/get', methods=['POST'])
def config_get():
    data = json.loads(request.get_data())
    credentials = get_credentials(data['config']['google_auth'])

    drive = googleapiclient.discovery.build(
        'drive', 'v3', credentials=credentials)
    
    da = drive_backend.DriveAPI(drive, data['config']['config_filename'], data['config'].get('config_fileid', None))
    return da.get_config()

@app.route('/getListing', methods=['POST'])
def config_listing():
    data = json.loads(request.get_data())
    credentials = get_credentials(data['config']['google_auth'])

    drive = googleapiclient.discovery.build(
        'drive', 'v3', credentials=credentials)
    
    da = drive_backend.DriveAPI(drive)
    return {
        "msg": "Success", 
        "listing": da.get_config_listing()
    }

@app.route('/creds')
def get_credss():
    return flask.session['credentials']
  
@app.route('/add_device_old', methods=['GET', 'POST', 'PUT'])
def add_device():
    # user_info = getUserInfo(credentials)
    if request.method == "GET":
        import random
        code = otp = random.randint(100000, 999999)
        if 'credentials' not in flask.session:
            return flask.redirect('authorize')
        # Place the secret code in db
        credentials = flask.session['credentials']
        # add_device_code(profiles, credentials['_id'],code)
        import time
        credentials['code'] = f'{code}'
        credentials['code_time'] = time.time()
        device_codes.replace_one({"_id": credentials['_id']}, credentials, upsert=True)
        return {"msg": code}
    elif request.method == "POST":
        req_data = json.loads(request.get_data())
        ans = verify_device_code(device_codes, req_data['code'])
        if not ans:
            return {"msg": "Failed"}
        return {"msg": "Success", "info": ans }
          
# @app.route('/add_device', methods=['GET', 'POST', 'PUT'])
# def add_device2():
#     # user_info = getUserInfo(credentials)
#     if request.method == "GET":
#         import random
#         secret_code = request.args.get('secret_code',9234)
#         # user_email = request.args.get('email')
#         # ! Later use something else than random
#         # code = random.randint(100000, 999999)
#         code = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
#         if 'credentials' not in flask.session:
#             return flask.redirect('authorize')
#         # Place the secret code in db
#         credentials = flask.session['credentials']
#         # add_device_code(profiles, credentials['_id'],code)
#         import time
#         credentials['code'] = f'{code}'
#         credentials['secret_code'] = secret_code
#         credentials['code_time'] = time.time()
#         print(credentials)
#         device_codes.replace_one({"_id": credentials['_id']}, credentials, upsert=True)
#         return {"msg": code}
#     elif request.method == "POST":
#         req_data = json.loads(request.get_data())
#         ans = verify_device_code(device_codes, req_data['code'], req_data.get('secret_code', 9234))
#         if not ans:
#             return {"msg": "Failed"}
#         return {"msg": "Success", "info": ans }
          
          
@app.route('/add_device/<special_code>', methods=['GET', 'POST', 'PUT'])
def add_device2(special_code):
    # user_info = getUserInfo(credentials)
    if request.method == "GET":
        # user_email = request.args.get('email')
        
        # ! Later use something else than random
        code = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
        
        if 'credentials' not in flask.session:
            return flask.redirect(flask.url_for('authorize'))
        
        # Place the secret code in db
        credentials = flask.session['credentials']
        
        credentials['code'] = f'{code}'
        credentials['special_code'] = special_code
        credentials['code_time'] = time.time()
        
        credentials['mfa_secret'] = profiles.find_one({"_id": credentials['_id']}).get("mfa_secret", None)
        
        if credentials['mfa_secret'] == None:
            return flask.redirect(flask.url_for('MFA_register'))
        
        print(credentials)
        device_codes.replace_one({"_id": credentials['_id']}, credentials, upsert=True)
        return {"msg": code}
    
    
    elif request.method == "POST":
        req_data = json.loads(request.get_data())
        ans = verify_device_code(device_codes,code=req_data['code'], special_code=special_code,mfa_code=req_data['mfa_code'])
        if not ans:
            return {"msg": "Failed"}
        return {"msg": "Success", "config": ans }
          
    

@app.route('/authorize')
def authorize():
    # if 'credentials' in flask.session:
    #     return flask.redirect(flask.url_for('test_api_request'))
    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)

    # The URI created here must exactly match one of the authorized redirect URIs
    # for the OAuth 2.0 client, which you configured in the API Console. If this
    # value doesn't match an authorized URI, you will get a 'redirect_uri_mismatch'
    # error.
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    authorization_url, state = flow.authorization_url(
        # Enable offline access so that you can refresh an access token without
        # re-prompting the user for permission. Recommended for web server apps.
        access_type='offline',
        # Enable incremental authorization. Recommended as a best practice.
        include_granted_scopes='true')

    # Store the state so the callback can verify the auth server response.
    flask.session['state'] = state

    # print(authorization_url)
    return flask.redirect(authorization_url)

@app.route('/MFA_register', methods=['GET'])
def mfa_register():
    if 'credentials' not in flask.session:
        return flask.redirect('authorize')
    credentials = flask.session['credentials']
    
    if not mfa_exists(profiles, credentials['_id']) or request.args.get('force') == "true":
        qr_code, secret = generate_mfa()
        profiles.update_one({"_id": credentials['_id']}, {'$set': {'mfa_secret': secret}})
        return render_template('mfa_register.html', qr_code=Markup(qr_code), force=True)
    return render_template('mfa_exists.html')
    
@app.route('/MFA_verify', methods=['GET'])
def mfa_verify():
    if 'credentials' in flask.session:
        credentials = flask.session['credentials']
    else:
        credentials = json.loads(request.get_data())
        if '_id' not in credentials:
            return {"msg": "Invalid Request"}
    if not mfa_exists(profiles, credentials['_id']):
        return flask.redirect(flask.url_for('MFA_register', _external=True))    
    the_code = (credentials['code'])
    
    return {"verification": verify_mfa(profiles, credentials['_id'], the_code)}
    

@app.route('/oauth2callback')
def oauth2callback():
    print(request.method)
    # Specify the state when creating the flow in the callback so that it can
    # verified in the authorization server response.
    state = flask.session['state']

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    # Use the authorization server's response to fetch the OAuth 2.0 tokens.
    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)

    
    credentials = flow.credentials
    # Store credentials in the session.
    # ACTION ITEM: In a production app, you likely want to save these
    #              credentials in a persistent database instead.
    user_info = getUserInfo(credentials)
    
    upsert_mongo(profiles, user_info)
    
    
    flask.session['credentials'] = client_cred_dict(credentials_to_dict(credentials), user_info['_id'])
    return flask.redirect(flask.url_for('test_api_request'))


@app.route('/revoke')
def revoke():
    if 'credentials' not in flask.session:
        return ('You need to <a href="/authorize">authorize</a> before ' +
                'testing the code to revoke credentials.')

    credentials = google.oauth2.credentials.Credentials(
        **build_credentials(flask.session['credentials']))

    revoke = requests.post('https://oauth2.googleapis.com/revoke',
                           params={'token': credentials.token},
                           headers={'content-type': 'application/x-www-form-urlencoded'})

    status_code = getattr(revoke, 'status_code')
    if status_code == 200:
        return('Credentials successfully revoked.')
    else:
        return('An error occurred.')

@app.route('/clear')
def clear_credentials():
    if 'credentials' in flask.session:
        del flask.session['credentials']
    return ('Credentials have been cleared.<br><br>')



if __name__ == '__main__':
    # When running locally, disable OAuthlib's HTTPs verification.
    # ACTION ITEM for developers:
    #     When running in production *do not* leave this option enabled.
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    # Specify a hostname and port that are set as a valid redirect URI
    # for your API project in the Google API Console.
    app.run('0.0.0.0', 5000, debug=True)
