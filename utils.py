from time import time
from pymongo import collection
import pyotp
import qrcode
import qrcode.image.svg
import googleapiclient
factory = qrcode.image.svg.SvgPathImage

def generate_mfa(secret = pyotp.random_base32()):
    totp = pyotp.TOTP(secret)
    link = totp.provisioning_uri(name="Shivansh MFA", issuer_name='Shivansh')
    img = qrcode.make(link, image_factory=factory)
    return img.to_string().decode(), secret

def verify_mfa(collection, _id,code):
    secret = collection.find_one({'_id':_id})['mfa_secret']
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

def verify_mfa_by_secret(mfa_secret,code):
    totp = pyotp.TOTP(mfa_secret)
    return totp.verify(code)

def getUserInfo(credentials):
    oauth2_client = googleapiclient.discovery.build('oauth2','v2',credentials=credentials)
    user_info = oauth2_client.userinfo().get().execute()
    return {
        "_id": str(hash(user_info['id'])),
        'email': user_info['email']
    }
    
def upsert_mongo(collection: collection.Collection, user_info):
    if not collection.find_one({"_id": user_info['_id']}):
        collection.insert_one(user_info)
        
def add_device_code(collection: collection.Collection, id, code):
    collection.update_one({"_id": id}, {'$set': {f'device_codes.{code}': time()}})

def verify_device_code(collection: collection.Collection, code, special_code, mfa_code = "000000"):
    user_info = collection.find_one({"code": code, "special_code": special_code})
    
    if user_info:
        response_obj = {
            "_id": user_info['_id'],
            "google_auth": {
                "refresh_token": user_info["refresh_token"],
                "token_uri": user_info["token_uri"],
                "token": user_info["token_uri"],
                "scopes": user_info["scopes"],
            }
        }
        if 'mfa_secret' in user_info:
            if not verify_mfa_by_secret(user_info['mfa_secret'], mfa_code):
                return False
        if user_info :
            if time()-user_info['code_time'] < 60:
                collection.delete_one({"code": code})
                return response_obj
            else:
                collection.delete_one({"code": code})
                return False
    return False
            
            
def mfa_exists(collection, id):
    user = collection.find_one({"_id": id})
    if 'mfa_secret' not in user:
        return False
    return True
    
    