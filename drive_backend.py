from __future__ import print_function
import json
import io
from googleapiclient.http import MediaIoBaseDownload
import os.path
import os
from random import random

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaFileUpload


class DriveAPI:

    #config_filename = "pyvault_config.json" # Intermediate file to store the configuration
    config_fileid = None # the fileid for the configuration file drive


    def __init__(self, service, config_filename = None, config_fileid = None) -> None:
        
        # Initialize the service
        self.service = service
        self.config_fileid = config_fileid
        self.config_filename = config_filename
        self.config_exists()
    """
        Sync the config data to the google drive
    """
    def upload_config(self, config_data):
        
        filename = "tmp/config"+str(hash(random()))+".json"
        #filename = "config_tmp.json"

        # Store the config into temporary files
        with open(filename, "w") as f:
            f.write(json.dumps(config_data))

        media = MediaFileUpload(filename,
                                mimetype='application/json')
        
        if(self.config_fileid):
            # Config file already exists, simply replace the config data
        
            file_metadata = {
                'name': self.config_filename
            }
            file = self.service.files().update(body=file_metadata,
                                            fileId=self.config_fileid,
                                            media_body=media,
                                            fields='id').execute()
        else:
            file_metadata = {
                'name': self.config_filename,
                'parents': ['appDataFolder']
            }
            file = self.service.files().create(body=file_metadata,
                                            media_body=media,
                                            fields='id').execute()
            self.config_fileid = file['id']
        return self.config_fileid
        # if os.path.exists(filename):
        #     os.remove(filename)


    """
        Get Configuration Data
    """
    def get_config(self) -> dict:
        if(self.config_exists()):
            request = self.service.files().get_media(fileId=self.config_fileid)

            fh = io.BytesIO()
            # fh = io.FileIO("downloaded.txt", "wb")
            downloader = MediaIoBaseDownload(fh, request)
            done = False
            while done is False:
                status, done = downloader.next_chunk()
            
            fh.seek(0)
            return json.loads(fh.read().decode('UTF-8'))
        return {}



    """
        Check if Config File exists
    """
    def config_exists(self) -> bool:
        response = self.service.files().list(spaces='appDataFolder').execute()
        # print(response)
        for file in response.get('files', []):
            if(file.get('name') == self.config_filename): 
                self.config_fileid = file.get('id')
                return True

        return False

    def get_config_listing(self):
        listing = []
        response = self.service.files().list(spaces='appDataFolder').execute()
        # print(response)
        for file in response.get('files', []):
            listing.append((file.get('id'), file.get('name')))

        return listing