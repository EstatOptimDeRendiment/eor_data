import os.path
import base64
import json
import re
import time
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import logging
import requests
import pandas

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly','https://www.googleapis.com/auth/gmail.modify']

def readEmails():
    """Shows basic usage of the Gmail API.
    Lists the user's Gmail labels.
    """
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(               
                # your creds file here. Please create json file as here https://cloud.google.com/docs/authentication/getting-started
                'client_secret_795606663844-racsft1kbh9aov5lr4j6v4mrs6gkrto5.apps.googleusercontent.com.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    try:
        # Call the Gmail API
        service = build('gmail', 'v1', credentials=creds)
        results = service.users().messages().list(userId='me', labelIds=['INBOX'], q="is:unread").execute()
        messages = results.get('messages',[]);
        if not messages:
            print('No new messages.')
        else:
            message_count = 0
            attachmentsInfo = []
            for message in messages:
                msg = service.users().messages().get(userId='me', id=message['id']).execute()
                messageParts = msg['payload']
                for header in msg['payload']['headers']:
                    if header['name'] == 'Message-ID':
                        messageId = header['value']
                parts = messageParts['parts']
                for part in parts:
                    if (part['mimeType'] == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"):
                        attachmentsInfo.append(
                            {'messageId': messageId,
                             'attachmentId': part['body']['attachmentId'],
                             'filename': part['filename']})
            
            for aInfo in attachmentsInfo:
                attachment = service.users().messages().attachments().get(
                userId='me', messageId=aInfo['messageId'], id=aInfo['attachmentId']).execute()
                if (len(attachment['data']) > 0):
                    data64 = attachment['data']
                    message_bytes = base64.urlsafe_b64decode(data64)
                    with open(aInfo['filename'], 'wb') as f:
                        f.write(message_bytes)
                    # TODO: convert xlsx to json
                    try:
                        excel_data_df = pandas.read_excel(aInfo['filename'], sheet_name='Hoja1')
                    except Exception as error:
                        if ("Worksheet named 'Hoja1' not found" in str(error)):
                            try:
                                excel_data_df = pandas.read_excel(aInfo['filename'], sheet_name='Sheet1')
                            except Exception as error:
                                print(f'An error ocurred: {error}')
                                exit()
                        else:
                            print(f'An error occurred: {error}')
                            exit()

                    json_str = excel_data_df.to_json(orient='records')

                    print('Excel Sheet to JSON:\n', json_str)

    except Exception as error:
        print(f'An error occurred: {error}')
        exit()
                
readEmails()
