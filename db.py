import os
import firebase_admin
from firebase_admin import credentials, firestore

# GCP Firestore variables
project_id = ""
# set environment variable 
os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "credentials json file path"

cred = credentials.ApplicationDefault()
firebase_admin.initialize_app(cred, {
    "projectID": project_id,
})

db = firestore.client()

def user_query():
    users = db.collection(u"users").stream()
    return users