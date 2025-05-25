import pyrebase

firebaseConfig = {
    "apiKey": "AIzaSyCfqooz6C97f00qRyYNHBlYvdEUs7UGYF4",
    "authDomain": "django-68990.firebaseapp.com",
    "databaseURL": "https://django-68990-default-rtdb.firebaseio.com/",
    "projectId": "django-68990",
    "storageBucket": "django-68990.firebasestorage.app",
    "messagingSenderId": "426408902785",
    "appId": "1:426408902785:web:f6cec8032f89bd7d020d80",
    "measurementId": "G-VHLW7B8SGY"
}

firebase = pyrebase.initialize_app(firebaseConfig)
auth = firebase.auth()
db = firebase.database()
