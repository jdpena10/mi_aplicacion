import firebase_admin
from firebase_admin import credentials, auth

# Configura Firebase Admin SDK con tu archivo de credenciales
cred = credentials.Certificate('/var/www/gestion_de_tareas_Django/serviceAccountKey.json')
#firebase_admin.initialize_app(cred)
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://django-68990-default-rtdb.firebaseio.com'
})
