from django.http import JsonResponse, HttpResponseForbidden
from django.shortcuts import render, redirect
from django.core.mail import send_mail
from django.conf import settings
from django.contrib import messages
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_http_methods
import traceback

# Pyrebase: se usa para autenticación de usuarios (login)
from . import firebase
from .firebase import auth, db

# Firebase Admin SDK: se usa para crear usuarios (registro)
from firebase_admin import auth as auth_admin, exceptions as firebase_exceptions
from firebase_admin import db as admin_db

# Inicialización de Firebase Admin
from . import firebase_config

from django.core.signing import Signer, TimestampSigner
from django.urls import reverse
from django.utils.http import urlencode
import base64
from django.core.signing import BadSignature, SignatureExpired
from functools import wraps
from django.http import Http404
import json
from urllib.parse import urlencode, quote_plus
import datetime
from collections import defaultdict
from django.contrib.auth import logout

#importaciones para generar pdf
from io import BytesIO
from django.http import FileResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader
import qrcode
from PIL import Image as PILImage

signer = TimestampSigner()


# Vista para el registro de usuarios
def registro(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        username = request.POST['username']

        # Combinar y firmar datos
        data = f"{email}|{password}|{username}"
        signed_data = signer.sign(data)
        token = base64.urlsafe_b64encode(signed_data.encode()).decode()

        # Crear enlace de verificación
        link = request.build_absolute_uri(
            reverse('verificar_email') + '?' + urlencode({'token': token})
        )

        # Enviar correo
        send_mail(
            'Verifica tu correo',
            f'Hola {username}, haz clic para verificar tu correo y activar tu cuenta:\n\n{link}',
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )
        messages.success(request, 'Revisa tu correo para verificar tu cuenta.')

        return render(request, 'registro.html', {

            'mensaje': 'Revisa tu correo para verificar tu cuenta.'
        })

    return render(request, 'registro.html')



#Verificacion desde el email
@csrf_exempt
def verificar_email(request):
    if request.method != 'GET':
        return JsonResponse({'success': False, 'error': 'Método no permitido'}, status=405)

    token = request.GET.get('token')
    if not token:
        return JsonResponse({'success': False, 'error': 'Token faltante'}, status=400)

    try:
        # Decodificar y verificar token
        signed_data = base64.urlsafe_b64decode(token.encode()).decode()
        raw_data = signer.unsign(signed_data, max_age=3600)  # Expira en 1 hora

        email, password, username = raw_data.split('|')

        # Crear usuario en Firebase
        user = auth_admin.create_user(
            email=email,
            password=password,
            display_name=username
        )

        # Guardar en Realtime Database
        # Guardar en Realtime Database usando el UID como clave
        admin_db.reference('logins').child(user.uid).set({
            'uid': user.uid,
            'nombre': username,
            'email': email,
            'rol': 'usuario',
            'fecha_login': datetime.datetime.now().isoformat()
        })
        # Mensaje de éxito
        messages.success(request, '¡Cuenta activada! Ya puedes iniciar sesión.')
        return JsonResponse({'success': True, 'message': 'Cuenta activada. Ahora puedes iniciar sesión.'})

    except SignatureExpired:
        return JsonResponse({'success': False, 'error': 'El enlace ha expirado.'}, status=410)

    except BadSignature:
        return JsonResponse({'success': False, 'error': 'Enlace inválido.'}, status=400)

    except auth_admin.EmailAlreadyExistsError:
        return JsonResponse({'success': False, 'error': 'El correo ya ha sido registrado previamente.'}, status=409)

    except Exception as e:
        return JsonResponse({'success': False, 'error': f'Error al activar cuenta: {e}'}, status=500)




# Vista para el login de usuarios
def login_view(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']

        try:
            # Intentar autenticar al usuario con email y password
            user = auth.sign_in_with_email_and_password(email, password)

            # Guardar el UID y el ID Token en la sesión de Django
            request.session['firebase_uid'] = user['localId']
            request.session['firebase_id_token'] = user['idToken']

            # Imprimir el UID para debugging (opcional)
            print(f"Sesión configurada para el usuario con UID: {user['localId']}")

            # Redirigir al usuario a la página de inicio
            return redirect('inicio')

        except Exception as e:
            print(f"Error de autenticación: {e}")
            #return render(request, 'login.html', {'error': 'Credenciales incorrectas.'})
            messages.error(request, 'Correo o contraseña incorrectos.')

    return render(request, 'login.html')


#Metodo de inicio
def inicio(request):
    if 'firebase_uid' in request.session and 'firebase_id_token' in request.session:
        id_token = request.session['firebase_id_token']
        try:
            user_info = auth.get_account_info(id_token)
            if 'users' in user_info and len(user_info['users']) > 0:
                user_data = user_info['users'][0]
                user_name = user_data.get('displayName', 'Usuario')
                user_email = user_data.get('email', '')

                # Obtener rol desde Realtime Database
                rol = ''
                try:
                    logins_ref = admin_db.reference('logins')
                    logins = logins_ref.get()
                    if logins:
                        for key, login in logins.items():
                            if login.get('email', '').lower() == user_email.lower():
                                rol = login.get('rol', '').lower()
                                break
                except Exception as e:
                    print(f"Error al obtener rol en Realtime DB: {e}")

                return render(request, 'inicio.html', {
                    'user_name': user_name,
                    'rol': rol
                })
        except Exception as e:
            print(f"Error al obtener la información del usuario: {e}")

    return render(request, 'inicio.html')


def logout_view(request):
    # Eliminar el UID de Firebase de la sesión
    if 'firebase_uid' in request.session:
        del request.session['firebase_uid']

    # Redirigir al login después de cerrar sesión
    return redirect('inicio')






def enviar_correo_firebase(email):
    try:
        link = auth.generate_password_reset_link(email)
        # Aquí puedes enviar el link por correo usando Django o cualquier servicio
        print(f"Enlace de recuperación: {link}")
    except firebase_exceptions.NotFoundError:
        print("El usuario no existe en Firebase.")






def password_reset_firebase(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            # Generar enlace de Firebase
            link = auth_admin.generate_password_reset_link(email)

            # Enviar el correo
            send_mail(
                subject='Restablece tu contraseña',
                message=f'Haz clic en este enlace para restablecer tu contraseña:\n\n{link}',
                from_email=settings.EMAIL_HOST_USER, 
                recipient_list=[email],
                fail_silently=False,
            )

            messages.success(request, 'Se ha enviado un enlace de recuperación si el correo está registrado.')
            return redirect('password_reset')

        except firebase_exceptions.NotFoundError:
            messages.error(request, 'El correo no está registrado en Firebase.')
        except Exception as e:
            traceback.print_exc()
            messages.error(request, 'Hubo un problema al enviar el correo. Intenta más tarde.')

    return render(request, 'password_reset.html')








#verificar si el usuario esta autenticado 
def firebase_login_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if 'firebase_uid' not in request.session:
            return redirect('login')
        return view_func(request, *args, **kwargs)
    return _wrapped_view





def obtener_propietario_tablero(tablero_id):
    todos_los_usuarios = db.child("tableros").get()
    for usuario in todos_los_usuarios.each():
        uid = usuario.key()
        tableros = usuario.val()
        if tablero_id in tableros:
            return uid
    return None



#Crear un tablero
#Crear un tablero
@firebase_login_required
def crear_tablero(request):
    if request.method == 'POST':
        nombre = request.POST.get('nombre')
        uid = request.session['firebase_uid']

        tablero_data = {
            'nombre': nombre,
            'propietario': uid 
        }

        nuevo_tablero = db.child("tableros").child(uid).push(tablero_data)
        return redirect('ver_tablero', tablero_id=nuevo_tablero['name'])

    return render(request, 'crear_tablero.html')


#Listar los tableros
@firebase_login_required
def listar_tableros(request):
    uid = request.session['firebase_uid']

    if request.method == 'POST' and request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        tablero_id = request.POST.get('tablero_id')
        if tablero_id:
            try:
                db.child("tableros").child(uid).child(tablero_id).remove()
                return JsonResponse({'success': True})
            except Exception as e:
                return JsonResponse({'success': False, 'error': str(e)})
        return JsonResponse({'success': False, 'error': 'ID no válido'})

    tableros = db.child("tableros").child(uid).get().val() or {}
    return render(request, 'listar_tableros.html', {'tableros': tableros})




# Ver tablero y agregar lista
@firebase_login_required
def ver_tablero(request, tablero_id):
    uid_actual = request.session['firebase_uid']
    uid_propietario = uid_actual  # Por defecto asumimos que el usuario es el propietario

    # Intentar primero bajo el UID del usuario actual
    tablero_ref = db.child("tableros").child(uid_actual).child(tablero_id)
    tablero = tablero_ref.get().val()

    # Si no se encuentra el tablero en su propio UID, buscar en todos los usuarios
    if not tablero:
        tableros_todos = db.child("tableros").get().val() or {}
        for uid_busqueda, tableros_usuario in tableros_todos.items():
            if tablero_id in tableros_usuario:
                tablero = tableros_usuario[tablero_id]
                uid_propietario = uid_busqueda
                break

    # Si el tablero no fue encontrado
    if not tablero:
        return JsonResponse({"error": "Tablero no encontrado."}, status=404)

    # Verificar si el usuario actual es el propietario o un invitado aprobado
    es_propietario = uid_actual == uid_propietario
    invitados = tablero.get("invitados", {})
    es_invitado_aprobado = invitados.get(uid_actual) is True

    if not es_propietario and not es_invitado_aprobado:
        return HttpResponseForbidden("No puedes ingresar a este tablero.")

    listas = tablero.get("listas", {})

    if request.method == 'POST':
        nombre_lista = request.POST.get('nombre')
        if nombre_lista:
            nueva_lista = {"nombre": nombre_lista}
            db.child("tableros").child(uid_propietario).child(tablero_id).child("listas").push(nueva_lista)
            return redirect('ver_tablero', tablero_id=tablero_id)

    return render(request, 'tablero.html', {
        'tablero_id': tablero_id,
        'tablero': tablero,
        'listas': listas
    })


# Agregar tarjeta
@firebase_login_required
def agregar_tarjeta(request, tablero_id, lista_id):
    if request.method == 'POST':
        try:
            uid_actual = request.session.get('firebase_uid')
            propietario_uid = obtener_propietario_tablero(tablero_id)

            if not propietario_uid:
                raise Exception("Tablero no encontrado.")

            # Verificar si es propietario o invitado
            es_propietario = uid_actual == propietario_uid
            es_invitado = db.child("tableros").child(propietario_uid).child(tablero_id).child("invitados").child(uid_actual).get().val()

            if not es_propietario and not es_invitado:
                return HttpResponseForbidden("No tienes permiso para agregar tarjetas.")

            # Procesar el formulario
            titulo = request.POST.get('titulo')
            descripcion = request.POST.get('descripcion')
            orden = request.POST.get('orden', 0)
            color = request.POST.get('color', '#ffffff')
            fecha_limite = request.POST.get('fecha_limite')

            tarjeta = {
                'titulo': titulo,
                'descripcion': descripcion,
                'orden': orden,
                'color': color,
                'fecha_limite': fecha_limite,
                'completada': False
            }

            db.child("tableros").child(propietario_uid).child(tablero_id).child("listas").child(lista_id).child("tarjetas").push(tarjeta)

            return redirect('ver_tablero', tablero_id=tablero_id)

        except Exception as e:
            print(f"Error al agregar tarjeta: {e}")
            return render(request, 'agregar_tarjeta.html', {
                'tablero_id': tablero_id,
                'lista_id': lista_id,
                'error': str(e)
            })

    return render(request, 'agregar_tarjeta.html', {
        'tablero_id': tablero_id,
        'lista_id': lista_id
    })



#eliminar lista
@csrf_exempt
@firebase_login_required
def eliminar_lista(request, tablero_id, lista_id):
    if request.method == 'POST':
        try:
            uid_actual = request.session.get('firebase_uid')
            propietario_uid = obtener_propietario_tablero(tablero_id)

            if not propietario_uid:
                raise Exception("Tablero no encontrado.")

            es_propietario = uid_actual == propietario_uid
            es_invitado = db.child("tableros").child(propietario_uid).child(tablero_id).child("invitados").child(uid_actual).get().val()

            if not es_propietario and not es_invitado:
                return HttpResponseForbidden("No tienes permiso para eliminar esta lista.")

            db.child("tableros").child(propietario_uid).child(tablero_id).child("listas").child(lista_id).remove()
            print("Lista eliminada correctamente.")

        except Exception as e:
            print(f"Error al eliminar lista: {e}")

        return redirect('ver_tablero', tablero_id=tablero_id)

    return JsonResponse({'success': False, 'error': 'Método no permitido'})



#Eliminar tarjeta
@csrf_exempt
@firebase_login_required
def eliminar_tarjeta(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            tarjeta_id = data['tarjeta_id']
            lista_id = data['lista_id']
            tablero_id = data['tablero_id']
            uid_actual = request.session.get('firebase_uid')

            propietario_uid = obtener_propietario_tablero(tablero_id)
            if not propietario_uid:
                raise Exception("Tablero no encontrado.")

            es_propietario = uid_actual == propietario_uid
            es_invitado = db.child("tableros").child(propietario_uid).child(tablero_id).child("invitados").child(uid_actual).get().val()

            if not es_propietario and not es_invitado:
                return JsonResponse({'success': False, 'error': 'No tienes permiso para eliminar esta tarjeta.'})

            tarjeta_path = f"tableros/{propietario_uid}/{tablero_id}/listas/{lista_id}/tarjetas/{tarjeta_id}"
            db.child(tarjeta_path).remove()

            print("Tarjeta eliminada correctamente.")
            return JsonResponse({'success': True})

        except Exception as e:
            print(f"Error al eliminar tarjeta: {e}")
            return JsonResponse({'success': False, 'error': str(e)})

    return JsonResponse({'success': False, 'error': 'Método no permitido'})



#Editar las tarjetas
@csrf_exempt
@firebase_login_required
def editar_tarjeta(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            tarjeta_id = data['tarjeta_id']
            lista_id = data['lista_id']
            tablero_id = data['tablero_id']
            uid_actual = request.session.get('firebase_uid')

            # Obtener el UID del propietario del tablero
            propietario_uid = obtener_propietario_tablero(tablero_id)
            if not propietario_uid:
                return JsonResponse({'success': False, 'error': 'Tablero no encontrado'}, status=404)

            # Verificar si el usuario actual es propietario o invitado
            es_propietario = uid_actual == propietario_uid
            es_invitado = db.child("tableros").child(propietario_uid).child(tablero_id).child("invitados").child(uid_actual).get().val()

            if not es_propietario and not es_invitado:
                return JsonResponse({'success': False, 'error': 'No tienes permiso para editar esta tarjeta'}, status=403)

            print(f"UID actual: {uid_actual}, Propietario UID: {propietario_uid}, Tablero ID: {tablero_id}, Lista ID: {lista_id}, Tarjeta ID: {tarjeta_id}")

            # Ruta con UID del propietario
            tarjeta_path = f"tableros/{propietario_uid}/{tablero_id}/listas/{lista_id}/tarjetas/{tarjeta_id}"

            # Obtener datos actuales
            tarjeta_actual = db.child(tarjeta_path).get().val()
            if tarjeta_actual is None:
                return JsonResponse({'success': False, 'error': 'Tarjeta no encontrada'}, status=404)

            completada = data.get('completada', False)

            db.child(tarjeta_path).update({
                'titulo': data['titulo'],
                'descripcion': data['descripcion'],
                'color': data['color'],
                'fecha_limite': data['fecha_limite'],
                'completada': completada
            })

            print("Tarjeta actualizada correctamente.")
            return JsonResponse({'success': True})

        except Exception as e:
            print(f"Error al actualizar tarjeta: {e}")
            return JsonResponse({'success': False, 'error': str(e)})

    return JsonResponse({'success': False, 'error': 'Método no permitido'})




#agregar calendario 
@firebase_login_required
def ver_calendario(request, tablero_id):
    firebase_uid = request.session.get('firebase_uid')

    # Ruta a las listas dentro del tablero del usuario
    ruta = f'tableros/{firebase_uid}/{tablero_id}/listas'

    listas_snapshot = db.child(ruta).get().val()  # igual que editar_tarjeta

    eventos = []

    if listas_snapshot:
        for lista_id, lista_data in listas_snapshot.items():
            tarjetas = lista_data.get('tarjetas', {})
            for tarjeta_id, tarjeta in tarjetas.items():
                fecha_limite = tarjeta.get('fecha_limite')
                if fecha_limite:
                    eventos.append({
                        'title': tarjeta.get('descripcion', 'Sin título'),
                        'start': fecha_limite,
                        'color': tarjeta.get('color', 'gray'),
                    })

    eventos_json = json.dumps(eventos)

    return render(request, 'calendario.html', {
        'firebase_uid': firebase_uid,
        'tablero_id': tablero_id,
        'eventos_json': eventos_json,
    })




# Graficas de usuarios
# Graficas de usuarios
def metricas_usuarios(request):
    from collections import defaultdict, Counter
    from datetime import datetime, date
    from firebase_admin import auth as auth_admin
    import datetime as dt
    import pytz
    from dateutil import parser
    from django.contrib import messages
    from django.shortcuts import redirect, render
    from django.http import HttpResponseForbidden

    tz_colombia = pytz.timezone('America/Bogota')

    # Validar sesión Firebase
    if 'firebase_uid' not in request.session or 'firebase_id_token' not in request.session:
        messages.error(request, 'Debes iniciar sesión para ver las métricas.')
        return redirect('login')

    firebase_uid = request.session.get('firebase_uid')

    # Verificar rol (administrador o visualizador)
    rol_usuario = admin_db.reference(f'logins/{firebase_uid}/rol').get()
    if rol_usuario not in ['administrador', 'visualizador']:
        return HttpResponseForbidden("Acceso denegado. Esta funcionalidad es solo para usuarios administradores o visualizadores.")

    id_token = request.session['firebase_id_token']

    try:
        user_info = auth.get_account_info(id_token)
        if 'users' not in user_info or len(user_info['users']) == 0:
            messages.error(request, 'Sesión inválida. Por favor inicia sesión de nuevo.')
            return redirect('login')
    except Exception as e:
        messages.error(request, 'Error con la sesión: ' + str(e))
        return redirect('login')

    # Obtener UID válidos de Firebase Auth
    uids_validos = set()
    lista_usuarios = []
    usuarios_creados_por_dia = Counter()

    try:
        page = auth_admin.list_users()
        while page:
            for user in page.users:
                uids_validos.add(user.uid)
                fecha_creacion = user.user_metadata.creation_timestamp / 1000
                fecha = dt.datetime.fromtimestamp(fecha_creacion, tz_colombia).date()
                usuarios_creados_por_dia[str(fecha)] += 1
                lista_usuarios.append({
                    'uid': user.uid,
                    'email': user.email,
                    'display_name': user.display_name,
                    'fecha_creacion': dt.datetime.fromtimestamp(fecha_creacion, tz_colombia).strftime('%Y-%m-%d %H:%M:%S'),
                })
            page = page.get_next_page()
    except Exception as e:
        print("Error al listar usuarios:", e)

    registros = db.child('logins').get()
    usuarios_por_dia = defaultdict(int)
    usuarios_activos = set()
    ultimo_login = None
    ultimo_usuario = None

    if registros.each():
        for registro in registros.each():
            data = registro.val()
            uid = data.get('uid')

            if uid not in uids_validos:
                try:
                    db.child("logins").child(registro.key()).remove()
                except Exception as e:
                    print(f"Error al eliminar el registro de login con UID {uid}: {e}")
                continue

            fecha_login = data.get('fecha_login')
            nombre = data.get('nombre')

            if not fecha_login or not nombre:
                continue

            try:
                fecha_dt = parser.isoparse(fecha_login)
                if fecha_dt.tzinfo is None:
                    fecha_dt = fecha_dt.replace(tzinfo=pytz.UTC)
                fecha_dt = fecha_dt.astimezone(tz_colombia)
            except Exception as e:
                print("Error al parsear fecha_login:", fecha_login, str(e))
                continue

            fecha = fecha_dt.date()
            usuarios_por_dia[fecha] += 1
            usuarios_activos.add(uid)

            if not ultimo_login or (fecha_dt and fecha_dt > ultimo_login):
                ultimo_login = fecha_dt
                ultimo_usuario = nombre

    usuarios_por_dia_str = {str(k): v for k, v in usuarios_por_dia.items()}
    fechas = list(usuarios_por_dia_str.keys())
    valores = list(usuarios_por_dia_str.values())

    context = {
        'usuarios_por_dia': usuarios_por_dia_str,
        'fechas': fechas,
        'valores': valores,
        'usuarios_activos': len(usuarios_activos),
        'ultimo_usuario': ultimo_usuario,
        'ultimo_login': ultimo_login.strftime('%Y-%m-%d %H:%M:%S') if ultimo_login else None,
        'user_name': user_info['users'][0].get('displayName', 'Usuario'),

        'lista_usuarios': lista_usuarios,
        'usuarios_creados_por_dia': dict(usuarios_creados_por_dia),
    }

    return render(request, 'metricas.html', context)




# Vista: Compartir tablero
@firebase_login_required
def compartir_tablero(request, tablero_id):
    uid = request.session['firebase_uid']
    tablero_ref = db.child("tableros").child(uid).child(tablero_id)
    tablero = tablero_ref.get().val() or {}

    if request.method == 'POST':
        email_destino = request.POST.get('email')
        if email_destino:
            # Buscar el uid del usuario que tenga ese email en la rama correcta (ejemplo: logins)
            usuarios = db.child("logins").get().val() or {}
            uid_invitado = None
            for u_id, info in usuarios.items():
                if info.get('email') == email_destino:
                    uid_invitado = u_id
                    break

            if not uid_invitado:
                mensaje = f"No se encontró ningún usuario con el correo {email_destino}."
                return render(request, 'tablero.html', {
                    'tablero_id': tablero_id,
                    'tablero': tablero,
                    'mensaje_compartir': mensaje,
                    'mostrar_form_compartir': True,
                })

            # Agregar el uid del invitado con estado False (pendiente de aprobación)
            db.child("tableros").child(uid).child(tablero_id).child("invitados").update({
                uid_invitado: False
            })

            # Construir la URL de solicitud
            url_solicitud = request.build_absolute_uri(
                reverse('solicitar_acceso_tablero', kwargs={
                    'tablero_id': tablero_id,
                    'email': email_destino
                })
            )

            # Enviar correo
            send_mail(
                subject=f"Invitación para ver el tablero: {tablero.get('nombre', 'Tablero')}",
                message=(
                    f"Hola, te han invitado a ver el tablero \"{tablero.get('nombre', 'Tablero')}\".\n\n"
                    f"Para solicitar acceso, haz clic en el siguiente enlace:\n{url_solicitud}"
                ),
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email_destino],
                fail_silently=False,
            )

            mensaje = f'Se ha enviado la invitación a {email_destino}.'
            return render(request, 'solicitud_enviada.html', {
                'tablero_id': tablero_id,
                'tablero': tablero,
                'mensaje_compartir': mensaje,
                'mostrar_form_compartir': True,
            })

    return render(request, 'tablero.html', {
        'tablero_id': tablero_id,
        'tablero': tablero,
    })


# Vista: Solicitar acceso y aprobar automáticamente
@firebase_login_required
def solicitar_acceso_tablero(request, tablero_id, email):
    uid_actual = request.session['firebase_uid']
    todos_tableros = db.child("tableros").get().val() or {}

    for uid_duenio, tableros_usuario in todos_tableros.items():
        if tablero_id in tableros_usuario:
            invitados = tableros_usuario[tablero_id].get('invitados', {})

            if uid_actual in invitados:
                db.child("tableros").child(uid_duenio).child(tablero_id).child("invitados").update({
                    uid_actual: True
                })
                return redirect('ver_tablero', tablero_id=tablero_id)
            else:
                return HttpResponse("<h2>No tienes una invitación para este tablero.</h2>")

    return HttpResponse("Tablero no encontrado.")



@firebase_login_required
def perfil(request):
    uid = request.session.get('firebase_uid')
    user_data = db.child("logins").child(uid).get().val()
    return render(request, 'perfil.html', {'user_data': user_data})


@csrf_exempt
@firebase_login_required
def eliminar_cuenta(request):
    if request.method == 'GET':
        return redirect('perfil')

    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Método no permitido'}, status=405)

    uid = request.session.get('firebase_uid')
    if not uid:
        return JsonResponse({'success': False, 'error': 'Usuario no autenticado'}, status=401)

    try:
        # Eliminar usuario de Firebase Authentication
        auth_admin.delete_user(uid)

        # Eliminar registros de logins
        logins_ref = admin_db.reference('logins')
        all_logins = logins_ref.get()
        if all_logins:
            for key, value in all_logins.items():
                if value.get('uid') == uid:
                    logins_ref.child(key).delete()

        # Eliminar tablero del usuario (suponiendo que el UID es la clave o parte de ella)
        tablero_ref = admin_db.reference('tableros')
        tableros = tablero_ref.get()
        if tableros:
            for key, value in tableros.items():
                if value.get('uid') == uid or key == uid:
                    tablero_ref.child(key).delete()

        logout(request)
        return redirect('perfil')

    except firebase_exceptions.FirebaseError as e:
        return JsonResponse({'success': False, 'error': f'Error de Firebase: {str(e)}'}, status=500)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)




#Graficos de tareas
@firebase_login_required
def ver_resumen(request, tablero_id):
    firebase_uid = request.session.get('firebase_uid')

    # Obtener el rol del usuario desde admin_db
    rol_usuario = admin_db.reference(f'logins/{firebase_uid}/rol').get()

    # Verificar si es administrador o premium
    if rol_usuario not in ['administrador', 'premium']:
        from django.http import HttpResponseForbidden
        return HttpResponseForbidden("Acceso denegado. Esta funcionalidad es solo para usuarios premium o administradores.")

    # Continuar con la lógica habitual para obtener datos del tablero
    ruta_listas = f'tableros/{firebase_uid}/{tablero_id}/listas'
    listas_snapshot = db.child(ruta_listas).get().val()

    ruta_tablero = f'tableros/{firebase_uid}/{tablero_id}'
    tablero_data = db.child(ruta_tablero).get().val()
    nombre_tablero = tablero_data.get('nombre', 'Sin nombre') if tablero_data else 'Sin nombre'

    total_tareas = 0
    tareas_completadas = 0
    tareas_pendientes = 0
    tareas_vencidas = 0

    hoy = datetime.datetime.now().date()

    if listas_snapshot:
        for lista_id, lista_data in listas_snapshot.items():
            tarjetas = lista_data.get('tarjetas', {})
            for tarjeta_id, tarjeta in tarjetas.items():
                total_tareas += 1
                completada = tarjeta.get('completada', False)
                fecha_limite_str = tarjeta.get('fecha_limite')
                fecha_limite = None

                if fecha_limite_str:
                    try:
                        fecha_limite = datetime.datetime.strptime(fecha_limite_str, "%Y-%m-%d").date()
                    except ValueError:
                        pass

                if completada:
                    tareas_completadas += 1
                elif fecha_limite and fecha_limite < hoy:
                    tareas_vencidas += 1
                else:
                    tareas_pendientes += 1

    return render(request, 'resumen.html', {
        'firebase_uid': firebase_uid,
        'tablero_id': tablero_id,
        'nombre_tablero': nombre_tablero,
        'total_tareas': total_tareas,
        'tareas_completadas': tareas_completadas,
        'tareas_pendientes': tareas_pendientes,
        'tareas_vencidas': tareas_vencidas,
    })





#Metodo para generar pdf del tablero 
@csrf_exempt
@firebase_login_required
@require_POST
def descargar_tablero_pdf(request, tablero_id):
    try:
        uid = request.session['firebase_uid']
        tablero = db.child("tableros").child(uid).child(tablero_id).get().val()
        if not tablero:
            return JsonResponse({"error": "No se encontró el tablero."}, status=404)

        nombre_tablero = tablero.get("nombre", "Tablero sin título")

        imagen = request.FILES.get("imagen_tablero")
        if not imagen:
            return JsonResponse({"error": "No se envió imagen del tablero."}, status=400)

        imagen.seek(0)
        img_pil = PILImage.open(imagen)
        img_width, img_height = img_pil.size
        aspect_ratio = img_height / img_width

        buffer = BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        page_width, page_height = letter

        # Margen
        margen = 36
        max_width = page_width - 2 * margen
        max_height = page_height - 2 * margen - 40  # espacio para título

        # Agregar título centrado arriba
        p.setFont("Helvetica-Bold", 18)
        p.drawCentredString(page_width / 2, page_height - margen, nombre_tablero)

        # Ajustar tamaño imagen
        if max_width * aspect_ratio <= max_height:
            new_width = max_width
            new_height = max_width * aspect_ratio
        else:
            new_height = max_height
            new_width = max_height / aspect_ratio

        x = margen + (max_width - new_width) / 2
        y = page_height - margen - 30 - new_height  # espacio debajo del título

        imagen.seek(0)
        image = ImageReader(imagen)
        p.drawImage(image, x, y, width=new_width, height=new_height)

        # Página nueva con QR
        p.showPage()
        p.setFont("Helvetica-Bold", 14)
        p.drawString(margen, page_height - margen - 20, "Escanea este código para ver el tablero en línea:")
        
        tablero_url = request.build_absolute_uri(f"/tablero/{tablero_id}/")
        qr = qrcode.make(tablero_url)
        qr_io = BytesIO()
        qr.save(qr_io, format='PNG')
        qr_io.seek(0)
        qr_image = ImageReader(qr_io)

        qr_size = 200
        p.drawImage(qr_image, margen, page_height - margen - 50 - qr_size, width=qr_size, height=qr_size)

        p.save()
        buffer.seek(0)
        return FileResponse(buffer, as_attachment=True, filename='tablero.pdf')

    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({"error": "Error interno al generar el PDF.", "detalle": str(e)}, status=500)
    
    
    
    
    
    
#-------------------------------------------------------------------------------------------------------------
#Dashboard

@firebase_login_required
def verificar_administrador(request):
    try:
        id_token = request.session.get('firebase_id_token')
        if id_token:
            info = auth_admin.verify_id_token(id_token)
            user_email = info.get('email')

            # Verifica en la base de datos si tiene rol "administrador"
            usuarios = admin_db.reference('logins').get() or {}
            for usuario in usuarios.values():
                if usuario.get('email') == user_email and usuario.get('rol') == 'administrador':
                    return True
    except Exception:
        pass
    return False

@firebase_login_required
def dashboard(request):
    if 'firebase_id_token' not in request.session:
        return redirect('login_view')

    usuarios = admin_db.reference('logins').get() or {}
    return render(request, 'dashboard.html', {'usuarios': usuarios})

@firebase_login_required
def crear_usuario(request):
    if 'firebase_id_token' not in request.session:
        return redirect('login_view')

    if not verificar_administrador(request):
        messages.error(request, 'No tienes permisos para esta acción.')
        return redirect('dashboard')  # Ya no va al login

    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        nombre = request.POST.get('nombre')
        rol = request.POST.get('rol')  # Puede ser administrador o visualizador

        try:
            user = auth_admin.create_user(email=email, password=password, display_name=nombre)
            admin_db.reference('logins').child(user.uid).set({    
                'uid': user.uid,
                'nombre': nombre,
                'email': email,
                'rol': rol,
                'fecha_login': datetime.datetime.now().isoformat()
            })
            messages.success(request, f'Usuario {email} creado correctamente.')
            return redirect('dashboard')
        except Exception as e:
            messages.error(request, f'Error al crear usuario: {e}')

    return render(request, 'crear_usuario.html')

@firebase_login_required
def editar_usuario(request, uid):
    if 'firebase_id_token' not in request.session:
        return redirect('login_view')

    if not verificar_administrador(request):
        messages.error(request, 'No tienes permisos para esta acción.')
        return redirect('dashboard')  # Redirige al dashboard, no al login

    usuarios = admin_db.reference('logins').get() or {}
    usuario_key = None
    usuario_data = None
    for key, val in usuarios.items():
        if val.get('uid') == uid:
            usuario_key = key
            usuario_data = val
            break

    if not usuario_data:
        messages.error(request, 'Usuario no encontrado.')
        return redirect('dashboard')

    if request.method == 'POST':
        rol = request.POST.get('rol')  # administrador o visualizador
        try:
            admin_db.reference(f'logins/{usuario_key}').update({'rol': rol})
            messages.success(request, 'Rol actualizado correctamente.')
            return redirect('dashboard')
        except Exception as e:
            messages.error(request, f'Error al actualizar rol: {e}')

    return render(request, 'editar_usuario.html', {'usuario': usuario_data})

@firebase_login_required
def eliminar_usuario(request, uid):
    if 'firebase_id_token' not in request.session:
        return redirect('login_view')

    if not verificar_administrador(request):
        messages.error(request, 'No tienes permisos para esta acción.')
        return redirect('dashboard')  # Redirige al dashboard, no al login

    try:
        auth_admin.delete_user(uid)
        usuarios = admin_db.reference('logins').get() or {}
        for key, val in usuarios.items():
            if val.get('uid') == uid:
                admin_db.reference(f'logins/{key}').delete()
                break

        messages.success(request, 'Usuario eliminado correctamente.')
    except Exception as e:
        messages.error(request, f'Error al eliminar usuario: {e}')

    return redirect('dashboard')






#--------------------------------------------------------------------------------------------------
#Metodos para que el usuario se convierta en premium
@firebase_login_required
def simular_pago_formulario(request):
    if 'firebase_id_token' not in request.session:
        return redirect('login_view')

    # Mostrar formulario
    return render(request, 'simular_pago.html', {
        'user_name': request.session.get('user_name', 'Usuario')
    })
    

@firebase_login_required
def procesar_pago_simulado(request):
    if request.method != 'POST':
        return redirect('simular_pago_formulario')

    try:
        id_token = request.session['firebase_id_token']
        info = auth_admin.verify_id_token(id_token)
        user_uid = info.get('uid')

        user_ref = admin_db.reference(f'logins/{user_uid}')
        user_data = user_ref.get()
        rol_actual = user_data.get('rol') if user_data else None

        if rol_actual == 'premium':
            messages.info(request, 'Ya eres usuario premium.')
            # Renderiza el formulario mostrando mensajes en la misma URL
            return render(request, 'simular_pago.html', {'user_name': info.get('name', 'Usuario')})

        monto_minimo = 9.99
        tarjeta = request.POST.get('tarjeta')
        fecha_exp = request.POST.get('fecha_exp')
        cvv = request.POST.get('cvv')
        monto = request.POST.get('monto')

        if not tarjeta or not fecha_exp or not cvv or not monto:
            messages.error(request, 'Por favor completa todos los campos.')
            return render(request, 'simular_pago.html', {'user_name': info.get('name', 'Usuario')})

        try:
            monto = float(monto)
        except ValueError:
            messages.error(request, 'Monto inválido.')
            return render(request, 'simular_pago.html', {'user_name': info.get('name', 'Usuario')})

        if monto < monto_minimo:
            messages.error(request, f'El monto mínimo para pagar es ${monto_minimo:.2f}.')
            return render(request, 'simular_pago.html', {'user_name': info.get('name', 'Usuario')})

        pago_exitoso = True

        if pago_exitoso:
            user_ref.update({'rol': 'premium'})
            messages.success(request, '¡Pago exitoso! Ahora eres un usuario premium.')
            return render(request, 'simular_pago.html', {'user_name': info.get('name', 'Usuario')})
        else:
            messages.error(request, 'El pago fue rechazado. Intenta de nuevo.')
            return render(request, 'simular_pago.html', {'user_name': info.get('name', 'Usuario')})

    except Exception as e:
        messages.error(request, f'Error durante la simulación de pago: {e}')
        return render(request, 'simular_pago.html', {'user_name': 'Usuario'})








































