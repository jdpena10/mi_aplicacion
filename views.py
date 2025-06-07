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
from datetime import date
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
import pytz
import math
import base64

signer = TimestampSigner()


# Vista para el registro de usuarios
def registro(request):

    if request.method == 'POST':
        # Obtener datos del formulario
        email = request.POST['email']
        password = request.POST['password']
        username = request.POST['username']

        # Combinar datos sensibles y firmarlos digitalmente
        data = f"{email}|{password}|{username}"
        signed_data = signer.sign(data)

        # Codificar el token firmado en base64 para incluirlo en la URL
        token = base64.urlsafe_b64encode(signed_data.encode()).decode()

        # Crear enlace absoluto para la verificación de correo
        link = request.build_absolute_uri(
            reverse('verificar_email') + '?' + urlencode({'token': token})
        )

        # Enviar correo electrónico con el enlace de verificación
        send_mail(
            'Verifica tu correo',
            f'Hola {username}, haz clic para verificar tu correo y activar tu cuenta:\n\n{link}',
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )

        # Mostrar mensaje de confirmación en la interfaz
        messages.success(request, 'Revisa tu correo para verificar tu cuenta.')

        # Renderizar plantilla de registro con mensaje
        return render(request, 'registro.html', {
            'mensaje': 'Revisa tu correo para verificar tu cuenta.'
        })

    # Si la solicitud no es POST, mostrar simplemente la plantilla
    return render(request, 'registro.html')


# ========================
# Vista: verificar_email
# ========================

@csrf_exempt
def verificar_email(request):
    if request.method != 'GET':
        return JsonResponse({'success': False, 'error': 'Método no permitido'}, status=405)

    token = request.GET.get('token')
    if not token:
        return JsonResponse({'success': False, 'error': 'Token faltante'}, status=400)

    try:
        # Decodificar el token desde base64
        signed_data = base64.urlsafe_b64decode(token.encode()).decode()

        # Verificar firma y tiempo de validez (1 hora)
        raw_data = signer.unsign(signed_data, max_age=3600)

        # Extraer datos originales
        email, password, username = raw_data.split('|')

        # Crear usuario en Firebase Authentication
        user = auth_admin.create_user(
            email=email,
            password=password,
            display_name=username
        )

        # Registrar datos del nuevo usuario en Firebase Realtime Database
        admin_db.reference('logins').child(user.uid).set({
            'uid': user.uid,
            'nombre': username,
            'email': email,
            'rol': 'usuario',
            'fecha_login': datetime.datetime.now().isoformat()
        })

        # ✅ Verificar si el email tenía invitaciones pendientes a tableros
        verificar_invitaciones_pendientes(user.uid, email)

        # Confirmar activación
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


# ✅ Función que procesa las invitaciones pendientes
def verificar_invitaciones_pendientes(uid_actual, email_actual):
    email_key = email_to_key(email_actual)
    invitaciones = db.child("invitaciones_pendientes").child(email_key).get().val()

    if invitaciones:
        for key, invitacion in invitaciones.items():
            tablero_id = invitacion['tablero_id']
            propietario_uid = invitacion['propietario_uid']

            db.child("tableros").child(propietario_uid).child(tablero_id).child("invitados").update({
                uid_actual: False
            })

        db.child("invitaciones_pendientes").child(email_key).remove()



# Vista para el login de usuarios
def login_view(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']

        # 1. Validar existencia del correo en la Realtime Database
        logins_ref = admin_db.reference('logins')
        logins = logins_ref.get()

        email_encontrado = False
        if logins:
            for key, login in logins.items():
                if login.get('email', '').lower() == email.lower():
                    email_encontrado = True
                    break

        if not email_encontrado:
            messages.error(request, 'Cuenta no activada. Este correo no está registrado.')
            return render(request, 'login.html')

        try:
            # 2. Validar credenciales con Firebase Auth
            user = auth.sign_in_with_email_and_password(email, password)

            # 3. Guardar en la sesión
            request.session['firebase_uid'] = user['localId']
            request.session['firebase_id_token'] = user['idToken']

            print(f"Sesión configurada para el usuario con UID: {user['localId']}")
            return redirect('inicio')

        except Exception as e:
            print(f"Error de autenticación: {e}")
            messages.error(request, 'Contraseña incorrecta.')
            return render(request, 'login.html')

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
    id_token = request.session.get('firebase_id_token')

    # Obtener el email para buscar el rol
    user_email = None
    rol = ''

    if id_token:
        try:
            info = auth_admin.verify_id_token(id_token)
            user_email = info.get('email')
        except Exception as e:
            print(f"Error verificando id_token: {e}")

    if user_email:
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

    # Intentar obtener el tablero bajo el UID actual
    tablero_ref = db.child("tableros").child(uid_actual).child(tablero_id)
    tablero = tablero_ref.get().val()

    # Si no se encuentra, buscar en todos los tableros para verificar si es colaborador
    if not tablero:
        tableros_todos = db.child("tableros").get().val()
        for uid_propietario, tableros_usuario in tableros_todos.items():
            if tablero_id in tableros_usuario:
                tablero = tableros_usuario[tablero_id]
                uid_actual = uid_propietario
                break

    # Si aún no se encuentra, responder con error
    if not tablero:
        return JsonResponse({"error": "Tablero no encontrado."}, status=404)

    # Obtener listas del tablero
    listas = tablero.get("listas", {})

    # Procesar formulario POST
    if request.method == 'POST':
        print("POST recibido:", request.POST)

        # Crear nueva lista
        if 'nombre' in request.POST and 'lista_id' not in request.POST:
            nombre_lista = request.POST.get('nombre')
            nueva_lista = {"nombre": nombre_lista}
            db.child("tableros").child(uid_actual).child(tablero_id).child("listas").push(nueva_lista)
            return redirect('ver_tablero', tablero_id=tablero_id)

        # Editar nombre de una lista existente
        elif 'nuevo_nombre' in request.POST and 'lista_id' in request.POST:
            lista_id = request.POST.get('lista_id')
            nuevo_nombre = request.POST.get('nuevo_nombre')

            print("Actualizando lista:", lista_id, "con nuevo nombre:", nuevo_nombre)

            db.child("tableros").child(uid_actual).child(tablero_id).child("listas").child(lista_id).update({
                "nombre": nuevo_nombre
            })
            return redirect('ver_tablero', tablero_id=tablero_id)

    return render(request, 'tablero.html', {
        'tablero_id': tablero_id,
        'tablero': tablero,
        'listas': listas,
        'rol': rol,
    })


# Agregar tarjeta
@firebase_login_required
def agregar_tarjeta(request, tablero_id, lista_id):
    if request.method == 'POST':
        try:
            uid_actual = request.session.get('firebase_uid')
            id_token = request.session.get('firebase_id_token')

            user_email = None
            if id_token:
                info = auth_admin.verify_id_token(id_token)
                user_email = info.get('email')

            # Buscar el uid dueño del tablero (y verificar si usuario actual está invitado y aprobado)
            todos_tableros = db.child("tableros").get().val() or {}
            uid_duenio = None
            autorizado = False

            for uid_dueño_iter, tableros_usuario in todos_tableros.items():
                if tablero_id in tableros_usuario:
                    uid_duenio = uid_dueño_iter
                    invitados = tableros_usuario[tablero_id].get('invitados', {})
                    if uid_actual == uid_duenio or invitados.get(uid_actual) == True:
                        autorizado = True
                    break

            if not autorizado:
                return HttpResponse("No tienes permiso para agregar tarjetas en este tablero.", status=403)

            titulo = request.POST.get('titulo')
            descripcion = request.POST.get('descripcion')
            orden = request.POST.get('orden', 0)
            color = request.POST.get('color', '#ffffff')

            # Obtener fechas y horas desde POST
            fecha_inicio_str = request.POST.get('fecha_inicio')  # ejemplo: '2025-06-06'
            hora_inicio_str = request.POST.get('hora_inicio')    # ejemplo: '08:00'

            fecha_limite_str = request.POST.get('fecha_limite')  # ejemplo: '2025-06-08'
            hora_limite_str = request.POST.get('hora_limite')    # ejemplo: '12:00'

            # Parsear fechas completas
            fecha_inicio_completa = None
            fecha_limite_completa = None

            try:
                if fecha_inicio_str and hora_inicio_str:
                    fecha_inicio_completa = datetime.datetime.strptime(
                        f"{fecha_inicio_str} {hora_inicio_str}", '%Y-%m-%d %H:%M'
                    )

                if fecha_limite_str and hora_limite_str:
                    fecha_limite_completa = datetime.datetime.strptime(
                        f"{fecha_limite_str} {hora_limite_str}", '%Y-%m-%d %H:%M'
                    )
            except Exception as e:
                print(f"Error al parsear fechas y horas: {e}")

            tarjeta = {
                'titulo': titulo,
                'descripcion': descripcion,
                'orden': orden,
                'color': color,
                'fecha_inicio': f"{fecha_inicio_str} {hora_inicio_str}" if fecha_inicio_str and hora_inicio_str else None,
                'fecha_limite': f"{fecha_limite_str} {hora_limite_str}" if fecha_limite_str and hora_limite_str else None,
                'completada': False,
                'email': user_email
            }

            # Guardar tarjeta en la base de datos Firebase
            db.child("tableros").child(uid_duenio).child(tablero_id).child("listas").child(lista_id).child("tarjetas").push(tarjeta)

            # Calcular tiempo restante entre inicio y fecha límite
            dias_restantes = None
            horas_restantes = None
            minutos_restantes = None

            zona_colombia = pytz.timezone("America/Bogota")

            if fecha_inicio_completa and fecha_limite_completa:
                # Localizar o convertir las fechas a zona horaria de Colombia
                if fecha_inicio_completa.tzinfo is None:
                    fecha_inicio_completa = zona_colombia.localize(fecha_inicio_completa)
                else:
                    fecha_inicio_completa = fecha_inicio_completa.astimezone(zona_colombia)

                if fecha_limite_completa.tzinfo is None:
                    fecha_limite_completa = zona_colombia.localize(fecha_limite_completa)
                else:
                    fecha_limite_completa = fecha_limite_completa.astimezone(zona_colombia)

                # Calcular diferencia si la fecha límite es mayor o igual a la fecha inicio
                if fecha_limite_completa >= fecha_inicio_completa:
                    delta = fecha_limite_completa - fecha_inicio_completa
                    total_segundos = int(delta.total_seconds())

                    dias_restantes = total_segundos // 86400
                    resto_dia = total_segundos % 86400
                    horas_restantes = resto_dia // 3600
                    minutos_restantes = (resto_dia % 3600) // 60
                else:
                    dias_restantes = horas_restantes = minutos_restantes = 0

            # Obtener UID del propietario desde la estructura del tablero
            propietario_uid = db.child("tableros").child(uid_duenio).child(tablero_id).child("propietario").get().val()

            email_duenio = None
            if propietario_uid:
                email_duenio = db.child("logins").child(propietario_uid).child("email").get().val()

            # Enviar correo al propietario si se encuentra su email
            if email_duenio:
                asunto = f"Nueva tarjeta agregada: {titulo}"
                mensaje = (
                    f"Se ha agregado una nueva tarjeta en tu tablero:\n\n"
                    f"Título: {titulo}\n"
                    f"Descripción: {descripcion}\n"
                    f"Fecha de inicio: {tarjeta['fecha_inicio'] or 'No definida'}\n"
                    f"Fecha límite: {tarjeta['fecha_limite'] or 'No definida'}\n"
                )

                if dias_restantes is not None and horas_restantes is not None and minutos_restantes is not None:
                    if dias_restantes > 0:
                        mensaje += f"Tiempo restante: {dias_restantes} día(s), {horas_restantes} hora(s), {minutos_restantes} minuto(s).\n"
                    else:
                        mensaje += f"Tiempo restante: {horas_restantes} hora(s), {minutos_restantes} minuto(s).\n"

                send_mail(asunto, mensaje, None, [email_duenio])
                print(f"Correo enviado al propietario: {email_duenio}")
            else:
                print("No se encontró el correo del propietario.")

            return redirect('ver_tablero', tablero_id=tablero_id)

        except Exception as e:
            print(f"Error al agregar tarjeta: {e}")
            return render(request, 'agregar_tarjeta.html', {
                'tablero_id': tablero_id,
                'lista_id': lista_id,
                'error': str(e)
            })

    # Si no es POST, renderiza la plantilla para agregar tarjeta
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
            # Obtener el UID del usuario autenticado
            uid = request.session.get('firebase_uid')

            # Eliminar la lista de la base de datos
            db.child("tableros").child(uid).child(tablero_id).child("listas").child(lista_id).remove()
            print("Lista eliminada correctamente.")

        except Exception as e:
            # Imprimir error en consola para depuración
            print(f"Error al eliminar lista: {e}")

        # Redirigir al tablero independientemente del resultado
        return redirect('ver_tablero', tablero_id=tablero_id)

    # Si no es POST, retornar error
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
            uid = request.session.get('firebase_uid')

            print(f"UID: {uid}, Tablero ID: {tablero_id}, Lista ID: {lista_id}, Tarjeta ID: {tarjeta_id}")

            # Verificar que el usuario sea el propietario del tablero
            tablero_ref = db.child("tableros").child(uid).child(tablero_id)
            tablero = tablero_ref.get().val()

            if not tablero:
                return JsonResponse({'success': False, 'error': 'Tablero no encontrado'}, status=404)

            propietario = tablero.get('propietario')
            if propietario != uid:
                return JsonResponse({'success': False, 'error': 'No tienes permisos para esta acción'}, status=403)

            # Construir la ruta y eliminar la tarjeta
            tarjeta_path = f"tableros/{uid}/{tablero_id}/listas/{lista_id}/tarjetas/{tarjeta_id}"
            db.child(tarjeta_path).remove()

            print("Tarjeta eliminada correctamente.")
            return JsonResponse({'success': True})

        except Exception as e:
            mensaje_error = f"Hubo un error al eliminar la lista: {str(e)}"
            return JsonResponse({'success': False, 'error': str(e)})

    return JsonResponse({'success': False, 'error': 'Método no permitido'}, status=405)



#Editar las tarjetas
@csrf_exempt
@firebase_login_required
def editar_tarjeta(request):
    if request.method == 'POST':
        try:
            import pytz
            import datetime
            import json

            data = json.loads(request.body)
            tarjeta_id = data['tarjeta_id']
            lista_id = data['lista_id']
            tablero_id = data['tablero_id']
            uid_editor = request.session.get('firebase_uid')

            print(f"UID Editor: {uid_editor}, Tablero ID: {tablero_id}, Lista ID: {lista_id}, Tarjeta ID: {tarjeta_id}")

            # Intentar obtener con el UID del editor
            tarjeta_path = f"tableros/{uid_editor}/{tablero_id}/listas/{lista_id}/tarjetas/{tarjeta_id}"
            tarjeta_actual = db.child(tarjeta_path).get().val()

            # Si no está, buscar UID propietario real del tablero
            if tarjeta_actual is None:
                print("Tarjeta no encontrada con UID del editor, se intentará encontrar el propietario del tablero.")
                todos_tableros = db.child("tableros").get().val() or {}
                uid_propietario = None
                autorizado = False

                for uid_iterador, tableros_usuario in todos_tableros.items():
                    if tablero_id in tableros_usuario:
                        uid_propietario = uid_iterador
                        invitados = tableros_usuario[tablero_id].get('invitados', {})
                        if uid_editor == uid_propietario or invitados.get(uid_editor) == True:
                            autorizado = True
                        break

                if not autorizado or not uid_propietario:
                    return JsonResponse({'success': False, 'error': 'No tienes permiso para editar esta tarjeta'}, status=403)

                tarjeta_path = f"tableros/{uid_propietario}/{tablero_id}/listas/{lista_id}/tarjetas/{tarjeta_id}"
                tarjeta_actual = db.child(tarjeta_path).get().val()

                if tarjeta_actual is None:
                    return JsonResponse({'success': False, 'error': 'Tarjeta no encontrada'}, status=404)
            else:
                uid_propietario = uid_editor  # El editor es el dueño

            print("Datos actuales de la tarjeta:", tarjeta_actual)

            # Leer valores nuevos
            completada = data.get('completada', False)
            titulo = data.get('titulo')
            descripcion = data.get('descripcion')
            color = data.get('color')
            fecha_limite_str = data.get('fecha_limite')

            # Actualizar los campos
            db.child(tarjeta_path).update({
                'titulo': titulo,
                'descripcion': descripcion,
                'color': color,
                'fecha_limite': fecha_limite_str,
                'completada': completada
            })

            # Comparar fecha límite anterior y nueva
            fecha_anterior = tarjeta_actual.get('fecha_limite')
            se_cambio_fecha = fecha_anterior != fecha_limite_str

            # Calcular tiempo restante
            dias_restantes = horas_restantes = minutos_restantes = None

            if se_cambio_fecha and fecha_limite_str:
                try:
                    fecha_limite = datetime.datetime.strptime(fecha_limite_str, '%Y-%m-%d').date()
                    hoy = datetime.date.today()
                    zona_colombia = pytz.timezone("America/Bogota")
                    ahora = datetime.datetime.now(zona_colombia)

                    if fecha_limite >= hoy:
                        fin_del_dia = datetime.datetime.combine(fecha_limite, datetime.time(23, 59, 59))
                        fin_del_dia = zona_colombia.localize(fin_del_dia)

                        delta = fin_del_dia - ahora
                        total_segundos = delta.total_seconds()

                        dias_restantes = int(total_segundos // 86400)
                        resto_dia = total_segundos % 86400
                        horas_restantes = int(resto_dia // 3600)
                        minutos_restantes = int((resto_dia % 3600) // 60)
                    else:
                        dias_restantes = horas_restantes = minutos_restantes = 0
                except Exception as e:
                    print(f"Error al parsear nueva fecha_limite: {e}")
                    dias_restantes = horas_restantes = minutos_restantes = None

            # Obtener UID del propietario desde la estructura del tablero (como me pediste)
            propietario_uid = db.child("tableros").child(uid_propietario).child(tablero_id).child("propietario").get().val()

            email_duenio = None
            if propietario_uid:
                email_duenio = db.child("logins").child(propietario_uid).child("email").get().val()

            # Enviar correo solo si se cambió la fecha y la tarjeta NO está completada
            if se_cambio_fecha and not completada:
                # Si tienes email dueño, enviar a él, sino a email en la tarjeta
                destinatario = email_duenio or tarjeta_actual.get('email')

                if destinatario:
                    asunto = f"Tarjeta actualizada: {titulo}"
                    mensaje = (
                        f"Se ha actualizado la fecha límite de una tarjeta asignada a ti.\n\n"
                        f"Título: {titulo}\n"
                        f"Descripción: {descripcion}\n"
                        f"Nueva fecha límite: {fecha_limite_str or 'No definida'}\n"
                    )

                    if dias_restantes is not None and horas_restantes is not None:
                        if dias_restantes > 0:
                            mensaje += f"Tiempo restante: {dias_restantes} día(s), {horas_restantes} hora(s) y {minutos_restantes} minuto(s).\n\n"
                        else:
                            mensaje += f"Tiempo restante: {horas_restantes} hora(s) y {minutos_restantes} minuto(s).\n\n"
                    else:
                        mensaje += "\n"

                    # Depuración
                    print(f"Email destinatario: {destinatario}")
                    print(f"Días restantes: {dias_restantes}, Horas restantes: {horas_restantes}, Minutos restantes: {minutos_restantes}")
                    print(f"Mensaje a enviar:\n{mensaje}")

                    send_mail(asunto, mensaje, None, [destinatario])

            print("Tarjeta actualizada correctamente.")
            return JsonResponse({'success': True})

        except Exception as e:
            print(f"Error al actualizar tarjeta: {e}")
            return JsonResponse({'success': False, 'error': str(e)})

    return JsonResponse({'success': False, 'error': 'Método no permitido'})



#agregar calendario 
@firebase_login_required
def ver_calendario(request, tablero_id):
    # Obtener UID del usuario autenticado
    firebase_uid = request.session.get('firebase_uid')

    # Ruta a todas las listas del tablero especificado
    ruta = f'tableros/{firebase_uid}/{tablero_id}/listas'

    # Obtener todas las listas y tarjetas del tablero
    listas_snapshot = db.child(ruta).get().val()

    eventos = []

    if listas_snapshot:
        for lista_id, lista_data in listas_snapshot.items():
            tarjetas = lista_data.get('tarjetas', {})  # Obtener las tarjetas de cada lista
            for tarjeta_id, tarjeta in tarjetas.items():
                fecha_limite = tarjeta.get('fecha_limite')
                if fecha_limite:
                    # Depuración: imprimir el color recibido de Firebase
                    print(f"Color de tarjeta {tarjeta_id}: {repr(tarjeta.get('color'))}")

                    # Validar y asignar color por defecto si es inválido o blanco
                    color = tarjeta.get('color')
                    if (not color or not isinstance(color, str) or
                        color.strip() == "" or color.strip().lower() == "#ffffff"):
                        color = '#007bff'  # Color por defecto: azul

                    # Agregar evento al calendario
                    eventos.append({
                        'title': tarjeta.get('descripcion', 'Sin título'),
                        'start': fecha_limite,
                        'color': color,
                    })

    # Convertir los eventos a formato JSON para enviarlos al frontend
    eventos_json = json.dumps(eventos)

    # Renderizar el calendario
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
def email_to_key(email):
    """Convierte un email a una clave segura para Firebase."""
    return email.replace('.', ',').replace('@', '_at_')


@firebase_login_required
def compartir_tablero(request, tablero_id):
    uid_actual = request.session['firebase_uid']

    # Obtener datos del tablero directamente (por uid actual y tablero_id)
    tablero_ref = db.child("tableros").child(uid_actual).child(tablero_id)
    tablero = tablero_ref.get().val()

    if not tablero:
        return JsonResponse({'success': False, 'error': 'No tienes permiso para compartir este tablero.'}, status=404)

    # Validar que el usuario autenticado sea el propietario del tablero
    propietario = tablero.get('propietario')
    if propietario != uid_actual:
        return JsonResponse({'success': False, 'error': 'No tienes permiso para compartir este tablero.'}, status=403)

    if request.method == 'POST':
        email_destino = request.POST.get('email')
        if email_destino:
            usuarios = db.child("logins").get().val() or {}
            uid_invitado = None
            for u_id, info in usuarios.items():
                if info.get('email') == email_destino:
                    uid_invitado = u_id
                    break

            if uid_invitado:
                # Usuario ya registrado, se agrega directamente al tablero
                db.child("tableros").child(uid_actual).child(tablero_id).child("invitados").update({
                    uid_invitado: False
                })
            else:
                # Usuario no registrado aún → guardar invitación pendiente con clave segura
                email_key = email_to_key(email_destino)
                db.child("invitaciones_pendientes").child(email_key).push({
                    'tablero_id': tablero_id,
                    'propietario_uid': uid_actual
                })

            # Enviar el correo con el enlace (siempre)
            url_solicitud = request.build_absolute_uri(
                reverse('solicitar_acceso_tablero', kwargs={
                    'tablero_id': tablero_id,
                    'email': email_destino
                })
            )

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

    # Renderizar la vista normalmente si no es POST
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








































