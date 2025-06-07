from django.core.management.base import BaseCommand
from django.core.mail import send_mail
from django.utils import timezone
import pytz
import datetime
from firebase_admin import db

class Command(BaseCommand):
    help = 'Verifica tarjetas y envía correo si faltan 5 horas para la fecha límite'

    def handle(self, *args, **kwargs):
        zona_colombia = pytz.timezone("America/Bogota")
        ahora = timezone.now().astimezone(zona_colombia)

        todos_tableros = db.reference("tableros").get() or {}

        for uid, tableros_usuario in todos_tableros.items():
            for tablero_id, datos_tablero in tableros_usuario.items():
                listas = datos_tablero.get("listas", {})

                for lista_id, lista in listas.items():
                    tarjetas = lista.get("tarjetas", {})

                    for tarjeta_id, tarjeta in tarjetas.items():
                        fecha_limite_str = tarjeta.get("fecha_limite")
                        aviso_enviado = tarjeta.get("tiempo_aviso_5h_enviado", False)

                        if fecha_limite_str and not aviso_enviado:
                            try:
                                fecha_limite = zona_colombia.localize(
                                    datetime.datetime.strptime(fecha_limite_str, "%Y-%m-%d %H:%M")
                                )
                                tiempo_restante = fecha_limite - ahora

                                if datetime.timedelta(hours=2, minutes=50) < tiempo_restante <= datetime.timedelta(hours=3):
                                    # Obtener el correo del dueño
                                    email_duenio = db.reference(f"logins/{uid}/email").get()
                                    if email_duenio:
                                        asunto = f"⏰ Alerta: Una tarjeta vence pronto"
                                        mensaje = (
                                            f"La tarjeta '{tarjeta.get('titulo')}' está a menos de 5 horas de vencer.\n\n"
                                            f"Fecha límite: {fecha_limite_str}\n"
                                            f"Descripción: {tarjeta.get('descripcion')}"
                                        )
                                        send_mail(asunto, mensaje, None, [email_duenio])
                                        print(f"Correo enviado a {email_duenio} por tarjeta {tarjeta_id}")

                                        # Marcar como aviso enviado
                                        db.reference(
                                            f"tableros/{uid}/{tablero_id}/listas/{lista_id}/tarjetas/{tarjeta_id}"
                                        ).update({
                                            "tiempo_aviso_5h_enviado": True
                                        })

                            except Exception as e:
                                print(f"Error procesando tarjeta {tarjeta_id}: {e}")
