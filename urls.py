from django.contrib import admin
from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.inicio, name='inicio'),  # ← Esta línea soluciona el error 404
    path('registro/', views.registro, name='registro'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('password_reset/', views.password_reset_firebase, name='password_reset'),

    #Recuperar contraseña
    path('password_reset/', auth_views.PasswordResetView.as_view(template_name='registration/password_reset.html'), name='password_reset'),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='registration/password_reset.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='registration/password_reset.html'), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='registration/password_reset.html'), name='password_reset_complete'),
    path('verificar_email/', views.verificar_email, name='verificar_email'),

    #Tableros
    path('tableros/', views.listar_tableros, name='listar_tableros'), 
    path('tableros/crear/', views.crear_tablero, name='crear_tablero'),
    path('tableros/<str:tablero_id>/', views.ver_tablero, name='ver_tablero'),
    path('tableros/<str:tablero_id>/listas/<str:lista_id>/tarjetas/agregar/', views.agregar_tarjeta, name='agregar_tarjeta'),
    path('tableros/<str:tablero_id>/listas/<str:lista_id>/eliminar/', views.eliminar_lista, name='eliminar_lista'),
    path('eliminar_tarjeta/', views.eliminar_tarjeta, name='eliminar_tarjeta'),
    path('editar_tarjeta/', views.editar_tarjeta, name='editar_tarjeta'),
    path('tablero/<str:tablero_id>/calendario/', views.ver_calendario, name='ver_calendario'),
    path('metricas/', views.metricas_usuarios, name='metricas_usuarios'),
    path('solicitar-acceso/<str:tablero_id>/<str:email>/', views.solicitar_acceso_tablero, name='solicitar_acceso_tablero'),
    path('tablero/<str:tablero_id>/compartir/', views.compartir_tablero, name='compartir_tablero'),
    path('perfil/', views.perfil, name='perfil'),
    path('eliminar_cuenta/', views.eliminar_cuenta, name='eliminar_cuenta'), 
    path('resumen/<str:tablero_id>/', views.ver_resumen, name='ver_resumen'),
    path('tablero/<str:tablero_id>/descargar/', views.descargar_tablero_pdf, name='descargar_tablero_pdf'), 
    #Administradores
    path('dashboard/', views.dashboard, name='dashboard'),
    path('dashboard/crear/', views.crear_usuario, name='crear_usuario'),
    path('dashboard/editar/<uid>/', views.editar_usuario, name='editar_usuario'),
    path('dashboard/eliminar/<uid>/', views.eliminar_usuario, name='eliminar_usuario'),
    # Formulario para simular el pago
    path('simular_pago/', views.simular_pago_formulario, name='simular_pago_formulario'),
    path('procesar_pago/', views.procesar_pago_simulado, name='procesar_pago'),  
]
