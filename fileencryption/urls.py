
from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static



urlpatterns = [
    path('',views.encrypt_file_view, name='encrypt_file'),
    path('encrypt/', views.encrypt_file_view, name='encrypt_file'),
    path('decrypt/<str:encrypted_file_name>/', views.decrypt_file_view, name='decrypt_file'),
    path('download/<str:encrypted_file_name>/', views.download_encrypted_file, name='download_encrypted_file'),

    path('fileencryption/download/<str:encrypted_data>/', views.download_encrypted_file, name='download_encrypted_file'),


]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)