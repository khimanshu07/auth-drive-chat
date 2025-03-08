# myapp/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('auth/google/', views.google_auth, name='google_auth'),
    path('auth/callback/', views.google_callback, name='google_callback'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('logout/', views.custom_logout, name='logout'),
    path('drive/connect/', views.connect_google_drive, name='connect_google_drive'),
    path('drive/upload/', views.upload_file, name='upload_file'),
    path('drive/download/<str:file_id>/', views.download_file, name='download_file'),
    path('drive/search/', views.search_files, name='search_files'),
    path('drive/preview/<str:file_id>/', views.preview_file, name='preview_file'),
    path('chat/', views.chat, name='chat'),  # Add this line for the chat view
    path('profile/', views.profile, name='profile'),  
    path('test/', views.test, name='test'),
    path('drive/', views.drive, name='drive'),      
]