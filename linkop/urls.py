"""linkop URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.contrib.auth import views as auth_views
from . import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.home_page, name='home_page'),
    
    # Login and Logout views
    # path('login/', auth_views.LoginView.as_view(template_name='login.html'), name='login'),
    path('login-page/', views.login_view, name='login_view'),
    path('login/', views.user_login, name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    
    # path('login/', views.user_login, name='login'),
    # path('logout/', views.user_logout, name='logout'),
    
    # User Registration view
    path('register/', views.register, name='register'),
    
    # Account Activation view 
    path('activate/<uidb64>/<token>/', views.activate_account, name='activate'),
    
    # Profile Update view
    path('profile/update/', views.update_profile, name='update_profile'),
    
    # Password Reset view
    path('password-reset/', auth_views.PasswordResetView.as_view(template_name='password_reset.html', html_email_template_name='password_reset_email.html'), name='password_reset'),
    path('password-reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='password_reset_done.html'), name='password_reset_done'),
    # path('password-reset-confirm/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='password_reset_confirm.html'), name='password_reset_confirm'),
    path('password-reset-confirm/<uidb64>/<token>/', views.CustomPasswordResetConfirmView.as_view(template_name='password_reset_confirm.html'), name='password_reset_confirm'),
    path('password-reset-complete/', auth_views.PasswordResetCompleteView.as_view(template_name='password_reset_complete.html'),name='password_reset_complete'),
    
    # Other URL patterns...
    path('activation-failed/', views.activation_failed, name='activation_failed'),
    path('event/create/', views.create_event, name='create_event'),
    path('event/<int:event_id>/', views.event_details, name='event_details'),
    path('event/<int:event_id>/update/', views.update_event, name='update_event'),
    path('event/<int:event_id>/delete/', views.delete_event, name='delete_event'),
    path('event/<int:event_id>/toggle-interest/', views.toggle_interest, name='toggle_interest'),
    path('event/<int:event_id>/attendees/', views.event_attendees, name='event_attendees'),
    path('user/<int:user_id>/', views.user_profile, name='user_profile'),
    path('user/<int:user_id>/pick-interest/', views.pick_interest, name='pick_interest'),
    path('user/<int:user_id>/mark-notification-as-read/<int:notification_id>/', views.mark_notification_as_read, name='mark_notification_as_read'),
    path('send-message/<int:receiver_id>/', views.send_message, name='send_message'),
    path('inbox/', views.message_inbox, name='message_inbox'),
    path('message/history/<int:sender_id>/', views.message_history, name='message_history'),
    path('message/reply/<int:sender_id>/', views.reply_to_message, name='reply_to_message'),
    path('event/<int:event_id>/rate-and-review/', views.rate_and_review_event, name='rate_and_review_event'),
] + static(settings.MEDIA_URL, document_root = settings.MEDIA_ROOT) + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
