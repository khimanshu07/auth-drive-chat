from django.db import models
from django.contrib.auth.models import User


class GoogleOAuthCredentials(models.Model):
    """Model to securely store Google OAuth credentials for users"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='google_credentials')
    google_user_id = models.CharField(max_length=255, blank=True, null=True)
    token = models.TextField()
    refresh_token = models.TextField(blank=True, null=True)
    token_uri = models.CharField(max_length=255)
    client_id = models.CharField(max_length=255)
    client_secret = models.CharField(max_length=255)
    scopes = models.TextField()
    expiry = models.CharField(max_length=50, blank=True, null=True)
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Google OAuth Credentials'
        verbose_name_plural = 'Google OAuth Credentials'

    def __str__(self):
        return f"OAuth Credentials for {self.user.email}"