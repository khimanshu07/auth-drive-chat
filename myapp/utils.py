# D:\1.3-90-north\assignment\myapp\utils.py
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from django.utils import timezone
import datetime
import logging

logger = logging.getLogger(__name__)

def refresh_google_credentials(oauth_credentials):
    """
    Refresh expired Google OAuth credentials
    
    Args:
        oauth_credentials: GoogleOAuthCredentials model instance
    
    Returns:
        Refreshed Credentials object or None if refresh failed
    """
    try:
        # Create a Credentials object from stored data
        credentials = Credentials(
            token=oauth_credentials.token,
            refresh_token=oauth_credentials.refresh_token,
            token_uri=oauth_credentials.token_uri,
            client_id=oauth_credentials.client_id,
            client_secret=oauth_credentials.client_secret,
            scopes=oauth_credentials.scopes.split()
        )
        
        # Check if token needs refreshing
        if credentials.expired:
            logger.info(f"Refreshing token for user {oauth_credentials.user.email}")
            
            # Refresh the token
            credentials.refresh(Request())
            
            # Update the stored credentials
            oauth_credentials.token = credentials.token
            if credentials.refresh_token:
                oauth_credentials.refresh_token = credentials.refresh_token
            oauth_credentials.expiry = credentials.expiry.isoformat() if credentials.expiry else None
            oauth_credentials.last_updated = timezone.now()
            oauth_credentials.save()
            
            logger.info(f"Token refreshed successfully for user {oauth_credentials.user.email}")
        
        return credentials
        
    except Exception as e:
        logger.error(f"Error refreshing token: {str(e)}")
        return None


def get_valid_credentials(user):
    """
    Helper function to get valid Google credentials for a user
    
    Args:
        user: Django User object
    
    Returns:
        Valid Credentials object or None
    """
    try:
        # Import here to avoid circular imports
        from .models import GoogleOAuthCredentials
        
        oauth_credentials = GoogleOAuthCredentials.objects.get(user=user)
        
        # Create Credentials object
        credentials = Credentials(
            token=oauth_credentials.token,
            refresh_token=oauth_credentials.refresh_token,
            token_uri=oauth_credentials.token_uri,
            client_id=oauth_credentials.client_id,
            client_secret=oauth_credentials.client_secret,
            scopes=oauth_credentials.scopes.split()
        )
        
        # Set expiry if available
        if oauth_credentials.expiry:
            try:
                credentials.expiry = datetime.datetime.fromisoformat(oauth_credentials.expiry)
            except (ValueError, TypeError):
                pass
        
        # Refresh if needed
        if credentials.expired:
            credentials = refresh_google_credentials(oauth_credentials)
        
        return credentials
    
    except GoogleOAuthCredentials.DoesNotExist:
        return None
    
    except Exception as e:
        logger.error(f"Error getting valid credentials: {str(e)}")
        return None