# D:\1.3-90-north\assignment\myapp\views.py
from django.shortcuts import redirect, render
from django.http import HttpResponseRedirect, HttpResponse
from django.urls import reverse
from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.models import User
from django.conf import settings
from django.utils import timezone

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from googleapiclient.http import MediaFileUpload
from googleapiclient.http import MediaIoBaseDownload
from io import BytesIO

# Import models
from .models import GoogleOAuthCredentials
from .utils import refresh_google_credentials

# Google OAuth settings
CLIENT_ID = getattr(settings, 'GOOGLE_OAUTH_CLIENT_ID', '')
CLIENT_SECRET = getattr(settings, 'GOOGLE_OAUTH_CLIENT_SECRET', '')
REDIRECT_URI = getattr(settings, 'GOOGLE_OAUTH_REDIRECT_URI', '')
# Scopes for Google OAuth
SCOPES = [
    'https://www.googleapis.com/auth/userinfo.email',  # Access to user's email
    'https://www.googleapis.com/auth/userinfo.profile',  # Access to user's profile
    'openid',  # Required for OpenID Connect
    'https://www.googleapis.com/auth/drive.file',  # Access to user's files
    'https://www.googleapis.com/auth/drive.readonly',  # Read-only access to user's files
]

def google_auth(request):
    """Initiate the Google OAuth flow"""
    # Create the flow instance
    flow = Flow.from_client_config(
        client_config={
            "web": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://accounts.google.com/o/oauth2/token",
                "redirect_uris": [REDIRECT_URI],
            }
        },
        scopes=SCOPES,
    )
    flow.redirect_uri = REDIRECT_URI
    
    # Generate authorization URL and state
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'  # Force to show consent screen to get refresh_token every time
    )
    
    # Store state in session for security verification
    request.session['oauth_state'] = state
    
    # Redirect user to Google's authorization page
    return redirect(authorization_url)



def google_callback(request):
    if 'error' in request.GET:
        return render(request, 'oauth/error.html', {
            'error': request.GET['error'],
            'error_description': request.GET.get('error_description', 'Authorization denied')
        })
    
    state = request.session.get('oauth_state')  # Retrieve state from session
    if not state or state != request.GET.get('state'):  # Validate state
        return render(request, 'oauth/error.html', {
            'error': 'Invalid state parameter',
            'error_description': 'State verification failed. This could be a CSRF attempt.'
        })
    
    try:
        flow = Flow.from_client_config(
            client_config={
                "web": {
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://accounts.google.com/o/oauth2/token",
                    "redirect_uris": [REDIRECT_URI],
                }
            },
            scopes=SCOPES,
            state=state,  # Pass the state here
        )
        flow.redirect_uri = REDIRECT_URI
        
        flow.fetch_token(authorization_response=request.build_absolute_uri())
        credentials = flow.credentials
        
        
        # Get user info from Google
        service = build('oauth2', 'v2', credentials=credentials)
        user_info = service.userinfo().get().execute()
        
        # Get or create user based on email
        email = user_info.get('email')
        if not email:
            return render(request, 'oauth/error.html', {
                'error': 'Email not found',
                'error_description': 'Google did not provide an email address.'
            })
        
        # Find user by email or create a new one
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # Create a new user
            user = User.objects.create_user(
                username=email.split('@')[0] + '_' + str(hash(email) % 10000),  # Create a unique username
                email=email,
                first_name=user_info.get('given_name', ''),
                last_name=user_info.get('family_name', '')
            )
            user.save()
        
        # Save the credentials in the database
        expiry = credentials.expiry.isoformat() if credentials.expiry else None
        
        # Update or create credentials for this user
        oauth_credentials, created = GoogleOAuthCredentials.objects.update_or_create(
            user=user,
            defaults={
                'token': credentials.token,
                'refresh_token': credentials.refresh_token or '',  # Handle None
                'token_uri': credentials.token_uri,
                'client_id': credentials.client_id,
                'client_secret': credentials.client_secret,
                'scopes': ' '.join(credentials.scopes),
                'expiry': expiry,
                'google_user_id': user_info.get('id'),
                'last_updated': timezone.now()
            }
        )
        
        # Log in the user
        login(request, user)
        
        # Clean up session
        if 'oauth_state' in request.session:
            del request.session['oauth_state']
        
        # Redirect to profile or dashboard
        return HttpResponseRedirect(reverse('dashboard'))
        
    except Exception as e:
        return render(request, 'oauth/error.html', {
            'error': 'Authentication Error',
            'error_description': str(e)
        })


def dashboard(request):
    """Dashboard view that uses the Google OAuth credentials if available"""
    if not request.user.is_authenticated:
        return redirect('login')
    
    try:
        # Get credentials from the database
        oauth_credentials = GoogleOAuthCredentials.objects.get(user=request.user)
        
        # Create Credentials object
        credentials = Credentials(
            token=oauth_credentials.token,
            refresh_token=oauth_credentials.refresh_token,
            token_uri=oauth_credentials.token_uri,
            client_id=oauth_credentials.client_id,
            client_secret=oauth_credentials.client_secret,
            scopes=oauth_credentials.scopes.split()
        )
        
        # Check if token is expired and refresh if needed
        if credentials.expired:
            credentials = refresh_google_credentials(oauth_credentials)
            if not credentials:
                # If refresh failed, redirect to re-authenticate
                return redirect('google_auth')
        
        # Use credentials to get user profile information
        service = build('oauth2', 'v2', credentials=credentials)
        user_info = service.userinfo().get().execute()
        
        # Build the Drive service
        drive_service = build('drive', 'v3', credentials=credentials)
        
        # List files from Google Drive
        results = drive_service.files().list(pageSize=10, fields="nextPageToken, files(id, name)").execute()
        files = results.get('files', [])
        
        # Display dashboard with user info and files
        return render(request, 'oauth/dashboard.html', {
            'user_info': user_info,
            'email': user_info.get('email'),
            'name': user_info.get('name'),
            'picture': user_info.get('picture'),
            'files': files,  # Pass the list of files to the template
        })
    
    except GoogleOAuthCredentials.DoesNotExist:
        # No credentials found, redirect to auth
        return redirect('google_auth')
    
    except HttpError as error:
        # Google API error
        return render(request, 'oauth/error.html', {
            'error': 'Google API Error',
            'error_description': str(error)
        })
    
    except Exception as e:
        # Other errors
        return render(request, 'oauth/error.html', {
            'error': 'Dashboard Error',
            'error_description': str(e)
        })
        
        
        
def custom_logout(request):
    logout(request)
    return redirect('home')

def home(request):
    return render(request, 'myapp/index.html')


def connect_google_drive(request):
    """Connect to Google Drive using stored OAuth credentials"""
    if not request.user.is_authenticated:
        return redirect('login')
    
    try:
        # Get credentials from the database
        oauth_credentials = GoogleOAuthCredentials.objects.get(user=request.user)
        
        # Create Credentials object
        credentials = Credentials(
            token=oauth_credentials.token,
            refresh_token=oauth_credentials.refresh_token,
            token_uri=oauth_credentials.token_uri,
            client_id=oauth_credentials.client_id,
            client_secret=oauth_credentials.client_secret,
            scopes=oauth_credentials.scopes.split()
        )
        
        # Build the Drive service
        drive_service = build('drive', 'v3', credentials=credentials)
        
        # Store the credentials in the session (optional, if needed elsewhere)
        request.session['credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes,
        }
        
        # Test the connection by listing files (optional)
        results = drive_service.files().list(pageSize=10, fields="nextPageToken, files(id, name)").execute()
        files = results.get('files', [])
        
        # Redirect to the dashboard with a success message
        messages.success(request, 'Successfully connected to Google Drive!')
        return redirect('dashboard')
    
    except GoogleOAuthCredentials.DoesNotExist:
        return render(request, 'oauth/error.html', {
            'error': 'No OAuth Credentials',
            'error_description': 'Please log in with Google first.'
        })
    
    except Exception as e:
        return render(request, 'oauth/error.html', {
            'error': 'Drive Connection Error',
            'error_description': str(e)
        })
        


def upload_file(request):
    """Upload a file to Google Drive"""
    if not request.user.is_authenticated:
        return redirect('login')
    
    if request.method == 'POST':
        try:
            # Check if a file was submitted
            if 'file' not in request.FILES:
                return render(request, 'myapp/upload.html', {
                    'error': 'No file selected',
                    'error_description': 'Please select a file to upload.'
                })
            
            # Get the file from the request
            file = request.FILES['file']
            file_path = default_storage.save(file.name, ContentFile(file.read()))
            
            # Get credentials from the session
            credentials_data = request.session.get('credentials')
            if not credentials_data:
                return redirect('connect_google_drive')
            
            # Recreate the Credentials object
            credentials = Credentials(
                token=credentials_data['token'],
                refresh_token=credentials_data['refresh_token'],
                token_uri=credentials_data['token_uri'],
                client_id=credentials_data['client_id'],
                client_secret=credentials_data['client_secret'],
                scopes=credentials_data['scopes'],
            )
            
            # Build the Drive service
            drive_service = build('drive', 'v3', credentials=credentials)
            
            # Create file metadata
            file_metadata = {
                'name': file.name,
            }
            
            # Upload the file to Google Drive
            media = MediaFileUpload(file_path, mimetype=file.content_type)
            drive_service.files().create(body=file_metadata, media_body=media, fields='id').execute()
            
            return redirect('dashboard')
        
        except Exception as e:
            return render(request, 'oauth/error.html', {
                'error': 'File Upload Error',
                'error_description': str(e)
            })
    
    return render(request, 'myapp/upload.html')



def download_file(request, file_id):
    """Download a file from Google Drive"""
    if not request.user.is_authenticated:
        return redirect('login')
    
    try:
        # Get credentials from the session
        credentials_data = request.session.get('credentials')
        if not credentials_data:
            return redirect('connect_google_drive')
        
        # Recreate the Credentials object
        credentials = Credentials(
            token=credentials_data['token'],
            refresh_token=credentials_data['refresh_token'],
            token_uri=credentials_data['token_uri'],
            client_id=credentials_data['client_id'],
            client_secret=credentials_data['client_secret'],
            scopes=credentials_data['scopes'],
        )
        
        # Build the Drive service
        drive_service = build('drive', 'v3', credentials=credentials)
        
        # Get file metadata
        file = drive_service.files().get(fileId=file_id).execute()
        file_name = file['name']
        
        # Download the file content
        request = drive_service.files().get_media(fileId=file_id)
        fh = BytesIO()
        downloader = MediaIoBaseDownload(fh, request)
        done = False
        while not done:
            status, done = downloader.next_chunk()
        
        # Serve the file as a downloadable response
        response = HttpResponse(fh.getvalue(), content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{file_name}"'
        return response
    
    except Exception as e:
        return render(request, 'oauth/error.html', {
            'error': 'File Download Error',
            'error_description': str(e)
        })
        
        
def search_files(request):
    """Search for files in Google Drive based on the user's query."""
    if not request.user.is_authenticated:
        return redirect('login')  # Redirect to login if user is not authenticated

    try:
        # Get the search query from the request
        query = request.GET.get('q')
        if not query:
            return redirect('drive')  # Redirect to drive page if no query is provided

        # Get credentials from the database
        oauth_credentials = GoogleOAuthCredentials.objects.get(user=request.user)

        # Create Credentials object
        credentials = Credentials(
            token=oauth_credentials.token,
            refresh_token=oauth_credentials.refresh_token,
            token_uri=oauth_credentials.token_uri,
            client_id=oauth_credentials.client_id,
            client_secret=oauth_credentials.client_secret,
            scopes=oauth_credentials.scopes.split()
        )

        # Check if token is expired and refresh if needed
        if credentials.expired:
            credentials = refresh_google_credentials(oauth_credentials)
            if not credentials:
                # If refresh failed, redirect to re-authenticate
                return redirect('google_auth')

        # Build the Drive service
        drive_service = build('drive', 'v3', credentials=credentials)

        # Search for files using the query
        results = drive_service.files().list(
            q=f"name contains '{query}'",  # Search for files with names containing the query
            pageSize=10,  # Limit to 10 results for simplicity
            fields="nextPageToken, files(id, name, mimeType)"
        ).execute()

        files = results.get('files', [])

        # Debugging: Print the search results
        print(f"Search Query: {query}")
        print(f"Files Found: {files}")

        # Pass search results to the template
        return render(request, 'myapp/drive.html', {
            'files': files,  # List of files matching the search query
            'search_query': query,  # Pass the search query back to the template
        })

    except GoogleOAuthCredentials.DoesNotExist:
        # No credentials found, redirect to auth
        return redirect('google_auth')

    except Exception as e:
        # Handle any other errors
        return render(request, 'oauth/error.html', {
            'error': 'Search Error',
            'error_description': str(e)
        })
        
        
        
def preview_file(request, file_id):
    """Preview a file from Google Drive"""
    if not request.user.is_authenticated:
        return redirect('login')
    
    try:
        # Get credentials from the session
        credentials_data = request.session.get('credentials')
        if not credentials_data:
            return redirect('connect_google_drive')
        
        # Recreate the Credentials object
        credentials = Credentials(
            token=credentials_data['token'],
            refresh_token=credentials_data['refresh_token'],
            token_uri=credentials_data['token_uri'],
            client_id=credentials_data['client_id'],
            client_secret=credentials_data['client_secret'],
            scopes=credentials_data['scopes'],
        )
        
        # Build the Drive service
        drive_service = build('drive', 'v3', credentials=credentials)
        
        # Get file metadata
        file = drive_service.files().get(fileId=file_id, fields="id, name, mimeType, webViewLink").execute()
        
        # Check if the file is previewable (e.g., PDF, images)
        previewable_mime_types = [
            'application/pdf',
            'image/jpeg',
            'image/png',
            'image/gif',
        ]
        if file['mimeType'] not in previewable_mime_types:
            return render(request, 'oauth/error.html', {
                'error': 'Preview Not Supported',
                'error_description': 'This file type cannot be previewed.'
            })
        
        # Redirect to the file's webViewLink for preview
        return redirect(file['webViewLink'])
    
    except Exception as e:
        return render(request, 'oauth/error.html', {
            'error': 'Preview Error',
            'error_description': str(e)
        })
        

def chat(request):
    """Render the chat page."""
    return render(request, 'myapp/chat.html')

def profile(request):
    """Render the profile page with user's Google profile information."""
    if not request.user.is_authenticated:
        return redirect('login')  # Redirect to login if user is not authenticated

    try:
        # Get credentials from the database
        oauth_credentials = GoogleOAuthCredentials.objects.get(user=request.user)

        # Create Credentials object
        credentials = Credentials(
            token=oauth_credentials.token,
            refresh_token=oauth_credentials.refresh_token,
            token_uri=oauth_credentials.token_uri,
            client_id=oauth_credentials.client_id,
            client_secret=oauth_credentials.client_secret,
            scopes=oauth_credentials.scopes.split()
        )

        # Check if token is expired and refresh if needed
        if credentials.expired:
            credentials = refresh_google_credentials(oauth_credentials)
            if not credentials:
                # If refresh failed, redirect to re-authenticate
                return redirect('google_auth')

        # Use credentials to get user profile information
        service = build('oauth2', 'v2', credentials=credentials)
        user_info = service.userinfo().get().execute()

        # Pass user info to the template
        return render(request, 'myapp/profile.html', {
            'name': user_info.get('name', 'User'),  # Default to 'User' if name is not available
            'email': user_info.get('email', 'No email'),  # Default to 'No email' if email is not available
            'picture': user_info.get('picture'),  # Profile picture URL
            'user_info': user_info,  # Pass the entire user_info dictionary for the table
        })

    except GoogleOAuthCredentials.DoesNotExist:
        # No credentials found, redirect to auth
        return redirect('google_auth')

    except Exception as e:
        # Handle any other errors
        return render(request, 'oauth/error.html', {
            'error': 'Profile Error',
            'error_description': str(e)
        })

def drive(request):
    """Drive view that displays the user's Google Drive files."""
    if not request.user.is_authenticated:
        return redirect('login')  # Redirect to login if user is not authenticated

    try:
        # Get credentials from the database
        oauth_credentials = GoogleOAuthCredentials.objects.get(user=request.user)

        # Create Credentials object
        credentials = Credentials(
            token=oauth_credentials.token,
            refresh_token=oauth_credentials.refresh_token,
            token_uri=oauth_credentials.token_uri,
            client_id=oauth_credentials.client_id,
            client_secret=oauth_credentials.client_secret,
            scopes=oauth_credentials.scopes.split()
        )

        # Check if token is expired and refresh if needed
        if credentials.expired:
            credentials = refresh_google_credentials(oauth_credentials)
            if not credentials:
                # If refresh failed, redirect to re-authenticate
                return redirect('google_auth')

        # Build the Drive service
        drive_service = build('drive', 'v3', credentials=credentials)

        # List files from Google Drive
        results = drive_service.files().list(
            pageSize=4,  # Limit to 10 files for simplicity
            fields="nextPageToken, files(id, name)"
        ).execute()
        files = results.get('files', [])

        # Pass files to the template
        return render(request, 'myapp/drive.html', {
            'files': files,  # List of files to display
        })

    except GoogleOAuthCredentials.DoesNotExist:
        # No credentials found, redirect to auth
        return redirect('google_auth')

    except Exception as e:
        # Handle any other errors
        return render(request, 'oauth/error.html', {
            'error': 'Drive Error',
            'error_description': str(e)
        })


def test(request):
    """Render the profile page."""
    return render(request, 'oauth/test.html')