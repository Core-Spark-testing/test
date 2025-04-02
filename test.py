from flask import Blueprint, request, jsonify, current_app, redirect, url_for, session, Response
import datetime
from utils.auth import create_token, token_required
import hashlib
import base64
import requests
import json
import os
import re 
from urllib.parse import urlencode
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
from config import Config
import xml.etree.ElementTree as ET
from xml.dom import minidom
import logging
import pandas as pd
from config import Config

auth_routes = Blueprint('auth', __name__)

# Google OAuth configuration
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
GOOGLE_REDIRECT_URI = os.environ.get('GOOGLE_REDIRECT_URI', 'http://localhost:5000/api/auth/google/callback')
GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth'
GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token'
GOOGLE_USER_INFO_URL = 'https://www.googleapis.com/oauth2/v3/userinfo'

# SAML configuration
SAML_METADATA_URL = os.environ.get('SAML_METADATA_URL')
SAML_ENTITY_ID = os.environ.get('SAML_ENTITY_ID', 'http://localhost:5000/api/metadata')
SAML_ACS_URL = os.environ.get('SAML_ACS_URL', 'http://localhost:5000/api/auth/saml/callback')

ALLOWED_EMAIL_DOMAINS = Config().get('domains')
PASSWORD_PATTERN = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
    
@auth_routes.route('/login', methods=['POST'])
def login():
    # Add defensive error handling to prevent 500 errors
    try:
        data = request.get_json()
        
        # Validate input
        if not data:
            print("No JSON data in request")
            return jsonify({'message': 'Email and password are required'}), 400
            
        if not data.get('email') or not data.get('password'):
            print(f"Missing required fields. Got: {list(data.keys())}")
            return jsonify({'message': 'Email and password are required'}), 400
        
        email = data.get('email')
        password = data.get('password')
        
        print(f"Login attempt for email: {email}")
        
        # Check if user exists in MongoDB
        user = current_app.mongo.db.users.find_one({'email': email})
        
        # If user not found or password doesn't match
        if not user:
            print(f"User not found: {email}")
            return jsonify({'message': 'Invalid credentials'}), 401
            
        hashed_password = hash_password(password)
        if user.get('password') != hashed_password:
            print(f"Invalid password for user: {email}")
            return jsonify({'message': 'Invalid credentials'}), 401
        
        print(f"Valid credentials for user: {email}")
        
        # Create JWT token
        token = create_token(
            str(user['_id']),
            user.get('name', 'User'),
            user.get('role', 'User'),
            email,
            current_app.config['JWT_SECRET'],
            current_app.config['TOKEN_EXPIRY_DAYS']
        )
        
        # Return token and user info
        return jsonify({
            'success': True,
            'token': token,
            'user': {
                'id': str(user['_id']),
                'name': user.get('name', 'User'),
                'email': user.get('email'),
                'role': user.get('role', 'User')
            }
        }), 200
        
    except Exception as e:
        print(f"Login error: {str(e)}")
        # Return a more informative error response
        return jsonify({
            'success': False,
            'message': 'Login failed',
            'error': str(e)
        }), 500
        
@auth_routes.route('/auth/google/url', methods=['GET'])
def get_google_auth_url():
    """Generate Google OAuth URL for the frontend to redirect to."""
    # Store basic timestamp in state parameter for security
    state = base64.b64encode(json.dumps({'timestamp': datetime.datetime.now().timestamp()}).encode()).decode()
    
    auth_params = {
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'scope': 'email profile',
        'response_type': 'code',
        'state': state,
        'access_type': 'offline',
        'prompt': 'consent'
    }
    
    auth_url = f"{GOOGLE_AUTH_URL}?{urlencode(auth_params)}"
    return jsonify({'authUrl': auth_url}), 200

@auth_routes.route('/auth/google/callback', methods=['GET', 'POST'])
def google_oauth_callback():
    # Original Google OAuth callback implementation
    # ... (keeping the original code here)
    """Handle the Google OAuth callback."""
    # For browser redirect (GET)
    if request.method == 'GET':
        code = request.args.get('code')
        
        if not code:
            return jsonify({'message': 'Authorization code is missing'}), 400
        
        # Exchange code for tokens
        token_data = {
            'code': code,
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'redirect_uri': GOOGLE_REDIRECT_URI,
            'grant_type': 'authorization_code'
        }
        
        token_response = requests.post(GOOGLE_TOKEN_URL, data=token_data)
        token_json = token_response.json()
        
        if 'access_token' not in token_json:
            return jsonify({'message': 'Failed to get access token'}), 400
        
        # Get user info with access token
        access_token = token_json['access_token']
        user_response = requests.get(GOOGLE_USER_INFO_URL, headers={
            'Authorization': f'Bearer {access_token}'
        })
        
        google_user = user_response.json()
        
        if 'email' not in google_user:
            return jsonify({'message': 'Failed to get user email'}), 400
        
        # Check if user exists or create a new one
        user = handle_google_user(google_user)
        
        if not user:
            return jsonify({'message': 'Failed to authenticate with Google'}), 400
        
        # Create JWT token
        token = create_token(
            str(user['_id']),
            user.get('name', 'User'),
            user.get('role', 'User'),
            current_app.config['JWT_SECRET'],
            current_app.config['TOKEN_EXPIRY_DAYS']
        )
        
        # Close popup and send message to parent window
        html_response = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authentication Successful</title>
            <script>
                window.onload = function() {{
                    window.opener.postMessage(
                        {{
                            type: 'GOOGLE_AUTH_SUCCESS',
                            payload: {{
                                token: '{token}',
                                user: {{
                                    id: '{str(user["_id"])}',
                                    name: '{user.get("name", "User")}',
                                    email: '{user.get("email")}',
                                    role: '{user.get("role", "User")}'
                                }}
                            }}
                        }},
                        window.location.origin
                    );
                    window.close();
                }};
            </script>
        </head>
        <body>
            <p>Authentication successful! This window will close automatically.</p>
        </body>
        </html>
        """
        return html_response
    
    # For API endpoint (POST) - used for mobile or direct API calls
    elif request.method == 'POST':
        data = request.get_json()
        code = data.get('code')
        
        if not code:
            return jsonify({'message': 'Authorization code is required'}), 400
        
        # Exchange code for tokens
        token_data = {
            'code': code,
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'redirect_uri': GOOGLE_REDIRECT_URI,
            'grant_type': 'authorization_code'
        }
        
        token_response = requests.post(GOOGLE_TOKEN_URL, data=token_data)
        token_json = token_response.json()
        
        if 'access_token' not in token_json:
            return jsonify({'message': 'Failed to get access token'}), 400
        
        # Get user info with access token
        access_token = token_json['access_token']
        user_response = requests.get(GOOGLE_USER_INFO_URL, headers={
            'Authorization': f'Bearer {access_token}'
        })
        
        google_user = user_response.json()
        
        if 'email' not in google_user:
            return jsonify({'message': 'Failed to get user email'}), 400
        
        # Check if user exists or create a new one
        user = handle_google_user(google_user)
        
        if not user:
            return jsonify({'message': 'Failed to authenticate with Google'}), 400
        
        # Create JWT token
        token = create_token(
            str(user['_id']),
            user.get('name', 'User'),
            user.get('role', 'User'),
            current_app.config['JWT_SECRET'],
            current_app.config['TOKEN_EXPIRY_DAYS']
        )
        
        # Return token and user info
        return jsonify({
            'token': token,
            'user': {
                'id': str(user['_id']),
                'name': user.get('name', 'User'),
                'email': user.get('email'),
                'role': user.get('role', 'User')
            }
        }), 200

def handle_google_user(google_user):
    """
    Process Google user data - check if user exists in our system
    or create a new one if they don't.
    """
    email = google_user.get('email')
    name = google_user.get('name', email.split('@')[0])
    
    try:
        # Check if user already exists in MongoDB
        user = current_app.mongo.db.users.find_one({'email': email})
        
        if user:
            # User exists, update last login
            current_app.mongo.db.users.update_one(
                {'_id': user['_id']},
                {'$set': {'last_login': datetime.datetime.utcnow()}}
            )
            return user
        
        # Create new user with default role
        user_data = {
            'name': name,
            'email': email,
            'role': 'User',  # Default role
            'google_id': google_user.get('sub'),
            'created_at': datetime.datetime.utcnow(),
            'last_login': datetime.datetime.utcnow(),
            'auth_type': 'google'
        }
        
        result = current_app.mongo.db.users.insert_one(user_data)
        user_data['_id'] = result.inserted_id
        return user_data
        
    except Exception as e:
        print(f"Error handling Google user: {str(e)}")
        return None

def hash_password(text_password):
    """
    Hash a password using SHA-256 and Base64 encoding
    """
    sha256 = hashlib.sha256()
    sha256.update(text_password.encode('utf-8'))
    hash_value = sha256.digest()
    hash_password = base64.b64encode(hash_value).decode('utf-8')

    return hash_password

@auth_routes.route('/me', methods=['GET'])
@token_required
def get_user():
    print(request.user)
    return jsonify({
        'id': request.user['sub'],
        'name': request.user['username'],
        'email': request.user.get('email', ''),
        'role': request.user['role']
    }), 200
    
@auth_routes.route('/signup', methods=['POST'])
def signup():
    """Register a new user with email and password."""
    try:
        data = request.get_json()
        
        # Validate input
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
            
        required_fields = ['name', 'email', 'password']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'message': f'{field} is required'}), 400
        
        name = data.get('name')
        email = data.get('email')
        password = data.get('password')
        
        # Check if email already exists
        existing_user = current_app.mongo.db.users.find_one({'email': email})
        if existing_user:
            return jsonify({'success': False, 'message': 'Email already registered'}), 409
        
        # Check if email is in allowed_emails.csv
        if not is_email_allowed(email):
            return jsonify({'success': False, 'message': 'This email is not authorized for registration'}), 403
        
        # Validate email domain
        domain = email.split('@')[-1] if '@' in email else ''
        if domain not in ALLOWED_EMAIL_DOMAINS:
            return jsonify({
                'success': False, 
                'message': f'Registration is only allowed for {", ".join(ALLOWED_EMAIL_DOMAINS)} email addresses'
            }), 403
            
        # Validate password with regex pattern
        if not re.match(PASSWORD_PATTERN, password):
            return jsonify({
                'success': False, 
                'message': 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character'
            }), 400
        
        # Hash the password before storing
        hashed_password = hash_password(password)
        
        # Create user document
        user_data = {
            'name': name,
            'email': email,
            'password': hashed_password,
            'role': 'User',  # Default role
            'created_at': datetime.datetime.utcnow(),
            'last_login': datetime.datetime.utcnow(),
            'auth_type': 'email'
        }
        
        # Insert the new user
        result = current_app.mongo.db.users.insert_one(user_data)
        
        # Generate JWT token for the new user
        token = create_token(
            str(result.inserted_id),
            name,
            'User',
            current_app.config['JWT_SECRET'],
            current_app.config['TOKEN_EXPIRY_DAYS']
        )
        
        return jsonify({
            'success': True,
            'message': 'User registered successfully',
            'token': token,
            'user': {
                'id': str(result.inserted_id),
                'name': name,
                'email': email,
                'role': 'User'
            }
        }), 201
        
    except Exception as e:
        print(f"Signup error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Registration failed',
            'error': str(e)
        }), 500

def is_email_allowed(email):
    """
    Check if the provided email exists in the allowed_emails.csv file.
    
    Args:
        email (str): Email address to check
        
    Returns:
        bool: True if email is in the allowed list, False otherwise
    """
    try:
        # Define the path to the CSV file
        csv_path = Config().get('rawfiles.users')
        
        # Check if file exists
        if not os.path.exists(csv_path):
            print(f"Warning: allowed_emails.csv not found at {csv_path}")
            return False
        
        df = pd.read_csv(csv_path)
        if df is not None and len(df) > 0:
            if df['Emails'].str.contains(email, case=False).any():
                return True  # Email found in the file
            else:
                return False
            
    except Exception as e:
        print(f"Error checking allowed emails: {str(e)}")
        # In case of error, default to not allowed for security
        return False
        
def prepare_flask_request(request):
    """Prepare SAML request from Flask request."""
    # Determine if HTTPS based on header or scheme
    is_https = request.scheme == 'https'
    
    # Some proxies set X-Forwarded-Proto header
    forwarded_proto = request.headers.get('X-Forwarded-Proto')
    if forwarded_proto:
        is_https = forwarded_proto == 'https'
    
    # Get host from headers, which may include port
    http_host = request.headers.get('Host', request.host)
    
    # Determine port from host or default
    server_port = '443' if is_https else '80'
    if ':' in http_host:
        host, port = http_host.split(':')
        server_port = port
        http_host = host
    
    return {
        'https': 'on' if is_https else 'off',
        'http_host': http_host,
        'server_port': server_port,
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy(),
        'query_string': request.query_string
    }

def manual_parse_metadata(metadata_file):
    """
    Manually parse IdP metadata XML if the OneLogin parser fails.
    This is a fallback method to extract the basic IdP information.
    """
    import xml.etree.ElementTree as ET
    
    try:
        logging.info(f"Attempting to manually parse metadata from {metadata_file}")
        
        # Register namespaces
        namespaces = {
            'md': 'urn:oasis:names:tc:SAML:2.0:metadata',
            'ds': 'http://www.w3.org/2000/09/xmldsig#'
        }
        
        tree = ET.parse(metadata_file)
        root = tree.getroot()
        
        # Extract entity ID
        entity_id = root.get('entityID')
        if not entity_id:
            for child in root:
                if 'EntityDescriptor' in child.tag:
                    entity_id = child.get('entityID')
                    break
        
        logging.info(f"Found entity ID: {entity_id}")
        
        # Find SSO service
        sso_url = None
        sso_binding = None
        
        for elem in root.iter():
            if 'SingleSignOnService' in elem.tag:
                sso_url = elem.get('Location')
                sso_binding = elem.get('Binding')
                if sso_url:
                    logging.info(f"Found SSO service: {sso_binding} at {sso_url}")
                    break
        
        # Find certificate
        cert = None
        for elem in root.iter():
            if 'X509Certificate' in elem.tag:
                cert = elem.text.strip()
                if cert:
                    logging.info("Found X509Certificate")
                    break
        
        # Build IdP data structure
        idp_data = {
            'idp': {
                'entityId': entity_id,
                'singleSignOnService': {
                    'url': sso_url,
                    'binding': sso_binding
                }
            }
        }
        
        if cert:
            idp_data['idp']['x509cert'] = cert
        
        return idp_data
        
    except Exception as e:
        logging.error(f"Manual metadata parsing failed: {str(e)}")
        raise

def init_saml_auth(req):
    """Initialize SAML authentication."""
    try:
        # Get configuration from the app config
        saml_config = Config.get('saml', {})
        
        # Get the metadata URL or file path
        metadata_source = saml_config.get('metadata_url') or os.environ.get('SAML_METADATA_URL')
        
        if not metadata_source:
            raise ValueError("SAML metadata source is required but not configured")
            
        logging.info(f"Using SAML metadata source: {metadata_source}")
        
        # Parse the IdP metadata from remote URL or local file
        try:
            if metadata_source.startswith(('http://', 'https://')):
                logging.info(f"Parsing remote metadata from {metadata_source}")
                idp_data = OneLogin_Saml2_IdPMetadataParser.parse_remote(metadata_source)
            else:
                logging.info(f"Parsing local metadata file from {metadata_source}")
                # Check if file exists and can be read
                if not os.path.isfile(metadata_source):
                    logging.error(f"Metadata file not found at {metadata_source}")
                    raise FileNotFoundError(f"SAML metadata file not found: {metadata_source}")
                
                # Read file content and check if it's valid XML
                with open(metadata_source, 'r') as f:
                    file_content = f.read()
                    
                logging.info(f"Read metadata file, content length: {len(file_content)}")
                
                # Check for XML content
                if not file_content.strip().startswith('<'):
                    logging.error(f"Metadata file does not appear to be XML: {file_content[:100]}...")
                    raise ValueError("SAML metadata file is not valid XML")
                    
                try:
                    idp_data = OneLogin_Saml2_IdPMetadataParser.parse(metadata_source)
                except Exception as parse_error:
                    logging.warning(f"OneLogin parser failed: {str(parse_error)}")
                    logging.info("Attempting to use manual fallback parser")
                    idp_data = manual_parse_metadata(metadata_source)
                
            logging.info(f"Successfully parsed IdP metadata with entity ID: {idp_data['idp'].get('entityId', 'UNKNOWN')}")
        except Exception as e:
            logging.error(f"Failed to parse IdP metadata: {str(e)}")
            raise
        
        # Get the scheme and host from the request
        https = req.get('https') == 'on'
        scheme = 'https' if https else 'http'
        host = req.get('http_host', '')
        
        # Ensure host doesn't already include scheme
        if host.startswith(('http://', 'https://')):
            app_base_url = host
        else:
            app_base_url = f"{scheme}://{host}"
        
        # Remove trailing slash if present
        app_base_url = app_base_url.rstrip('/')
        
        # Explicitly define ACS URL with full scheme, host and path
        acs_url = f"{app_base_url}/api/auth/saml/callback"
        entity_id = f"{app_base_url}/api/metadata"
        
        # Create SAML settings
        settings = {
            "strict": True,
            "debug": Config.get('flask', {}).get('debug', False),
            "sp": {
                "entityId": entity_id,
                "assertionConsumerService": {
                    "url": acs_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                },
                "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
            },
            "idp": idp_data['idp']
        }
        
        # Create SAML auth object
        auth = OneLogin_Saml2_Auth(req, settings)
        return auth
        
    except Exception as e:
        logging.error(f"SAML init error: {str(e)}")
        raise

@auth_routes.route('/auth/saml/init', methods=['GET'])
def saml_init():
    """Initiate SAML login flow."""
    try:
        req = prepare_flask_request(request)
        auth = init_saml_auth(req)
        
        # Get the IdP-initiated SSO URL
        sso_url = auth.login()
        
        return jsonify({'samlUrl': sso_url}), 200
        
    except Exception as e:
        logging.error(f"SAML Init Error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to initialize SAML authentication',
            'error': str(e)
        }), 500
        
@auth_routes.route('/auth/saml/callback', methods=['POST'])
def saml_callback():
    """Handle SAML response from IdP."""
    try:
        req = prepare_flask_request(request)
        auth = init_saml_auth(req)
        
        # Process the SAML response
        auth.process_response()
        
        # Check if authentication was successful
        errors = auth.get_errors()
        if errors:
            error_reason = auth.get_last_error_reason()
            
            # Prepare error message for frontend
            error_html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Authentication Failed</title>
                <script>
                    window.onload = function() {{
                        window.opener.postMessage(
                            {{
                                type: 'SAML_AUTH_ERROR',
                                payload: {{
                                    message: 'Authentication failed: {", ".join(errors)}'
                                }}
                            }},
                            window.location.origin
                        );
                        window.close();
                    }};
                </script>
            </head>
            <body>
                <p>Authentication failed! This window will close automatically.</p>
            </body>
            </html>
            """
            return error_html
        
        # Authentication successful
        if not auth.is_authenticated():
            return jsonify({'message': 'Authentication failed'}), 401
        
        # Get authenticated user details from SAML response
        saml_attributes = auth.get_attributes()
        nameID = auth.get_nameid()
        
        # Extract user details from SAML attributes
        email = nameID  # Often the nameID is the email
        name = email.split('@')[0] if '@' in email else email
        
        # Try to get better user info from attributes
        # Map common attribute names that might contain these values
        email_attrs = ['email', 'mail', 'emailAddress', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']
        name_attrs = ['displayName', 'name', 'givenName', 'cn', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name']
        
        # Try to find email in attributes
        for attr in email_attrs:
            if attr in saml_attributes and saml_attributes[attr]:
                email = saml_attributes[attr][0]
                break
                
        # Try to find name in attributes
        for attr in name_attrs:
            if attr in saml_attributes and saml_attributes[attr]:
                name = saml_attributes[attr][0]
                break
            
        # Check if user exists in our database or create a new one
        user = handle_saml_user(email, name, saml_attributes)
        
        if not user:
            return jsonify({'message': 'Failed to authenticate with SAML'}), 400
        
        # Create JWT token
        token = create_token(
            str(user['_id']),
            user.get('name', 'User'),
            user.get('role', 'User'),
            current_app.config['JWT_SECRET'],
            current_app.config['TOKEN_EXPIRY_DAYS']
        )
        
        # Respond with HTML that posts message to parent window and closes
        html_response = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authentication Successful</title>
            <script>
                window.onload = function() {{
                    window.opener.postMessage(
                        {{
                            type: 'SAML_AUTH_SUCCESS',
                            payload: {{
                                token: '{token}',
                                user: {{
                                    id: '{str(user["_id"])}',
                                    name: '{user.get("name", "User")}',
                                    email: '{user.get("email")}',
                                    role: '{user.get("role", "User")}'
                                }}
                            }}
                        }},
                        window.location.origin
                    );
                    window.close();
                }};
            </script>
        </head>
        <body>
            <p>Authentication successful! This window will close automatically.</p>
        </body>
        </html>
        """
        return html_response
        
    except Exception as e:
        logging.error(f"SAML Callback Error: {str(e)}")
        error_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authentication Error</title>
            <script>
                window.onload = function() {{
                    window.opener.postMessage(
                        {{
                            type: 'SAML_AUTH_ERROR',
                            payload: {{
                                message: 'Authentication error: {str(e)}'
                            }}
                        }},
                        window.location.origin
                    );
                    window.close();
                }};
            </script>
        </head>
        <body>
            <p>Authentication error! This window will close automatically.</p>
        </body>
        </html>
        """
        return error_html

@auth_routes.route('/metadata', methods=['GET'])
def metadata():
    """Serve the SP metadata XML for SAML configuration."""
    try:
        req = prepare_flask_request(request)
        auth = init_saml_auth(req)
        
        # Generate metadata XML
        settings = auth.get_settings()
        metadata = settings.get_sp_metadata()
        errors = settings.validate_metadata(metadata)

        if errors:
            return jsonify({'errors': errors}), 500

        # Return the XML with correct content type
        response = Response(metadata, mimetype='text/xml')
        response.headers['Content-Type'] = 'text/xml; charset=utf-8'
        return response
    except Exception as e:
        logging.error(f"Metadata generation error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Metadata generation failed',
            'error': str(e)
        }), 500

def handle_saml_user(email, name, attributes):
    """
    Process SAML user data - check if user exists in our system
    or create a new one if they don't.
    """
    try:
        # Check if user already exists in MongoDB
        user = current_app.mongo.db.users.find_one({'email': email})
        
        if user:
            # User exists, update last login and any other relevant attributes
            current_app.mongo.db.users.update_one(
                {'_id': user['_id']},
                {'$set': {
                    'last_login': datetime.datetime.utcnow(),
                    'name': name,  # Update name in case it changed
                    'saml_attributes': attributes  # Store the latest SAML attributes
                }}
            )
            return user
        
        # Create new user with default role
        user_data = {
            'name': name,
            'email': email,
            'role': 'User',  # Default role
            'created_at': datetime.datetime.utcnow(),
            'last_login': datetime.datetime.utcnow(),
            'auth_type': 'saml',
            'saml_attributes': attributes  # Store all attributes for reference
        }
        
        result = current_app.mongo.db.users.insert_one(user_data)
        user_data['_id'] = result.inserted_id
        return user_data
        
    except Exception as e:
        logging.error(f"Error handling SAML user: {str(e)}")
        return None
