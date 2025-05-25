# pyright: basic
from datetime import timedelta
import json
import os
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email import encoders
import mimetypes
import hashlib
from typing import List, Optional
import logging

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.transport.requests import Request

import flask
from flask import flash, request, redirect, jsonify, current_app
from werkzeug.utils import secure_filename

IS_PRODUCTION = os.environ.get("RENDER") == "true"
CLIENT_SECRETS_FILE = ".client_secret.json"

app = flask.Flask(__name__)

# --- Logging Configuration ---
if IS_PRODUCTION:
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)

app.debug = os.environ.get("FLASK_DEBUG", "False").lower() == "true"

if not app.debug: 
    app.logger.setLevel(logging.INFO)
else:
    app.logger.setLevel(logging.DEBUG)

app.logger.info(f"Flask app initialized. Production: {IS_PRODUCTION}, Debug: {app.debug}")

app.secret_key = os.environ.get("FLASK_SECRET_KEY") or None

if not app.secret_key and IS_PRODUCTION:
    app.logger.critical("FATAL: FLASK_SECRET_KEY is not set in production!")
elif not app.secret_key:
    app.logger.warning("FLASK_SECRET_KEY not set, using default for development. THIS IS INSECURE FOR PRODUCTION.")
    app.secret_key = "jero-aurora"

# Client secret configuration
if IS_PRODUCTION:
    CLIENT_SECRETS_FILE = "/etc/secrets/.client_secret.json"
    if os.path.exists(CLIENT_SECRETS_FILE):
        client_secret_json_str = os.environ.get("GOOGLE_CLIENT_SECRET_JSON")
        app.logger.info(f"Successfully loaded {CLIENT_SECRETS_FILE} from environment variable.")
    else:
        app.logger.critical(f"FATAL: GOOGLE_CLIENT_SECRET_JSON environment variable not set in production.")
elif not os.path.exists(CLIENT_SECRETS_FILE):
    app.logger.warning(f"{CLIENT_SECRETS_FILE} not found for local development.")

# OAuth Redirect URI and Insecure Transport
if IS_PRODUCTION:
    render_url = os.environ.get("RENDER_EXTERNAL_URL")
    if not render_url:
        app.logger.warning("RENDER_EXTERNAL_URL not found in production environment! Using Fallback")
        REDIRECT_URI = "https://emailer-run.onrender.com/login/callback"
    else:
        REDIRECT_URI = f"{render_url}/login/callback"
    if "OAUTHLIB_INSECURE_TRANSPORT" in os.environ:
        del os.environ["OAUTHLIB_INSECURE_TRANSPORT"]
else:
    REDIRECT_URI = "http://localhost:8000/login/callback"
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"

app.logger.info(f"Using REDIRECT_URI: {REDIRECT_URI}")

SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/gmail.send",
]

class EmailService:
    def __init__(self, service, logger):
        self.service = service
        self.logger = logger
        self.logger.info("EmailService initialized.")
    
    def send_bulk_email(self, recipients: List[str], subject: str, body: str, 
                       cc: str = "", bcc: str = "", attachments: List = None, 
                       signature_file = None, sender_email: str = ""):
        self.logger.info(f"Starting bulk email send to {len(recipients)} recipients. Subject: '{subject}'")
        results = []
        attachments = attachments or []
        
        for recipient in recipients:
            recipient_email = recipient.strip()
            self.logger.debug(f"Processing recipient: {recipient_email} in send_bulk_email loop.")
            try:
                result = self._send_single_email(
                    recipient=recipient_email,
                    subject=subject,
                    body=body,
                    cc=cc,
                    bcc=bcc,
                    attachments=attachments,
                    signature_file=signature_file,
                    sender_email=sender_email
                )
                results.append({
                    "recipient": recipient_email,
                    "status": "success",
                    "message_id": result.get('id')
                })
                self.logger.info(f"Successfully prepared and sent email for {recipient_email}. Message ID: {result.get('id')}")
            except Exception as e:
                self.logger.error(f"Failed to send email to {recipient_email} (error caught in send_bulk_email): {e}", exc_info=True)
                results.append({
                    "recipient": recipient_email,
                    "status": "error",
                    "error": str(e)
                })
        
        self.logger.info(f"Bulk email sending complete. Success: {sum(1 for r in results if r['status'] == 'success')}, Failed: {sum(1 for r in results if r['status'] == 'error')}")
        return results


    def _send_single_email(self, recipient: str, subject: str, body: str,
                          cc: str = "", bcc: str = "", attachments: List = None,
                          signature_file = None, sender_email: str = ""):
        self.logger.info(f"--- ENTERING _send_single_email for {recipient} ---")
        try:
            self.logger.debug(f"Recipient: {recipient}, Subject: '{subject}', Sender: {sender_email}")
            
            message = MIMEMultipart("related")
            message["To"] = recipient
            message["From"] = sender_email
            message["Subject"] = subject
            self.logger.debug("MIMEMultipart('related') created and basic headers set.")

            if cc:
                message["Cc"] = cc
                self.logger.debug(f"CC set to: {cc}")
            if bcc:
                message["Bcc"] = bcc
                self.logger.debug(f"BCC set to: {bcc}")

            message_alt = MIMEMultipart("alternative")
            self.logger.debug("MIMEMultipart('alternative') created for text/html bodies.")

            text_part = MIMEText(body, "plain", "utf-8")
            message_alt.attach(text_part)
            self.logger.debug("Plain text part created and attached to alternative.")

            message.attach(message_alt)
            self.logger.debug("Multipart/alternative (with plain text) attached to main message.")

            self.logger.debug("Attempting to create HTML body (which may embed signature to main 'message')...")
            html_body_content = self._create_html_body(body, message, signature_file)
            self.logger.debug("HTML body content string created.")
            
            html_part = MIMEText(html_body_content, "html", "utf-8")
            message_alt.attach(html_part)
            self.logger.debug("HTML part created and attached to alternative.")

            # Add general attachments to the main 'message' (multipart/related)
            # These will appear after the multipart/alternative and after the signature image.
            if attachments:
                self.logger.info(f"Processing {len(attachments)} general attachments.")
                for file_idx, file_obj in enumerate(attachments):
                    if file_obj and file_obj.filename:
                        self.logger.debug(f"Adding general attachment {file_idx + 1}: {file_obj.filename}")
                        self._add_attachment(message, file_obj)
                    else:
                        self.logger.debug(f"Skipping general attachment {file_idx+1} (no file/filename).")
            else:
                self.logger.debug("No general attachments to process.")

            self.logger.debug("All parts prepared. Calling _debug_message...")
            self._debug_message(message)
            self.logger.info(f"Attempting to send email to {recipient} via Gmail API (after _debug_message).")
            return self._send_via_gmail_api(message)
        except Exception as e:
            self.logger.error(f"--- ERROR within _send_single_email for {recipient} BEFORE API call: {e} ---", exc_info=True)
            raise

    def _create_html_body(self, body: str, message: MIMEMultipart, signature_file) -> str:
        self.logger.debug("--- ENTERING _create_html_body ---")
        body_str = str(body) if body is not None else ""

        signature_html = self._get_signature_html(message, signature_file)
        html_body_content = f"""
        <html>
        <body>
            <div style="font-family: Arial, sans-serif; line-height: 1.6;">
                {body_str.replace('\n', '<br>')}
                {signature_html}
            </div>
        </body>
        </html>
        """
        self.logger.debug(f"HTML body created in _create_html_body. Signature included: {bool(signature_html)}")
        self.logger.debug("--- LEAVING _create_html_body ---")
        return html_body_content
    
    def _get_signature_html(self, msg: MIMEMultipart, signature_file) -> str:
        self.logger.debug("--- ENTERING _get_signature_html ---")
        if not signature_file or not signature_file.filename:
            self.logger.debug("No signature file provided or filename is empty in _get_signature_html.")
            self.logger.debug("--- LEAVING _get_signature_html (no signature) ---")
            return ""
        
        self.logger.info(f"Processing signature file in _get_signature_html: {signature_file.filename}")
        try:
            cid = f"signature_{hashlib.md5(signature_file.filename.encode()).hexdigest()}"
            self.logger.debug(f"Signature CID generated: {cid}")
            
            self.logger.debug(f"Reading signature file content for {signature_file.filename}...")
            file_content = signature_file.read()
            self.logger.debug(f"Signature file content read ({len(file_content)} bytes). Seeking to 0 for {signature_file.filename}.")
            signature_file.seek(0)
            self.logger.debug(f"Creating MIMEImage for signature {signature_file.filename}...")

            actual_subtype = mimetypes.guess_type(signature_file.filename)[0]
            if actual_subtype:
                actual_subtype = actual_subtype.split('/')[-1]
                self.logger.debug(f"Using subtype '{actual_subtype}' for signature MIMEImage.")
                img = MIMEImage(file_content, _subtype=actual_subtype)
            else:
                self.logger.debug(f"Creating MIMEImage for signature {signature_file.filename}...")
                img = MIMEImage(file_content)

            img.add_header('Content-ID', f'<{cid}>')
            img.add_header('Content-Disposition', 'inline', filename=signature_file.filename)
            self.logger.debug(f"Attaching MIMEImage (signature) {signature_file.filename} to message...")
            msg.attach(img)
            self.logger.info(f"Signature image '{signature_file.filename}' embedded with CID: {cid}")
            
            html_to_return = f"""
            <div style="margin-top: 20px; padding-top: 10px;">
                <img src="cid:{cid}" 
                     alt="Signature" 
                     style="max-width: 300px; height: auto; display: block;">
            </div>
            """
            self.logger.debug("--- LEAVING _get_signature_html (SUCCESS) ---")
            return html_to_return
        except Exception as e:
            self.logger.error(f"Error processing signature file '{signature_file.filename}' in _get_signature_html: {e}", exc_info=True)
            self.logger.debug("--- LEAVING _get_signature_html (ERROR) ---")
            return "" 
    
    def _add_attachment(self, msg: MIMEMultipart, file_storage_obj):
        self.logger.debug(f"--- ENTERING _add_attachment for {file_storage_obj.filename} ---")
        try:
            filename = file_storage_obj.filename
            self.logger.debug(f"Processing attachment: {filename}")

            content_type, encoding = mimetypes.guess_type(filename)
            self.logger.debug(f"Guessed content_type: {content_type}, encoding: {encoding} for {filename}")
            if content_type is None or encoding is not None:
                content_type = 'application/octet-stream'
                self.logger.debug(f"Defaulted content_type to 'application/octet-stream' for {filename}")
            
            main_type, sub_type = content_type.split('/', 1)
            self.logger.debug(f"Reading content of attachment: {filename}")
            file_content = file_storage_obj.read()
            self.logger.debug(f"Attachment content read ({len(file_content)} bytes). Seeking to 0 for {filename}.")
            file_storage_obj.seek(0)
            
            attachment_part = None 
            if main_type == 'image':
                self.logger.debug(f"Creating MIMEImage for attachment: {filename}")
                attachment_part = MIMEImage(file_content, _subtype=sub_type)
            else: 
                self.logger.debug(f"Creating MIMEBase for attachment: {filename}, main_type: {main_type}, sub_type: {sub_type}")
                attachment_part = MIMEBase(main_type, sub_type)
                attachment_part.set_payload(file_content)
                self.logger.debug(f"Encoding MIMEBase attachment: {filename}")
                encoders.encode_base64(attachment_part)
            
            attachment_part.add_header(
                'Content-Disposition',
                f'attachment; filename="{filename}"'
            )
            self.logger.debug(f"Content-Disposition header set for {filename}")
            
            msg.attach(attachment_part)
            self.logger.info(f"Successfully created and attached MIME part for attachment: {filename}")
            self.logger.debug(f"--- LEAVING _add_attachment for {filename} (SUCCESS) ---")
            
        except Exception as e:
            self.logger.error(f"Error in _add_attachment for {file_storage_obj.filename}: {e}", exc_info=True)
            self.logger.debug(f"--- LEAVING _add_attachment for {file_storage_obj.filename} (ERROR) ---")
            raise
    
    def _debug_message(self, msg: MIMEMultipart):
        self.logger.debug("=== MESSAGE DEBUG START ===")
        self.logger.debug(f"Message headers: {dict(msg.items())}")
        payload = msg.get_payload()
        if isinstance(payload, list):
            self.logger.debug(f"Message parts: {len(payload)}")
            for i, part in enumerate(payload):
                self.logger.debug(f"Part {i}: Content-Type='{part.get_content_type()}', "
                                 f"Content-Disposition='{part.get('Content-Disposition')}', "
                                 f"Filename='{part.get_filename()}', "
                                 f"CID='{part.get('Content-ID')}'")
                if part.get_content_maintype() == 'multipart':
                    self.logger.debug(f"  Sub-Part {i} details ({part.get_content_type()}):")
                    for j, sub_part in enumerate(part.get_payload()):
                        self.logger.debug(f"    Sub-Part {i}.{j}: Content-Type='{sub_part.get_content_type()}', "
                                         f"Charset='{sub_part.get_charset()}', "
                                         f"Filename='{sub_part.get_filename()}'")
        else:
             self.logger.debug(f"Message payload (not a list): Content-Type='{msg.get_content_type()}'")
        self.logger.debug("=== MESSAGE DEBUG END ===")
    
    def _send_via_gmail_api(self, msg: MIMEMultipart):
        try:
            self.logger.info("Attempting to send email via Gmail API (Method 1: as_string, utf-8 encode)")
            raw_message = msg.as_string()
            encoded_message = base64.urlsafe_b64encode(raw_message.encode('utf-8')).decode('ascii')
            create_message = {"raw": encoded_message}
            
            self.logger.debug("Executing Gmail API send request (Method 1)")
            result = (
                self.service.users()
                .messages()
                .send(userId="me", body=create_message)
                .execute()
            )
            self.logger.info(f"Email sent successfully (Method 1). Message ID: {result.get('id')}")
            return result
        except Exception as e1:
            self.logger.warning(f"Gmail API send (Method 1) failed: {e1}", exc_info=True)
            self.logger.info("Attempting to send email via Gmail API (Method 2: as_bytes)")
            try:
                raw_message = msg.as_bytes() 
                encoded_message = base64.urlsafe_b64encode(raw_message).decode('ascii')
                create_message = {"raw": encoded_message}
                
                self.logger.debug("Executing Gmail API send request (Method 2)")
                result = (
                    self.service.users()
                    .messages()
                    .send(userId="me", body=create_message)
                    .execute()
                )
                self.logger.info(f"Email sent successfully with (Method 2). Message ID: {result.get('id')}")
                return result
            except HttpError as e:
                error_content = e.content.decode('utf-8') if hasattr(e, 'content') and e.content else str(e.resp)
                self.logger.error(f"Gmail API HttpError (Method 2): {e.resp.status} - {error_content}", exc_info=True)
                raise Exception(f"Gmail API error ({e.resp.status}): {error_content}")
            except Exception as e2:
                self.logger.error(f"Both Gmail API send methods failed. Method 1 error: {e1}, Method 2 error: {e2}", exc_info=True)
                raise Exception(f"Failed to send email after trying multiple methods: {e2}")

def get_gmail_service():
    """Get authenticated Gmail service"""
    logger = current_app.logger
    logger.debug("Attempting to get Gmail service.")
    creds = None
    
    if "credentials" in flask.session:
        logger.debug("Credentials found in session.")
        try:
            creds = Credentials.from_authorized_user_info(
                json.loads(flask.session["credentials"])
            )
        except Exception as e:
            logger.error(f"Error loading credentials from session: {e}", exc_info=True)
            flask.session.pop("credentials", None)
            return None
    
    if not creds or not creds.valid:
        if creds: # creds exist but are not valid
            logger.warning(f"Credentials invalid. Expired: {creds.expired}, Refresh Token: {bool(creds.refresh_token)}")
            if creds.expired and creds.refresh_token:
                logger.info("Attempting to refresh credentials.")
                try:
                    creds.refresh(Request())
                    flask.session["credentials"] = creds.to_json()
                    logger.info("Credentials refreshed successfully.")
                except Exception as e:
                    logger.error(f"Error refreshing credentials: {e}", exc_info=True)
                    flask.session.pop("credentials", None) # Clear failed refresh attempt
                    flask.session.pop("user_info", None)
                    return None
            else: # No refresh token or not expired but invalid
                logger.warning("Credentials invalid and cannot be refreshed. User needs to re-authenticate.")
                flask.session.pop("credentials", None)
                flask.session.pop("user_info", None)
                return None
        else: # No creds at all
            logger.info("No valid credentials found in session. User needs to authenticate.")
            return None
    
    try:
        logger.debug("Building Gmail service.")
        service = build("gmail", "v1", credentials=creds)
        logger.info("Gmail service built successfully.")
        return service
    except Exception as e:
        logger.error(f"Error building Gmail service: {e}", exc_info=True)
        return None

@app.route("/")
def read_root():
    app.logger.info("Root route '/' accessed.")
    user_info = flask.session.get("user_info")
    is_authorized = False
    username = None

    if user_info and user_info.get("isAuthorized"):
        is_authorized = True
        # Prefer 'name' or 'given_name' for display if available, fallback to email
        username = user_info.get("name", user_info.get("given_name", user_info.get("email")))
        app.logger.debug(f"User {username} is authorized.")
    else:
        app.logger.debug("User is not authorized.")
        
    return flask.render_template(
        "index.html",
        isAuthorized=is_authorized,
        username=username
    )
@app.get("/login")
def authorize():
    app.logger.info("Login route '/login' accessed. Initiating OAuth flow.")
    try:
        flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
        flow.redirect_uri = REDIRECT_URI
        
        authorization_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent", 
        )
        
        flask.session["state"] = state
        app.logger.info(f"Authorization URL generated. Redirecting user. State: {state}")
        return flask.redirect(authorization_url)
    except FileNotFoundError:
        app.logger.critical(f"{CLIENT_SECRETS_FILE} not found. Cannot initiate OAuth flow.")
        return f"Error: Server configuration issue ({CLIENT_SECRETS_FILE} missing). Please contact admin.", 500
    except Exception as e:
        app.logger.error(f"Error in /login route: {e}", exc_info=True)
        return "An unexpected error occurred during login initiation.", 500


@app.route("/login/callback")
def login_callback():
    app.logger.info("Login callback '/login/callback' accessed.")
    try:
        state = flask.session.get("state")
        if not state:
            app.logger.error("Invalid session state in callback.")
            return "Error: Invalid session state. Please try logging in again.", 400
        
        app.logger.debug(f"Session state: {state}")
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE, scopes=SCOPES, state=state
        )
        flow.redirect_uri = REDIRECT_URI
        
        authorization_response = flask.request.url
        app.logger.debug(f"Authorization response URL: {authorization_response}")
        flow.fetch_token(authorization_response=authorization_response)
        app.logger.info("Token fetched successfully.")
        
        credentials = flow.credentials
        flask.session["credentials"] = credentials.to_json()
        app.logger.info("Credentials stored in session.")
        
        granted_scopes = set(credentials.granted_scopes or [])
        app.logger.debug(f"Granted scopes: {granted_scopes}")
        all_scopes_granted = True
        missing_scopes = []
        for scope in SCOPES:
            if scope not in granted_scopes:
                app.logger.warning(f"Required scope '{scope}' not granted.")
                all_scopes_granted = False
                missing_scopes.append(scope)
        
        if not all_scopes_granted:
             app.logger.error(f"Required permissions not granted by user. Missing: {missing_scopes}")
             flask.session.clear() # Clear all session data for clean re-auth
             return f"Error: Required permissions not granted ({', '.join(missing_scopes)}). Please ensure all requested scopes are approved during login.", 403
        
        app.logger.debug("Fetching user info.")
        user_info_service = build("oauth2", "v2", credentials=credentials)
        user_info = user_info_service.userinfo().get().execute()
        user_info["isAuthorized"] = True
        flask.session["user_info"] = user_info
        app.logger.info(f"User info fetched and stored in session for: {user_info.get('email')}")
        
        return flask.redirect("/compose")
        
    except FileNotFoundError:
        app.logger.critical(f"{CLIENT_SECRETS_FILE} not found during callback. Cannot complete OAuth flow.")
        flask.session.clear()
        return f"Error: Server configuration issue ({CLIENT_SECRETS_FILE} missing). Please contact admin.", 500
    except Exception as e:
        app.logger.error(f"Login callback error: {e}", exc_info=True)
        flask.session.clear()
        return f"Authentication error: {str(e)}. Please try logging in again.", 500

@app.route("/compose", methods=["GET", "POST"])
def compose():
    logger = current_app.logger
    if request.method == "GET":
        logger.info("Compose route '/compose' accessed (GET).")
        user = flask.session.get("user_info")
        if not user or not user.get("isAuthorized"): # Check authorization flag
            logger.warning("User not authenticated or not authorized for compose page. Redirecting to login.")
            return flask.redirect("/login")
        logger.debug(f"User {user.get('email')} accessing compose page.")
        return flask.render_template("compose.html", user=user)
    
    if request.method == "POST":
        logger.info("Compose route '/compose' accessed (POST) - attempting to send email.")
        try:
            if "user_info" not in flask.session or not flask.session["user_info"].get("isAuthorized"):
                logger.warning("Attempt to send email without proper authentication/authorization.")
                return jsonify({"status": "error", "message": "Not authenticated or authorized. Please log in."}), 401
            
            user_email = flask.session["user_info"]["email"]
            logger.info(f"Email send request initiated by user: {user_email}")

            service = get_gmail_service()
            if not service:
                logger.error("Gmail service unavailable for sending email.")
                return jsonify({"status": "error", "message": "Gmail service unavailable. Please try logging in again."}), 401
            
            data = request.form
            recipients_str = data.get("recipientsList", "")
            logger.debug(f"Recipients string from form: '{recipients_str}'")
            if not recipients_str.strip():
                logger.warning("No recipients specified in form.")
                return jsonify({"status": "error", "message": "No recipients specified"}), 400
            
            recipients = [r.strip() for r in recipients_str.split(",") if r.strip()]
            subject = data.get("subject", "")
            body = data.get("body", "")
            cc = data.get("Cc", "")
            bcc = data.get("Cco", "") 
            
            logger.info(f"Form data received: Recipients: {len(recipients)}, Subject: '{subject}', CC: '{cc}', BCC: '{bcc}'")

            attachments_from_form = []
            files = request.files.getlist("file")
            if files:
                logger.info(f"Processing {len(files)} potential file attachments.")
                for file_idx, file_storage in enumerate(files): # file_storage is a FileStorage object
                    if file_storage and file_storage.filename:
                        original_filename = file_storage.filename
                        # Secure filename happens ONCE here before passing FileStorage object around
                        secured_filename = secure_filename(file_storage.filename)
                        if not secured_filename: # secure_filename might return empty if original is dangerous/empty
                            logger.warning(f"Filename '{original_filename}' became empty after securing. Skipping.")
                            continue
                        file_storage.filename = secured_filename # Overwrite FileStorage's filename attribute
                        attachments_from_form.append(file_storage)
                        logger.debug(f"Attachment {file_idx+1}: '{original_filename}' (secured to '{file_storage.filename}') added to list.")
                    elif file_storage and not file_storage.filename:
                        logger.debug(f"Attachment {file_idx+1} has no filename, skipping.")
            else:
                logger.info("No file attachments found in request.")

            signature_file_from_form = None
            signature_file_storage = request.files.get('signature') # FileStorage object
            if signature_file_storage and signature_file_storage.filename:
                original_sig_filename = signature_file_storage.filename
                secured_sig_filename = secure_filename(signature_file_storage.filename)
                if not secured_sig_filename:
                    logger.warning(f"Signature filename '{original_sig_filename}' became empty after securing. Not using signature.")
                else:
                    signature_file_storage.filename = secured_sig_filename # Overwrite
                    signature_file_from_form = signature_file_storage
                    logger.info(f"Signature file '{original_sig_filename}' (secured to '{signature_file_storage.filename}') found.")
            else:
                logger.info("No signature file provided or filename is empty.")
            
            email_service = EmailService(service, logger) 
            results = email_service.send_bulk_email(
                recipients=recipients,
                subject=subject,
                body=body,
                cc=cc,
                bcc=bcc,
                attachments=attachments_from_form, # Pass list of FileStorage objects
                signature_file=signature_file_from_form, # Pass FileStorage object or None
                sender_email=user_email
            )
            
            successful = [r for r in results if r["status"] == "success"]
            failed = [r for r in results if r["status"] == "error"]
            
            logger.info(f"Email sending process completed. Total: {len(results)}, Successful: {len(successful)}, Failed: {len(failed)}")
            
            response_data = {
                "status": "completed",
                "total": len(results),
                "successful": len(successful),
                "failed": len(failed),
                "results": results
            }
            
            if failed:
                response_data["message"] = f"Sent to {len(successful)}/{len(results)} recipients. Some errors occurred."
            else:
                response_data["message"] = f"Successfully sent to all {len(successful)} recipients."
            
            logger.debug(f"Sending response: {response_data}")
            return jsonify(response_data)
            
        except Exception as e:
            logger.error(f"Error in /compose POST handler: {e}", exc_info=True)
            return jsonify({"status": "error", "message": f"An unexpected server error occurred: {str(e)}"}), 500

if __name__ == "__main__":
    if not IS_PRODUCTION:
        app.run(host="localhost", port=8000, debug=app.debug)
        app.logger.info("Starting Flask development server.")
    else:
        app.logger.info("Running in production mode - Gunicorn should be managing this process.")
