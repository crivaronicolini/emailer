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

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.transport.requests import Request

import flask
from flask import flash, request, redirect, jsonify
from werkzeug.utils import secure_filename

CLIENT_SECRETS_FILE = ".client_secret.json"
SCOPES = [
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]
REDIRECT_URI = "http://localhost:8000/login/callback"

app = flask.Flask(__name__)
app.secret_key = "your-secret-key-here"  # Change this in production

class EmailService:
    def __init__(self, service):
        self.service = service
    
    def send_bulk_email(self, recipients: List[str], subject: str, body: str, 
                       cc: str = "", bcc: str = "", attachments: List = None, 
                       signature_file = None, sender_email: str = ""):
        """Send the same email to multiple recipients individually"""
        results = []
        attachments = attachments or []
        
        for recipient in recipients:
            try:
                result = self._send_single_email(
                    recipient=recipient.strip(),
                    subject=subject,
                    body=body,
                    cc=cc,
                    bcc=bcc,
                    attachments=attachments,
                    signature_file=signature_file,
                    sender_email=sender_email
                )
                results.append({
                    "recipient": recipient.strip(),
                    "status": "success",
                    "message_id": result.get('id')
                })
            except Exception as e:
                results.append({
                    "recipient": recipient.strip(),
                    "status": "error",
                    "error": str(e)
                })
        
        return results
    
    def _send_single_email(self, recipient: str, subject: str, body: str,
                          cc: str = "", bcc: str = "", attachments: List = None,
                          signature_file = None, sender_email: str = ""):
        """Send email to a single recipient"""
        message = MIMEMultipart("related")
        message["To"] = recipient
        message["From"] = sender_email
        message["Subject"] = subject
        
        if cc:
            message["Cc"] = cc
        if bcc:
            message["Bcc"] = bcc
        
        # Create the email body
        html_body = self._create_html_body(body, message, signature_file)
        
        # Create multipart alternative for text and HTML
        message_alt = MIMEMultipart("alternative")
        message.attach(message_alt)
        
        # Add plain text version
        text_part = MIMEText(body, "plain", "utf-8")
        message_alt.attach(text_part)
        
        # Add HTML version
        html_part = MIMEText(html_body, "html", "utf-8")
        message_alt.attach(html_part)
        
        # Add attachments
        if attachments:
            for file in attachments:
                if file and file.filename:
                    self._add_attachment(message, file)
        
        self._debug_message(message)
        return self._send_via_gmail_api(message)
    
    def _create_html_body(self, body: str, message: MIMEMultipart, signature_file) -> str:
        """Create HTML email body with optional signature"""
        html_body = f"""
        <html>
        <body>
            <div style="font-family: Arial, sans-serif; line-height: 1.6;">
                {body.replace('\n', '<br>')}
                {self._get_signature_html(message, signature_file)}
            </div>
        </body>
        </html>
        """
        return html_body
    
    def _get_signature_html(self, msg: MIMEMultipart, signature_file) -> str:
        """Embed signature image using Content-ID"""
        if not signature_file or not signature_file.filename:
            return ""
        
        try:
            # Create unique CID
            cid = f"signature_{hashlib.md5(signature_file.filename.encode()).hexdigest()}"
            
            # Read file content
            file_content = signature_file.read()
            signature_file.seek(0)  # Reset file pointer
            
            # Create image attachment with CID
            img = MIMEImage(file_content)
            img.add_header('Content-ID', f'<{cid}>')
            img.add_header('Content-Disposition', 'inline', filename=signature_file.filename)
            msg.attach(img)
            
            # Return HTML that references the CID
            return f"""
            <div style="margin-top: 20px; border-top: 1px solid #ccc; padding-top: 10px;">
                <img src="cid:{cid}" 
                     alt="Signature" 
                     style="max-width: 300px; height: auto; display: block;">
            </div>
            """
        except Exception as e:
            print(f"Error processing signature: {e}")
            return ""
    
    def _add_attachment(self, msg: MIMEMultipart, file):
        """Add a file as an attachment to the email"""
        try:
            # Get MIME type
            content_type, encoding = mimetypes.guess_type(file.filename)
            if content_type is None or encoding is not None:
                content_type = 'application/octet-stream'
            
            main_type, sub_type = content_type.split('/', 1)
            file_content = file.read()
            file.seek(0)  # Reset file pointer
            
            if main_type == 'image':
                attachment = MIMEImage(file_content, _subtype=sub_type)
            else:
                attachment = MIMEBase(main_type, sub_type)
                attachment.set_payload(file_content)
                encoders.encode_base64(attachment)
            
            attachment.add_header(
                'Content-Disposition',
                f'attachment; filename="{file.filename}"'
            )
            
            msg.attach(attachment)
            
        except Exception as e:
            print(f"Error adding attachment {file.filename}: {e}")
            raise
    
    def _debug_message(self, msg: MIMEMultipart):
        """Debug helper to inspect the message structure"""
        print("=== MESSAGE DEBUG ===")
        print(f"Message headers: {dict(msg.items())}")
        print(f"Message parts: {len(msg.get_payload())}")
        for i, part in enumerate(msg.get_payload()):
            print(f"Part {i}: {part.get_content_type()}")
        print("=== END DEBUG ===")
    
    def _send_via_gmail_api(self, msg: MIMEMultipart):
        """Send email via Gmail API"""
        try:
            # Method 1: Standard approach (try this first)
            raw_message = msg.as_string()
            encoded_message = base64.urlsafe_b64encode(raw_message.encode('utf-8')).decode('ascii')
            
            create_message = {"raw": encoded_message}
            
            result = (
                self.service.users()
                .messages()
                .send(userId="me", body=create_message)
                .execute()
            )
            
            print(f"Email sent successfully. Message ID: {result.get('id')}")
            return result
            
        except Exception as e1:
            print(f"Method 1 failed: {e1}")
            try:
                # Method 2: Alternative encoding approach
                raw_message = msg.as_bytes()
                encoded_message = base64.urlsafe_b64encode(raw_message).decode('ascii')
                
                create_message = {"raw": encoded_message}
                
                result = (
                    self.service.users()
                    .messages()
                    .send(userId="me", body=create_message)
                    .execute()
                )
                
                print(f"Email sent successfully with method 2. Message ID: {result.get('id')}")
                return result
                
            except HttpError as e:
                error_content = e.content.decode('utf-8') if hasattr(e, 'content') else str(e)
                print(f"Gmail API HttpError: {e.resp.status} - {error_content}")
                raise Exception(f"Gmail API error ({e.resp.status}): {error_content}")
            except Exception as e2:
                print(f"Both methods failed. Method 1: {e1}, Method 2: {e2}")
                raise Exception(f"Failed to send email after trying multiple methods: {e2}")

def get_gmail_service():
    """Get authenticated Gmail service"""
    creds = None
    
    if "credentials" in flask.session:
        creds = Credentials.from_authorized_user_info(
            json.loads(flask.session["credentials"])
        )
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                flask.session["credentials"] = creds.to_json()
            except Exception as e:
                print(f"Error refreshing credentials: {e}")
                return None
        else:
            return None
    
    try:
        service = build("gmail", "v1", credentials=creds)
        return service
    except Exception as e:
        print(f"Error building Gmail service: {e}")
        return None

@app.route("/")
def read_root():
    return flask.render_template("index.html")

@app.get("/login")
def authorize():
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri = REDIRECT_URI
    
    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    
    flask.session["state"] = state
    return flask.redirect(authorization_url)

@app.route("/login/callback")
def login_callback():
    try:
        state = flask.session.get("state")
        if not state:
            return "Error: Invalid session state", 400
        
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE, scopes=SCOPES, state=state
        )
        flow.redirect_uri = REDIRECT_URI
        
        authorization_response = flask.request.url
        flow.fetch_token(authorization_response=authorization_response)
        
        credentials = flow.credentials
        flask.session["credentials"] = credentials.to_json()
        
        # Verify required scopes
        for scope in SCOPES:
            if scope not in credentials.granted_scopes:
                return "Error: Required permissions not granted", 403
        
        # Get user info
        user_info_service = build("oauth2", "v2", credentials=credentials)
        user_info = user_info_service.userinfo().get().execute()
        user_info["isAuthorized"] = True
        flask.session["user_info"] = user_info
        
        return flask.redirect("/compose")
        
    except Exception as e:
        print(f"Login callback error: {e}")
        return f"Authentication error: {str(e)}", 500

@app.route("/compose", methods=["GET", "POST"])
def compose():
    if request.method == "GET":
        user = flask.session.get("user_info")
        if not user:
            return flask.redirect("/login")
        return flask.render_template("compose.html", user=user)
    
    if request.method == "POST":
        try:
            # Check authentication
            if "user_info" not in flask.session:
                return jsonify({"status": "error", "message": "Not authenticated"}), 401
            
            service = get_gmail_service()
            if not service:
                return jsonify({"status": "error", "message": "Gmail service unavailable"}), 401
            
            # Get form data
            data = request.form
            recipients_str = data.get("recipientsList", "")
            if not recipients_str.strip():
                return jsonify({"status": "error", "message": "No recipients specified"}), 400
            
            recipients = [r.strip() for r in recipients_str.split(",") if r.strip()]
            subject = data.get("subject", "")
            body = data.get("body", "")
            cc = data.get("Cc", "")
            bcc = data.get("Cco", "")
            user_email = flask.session["user_info"]["email"]
            
            # Handle attachments
            attachments = []
            files = request.files.getlist("file")
            for file in files:
                if file and file.filename:
                    file.filename = secure_filename(file.filename)
                    attachments.append(file)
            
            # Handle signature
            signature_file = request.files.get('signature')
            if signature_file and signature_file.filename:
                signature_file.filename = secure_filename(signature_file.filename)
            else:
                signature_file = None
            
            # Send emails
            email_service = EmailService(service)
            results = email_service.send_bulk_email(
                recipients=recipients,
                subject=subject,
                body=body,
                cc=cc,
                bcc=bcc,
                attachments=attachments,
                signature_file=signature_file,
                sender_email=user_email
            )
            
            # Check results
            successful = [r for r in results if r["status"] == "success"]
            failed = [r for r in results if r["status"] == "error"]
            
            response_data = {
                "status": "completed",
                "total": len(results),
                "successful": len(successful),
                "failed": len(failed),
                "results": results
            }
            
            if failed:
                response_data["message"] = f"Sent to {len(successful)}/{len(results)} recipients"
            else:
                response_data["message"] = f"Successfully sent to all {len(successful)} recipients"
            
            return jsonify(response_data)
            
        except Exception as e:
            print(f"Compose error: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    # Development settings
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"
    
    app.run("localhost", 8000, debug=True)
