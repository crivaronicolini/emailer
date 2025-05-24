# pyright: basic
from datetime import timedelta
import json
import os
import base64
from email.message import EmailMessage
import re

# from email_validator import validate_email, EmailNotValidError
email = "my+address@example.org"

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

import flask
from flask import flash, request, redirect
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif", "md"}

CLIENT_SECRETS_FILE = ".client_secret.json"
SCOPES = [
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]
API_SERVICE_NAME = "gmail"
API_VERSION = "v1"
REDIRECT_URI = "http://localhost:8000/login/callback"

app = flask.Flask(__name__)
app.secret_key = "ola"
# app.permanent_session_lifetime = timedelta(days=30)

# app.config.update(
#     SESSION_COOKIE_SECURE=True,
#     SESSION_COOKIE_HTTPONLY=True,
#     SESSION_COOKIE_SAMESITE="Strict",
# )
#


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/")
def read_root():
    # from google.oauth2.credentials import Credentials
    # import json
    #
    # # Load credentials from stored JSON
    # credentials_info = json.loads(flask.session['credentials'])
    # credentials = Credentials.from_authorized_user_info(credentials_info)
    #
    # # Refresh the token if it’s expired or close to expiring
    # if credentials.expired or not credentials.valid:
    #     credentials.refresh(request)
    #     # Optionally, update your stored credentials with the new tokens
    #     flask.session['credentials'] = credentials.to_json()
    # try:
    #     if credentials.expired or not credentials.valid:
    #         credentials.refresh(request)
    #         flask.session['credentials'] = credentials.to_json()
    # except Exception as e:
    #     # Handle errors (e.g., log error, prompt re-authentication)
    #     print("Error refreshing token:", e)
    return flask.render_template("index.html")


@app.get("/login")
def authorize():
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)

    flow.redirect_uri = REDIRECT_URI

    authorization_url, state = flow.authorization_url(
        # Recommended, enable offline access so that you can refresh an access token without
        # re-prompting the user for permission. Recommended for web server apps.
        access_type="offline",
        # Optional, enable incremental authorization. Recommended as a best practice.
        include_granted_scopes="true",
        # Optional, if your application knows which user is trying to authenticate, it can use this
        # parameter to provide a hint to the Google Authentication Server.
        login_hint="hint@example.com",
        # Optional, set prompt to 'consent' will prompt the user for consent
        prompt="consent",
    )

    # print("hola")
    # print(f"{state=}")
    flask.session["state"] = state

    return flask.redirect(authorization_url)


@app.route("/login/callback")
def login_callback():
    # print(f"{flask.session=}")
    state = flask.session["state"]

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state
    )

    flow.redirect_uri = REDIRECT_URI

    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)

    credentials = flow.credentials
    # print(f"{credentials.to_json()=}")
    flask.session["credentials"] = credentials.to_json()

    # TODO devolver una pagina de error
    for scope in SCOPES:
        if scope not in credentials.granted_scopes:
            return "Error: No se dió acceso a todos los servicios"

    try:
        user_info_service = build("oauth2", "v2", credentials=credentials)
        user_info = user_info_service.userinfo().get().execute()
        # user_info={'id': 'int', 'email': 'str', 'verified_email': True, 'name': 'str', 'given_name': 'str', 'family_name': 'str', 'picture': 'str'}

        user_info["isAuthorized"] = True
        # print(f"{user_info=}")
        flask.session["user_info"] = user_info

    except Exception as e:
        print(f"service could not be built: {e}")

    return flask.redirect("/compose")


@app.route("/compose", methods=["POST", "GET"])
def compose():
    if request.method == "GET":
        user = flask.session["user_info"]
        return flask.render_template("compose.html", user=user)

    if request.method == "POST":
        attachments = []
        # check if the post request has the file part
        if "file" not in request.files:
            flash("No file part")
            return redirect(request.url)
        for file in request.files.getlist("file"):
            print(f"{request.files.getlist("file")=}")
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                print(f"{file=}, {filename=}, {file.mimetype=}")
                attachments.append((filename, file, file.mimetype))

    if "credentials" in flask.session:
        credentials = Credentials.from_authorized_user_info(
            json.loads(flask.session["credentials"])
        )
        if not credentials.refresh_token:
            # Force re-consent to get a refresh_token
            return flask.redirect("/login")
    else:
        return flask.redirect("/login")


    try:
        service = build("gmail", "v1", credentials=credentials)
        print(f"{service=}")

        data = request.form
        print(f"{data=}")
        recipients = data["recipientsList"].split(",")
        # print(recipients)
        userEmail = flask.session["user_info"]["email"]
        # return flask.render_template("compose.html")

        for recipient in recipients:
            message = EmailMessage()
            message.set_content(data["body"])
            message["From"] = userEmail
            message["Subject"] = data["subject"]
            message["Cc"] = data["Cc"]
            message["Bcc"] = data["Cco"]
            print(message)

            for filename, file, mimetype in attachments:
                maintype, subtype = mimetype.split("/")
                message.add_attachment(
                    file.read(), maintype, subtype, filename=filename
                )

            message["To"] = recipient
            encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

            create_message = {"raw": encoded_message}
            send_message = (
                service.users()
                .messages()
                .send(userId="me", body=create_message)
                .execute()
            )
            print(f"Message Id: {send_message['id']}")

    except HttpError as error:
        print(f"An error occurred: {error}")

    return flask.render_template("index.html")


# try:
#
#   # Check that the email address is valid. Turn on check_deliverability
#   # for first-time validations like on account creation pages (but not
#   # login pages).
#   emailinfo = validate_email(email, check_deliverability=False)
#
#   # After this point, use only the normalized form of the email address,
#   # especially before going to a database query.
#   email = emailinfo.normalized
#
# except EmailNotValidError as e:
#
#   # The exception message is human-readable explanation of why it's
#   # not a valid (or deliverable) email address.
#   print(str(e))


if __name__ == "__main__":
    # When running locally, disable OAuthlib's HTTPs verification.
    # ACTION ITEM for developers:
    #     When running in production *do not* leave this option enabled.
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "0"

    # This disables the requested scopes and granted scopes check.
    # If users only grant partial request, the warning would not be thrown.
    os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"

    # Specify a hostname and port that are set as a valid redirect URI
    # for your API project in the Google API Console.
    app.run("localhost", 8000, debug=True)
