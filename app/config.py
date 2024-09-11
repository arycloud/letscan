import os

class Config(object):
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "default_secret_key")
    SESSION_COOKIE_SECURE = True
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///instance/app.sqlite3")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    GOOGLE_OAUTH_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "default_client_id")
    GOOGLE_OAUTH_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "default_client_secret")

    OAUTHLIB_INSECURE_TRANSPORT = os.environ.get('OAUTHLIB_INSECURE_TRANSPORT', '1')
    OAUTHLIB_RELAX_TOKEN_SCOPE = os.environ.get('OAUTHLIB_RELAX_TOKEN_SCOPE', '1')