import os


class Config(object):
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY") or "supersekrit"
<<<<<<< HEAD
=======
    # SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or "sqlite:///app.sqlite3"
>>>>>>> origin/master
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or "sqlite:////home/abdul/LetScan/letscan/instance/app.sqlite3"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    GOOGLE_OAUTH_CLIENT_ID = '726773540164-feratonqe02cnho2in1nn451kub737as.apps.googleusercontent.com'
    GOOGLE_OAUTH_CLIENT_SECRET = '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'
    OAUTHLIB_INSECURE_TRANSPORT = '1'
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
