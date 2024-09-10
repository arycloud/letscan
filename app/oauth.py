from flask import flash, redirect, url_for
from flask_login import current_user, login_user
from flask_dance.contrib.google import make_google_blueprint
from flask_dance.consumer import oauth_authorized, oauth_error
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage
from sqlalchemy.orm.exc import NoResultFound
from .models import db, User, OAuth


# blueprint = make_google_blueprint(
#     scope=["openid"],
    
# )
blueprint = make_google_blueprint(
    # client_id="my-key-here",
    # client_secret="my-secret-here",
    scope=["openid", "profile", "email"],
    storage=SQLAlchemyStorage(OAuth, db.session, user=current_user),
)


# # create/login local user on successful OAuth login
# @oauth_authorized.connect_via(blueprint)
# def google_logged_in(blueprint, token):
#     if not token:
#         flash("Failed to log in.", category="error")
#         return False

#     resp = blueprint.session.get("/oauth2/v1/userinfo")
#     if not resp.ok:
#         msg = "Failed to fetch user info."
#         flash(msg, category="error")
#         return False

#     info = resp.json()
#     user_id = info["id"]

#     # Find this OAuth token in the database, or create it
#     query = OAuth.query.filter_by(provider=blueprint.name, provider_user_id=user_id)
#     try:
#         oauth = query.one()
#     except NoResultFound:
#         oauth = OAuth(provider=blueprint.name, provider_user_id=user_id, token=token)

#     if oauth.user:
#         login_user(oauth.user)
#         flash("Successfully signed in.")
#         return redirect(url_for('scan'))

#     else:
#         # Create a new local user account for this user
#         user = User(email=info["email"])
#         # Associate the new local user account with the OAuth token
#         oauth.user = user
#         # Save and commit our database models
#         db.session.add_all([user, oauth])
#         db.session.commit()
#         # Log in the new local user account
#         login_user(user)
#         flash("Successfully signed in.")
#         return redirect(url_for('scan'))

#     # Disable Flask-Dance's default behavior for saving the OAuth token
#     return False

@oauth_authorized.connect_via(blueprint)
def google_logged_in(blueprint, token):
    if not token:
        flash("Failed to log in.", category="error")
        return False

    resp = blueprint.session.get("/oauth2/v1/userinfo")
    if not resp.ok:
        msg = "Failed to fetch user info."
        flash(msg, category="error")
        return False

    info = resp.json()
    user_id = info["id"]
    email = info["email"]

    # Find this OAuth token in the database, or create it
    query = OAuth.query.filter_by(provider=blueprint.name, provider_user_id=user_id)
    try:
        oauth = query.one()
    except NoResultFound:
        oauth = OAuth(provider=blueprint.name, provider_user_id=user_id, token=token)

    if oauth.user:
        login_user(oauth.user)
        flash("Successfully signed in.")
        return redirect(url_for('scan'))

    # Check if a user with the same email already exists in the User table
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        # If the user exists, associate the OAuth entry with the existing user
        oauth.user = existing_user
        db.session.add(oauth)
        db.session.commit()
        login_user(existing_user)
        flash("Successfully signed in.")
        return redirect(url_for('scan'))

    else:
        # Create a new local user account for this user
        user = User(email=email)
        oauth.user = user
        db.session.add_all([user, oauth])
        db.session.commit()
        login_user(user)
        flash("Successfully signed in.")
        return redirect(url_for('scan'))

    return False






# notify on OAuth provider error
@oauth_error.connect_via(blueprint)
def google_error(blueprint, message, response):
    msg = ("OAuth error from {name}! " "message={message} response={response}").format(
        name=blueprint.name, message=message, response=response
    )
    flash(msg, category="error")
