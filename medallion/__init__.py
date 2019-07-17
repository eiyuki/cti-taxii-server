import importlib
import json
import logging

import flask
import jwt
from datetime import datetime, timedelta
from flask import Flask, Response, current_app, session, g, abort
from flask_httpauth import HTTPTokenAuth, HTTPBasicAuth, MultiAuth
from werkzeug.security import check_password_hash

from medallion.exceptions import BackendError, ProcessingError
from medallion.version import __version__  # noqa
from medallion.views import MEDIA_TYPE_TAXII_V20

# Console Handler for medallion messages
ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter("[%(name)s] [%(levelname)-8s] [%(asctime)s] %(message)s"))

# Module-level logger
log = logging.getLogger(__name__)
log.addHandler(ch)

jwt_auth = HTTPTokenAuth(scheme='JWT')
basic_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth(scheme='Token')
auth = MultiAuth(basic_auth, token_auth)

application_instance = Flask(__name__)


def set_users_config(flask_application_instance, config):
    with flask_application_instance.app_context():
        log.debug("Registering medallion users configuration into {}".format(current_app))
        flask_application_instance.users_backend = config


def set_taxii_config(flask_application_instance, config):
    with flask_application_instance.app_context():
        log.debug("Registering medallion taxii configuration into {}".format(current_app))
        flask_application_instance.taxii_config = config


def connect_to_backend(config_info):
    log.debug("Initializing backend configuration using: {}".format(config_info))

    if "module" not in config_info:
        raise ValueError("No module parameter provided for the TAXII server.")
    if "module_class" not in config_info:
        raise ValueError("No module_class parameter provided for the TAXII server.")

    try:
        module = importlib.import_module(config_info["module"])
        module_class = getattr(module, config_info["module_class"])
        log.debug("Instantiating medallion backend with {}".format(module_class))
        return module_class(**config_info)
    except Exception as e:
        log.error("Unknown backend for TAXII server. {} ".format(str(e)))
        raise e


def init_backend(flask_application_instance, config_info):
    with flask_application_instance.app_context():
        log.debug("Registering medallion_backend into {}".format(current_app))
        current_app.medallion_backend = connect_to_backend(config_info)


def register_blueprints(app):
    from medallion.views import collections
    from medallion.views import discovery
    from medallion.views import manifest
    from medallion.views import objects
    from medallion.views.auth import auth_bp

    log.debug("Registering medallion blueprints into {}".format(app))
    app.register_blueprint(collections.mod)
    app.register_blueprint(discovery.mod)
    app.register_blueprint(manifest.mod)
    app.register_blueprint(objects.mod)
    app.register_blueprint(auth_bp)


def handle_error(error):
    error = {
        "title": error.args[0],
        "http_status": "500"
    }
    return Response(response=flask.json.dumps(error),
                    status=500,
                    mimetype=MEDIA_TYPE_TAXII_V20)


def handle_processing_error(error):
    e = {
        "title": "ProcessingError",
        "http_status": "422",
        "description": str(error)
    }
    return Response(response=flask.json.dumps(e),
                    status=422,
                    mimetype=MEDIA_TYPE_TAXII_V20)


def handle_backend_error(error):
    e = {
        "title": "MongoBackendError",
        "http_status": "500",
        "description": str(error)
    }
    return Response(response=flask.json.dumps(e),
                    status=500,
                    mimetype=MEDIA_TYPE_TAXII_V20)


def register_error_handlers(app):
    app.register_error_handler(500, handle_error)
    app.register_error_handler(ProcessingError, handle_processing_error)
    app.register_error_handler(BackendError, handle_backend_error)


def jwt_encode(username):
    exp = datetime.utcnow() + timedelta(minutes=int(current_app.config.get("JWT_EXP", 60)))
    payload = {
        'exp': exp,
        'user': username
    }
    return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')


def jwt_decode(token):
    return jwt.decode(token, key=current_app.config['SECRET_KEY'])


@basic_auth.verify_password
def verify_basic_auth(username, password):
    password_hash = current_app.users_backend.get(username)
    return False if password_hash is None else check_password_hash(password_hash, password)


@jwt_auth.verify_token
def verify_token(token):
    current_dt = datetime.utcnow()
    try:
        decoded_token = jwt_decode(token)
        is_authorized = datetime.utcfromtimestamp(float(decoded_token['exp'])) > current_dt
        if is_authorized:
            g.user = decoded_token['user']
    except jwt.exceptions.InvalidTokenError:
        is_authorized = False

    return is_authorized


@token_auth.verify_token
def api_key_auth(api_key):
    user = current_app.api_key_backend.get(api_key)
    if not user:
        return False
    g.user = user
    return True


def set_api_key_config(app, config):
    with app.app_context():
        log.debug("Registering medallion api keys configuration into {}".format(current_app))
        app.api_key_backend = config


def create_app(config_file):
    # TODO: application factory.
    # app = Flask(__name__)
    app = application_instance

    with open(config_file, "r") as f:
        configuration = json.load(f)

    app.config.from_mapping(**configuration)

    set_users_config(app, configuration["users"])
    set_api_key_config(app, configuration["api_keys"])
    set_taxii_config(app, configuration["taxii"])
    init_backend(app, configuration["backend"])

    register_blueprints(app)
    register_error_handlers(app)

    return app
