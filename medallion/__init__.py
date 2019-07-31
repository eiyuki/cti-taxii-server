import importlib
import json
import logging

import flask
import jwt
from datetime import datetime, timedelta
from flask import Flask, Response, current_app, g
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth, MultiAuth
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
auth = MultiAuth(None)


def set_multi_auth_config(auth_types):
    type_to_app = {
        'jwt': jwt_auth,
        'api_key': token_auth,
        'basic': basic_auth
    }

    auth_types = tuple(set(auth_types))
    assert len(auth_types) > 0, 'at least one auth type required'

    auth.main_auth = type_to_app[auth_types[0]]
    auth.additional_auth = tuple(type_to_app[a] for a in auth_types[1:])


def set_auth_config(flask_application_instance, config_info):
    with flask_application_instance.app_context():
        log.debug("Registering medallion users configuration into {}".format(current_app))
        flask_application_instance.auth_backend = connect_to_backend(config_info)


def set_taxii_config(flask_application_instance, config_info):
    with flask_application_instance.app_context():
        log.debug("Registering medallion taxii configuration into {}".format(current_app))
        flask_application_instance.taxii_config = config_info


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
    from medallion.views.healthcheck import healthecheck_bp

    log.debug("Registering medallion blueprints into {}".format(app))
    app.register_blueprint(collections.mod)
    app.register_blueprint(discovery.mod)
    app.register_blueprint(manifest.mod)
    app.register_blueprint(objects.mod)
    app.register_blueprint(auth_bp)
    app.register_blueprint(healthecheck_bp)


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
    secret = current_app.config['SECRET_KEY']
    return jwt.encode(payload, secret, algorithm='HS256')


def jwt_decode(token):
    secret = current_app.config['SECRET_KEY']
    return jwt.decode(token, secret, algorithms=['HS256'])


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


@basic_auth.verify_password
def verify_basic_auth(username, password):
    password_hash = current_app.auth_backend.get_password_hash(username)
    return False if password_hash is None else check_password_hash(password_hash, password)


@token_auth.verify_token
def api_key_auth(api_key):
    user = current_app.auth_backend.get_username_for_api_key(api_key)
    if not user:
        return False
    g.user = user
    return True


def create_app(cfg):
    app = Flask(__name__)

    if isinstance(cfg, dict):
        configuration = cfg
    else:
        with open(cfg, "r") as f:
            configuration = json.load(f)

    app.config.from_mapping(**configuration)
    set_multi_auth_config(configuration.get('multi-auth', ('basic',)))

    set_auth_config(app, configuration["auth"])
    set_taxii_config(app, configuration["taxii"])
    init_backend(app, configuration["backend"])

    register_blueprints(app)
    register_error_handlers(app)

    return app
