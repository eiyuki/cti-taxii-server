#!/usr/bin/env python
import json

from flask import Blueprint, abort, current_app, g, jsonify, request, session, Response
from werkzeug.security import check_password_hash

from medallion import auth, jwt_encode

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['POST'])
def login():
    auth_info = request.json
    if not auth_info:
        abort(400)
    username, password = auth_info['username'], auth_info['password']

    password_hash = current_app.users_backend.get(username)

    if not password_hash or not check_password_hash(password_hash, password):
        abort(401)

    session[username] = jwt_encode(username)
    return jsonify({'access_token': session[username]})


@auth_bp.route('/logout', methods=['GET'])
@auth.login_required
def logout():
    resp = Response(content_type='application/vnd.oasis.taxii+json; version=2.0')
    resp.data = json.dumps({'user': g.user})
    if g.user not in session:
        del session[g.user]
    return resp


@auth_bp.route('/routes', methods=['GET'])
@auth.login_required
def routes():
    return jsonify([
        {
            'path': str(rule.rule),
            'arguments': list(rule.arguments),
            'defaults': rule.defaults,
            'methods': list(rule.methods)
        }
        for rule in current_app.url_map.iter_rules()
    ])


if __name__ == '__main__':
    pass
