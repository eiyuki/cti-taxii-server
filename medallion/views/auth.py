#!/usr/bin/env python
from flask import Blueprint, request, abort, jsonify, g, current_app, session
from werkzeug.security import check_password_hash

from medallion import jwt_encode, auth

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


@auth_bp.route('/logout')
@auth.login_required
def logout():
    resp = jsonify({'user': g.user})
    if g.user not in session:
        return resp, 404
    del session[g.user]
    return resp


@auth_bp.route('/testlogin')
@auth.login_required
def test_login():
    return jsonify({'user': g.user})


if __name__ == '__main__':
    pass
