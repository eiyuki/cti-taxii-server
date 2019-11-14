from flask import Blueprint, jsonify

healthecheck_bp = Blueprint('healthcheck', __name__)


@healthecheck_bp.route('/taxii-ping', methods=['GET'])
def ping():
    return jsonify({"pong": True})
