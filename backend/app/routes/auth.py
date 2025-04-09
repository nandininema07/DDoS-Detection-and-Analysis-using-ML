from flask import Blueprint, request, jsonify

auth_bp = Blueprint('auth', __name__)

users = {"admin": "123456"}  # placeholder auth

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    if users.get(data.get("username")) == data.get("password"):
        return jsonify({"status": "success", "user": data.get("username")})
    return jsonify({"status": "fail"}), 401
