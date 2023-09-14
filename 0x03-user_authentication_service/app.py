#!/usr/bin/env python3
""" A flask setup for connection
"""
from flask import Flask, jsonify, request, abort, redirect
from auth import Auth

app = Flask(__name__)
auth = Auth()


@app.route('/', methods=['GET'], strict_slashes=False)
def index() -> str:
    """GET /
     Return:
         - The home page's payload.
     """
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'], strict_slashes=False)
def users() -> str:
    """POST /users
    Return:
        - The account creation payload.
    """
    data = request.form
    email = data.get('email')
    password = data.get('password')

    try:
        auth.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})

    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login() -> str:
    """POST /sessions
    Return:
        - The account login payload.
    """
    data = request.form
    email = data.get('email')
    password = data.get('password')
    if not auth.valid_login(email, password):
        abort(401)

    session_id = auth.create_session(email)
    response = jsonify({"email": email, "message": "logged in"})
    response.set_cookie("session_id", session_id)
    return response


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout() -> None:
    """DELETE /sessions
    Return:
        - Redirects to home route.
    """
    session_id = request.cookies.get('session_id')
    user = auth.get_user_from_session_id(session_id)

    if user:
        auth.destroy_session(user.id)
        return redirect('/')
    abort(403)  # if user does not exist


@app.route('/profile', methods=['GET'], strict_slashes=False)
def profile() -> str:
    """GET /profile
        Return:
            - The user's profile information.
    """
    session_id = request.cookies.get('session_id')
    user = auth.get_user_from_session_id(session_id)
    if user is None:
        abort(403)
    return jsonify({"email": user.email}), 200


@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def reset_password_token() -> str:
    """POST /reset_password
     Return:
         - The user's password reset payload.
     """
    email = request.form.get('email')
    try:
        reset_token = auth.get_reset_password_token(email)
    except ValueError:
        abort(403)
    return jsonify({"email": email, "reset_token": reset_token}), 200


@app.route('/reset_password', methods=['PUT'], strict_slashes=False)
def update_password() -> str:
    """PUT /reset_password

    Return:
        - The user's password updated payload.
    """
    data = request.form
    email = data.get('email')
    reset_token = data.get('reset_token')
    new_password = data.get('new_password')

    try:
        auth.update_password(reset_token, new_password)
        return jsonify({"email": email, "message": "Password updated"}), 200
    except ValueError:
        abort(403)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port='5000')
