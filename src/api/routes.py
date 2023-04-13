"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_jwt_extended import create_access_token, jwt_required, get_jwt
import bcrypt

api = Blueprint('api', __name__)


@api.route('/user/<int:id>', methods=['GET'])
@jwt_required()
def get_user_id(id):
    user = User.query.get(id)
    token = get_jwt()
    print(token)
    return jsonify(user.serialize()), 201

@api.route('/user/register', methods=['POST'])
def register():
    body = request.get_json()
    hashed = bcrypt.hashpw(body['password'].encode(), bcrypt.gensalt(14)) # encode convierte en bytes
    new_user = User(body['email'],hashed.decode()) # decode para guardar psswd encriptado
    print(new_user)
    db.session.add(new_user)
    db.session.commit()

    return jsonify(new_user.serialize(), 201)

@api.route('/user/login', methods=['POST'])
def login():
    body = request.get_json()
    user = User.query.filter_by(email = body['email']).one()
    if bcrypt.checkpw(body['password'].encode(), user.password.encode()):
        create_token = create_access_token(identity=user.serialize())
        return jsonify(create_token, 200)
    else:
        return jsonify('NO LOGIN', 401)