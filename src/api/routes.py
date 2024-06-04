"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_cors import CORS
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

api = Blueprint('api', __name__)

# Allow CORS requests to this API
CORS(api)

@api.route('/signup', methods=['POST'])
def handle_signup():
    data = request.get_json()
    if User.query.filter_by(email = data['email']).first():
        return jsonify('User already exist')
    new_user = User(
        email = data['email'],
        password = data['password'],
        is_active = True)
    db.session.add(new_user)
    db.session.commit()    
   
    access_token = create_access_token(identity=new_user.id)
    return jsonify({ "token": access_token, "user": new_user.serialize() })



@api.route('/login', methods=['POST'])
def handle_login():
    body = request.get_json()
    email = body["email"]
    password = body["password"]
    user = User.query.filter_by(email=email, password=password).first()
    
   
    if user is None:
        return jsonify({"msg": "Bad email or password"}), 401
    
    
    access_token = create_access_token(identity=user.id)
    return jsonify({ "token": access_token, "user_id": user.id })



@api.route('/private', methods=['GET'])
@jwt_required()
def handle_private():

    response_body = {
        "message": "Acceso denegado: Token no proporcionado"
    }

    return jsonify(response_body), 200
