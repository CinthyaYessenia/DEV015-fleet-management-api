from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from datetime import timedelta
from sqlalchemy import func
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, create_access_token
from flask_bcrypt import Bcrypt
from flask_jwt_extended import jwt_required

app = Flask(__name__)

# Configuración de la base de datos
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://default:Mcv9lrg6zIYb@ep-bold-silence-a4c6erpu.us-east-1.aws.neon.tech:5432/verceldb?sslmode=require'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuración de JWT
app.config['JWT_SECRET_KEY'] = 'Laboratoria_2024'  # Cambia esto por una clave segura
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Tiempo de expiración del token


db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)

# Definir el modelo de la tabla 'taxis'
class Taxi(db.Model):
    __tablename__ = 'taxis'
    id = db.Column(db.Integer, primary_key=True)
    plate = db.Column(db.String, nullable=False)

# Definir el modelo de la tabla 'trajectories'
class Trajectory(db.Model):
    __tablename__ = 'trajectories'
    id = db.Column(db.Integer, primary_key=True)
    taxi_id = db.Column(db.Integer, db.ForeignKey('taxis.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)

# Definir el modelo de la tabla 'users'
class User(db.Model):
    __tablename__ = 'usuarios'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'


@jwt.unauthorized_loader
def unauthorized_response(callback):
    return jsonify({"message": "Token de autorización no encontrado o no válido"}), 401


@app.route("/")
def hello_world():
    return "<p>Aplicación de Fleet Managament API</p>"

# Endpoint para obtener los taxis (ahora protegido)
@app.route('/taxis', methods=['GET'])
def get_taxis():
    # Obtener los parámetros de la URL
    plate = request.args.get('plate')
    page = request.args.get('page', default=1, type=int)
    limit = request.args.get('limit', default=10, type=int)

    # Crear la consulta base
    query = Taxi.query

    # Filtrar por 'plate' si está presente
    if plate:
        query = query.filter(Taxi.plate.ilike(f"%{plate}%"))  # Búsqueda parcial de 'plate'

    # Paginación
    taxis_paginated = query.paginate(page=page, per_page=limit, error_out=False)

    # Si no hay taxis en la página solicitada
    if not taxis_paginated.items:
        return jsonify({"message": "No taxis found"}), 404

    # Convertir los registros a formato JSON
    taxis_list = [{"id": taxi.id, "plate": taxi.plate} for taxi in taxis_paginated.items]

    return jsonify(taxis_list)

# Endpoint para obtener las trajectorias de los taxis
@app.route("/trajectories", methods=['GET'])
@jwt_required()
def get_trajectories():
    # Obtener parámetros de la URL
    taxi_id = request.args.get('taxi_id', type=int)
    date_str = request.args.get('date')

    # Validar si se proporcionaron taxi_id y date
    if not taxi_id or not date_str:
        return jsonify({"message": "Missing taxi_id or date"}), 400

    # Convertir la fecha proporcionada en un objeto datetime
    try:
        date = datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        return jsonify({"message": "Invalid date format. Use YYYY-MM-DD"}), 400

    # Consultar las trayectorias del taxi en la fecha dada
    trajectories = Trajectory.query.filter(
        Trajectory.taxi_id == taxi_id,
        db.func.date(Trajectory.date) == date
    ).all()

    # Si no se encuentran trayectorias
    if not trajectories:
        return jsonify({"message": "No trajectories found for the given taxi and date"}), 404

    # Convertir las trayectorias a formato JSON
    trajectories_list = [
        {
            "latitude": trajectory.latitude,
            "longitude": trajectory.longitude,
            "timestamp": trajectory.date.strftime("%Y-%m-%d %H:%M:%S")
        } 
        for trajectory in trajectories
    ]

    return jsonify(trajectories_list)

# Endpoint para obtener la última ubicación reportada por cada taxi
@app.route('/trajectories/latest', methods=['GET'])
@jwt_required()
def get_latest_trajectories():
    # Subconsulta para obtener la última fecha de cada taxi
    latest_dates = db.session.query(
            Trajectory.taxi_id, 
            func.max(Trajectory.id).label('latest_id')  # Usar el ID más alto como referencia
        ).group_by(Trajectory.taxi_id).subquery()

    # Consulta para obtener la última ubicación de cada taxi
    latest_trajectories = db.session.query(
            Taxi.id, 
            Taxi.plate, 
            Trajectory.latitude, 
            Trajectory.longitude, 
            Trajectory.date
        ).join(Trajectory, Taxi.id == Trajectory.taxi_id)\
        .join(latest_dates, Trajectory.id == latest_dates.c.latest_id)\
        .all()

    # Si no se encuentran trayectorias
    if not latest_trajectories:
        return jsonify({"message": "No latest trajectories found"}), 404

    # Convertir los registros a formato JSON
    result = [
        {
            "id": taxi_id,
            "plate": plate,
            "latitude": latitude,
            "longitude": longitude,
            "timestamp": date.strftime("%Y-%m-%d %H:%M:%S")
        }
        for taxi_id, plate, latitude, longitude, date in latest_trajectories
    ]

    return jsonify(result)

# Endpoint para crear un usuario
@app.route('/users', methods=['POST'])
@jwt_required()
def create_user():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({"error": "Falta información"}), 400

    # Hashear la contraseña
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    new_user = User(username=username, email=email, password=hashed_password)

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User created successfully"}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 400

# Endpoint para obtener todos los usuarios o uno por id
@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    user_id = request.args.get('id') #necesita un /users?id=

    if user_id:
        user = User.query.get(user_id)
        if not user:
            return jsonify({"message": "User not found"}), 404
        return jsonify({"id": user.id, "username": user.username, "email": user.email})

    # Si no se proporciona un id, devuelve todos los usuarios
    users = User.query.all()
    users_list = [{"id": u.id, "username": u.username, "email": u.email} for u in users]
    return jsonify(users_list)

# Endpoint para actualizar un usuario
@app.route('/users/<int:id>', methods=['PUT', 'PATCH'])
@jwt_required()
def update_user(id):
    data = request.get_json()
    user = User.query.get(id)

    if not user:
        return jsonify({"message": "User not found"}), 404

    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if username:
        user.username = username
    if email:
        user.email = email
    if password:
        user.password = password

    try:
        db.session.commit()
        return jsonify({"message": "User updated successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 400

# Endpoint para eliminar un usuario
@app.route('/users/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_user(id):
    user = User.query.get(id)

    if not user:
        return jsonify({"message": "User not found"}), 404

    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "User deleted successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 400

# Endpoint de autenticación
@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    # Buscar al usuario en la base de datos
    user = User.query.filter_by(email=email).first()

    if user and bcrypt.check_password_hash(user.password, password):
        # Crear el token JWT
        access_token = create_access_token(identity={'id': user.id, 'email': user.email})
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"message": "Credenciales inválidas"}), 404

if __name__ == '__main__':
    app.run(debug=True)
