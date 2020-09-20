import datetime
import jwt
import uuid
from functools import wraps
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgres@localhost/todo'

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message: Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is Invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/user', methods=['GET'])
@token_required
def get_users(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that action!'})

    users = []
    for user in User.query.all():
        user_data = {'public_id': user.public_id, 'name': user.name, 'password': user.password, 'admin': user.admin}
        user.append(user_data)
    return jsonify(users)


@app.route('/user/<id>', methods=['GET'])
@token_required
def get_user(current_user, id):
    if not current_user.admin:
        return jsonify({'message': 'Can not perform that action!'})

    user = User.query.filter_by(public_id=id).first()
    if not user:
        return jsonify({'message': 'User not found!'})
    return jsonify({'users': {'public_id': user.public_id, 'name': user.name, 'password': user.password, 'admin': user.admin}})


@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Can not perform that action!'})

    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'Created new user!'})


@app.route('/user/<id>', methods=['PUT'])
@token_required
def grant_admin_user(current_user, id):
    if not current_user.admin:
        return jsonify({'message': 'Can not perform that action!'})

    user = User.query.filter_by(public_id=id).first()
    if not user:
        return jsonify({'message': 'User not found!'})
    user.admin = True
    db.session.commit()
    return jsonify({'message': 'User is now an Admin!'})


@app.route('/user/<id>', methods=['DELETE'])
@token_required
def delete_users(current_user, id):
    if not current_user.admin:
        return jsonify({'message': 'Can not perform that action!'})

    user = User.query.filter_by(public_id=id).first()
    if not user:
        return jsonify({'message': 'User not found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'User has been deleted!'})


@app.route('/todo', methods=['GET'])
@token_required
def get_all_todos(current_user):
    todos = []

    for todo in Todo.query.filter_by(user_id=current_user.id).all():
        todos.append({'id': todo.id, 'text': todo.text, 'complete': todo.complete})

    return jsonify({'todos': todos})


@app.route('/todo/<id>', methods=['GET'])
@token_required
def get_todo(current_user, id):
    todo = Todo.query.filter_by(id=id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'message': 'Todo not found!'})

    return jsonify({'id': todo.id, 'text': todo.text, 'complete': todo.complete})


@app.route('/todo', methods=['POST'])
@token_required
def create_todo(current_user):
    todo = request.get_json()

    new_todo = Todo(text=todo['text'], complete=False, user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()

    return jsonify({"message": "Created todo!"})


@app.route('/todo/<id>', methods=['DELETE'])
@token_required
def delete_todo(current_user, id):
    todo = Todo.query.filter_by(id=id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'message': 'Todo not found!'})
    db.session.delete(todo)
    db.session.commit()

    return jsonify({"message": "Todo has been deleted!"})


@app.route('/todo/<id>', methods=['PUT'])
@token_required
def complete_todo(current_user, id):
    todo = Todo.query.filter_by(id=id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'message': 'Todo not found!'})
    todo.complete = True
    db.session.commit()

    return jsonify({"message": "Todo item has been completed!"})


@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify!', 401, {'WWW-Authenticate': 'Basic realm=Login Required!'})

    user = User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response('Could not verify!', 401, {'WWW-Authenticate': 'Basic realm=User not found!'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id,
                            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
                           app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})

    return make_response('Could not verify!', 401, {'WWW-Authenticate': 'Basic realm=Please check your password!'})


if __name__ == "__main__":
    app.run(debug=True)
