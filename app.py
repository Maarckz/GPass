import os
import json
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, redirect, url_for, session, flash, render_template, make_response
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity, set_access_cookies
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import bcrypt

# Configuração do Flask
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(32))  # Chave secreta para sessões
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', secrets.token_hex(32))  # Chave secreta para JWT
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30)  # Expiração curta para tokens JWT
app.config['JWT_COOKIE_SECURE'] = True  # Cookies JWT só são enviados por HTTPS
app.config['JWT_COOKIE_CSRF_PROTECT'] = False  # Desabilita a proteção CSRF para cookies JWT
app.config['JWT_TOKEN_LOCATION'] = ['cookies']  # Armazena tokens JWT em cookies

# Inicializa extensões de segurança
jwt = JWTManager(app)

# Configuração do Limiter
limiter = Limiter(
    get_remote_address,  # Função para obter o endereço IP do cliente
    app=app,  # Aplicação Flask
    default_limits=["200 per day", "50 per hour"]  # Limites padrão
)

talisman = Talisman(
    app,
    force_https=True,  # Força o uso de HTTPS
    strict_transport_security=True,  # Habilita HSTS
    session_cookie_secure=True,  # Cookies de sessão só são enviados por HTTPS
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self'",
        'style-src': "'self'",
    }
)

# Caminho para o banco de dados JSON
DATA_DIR = "data"
DB_PATH = os.path.join(DATA_DIR, "passwords.json")

# Garante que a pasta `data` exista
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

# Função para carregar dados do banco de dados JSON
def load_db():
    if not os.path.exists(DB_PATH):
        return {"passwords": []}  # Retorna um dicionário com uma lista vazia se o arquivo não existir
    
    with open(DB_PATH, "r") as f:
        try:
            data = json.load(f)
            # Garante que o arquivo JSON seja um dicionário
            if isinstance(data, dict):
                return data
            else:
                # Se não for um dicionário, retorna um dicionário com a chave "passwords"
                return {"passwords": []}
        except json.JSONDecodeError:
            # Se o arquivo estiver corrompido, retorna um dicionário vazio
            return {"passwords": []}

# Função para salvar dados no banco de dados JSON
def save_db(data):
    with open(DB_PATH, "w") as f:
        json.dump(data, f, indent=4)

# Função para hashear senhas
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

# Função para verificar senhas
def verify_password(hashed_password, input_password):
    return bcrypt.checkpw(input_password.encode('utf-8'), hashed_password.encode('utf-8'))

# Decorator para verificar se o usuário está autenticado
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Por favor, faça login para acessar esta página.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Rota de login
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limita tentativas de login
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Autenticação simples (apenas admin por enquanto)
        if username == 'admin' and verify_password(hash_password('admin'), password):
            # Cria um token JWT para o usuário
            access_token = create_access_token(identity=username)
            
            # Define o token JWT em um cookie seguro
            response = make_response(redirect(url_for('dashboard')))
            set_access_cookies(response, access_token)  # Define o cookie JWT
            session['logged_in'] = True
            return response
        else:
            flash('Usuário ou senha inválidos', 'error')

    return render_template('login.html')

# Rota de logout
@app.route('/logout')
def logout():
    session.clear()
    response = make_response(redirect(url_for('login')))
    response.delete_cookie('access_token_cookie')  # Remove o cookie do token JWT
    return response

# Rota principal (dashboard)
@app.route('/')
@login_required
@jwt_required()  # Exige um token JWT válido
def dashboard():
    current_user = get_jwt_identity()  # Obtém o usuário atual do token JWT
    db = load_db()
    passwords = db.get("passwords", [])
    return render_template('dashboard.html', passwords=passwords, active_section='passwords')

# Rota para notas seguras
@app.route('/secure-notes')
@login_required
@jwt_required()
def secure_notes():
    return render_template('dashboard.html', active_section='secure-notes')

# Rota para arquivos
@app.route('/files')
@login_required
@jwt_required()
def files():
    return render_template('dashboard.html', active_section='files')

# Rota para configurações
@app.route('/settings')
@login_required
@jwt_required()
def settings():
    return render_template('dashboard.html', active_section='settings')

# Rota para adicionar uma nova senha
@app.route('/password/add', methods=['POST'])
@login_required
@jwt_required()
def add_password():
    data = request.form
    db = load_db()
    new_id = max([p['id'] for p in db['passwords']], default=0) + 1
    new_password = {
        'id': new_id,
        'machine_name': data['machine_name'],
        'ip': data['ip'],
        'login': data['login'],
        'password': data['password']
    }
    db['passwords'].append(new_password)
    save_db(db)
    return redirect(url_for('dashboard'))

# Rota para editar uma senha
@app.route('/password/edit/<int:id>', methods=['POST'])
@login_required
@jwt_required()
def edit_password(id):
    data = request.form
    db = load_db()
    for password in db['passwords']:
        if password['id'] == id:
            password['machine_name'] = data['machine_name']
            password['ip'] = data['ip']
            password['login'] = data['login']
            password['password'] = data['password']
            break
    save_db(db)
    return redirect(url_for('dashboard'))

# Rota para excluir uma senha
@app.route('/password/delete/<int:id>', methods=['POST'])
@login_required
@jwt_required()
def delete_password(id):
    db = load_db()
    db['passwords'] = [p for p in db['passwords'] if p['id'] != id]
    save_db(db)
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)  # Desative o modo debug em produção