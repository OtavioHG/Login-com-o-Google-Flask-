from flask import Flask, redirect, url_for, session, request, render_template, flash
from authlib.integrations.flask_client import OAuth
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
import logging
import os
import secrets
import zipfile

# Configuração de logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configuração do banco de dados
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Definição do modelo de usuário
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    name = db.Column(db.String(150), nullable=False)
    password_hash = db.Column(db.String(150), nullable=True)
    profile_pic = db.Column(db.String(250), nullable=True)

# Criação das tabelas no banco de dados
with app.app_context():
    db.create_all()

# Configuração do OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='Id so clinete tirando do  google cloud', # de para tira esse id tem que usar o google cloud 
    client_secret='clinet secreto ', # de para tira esse id tem que usar o google cloud 
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    client_kwargs={'scope': 'openid profile email'},
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs',
)

@app.route('/')
def index():
    logging.debug('Rota / acessada')
    return render_template('index.html')

@app.route('/login')
def login():
    logging.debug('Rota /login acessada')
    redirect_uri = url_for('authorize', _external=True)
    nonce = secrets.token_urlsafe()
    session['nonce'] = nonce
    logging.debug(f'Redirecionando para o Google com redirect_uri: {redirect_uri} e nonce: {nonce}')
    return google.authorize_redirect(redirect_uri, nonce=nonce)

@app.route('/logout')
def logout():
    logging.debug('Rota /logout acessada')
    session.pop('user', None)
    return redirect(url_for('index'))

@app.route('/authorize')
def authorize():
    logging.debug('Rota /authorize acessada')
    try:
        token = google.authorize_access_token()
        logging.debug(f'Token obtido: {token}')
        
        if not token:
            raise ValueError('Token não obtido')

        nonce = session.pop('nonce', None)
        if not nonce:
            raise ValueError('Nonce não encontrado na sessão')

        resp = google.parse_id_token(token, nonce=nonce)
        logging.debug(f'Resposta do Google: {resp}')
        
        if not resp:
            raise ValueError('ID Token não obtido')

        # Armazena as informações do usuário na sessão
        user_info = {
            'email': resp['email'], 
            'name': resp['name'],
            'profile_pic': resp.get('picture')  # Obtém a URL da foto de perfil
        }
        session['user'] = user_info

        # Armazena ou atualiza as informações do usuário no banco de dados
        user = User.query.filter_by(email=resp['email']).first()
        if user:
            user.name = resp['name']
            user.profile_pic = resp.get('picture')  # Atualiza a foto de perfil
        else:
            user = User(
                email=resp['email'], 
                name=resp['name'],
                profile_pic=resp.get('picture')  # Adiciona a foto de perfil
            )
            db.session.add(user)
        db.session.commit()
    except Exception as e:
        logging.error(f'Erro na autorização: {e}')
        return redirect(url_for('error'))  # Redireciona para a página de erro
        
    return redirect(url_for('set_password'))

@app.route('/set_password', methods=['GET', 'POST'])
def set_password():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form.get('password')
        email = session['user']['email']
        user = User.query.filter_by(email=email).first()

        if user and password:
            user.password_hash = generate_password_hash(password)
            db.session.commit()
            flash('Senha definida com sucesso!')
            return redirect(url_for('success'))
        else:
            flash('Erro ao definir a senha.')

    return render_template('set_password.html')

@app.route('/login_with_password', methods=['GET', 'POST'])
def login_with_password():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            session['user'] = {'email': user.email, 'name': user.name}
            return redirect(url_for('success'))
        else:
            flash('Email ou senha incorretos.')

    return render_template('login_with_password.html')

@app.route('/success')
def success():
    logging.debug('Rota /success acessada')
    if 'user' in session:
        user = session['user']
        return render_template('success.html', user=user)
    else:
        logging.debug('Nenhum usuário encontrado na sessão')
        return redirect(url_for('index'))

@app.route('/error')
def error():
    logging.debug('Rota /error acessada')
    return render_template('error.html')

if __name__ == '__main__':
    logging.debug('Iniciando a aplicação Flask')
    app.run(debug=True)
