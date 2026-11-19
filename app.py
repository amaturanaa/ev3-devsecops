from flask import (Flask, request, render_template_string, redirect,
                   url_for, session, flash)
import sqlite3
import os
import re
from functools import wraps
from werkzeug.security import check_password_hash
from flask_wtf import CSRFProtect
from werkzeug.serving import WSGIRequestHandler

app = Flask(__name__)
# CORRECCION: clave secreta desde variable de entorno (no hardcodeada).
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(24)

# CORRECCION (CSRF): protege automaticamente todos los formularios POST.
csrf = CSRFProtect(app)

@app.after_request
def cabeceras_seguridad(resp):
    resp.headers['Content-Security-Policy'] = (
        "default-src 'self'; frame-ancestors 'none'; "
        "form-action 'self'; base-uri 'self'")
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['Server'] = 'webserver'   # oculta Werkzeug/Python y sus versiones
    return resp

# CORRECCION (cookie insegura): la sesion de Flask va firmada y con flags seguras.
app.config['SESSION_COOKIE_HTTPONLY'] = True   # el JS no puede leer la cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # defensa extra contra CSRF
# En produccion con HTTPS: app.config['SESSION_COOKIE_SECURE'] = True


def get_db():
    conn = sqlite3.connect('vulnerable.db')
    conn.row_factory = sqlite3.Row
    return conn


# Validacion de entrada (lista blanca)
USERNAME_RE = re.compile(r'^[A-Za-z0-9_]{3,20}$')


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper


# --- LOGIN (SQLi y contrasenas corregidos) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('username', '')
        pw = request.form.get('password', '')

        # Validacion de formato antes de consultar la BD
        if not USERNAME_RE.fullmatch(user) or not pw:
            flash('Credenciales con formato invalido.')
            return redirect(url_for('login'))

        conn = get_db()
        # CORRECCION (SQLi): consulta parametrizada, el dato va aparte con ?
        fila = conn.execute(
            'SELECT * FROM usuarios WHERE username = ?', (user,)).fetchone()
        conn.close()

        # CORRECCION (contrasenas): se verifica el hash seguro, no texto plano
        if fila and check_password_hash(fila['password'], pw):
            session.clear()                 # evita fijacion de sesion
            session['username'] = fila['username']
            session['rol'] = fila['rol']
            return redirect(url_for('dashboard'))

        flash('Acceso denegado')
        return redirect(url_for('login'))

    return render_template_string('''
        {% with messages = get_flashed_messages() %}
          {% for m in messages %}<p><b>{{ m }}</b></p>{% endfor %}
        {% endwith %}
        <h2>Login del Sistema Academico</h2>
        <form method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            Usuario: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Ingresar">
        </form>
    ''')


# --- DASHBOARD (XSS corregido) ---
@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    datos = conn.execute(
        'SELECT * FROM usuarios WHERE username = ?',
        (session['username'],)).fetchone()
    conn.close()

    # CORRECCION (XSS): las variables se pasan por contexto y Jinja2 las
    # escapa automaticamente con {{ }}. Un <script> se muestra como texto.
    return render_template_string('''
        <h1>Panel de {{ usuario }}</h1>
        <p><b>Rol:</b> {{ rol }}</p>
        <p><b>Biografia:</b> {{ bio }}</p>
        <hr>
        <h3>Actualizar Biografia</h3>
        <form action="{{ url_for('update_bio') }}" method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <input type="text" name="nueva_bio" placeholder="Escribe algo...">
            <input type="submit" value="Guardar Cambios">
        </form>
        <br><a href="{{ url_for('logout') }}">Cerrar Sesion</a>
    ''', usuario=datos['username'], rol=datos['rol'], bio=datos['bio'])


@app.route('/update_bio', methods=['POST'])
@login_required
def update_bio():
    nueva_bio = request.form.get('nueva_bio', '')

    # Validacion simple de largo
    if len(nueva_bio) > 500:
        flash('La biografia es demasiado larga.')
        return redirect(url_for('dashboard'))

    conn = get_db()
    # CORRECCION (SQLi): parametrizada. El CSRF ya lo cubre CSRFProtect.
    conn.execute(
        'UPDATE usuarios SET bio = ? WHERE username = ?',
        (nueva_bio, session['username']))
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
def home():
    return redirect(url_for('login'))

class HandlerSeguro(WSGIRequestHandler):
    server_version = 'webserver'
    sys_version = ''

if __name__ == '__main__':
    # CORRECCION (debug): debug=False para no exponer el depurador de Werkzeug.
    # host 0.0.0.0 para que sea accesible desde el contenedor de ZAP.
    app.run(debug=False, host='0.0.0.0', port=5000, request_handler=HandlerSeguro)
