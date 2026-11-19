"""Pruebas automatizadas de seguridad de la aplicacion corregida.

Se ejecutan en la etapa de Test del pipeline de Jenkins. Si alguna
vulnerabilidad vuelve a aparecer en el codigo, la prueba falla y el
pipeline se detiene antes del despliegue.
"""
import pytest

import init_db
from app import app


@pytest.fixture
def client():
    init_db.crear_base_de_datos()
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    with app.test_client() as c:
        yield c


def login(c, usuario, clave):
    return c.post('/login', data={'username': usuario, 'password': clave},
                  follow_redirects=True)


def test_login_valido(client):
    r = login(client, 'admin', 'admin123')
    assert b'Panel de admin' in r.data


def test_password_incorrecta(client):
    r = login(client, 'admin', 'clave_incorrecta')
    assert b'Panel de admin' not in r.data


def test_inyeccion_sql_bloqueada(client):
    r = login(client, "admin' --", 'x')
    assert b'Panel de admin' not in r.data


def test_inyeccion_sql_or_bloqueada(client):
    r = login(client, 'admin', "' OR '1'='1")
    assert b'Panel de admin' not in r.data


def test_xss_escapado(client):
    login(client, 'admin', 'admin123')
    client.post('/update_bio', data={'nueva_bio': '<script>alert("XSS")</script>'})
    r = client.get('/dashboard')
    assert b'<script>alert' not in r.data
    assert b'&lt;script&gt;' in r.data


def test_csrf_requerido():
    app.config['WTF_CSRF_ENABLED'] = True
    try:
        c = app.test_client()
        r = c.post('/update_bio', data={'nueva_bio': 'hackeado'})
        assert r.status_code == 400
    finally:
        app.config['WTF_CSRF_ENABLED'] = False


def test_cookie_httponly(client):
    r = client.post('/login', data={'username': 'admin', 'password': 'admin123'})
    cookies = ' '.join(r.headers.getlist('Set-Cookie'))
    assert 'HttpOnly' in cookies
    assert 'SameSite=Lax' in cookies


def test_dashboard_requiere_login(client):
    r = client.get('/dashboard')
    assert r.status_code == 302


def test_debug_desactivado():
    assert app.debug is False
