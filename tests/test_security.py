import pytest
import random
import requests
from requests.utils import unquote
import quopri
import re

# crear token
MAILHOG_API = "http://localhost:8025/api/v2/messages"

# --- Funciones auxiliares ---
def get_last_email_body():
    resp = requests.get(MAILHOG_API)
    resp.raise_for_status()
    data = resp.json()

    if not data["items"]:
        return None  # no emails received yet

    last_email = data["items"][0]
    body = last_email["Content"]["Body"]
    decoded = quopri.decodestring(body).decode("utf-8", errors="replace")
    return unquote(decoded)

def extract_links(decoded_html):
    return re.findall(r'<a\s+href=["\']([^"\']+)["\']', decoded_html, re.IGNORECASE)[0]

def extract_query_params(url):
    # regex: busca ?token= o &token= seguido de cualquier cosa hasta &, # o fin de string
    patron = re.compile(r"(?:[?&])token=([^&#]+)")
    m = patron.search(url)
    return m.group(1) if m else None

# --- Fixtures ---
@pytest.fixture(autouse=True)
def setup_create_user():
    # random username
    i= random.randint(1000, 999999)
    username = f'user{i}'
    email = f'{username}@test.com'
    password = 'password'
    salida = requests.post("http://localhost:5000/users",
                        data={
                            "username": username, 
                            "password": password,
                            "email":email,          # -> Sólo admite formato válido de correo.
                            "first_name":"Name",    # -> Sólo admite letras.
                            "last_name":"Lastname"  # -> Sólo admite letras.
                            })
    # user created
    assert salida.status_code == 201

    mail = get_last_email_body()
    link = extract_links(mail)
    token = extract_query_params(link)

    # activate user
    response = requests.post("http://localhost:5000/auth/set-password", json={"username": username, "token": token, "newPassword": password})

    return [username,password]

def test_login(setup_create_user):
    username = setup_create_user[0]
    password = setup_create_user[1]

    response = requests.post("http://localhost:5000/auth/login", json={"username": username, "password": password})
    auth_token = response.json()["token"]
    assert auth_token

'''
Teoría: Las pruebas de regresión son las que se encargan de probar todo el sistema.

Ante una nueva funcionalidad del sistema ejecutamos la prueba de regresión para asegurarnos del correcto funcionamiento del sistema.
Lo que hacemos es correr todos los tests desarrollados en etapas anteriores más los nuevos que corroboran la feature en específico. También debemos tener presente que en caso de no tener tiempo de correr todos los tests
nuevamente, lo que haríamos sería correr únicamente los nuevos junto con los anteriores que evaluamos puedan verse afectados por la implementación.

Como siguiente punto los test que vemos en esta clase, vemos que utilizan tanto la libería de pytest para ejecutarlos y desarrollarlos así como también la asistencia de la librería
"Requests" para realizar las peticiones en el tiempo de ejecución de los test para poder evaluar los resultados.

Volviendo específicamente a las funcionalidades dadas, nos encontramos con la creación y login de un nuevo usuario. En esta oportunidad reutilizaremos la lógica del login para obtener el token ya que
el endpoint con el que vamos a trabajar necesitamos estar autenticados y autorizados.

En esta oportunidad al no afectar el create user ni el login tomé la decisión de comentar los mismos ya que no se requieren.
'''
def test_sqli(setup_create_user):
    'Al igual que en el test dado obtenemos el token para poder realizar la consulta maliciosa '
    'autenticados y autorizados, utilizando un user y password conocido'

    'Crear usuario.'
    username = setup_create_user[0]
    password = setup_create_user[1]
    
    response = response = requests.post("http://localhost:5000/auth/login", json={"username": username, "password": password})
    auth_token = response.json()["token"]
    'Verifico que reciba el token'
    assert auth_token

    '''
    Creo la consulta para verificar la vulnerabildad, sigo la relizada en el práctico 2,
    lo que hacemos es mandar al servicio "Invoices" una consulta SQL en el parámetro que
    recibe desde el usuario.
    '''

    sqli_response = requests.get(
    "http://localhost:5000/Invoices?status=' OR (1/0)::int IS NOT NULL--", # divide entre 0, por lo que si SQLi no está mitigado, dará una excepción específica del DBMS.
    headers={"Authorization": f"Bearer {auth_token}"},
    )

    '''
    Para testear que funciona correctamente, osea, la vulnerabilidad no existe y está mitigada
    realizo un assert "not data" ya que la mitigiación realizada anteriormente devuelve
    un array vacio en caso de intentarlo
    '''

    data = sqli_response.json()
    assert not data

'''
Fuentes consultadas:
https://qalified.com/es/blog/pruebas-regresion/
https://docs.pytest.org/en/stable/getting-started.html#get-started
'''