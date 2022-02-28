from flask import Flask, g
from flask_hal import HAL
from flask_hal.document import Document, Embedded
from flask_hal.link import Link
import redis
from jwt import decode
from os import getenv
from dotenv import load_dotenv
from flask import request, make_response
from redis import StrictRedis
import json
load_dotenv()
app = Flask(__name__)
HAL(app)
JWT_SECRET = getenv('JWT_SECRET')
WEB_URL = getenv('WEB_URL')
REDIS_PASS = getenv('REDIS_PASS')
REDIS_HOST = getenv('REDIS_HOST')
#db = StrictRedis(host='redis',port=6379, db=0, decode_responses=True)
db = StrictRedis(REDIS_HOST, port=9899, password=REDIS_PASS, db=1, decode_responses=True)

SESSION_TYPE = 'redis'
SESSION_REDIS = db
app = Flask(__name__)
app.config.from_object(__name__)
app.secret_key = getenv('SECRET_KEY')

@app.route('/', methods=['GET'])
def home():
    links = []
    links.append(Link('labels', '/labels/all'))
    document = Document(data = {}, links=links)
    return document.to_json(), 200


@app.before_request
def before_request_func():
    token = request.headers.get('Authorization','').replace('Bearer ','')
    try:
      g.authorization = decode(token, JWT_SECRET, algorithms=['HS256'])
      print('Authorized: ' + str(g.authorization))
    except Exception as e:
      print('Unauthorized: ' + str(e))
      g.authorization = {}


def get_labels():
    label=[]
    for k in db.scan_iter(f'label:*'):
        vals = dict()
        vals['recipient'] = db.hget(k, 'recipient')
        vals['identificator'] = db.hget(k, 'identificator')
        vals['size'] = db.hget(k, 'size')
        vals['pid'] = db.hget(k, 'pid')
        vals['status'] = db.hget(k, 'status')
        label.append(vals)
    return label

def get_user_labels(username):
    label=[]
    for k in db.scan_iter(f'label:*'):
        vals = dict()
        vals['recipient'] = db.hget(k, 'recipient')
        vals['identificator'] = db.hget(k, 'identificator')
        vals['size'] = db.hget(k, 'size')
        vals['pid'] = db.hget(k, 'pid')
        vals['status'] = db.hget(k, 'status')
        if(db.hget(k, 'sendername') == username):
            label.append(vals)
    return label

def is_redis_available():
    try:
        db.ping()
    except (redis.exceptions.ConnectionError):
        return False
    return True

@app.route('/labels/all', methods=['GET'])
def get_all():
    if g.authorization.get('sub') is None:
        return 'Brak dostępu', 401
    if g.authorization.get('iss') is None:
        return 'Brak dostępu', 401
    if not is_redis_available:
        return 'Brak połączenia z bazą', 503

    labels = []
    labeles = []
    link = []
    if g.authorization.get('iss') == 'client':
        labels = get_user_labels(g.authorization.get('sub'))
    elif g.authorization.get('iss') == 'courier':
        labels = get_labels()  
    link.append(Link('self', '/labels/all'))
    for label in labels:
        links = []
        links.append(Link('delete', '/labels/delete/' + label['pid']))
        links.append(Link('post', '/labels/post/' + label['pid']))
        data = { 
            'pid':label['pid'], 
            'recipient':label['recipient'], 
            'size':label['size'], 
            'identificator':label['identificator'], 
            'status':label['status'] 
            }
        labeles.append(Embedded(data = data, links = links))
    document = Document(embedded={'labels':Embedded(data=labeles)}, links=link)
    return document.to_json(), 200


@app.route('/labels/delete/<pid>', methods=['DELETE'])       
def delete(pid):
    print(g.authorization.get('sub'))
    if g.authorization.get('sub') is None:
        return 'Brak dostepu', 401
    if g.authorization.get('iss') is None:
        return 'Brak dostępu', 401
    if not db.hexists(f'label:{pid}', 'pid'):
        return 'Obiekt nie istnieje', 404
    if not is_redis_available:
        return 'Brak połączenia z bazą', 503
    
    if g.authorization.get('iss') == 'client' and db.hget(f'label:{pid}', 'status') == 'oczekuje':
        db.delete(f'label:{pid}')
    elif g.authorization.get('iss') == 'courier':
        db.delete(f'label:{pid}')
    else:
        return 'Brak dostępu', 403
    links = []
    links.append(Link('self', '/labels/delete/' + str(pid)))
    links.append(Link('all', '/labels/all'))
    document = Document(data = {}, links=links)
    return document.to_json(), 200

@app.route('/labels/add/<pid>', methods=['POST'])       
def add(pid):
    if g.authorization.get('sub') is None:
        return 'Brak dostępu', 401
    if g.authorization.get('iss') != 'client':
        return 'Brak dostępu', 403
    if not is_redis_available:
        return 'Brak połączenia z bazą', 503
    label = request.json
    links = []
    links.append(Link('self', '/labels/add/' + str(pid)))
    links.append(Link('all', '/labels/all'))
    db.hset(f'label:{pid}', 'sendername', label['sendername'])
    db.hset(f'label:{pid}', 'recipient', label['recipient'])
    db.hset(f'label:{pid}', 'size', label['size'])
    db.hset(f'label:{pid}', 'identificator', label['identificator'])
    db.hset(f'label:{pid}', 'pid', pid)
    db.hset(f'label:{pid}', 'status', label['status'])  
    document = Document(data = {}, links=links)
    return document.to_json(), 200

@app.route('/labels/post/<pid>', methods=['POST'])       
def post(pid):
    if g.authorization.get('sub') is None:
        return 'Brak dostępu', 401
    if g.authorization.get('iss') is None:
        return 'Brak dostępu', 401
    if g.authorization.get('sub') != 'courier':
        return 'Brak dostępu', 403
    if g.authorization.get('iss') != 'courier':
        return 'Brak dostępu', 403
    if not db.hexists(f'label:{pid}', 'pid'):
        return 'Obiekt nie istnieje', 404
    if not is_redis_available:
        return 'Brak połączenia z bazą', 503
    links = []
    links.append(Link('self', '/labels/post/' + str(pid)))
    links.append(Link('all', '/labels/all'))
    status = request.json
    db.hset(f'label:{pid}', 'status', status['status'])  
    document = Document(data = {}, links=links)
    return document.to_json(), 200
if __name__ == '__main__':
    app.run(port=5000, debug=True)
