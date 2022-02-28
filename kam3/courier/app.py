from jwt import decode, encode
from os import getenv
from dotenv import load_dotenv
from flask import request, make_response
from redis import StrictRedis
import datetime
import json
import requests
load_dotenv()

JWT_SECRET = getenv('JWT_SECRET')
WEB_URL = getenv('WEB_URL')

def token_gen():
    payload = {
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1, seconds=10),
        'sub': 'courier',
        'iss': 'courier',
        }
    token = encode(payload, JWT_SECRET, algorithm='HS256').decode('utf-8')
    return token

def show():
    res = requests.get(WEB_URL + "/labels/all", headers = hed)
    if res.status_code == 200:
        print(json.dumps(json.loads(res.text), sort_keys=True, indent=4))
    else:
        print(res.text)

def delete():
    url = input('podaj link: ')
    try:
      res = requests.delete(WEB_URL + url, headers = hed, timeout=5)
    except Exception as e:
      print(str(e))
      return
    if res.status_code == 200:
        print(json.dumps(json.loads(res.text), sort_keys=True, indent=4))
    else:
        print(res.text)

def post():
    url = input('podaj link: ')
    status = input('status(1 - paczka w drodze, 2 - paczka dostarczona, 3 - paczka odebrana: ')
    packageStatus = dict()
    if status == '1':
        packageStatus['status'] = "nadana-w_drodze"
    elif status == '2':
        packageStatus['status'] = "nadana-dostarczona"
    elif status == '3':
        packageStatus['status'] = "nadana-odebrana"
    else:
        print('nie udało się zmienić statusu')
        return
    try:
      res = requests.post(WEB_URL + url, headers = hed, json = packageStatus, timeout=5)
    except Exception as e:
      print(str(e))
      return
    if res.status_code == 200:
        print(json.dumps(json.loads(res.text), sort_keys=True, indent=4))
    else:
        print(res.text)

token = token_gen()
hed = {'Authorization': f'Bearer {token}'}  

def get_user_choice():
    print("komendy")
    print('show - pokazuje wszystkie etykiety')
    print('post - nadaj paczke i ustaw status, konieczny link do wysłania')
    print('delete - usuwa etykiety i paczki, konieczny link do usuniecia')
    print('exit - wyjdź')
    
    return input("wpisz komende: ")

print('hello')
com = ''
while(com != 'exit'):
    com = get_user_choice()
    if com == 'show':
        show()
    if com == 'delete':
        delete()
    if com == 'post':
        post()
    if com == 'exit':
        print('bye')
