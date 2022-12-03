from client import Client
from gateway import Gateway
from request_model import Request
from utils import get_secret_key

secret_key = get_secret_key()

client = Client(secret_key)
gateway = Gateway()

payload = {'MAC': '00:00', 'method': 'get_temperature'}
client.connect(gateway)
request = client.create_request(payload)
is_send = client.send_request(request)
print('Is valid request with correct secret key authorized: ' + str(is_send))

# try replay same Request
is_send = client.send_request(request)
print('Is replayed request with correct secret key authorized: ' + str(is_send))

# try sending message with wrong secret key
new_client = Client('secret_key')
new_client.connect(gateway)
new_request = new_client.create_request(payload)
is_send = new_client.send_request(new_request)
print('Is valid request with wrong secret key authorized: ' + str(is_send))