from request_model import Request
from passlib.hash import pbkdf2_sha256 as hasher
import pickle

class Client:
    def __init__(self,key=""):
        self.key = key

    def connect(self,gateway):
        self.gateway = gateway

    def create_token(self,payload):
        request = Request(payload)
        request.hash = hasher.hash(str(request.payload) + str(request.timestamp) + self.key)
        self.request = request
        return pickle.dumps(request)

    def send_request(self, request = None):
        if request == None:
            request = self.request
        try:
            self.gateway.handle_request(request)
            return True
        except BaseException as e:
            print(e)
            return False
    