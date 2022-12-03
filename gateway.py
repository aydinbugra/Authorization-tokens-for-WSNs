from passlib.hash import pbkdf2_sha256 as hasher
from time import time
from utils import get_secret_key
import pickle

class Gateway:
    def __init__(self) -> None:
        self.TIMESTAMP_VALIDITY_PERIOD = 100 #requests are valid for 100 seconds
        self.prev_requests_in_validity_period = [] #To prevent replay attacks, requests are kept during their validity period
        self.secret_key = get_secret_key()

    def handle_request(self, request):
        request = pickle.loads(request)
        if self._is_authorized(request):
            self.prev_requests_in_validity_period.append(request)
            self.prev_requests_in_validity_period = list(filter(lambda r: r.timestamp + self.TIMESTAMP_VALIDITY_PERIOD > int(time()),
                                                            self.prev_requests_in_validity_period))
            self._route(request, request.payload['MAC'])
        else:
            raise BaseException('Unauthorized Request.')


    def _is_authorized(self, request): # h(payload||timestamp||secret) should be verified to authorize
        if int(time()) > request.timestamp + self.TIMESTAMP_VALIDITY_PERIOD:
            return False
        if self._is_replayed(request):
            return False
        return hasher.verify(str(request.payload) + str(request.timestamp) + self.secret_key, request.hash)
        

    def _is_replayed(self,request):
        return len([1 for r in self.prev_requests_in_validity_period if r.payload == request.payload and r.timestamp == request.timestamp])

    def _route(self, request, MAC): # NOT IMPLEMENTED for it is out of scope for the paper
        # routes the autorized requests to the corresponding sensor
        pass