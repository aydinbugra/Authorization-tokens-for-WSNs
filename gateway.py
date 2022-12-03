from passlib.hash import pbkdf2_sha256 as hasher
from time import time
from utils import get_secret_key

class Gateway:
    def __init__(self) -> None:
        self.TIMESTAMP_VALIDITY_PERIOD = 100 #requests are valid for 100 seconds
        self.prev_requests_in_validity_period = [] #To prevent replay attacks, requests are kept during their validity period
        self.secret_key = get_secret_key()

    def handle_request(self, request):
        if self.is_authorized(request):
            self.prev_requests_in_validity_period.append(request)
            self.prev_requests_in_validity_period = list(filter(lambda r: r.timestamp + self.TIMESTAMP_VALIDITY_PERIOD > int(time()),
                                                            self.prev_requests_in_validity_period))
            self.route(request, request.payload['MAC'])
        else:
            raise BaseException('Unauthorized Request.')


    def is_authorized(self, request): # h(payload||timestamp||secret) should be verified to authorize
        if int(time()) > request.timestamp + self.TIMESTAMP_VALIDITY_PERIOD:
            return False
        if request in self.prev_requests_in_validity_period:
            return False
        return hasher.verify(str(request.payload) + str(request.timestamp) + self.secret_key, request.hash)
        

    def route(self, request, MAC): # NOT IMPLEMENTED for it is out of scope for the paper
        # routes the autorized requests to the corresponding sensor
        pass