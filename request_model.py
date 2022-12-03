from time import time

class Request:
   def  __init__(self, payload, timestamp = int(time()), hash_val = None):
    self.payload = payload
    self.timestamp = timestamp
    self.hash_val = hash_val
