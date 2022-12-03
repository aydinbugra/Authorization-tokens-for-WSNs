# BLG510E Security in Computer Networks Assignment
The authorization responsibility of the whole system is on the gateway device.

## Authorization token system for WSNs Implemantation
Gateway receives the requests as (payload, timestamp, hash) tuple. \
The hash value is hash = sha256(payload || timestamp || secret key) (with salt as passlib library is used.) \
gateway recomputes the hash with a shared secret key and verifies if it is equivalent. \
In order to prevent replay attacks, a timestamp value is used. Gateway keeps all valid requests in memory. \
Each request has limited time to use memory efficiently and scale the process. After this time they are removed
from the memory as a replay attack is not possible for expired tokens as they are invalid.

### Is this not a message authentication?
Secret keys are considered role specific secret keys. Keys are not mapped to individuals, they are mapped to roles.
