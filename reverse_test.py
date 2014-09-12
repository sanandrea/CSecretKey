import hmac
import binascii
from hashlib import sha256,sha1
import string



key = "lorux0369ADwW:zzzzz:'^-->.;*+CHMRWbglqv05+DINSXchm" 
text = "Hi There" 
hashed = hmac.new(key, text, sha256)
# The signature
print binascii.b2a_base64(hashed.digest())[:-1]