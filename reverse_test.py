import hmac
import binascii
from hashlib import sha256,sha1
import string
import subprocess

proc = subprocess.Popen(["./test",""],stdout=subprocess.PIPE)
counter = 0
while True:
    line = proc.stdout.readline()
    if line != '':
        counter += 1
        if counter == 1:
            password = line[18:].rstrip()
        if counter == 2:
            output = line[15:-3].rstrip()
    else:
        break

assert counter > 2, "Are you using production build?"
 
text = "Hi There"
hashed = hmac.new(password, text, sha256)
# The signature
signature = binascii.b2a_base64(hashed.digest())[:-1]

assert output == signature
print "Test Passed!"