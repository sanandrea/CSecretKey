import hmac
import binascii
from hashlib import sha256,sha1
import string
import subprocess
from ctypes import *
import os
import sys
import threading

print "Start Test"
def drain_pipe():
    global captured_stdout
    while True:
        data = os.read(stdout_pipe[0], 1024)
        if not data:
            break
        captured_stdout += data

#OPEN PIPE and stuff
stdout_fileno = sys.stdout.fileno()
stdout_save = os.dup(stdout_fileno)
stdout_pipe = os.pipe()
os.dup2(stdout_pipe[1], stdout_fileno)
os.close(stdout_pipe[1])
captured_stdout = ''
t = threading.Thread(target=drain_pipe)
t.start()


#OPEN LIB
lib = cdll.LoadLibrary("libhmacenc.so")

#Assign function to variable
testFun = lib.g

#Assign return type
testFun.restype = c_char_p

#Message to be encrypted:
text = "Hi There"

#Input for my c Function
message = c_char_p(text)
i = c_int()
e = c_int()


result = testFun(message,len(text),byref(e),byref(i))


# Close the write end of the pipe to unblock the reader thread and trigger it
# to exit
os.close(stdout_fileno)
t.join()

# Clean up the pipe and restore the original stdout
os.close(stdout_pipe[0])
os.dup2(stdout_save, stdout_fileno)
os.close(stdout_save)

#print 'Captured stdout:\n%s' % captured_stdout

outList = captured_stdout.split('\n')

assert len(outList) > 1, "Are you using production build?"
for index,item in enumerate(outList):
    if index == 0:
        password = item[18:].rstrip()
        print "Password produced: ", password
    if index == 1:
        output = item[15:-3].rstrip()
        print "Encrypted message: ", output


        
#Python implementation of HMAC
hashed = hmac.new(password, text, sha256)
# The signature
signature = binascii.b2a_base64(hashed.digest())[:-1]

assert output == signature
print "Test Passed!"

