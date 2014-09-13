CSecretKey
=
This is an implementation of the hmac, key-hashing authentication code in the C language.
The generation of the secret key is included in the final binary. 

The secret key is obtained by concatenating 3 String against some pseudo random Strings that make the retrieval of the key a little harder for discrete programmers(hackers). 

This can be really useful (I hope so) in mobile Applications (Android & iOS) where the client must be equipped with a secret key to access a private API across the network.

###To customize
In hmac_256.c:
* Change aux1, aux2, aux3 contents with yours.
* Change rain and salt to some integers 
* Change snow and pepper to some integers 


###iOS
To show the password generated

`make test`

`./test`



Once the password is generated you can hide it by:

`make production`

At this point, `libhmacenc.so` is ready to be used in production! Running `./test` will not print the password this time.

###Android
To build as JNI code for Android:
leave only source files and `Android.mk` define or undefined `SHOW_PASS` to show password in logcat

###Cross-check
To cross-check take the input text string and the password generated and put them in
`reverse_test.py`. The output must be the same

####Credits
I would like to thank Olivier Gay for providing standard [hmac](https://github.com/ogay/hmac) library
