all: lib test
test: clean lib_plain
	gcc -o test test.c -lhmacenc -L.

production: clean lib
	gcc -o test test.c -lhmacenc -L.

hmac_256.o: hmac_sha256.c hmac_sha256.h
	$(CC) -Wall -c hmac_sha256.c -o hmac_256.o

hmac_256_plain.o: hmac_sha256.c hmac_sha256.h
	$(CC) -Wall -DSHOW_PASS -c hmac_sha256.c -o hmac_256_plain.o

lib: hmac_256.o sha2.o
	gcc -shared -Wl -o libhmacenc.so hmac_256.o sha2.o -lc

lib_plain: hmac_256_plain.o sha2.o
	gcc -shared -Wl -o libhmacenc.so hmac_256_plain.o sha2.o -lc

sha2.o: sha2.c sha2.h
	$(CC) -c sha2.c -o sha2.o

clean:
	- rm -rf *.o hmac *.so
