CFLAGS=-Wall
TEST_BUILD=test

ALL_SOURCES = $(wildcard *.c)
SOURCES := $(filter-out test.c,$(ALL_SOURCES))
OBJECTS = $(SOURCES:.c=.o)

all: lib test

test: CFLAGS+= -DSHOW_PASS
test: clean lib
	@python reverse_test.py


production: clean lib
	$(CC) -o $(TEST_BUILD) test.c -lhmacenc -L.

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

lib: $(OBJECTS)
	$(info ************  CREATE LIBRARY ************)
	$(CC) -shared -o libhmacenc.so $(OBJECTS) -lc
	strip libhmacenc.so

static_lib: $(OBJECTS)
	$(AR) rcs libhmacenc.a $(OBJECTS)

cygwin: clean static_lib
	$(CC) -static test.c -L. -lhmacenc -o $(TEST_BUILD)

clean:
	$(info ************ CLEAN ************)
	-@rm -rf *.o hmac *.so *.a $(TEST_BUILD)
