SHELL = /bin/bash
CFLAGS = -fPIC -Iinclude
LDFLAGS = -shared

HEADERS = $(shell echo include/*.h)
SOURCES = $(shell echo src/*.c)
OBJECTS = $(SOURCES:.c=.o)
TARGET = libdfa.so

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o $@ $(LDFLAGS)

.PHONY: test clean

test: $(TARGET)
	gcc -Iinclude -L. -ldfa test/test_aes_128.c -o test_aes_128
	./test_aes_128

clean:
	rm $(TARGET)
	rm src/*.o
