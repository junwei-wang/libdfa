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

%.bin: %.c

clean:
	rm $(TARGET)
	rm src/*.o
