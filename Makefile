TARGET = goodbyedpi.exe
LIBS = -L ../binary -lWinDivert -lws2_32
CC = x86_64-w64-mingw32-gcc
CCWINDRES = x86_64-w64-mingw32-windres
CFLAGS = -Wall -I ../../include -L ../binary -O2

.PHONY: default all clean

default: manifest $(TARGET)
all: default

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c)) goodbyedpi-rc.o
HEADERS = $(wildcard *.h)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

manifest:
	$(CCWINDRES) goodbyedpi-rc.rc goodbyedpi-rc.o

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -Wall $(LIBS) -s -o $@

clean:
	-rm -f *.o
	-rm -f $(TARGET)
