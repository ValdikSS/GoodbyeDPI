ifndef MSYSTEM
	CPREFIX = x86_64-w64-mingw32-
endif

WINDIVERTHEADERS = ../../include
WINDIVERTLIBS = ../binary

TARGET = goodbyedpi.exe
LIBS = -L$(WINDIVERTLIBS) -lWinDivert -lws2_32
CC = $(CPREFIX)gcc
CCWINDRES = $(CPREFIX)windres
CFLAGS = -Wall -Wextra -I$(WINDIVERTHEADERS) -L$(WINDIVERTLIBS) \
         -O2 -pie -fPIE -Wformat -Werror=format-security -D_FORTIFY_SOURCE=2
LDFLAGS = -Wl,-O1,--sort-common,--as-needed

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
	$(CC) $(OBJECTS) -Wall $(LDFLAGS) $(LIBS) -s -o $@

clean:
	-rm -f *.o
	-rm -f $(TARGET)
