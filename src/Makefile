ifndef MSYSTEM
	CPREFIX = x86_64-w64-mingw32-
endif

WINDIVERTHEADERS = ../../../include
WINDIVERTLIBS = ../../binary
MINGWLIB = /usr/x86_64-w64-mingw32/lib/

TARGET = goodbyedpi.exe
# Linking SSP does not work for some reason, the executable doesn't start.
#LIBS = -L$(WINDIVERTLIBS) -Wl,-Bstatic -lssp -Wl,-Bdynamic -lWinDivert -lws2_32
LIBS = -L$(WINDIVERTLIBS) -lWinDivert -lws2_32
CC = $(CPREFIX)gcc
CCWINDRES = $(CPREFIX)windres
CFLAGS = -std=c99 -pie -fPIE -pipe -I$(WINDIVERTHEADERS) -L$(WINDIVERTLIBS) \
         -O2 -D_FORTIFY_SOURCE=2 \
         -Wall -Wextra -Wpedantic -Wformat=2 -Wshadow -Wstrict-aliasing=1 -Werror=format-security \
         -Wfloat-equal -Wcast-align -Wsign-conversion \
         #-fstack-protector-strong
LDFLAGS = -Wl,-O1,-pie,--dynamicbase,--nxcompat,--sort-common,--as-needed \
-Wl,--image-base,0x140000000 -Wl,--disable-auto-image-base

ifdef BIT64
	LDFLAGS += -Wl,--high-entropy-va -Wl,--pic-executable,-e,mainCRTStartup
else
	LDFLAGS += -Wl,--pic-executable,-e,_mainCRTStartup
endif

.PHONY: default all clean

default: manifest $(TARGET)
all: default

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c utils/*.c)) goodbyedpi-rc.o
HEADERS = $(wildcard *.h utils/*.h)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

manifest:
	$(CCWINDRES) goodbyedpi-rc.rc goodbyedpi-rc.o

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) $(LIBS) -s -o $@

clean:
	-rm -f *.o utils/*.o
	-rm -f $(TARGET)
