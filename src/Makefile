ifndef MSYSTEM
	CPREFIX = x86_64-w64-mingw32-
endif

WINDIVERTHEADERS = ../../../include
WINDIVERTLIBS = ../../binary
MINGWLIB = /usr/x86_64-w64-mingw32/lib/

TARGET = ../build/goodbyedpi.exe
# Linking SSP does not work for some reason, the executable doesn't start.
#LIBS = -L$(WINDIVERTLIBS) -Wl,-Bstatic -lssp -Wl,-Bdynamic -lWinDivert -lws2_32
LIBS = -L$(WINDIVERTLIBS) -lWinDivert -lws2_32 -l:libssp.a
CC = $(CPREFIX)gcc

CCWINDRES = $(CPREFIX)windres
ifeq (, $(shell which $(CPREFIX)windres))
	CCWINDRES = windres
endif

CFLAGS = -std=c99 -pie -fPIE -pipe -I$(WINDIVERTHEADERS) -L$(WINDIVERTLIBS) \
         -O2 -D_FORTIFY_SOURCE=2 -fstack-protector \
         -Wall -Wextra -Wpedantic -Wformat=2 -Wformat-overflow=2 -Wformat-truncation=2 \
         -Wformat-security -Wno-format-nonliteral -Wshadow -Wstrict-aliasing=1 \
         -Wnull-dereference -Warray-bounds=2 -Wimplicit-fallthrough=3 \
         -Wstringop-overflow=4 \
         -Wformat-signedness -Wstrict-overflow=2 -Wcast-align=strict \
         -Wfloat-equal -Wcast-align -Wsign-conversion \
         #-fstack-protector-strong
LDFLAGS = -fstack-protector -Wl,-O1,-pie,--dynamicbase,--nxcompat,--sort-common,--as-needed \
-Wl,--disable-auto-image-base

ifdef BIT64
	LDFLAGS += -Wl,--high-entropy-va -Wl,--pic-executable,-e,mainCRTStartup
else
	CFLAGS += -m32
	LDFLAGS += -Wl,--pic-executable,-e,_mainCRTStartup -m32
endif

.PHONY: default all clean

default: $(TARGET)
all: default

OBJECTS = $(patsubst %.c, ../build/%.o, $(wildcard *.c utils/*.c)) ../build/goodbyedpi-rc.o
HEADERS = $(wildcard *.h utils/*.h)

../build/%.o: %.c $(HEADERS)
	@mkdir -p ../build/utils
	$(CC) $(CFLAGS) -c $< -o $@

../build/goodbyedpi-rc.o:
	@mkdir -p ../build/utils
	$(CCWINDRES) goodbyedpi-rc.rc ../build/goodbyedpi-rc.o

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) $(LIBS) -s -o $@

clean:
	-rm -f ../build/*.o ../build/utils/*.o
	-rm -f $(TARGET)
