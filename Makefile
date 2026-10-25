CC ?= gcc
CFLAGS ?= -Os -pipe -Wall -Wextra -fomit-frame-pointer \
	-fno-asynchronous-unwind-tables -fno-unwind-tables \
	-ffunction-sections -fdata-sections -Wl,--gc-sections
LDFLAGS ?= -ldl
TARGET = anytls-tiny
SRC = src/anytls-tiny.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) $(LDFLAGS) -o $(TARGET)
	@echo "Build successful: $(TARGET)"
	@ls -lh $(TARGET)

strip: $(TARGET)
	strip -s $(TARGET)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -d $(DESTDIR)/usr/bin
	install -m 755 $(TARGET) $(DESTDIR)/usr/bin/$(TARGET)

.PHONY: all clean strip install
