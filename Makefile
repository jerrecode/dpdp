CC ?= cc
PKG_CONFIG ?= pkg-config
CPPFLAGS += -D_GNU_SOURCE
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Wformat=2 -Werror=format-security
JSON_CFLAGS := $(shell $(PKG_CONFIG) --cflags json-c)
JSON_LIBS := $(shell $(PKG_CONFIG) --libs json-c)
TARGET := build/dpdp
.PHONY: all clean test sanitize
all: $(TARGET)
$(TARGET): src/dpdp.c
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(JSON_CFLAGS) -o $@ $< $(LDFLAGS) $(JSON_LIBS)
test: $(TARGET)
	bash tests/smoke.sh
	bash tests/sleep_states.sh
sanitize:
	$(MAKE) clean
	$(MAKE) CFLAGS='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra -Wpedantic' LDFLAGS='-fsanitize=address,undefined'
	$(MAKE) test
clean:
	rm -rf build
