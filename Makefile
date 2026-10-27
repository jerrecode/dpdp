CC ?= cc
PKG_CONFIG ?= pkg-config
CPPFLAGS += -D_GNU_SOURCE
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Wformat=2 -Werror=format-security
JSON_CFLAGS := $(shell $(PKG_CONFIG) --cflags json-c)
JSON_LIBS := $(shell $(PKG_CONFIG) --libs json-c)
TARGET := build/dpdp
.PHONY: all clean test unit-test sanitize
all: $(TARGET)
$(TARGET): src/dpdp.c
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(JSON_CFLAGS) -o $@ $< $(LDFLAGS) $(JSON_LIBS)
build/registry-test: tests/registry.c src/dpdp.c
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(JSON_CFLAGS) -o $@ $< $(LDFLAGS) $(JSON_LIBS)
build/protocol-test: tests/protocol.c src/dpdp.c
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(JSON_CFLAGS) -o $@ $< $(LDFLAGS) $(JSON_LIBS)
build/identity-test: tests/identity.c src/dpdp.c
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(JSON_CFLAGS) -o $@ $< $(LDFLAGS) $(JSON_LIBS)
unit-test: build/registry-test build/protocol-test build/identity-test
	./build/registry-test
	./build/protocol-test
	./build/identity-test
test: $(TARGET) unit-test
	bash tests/smoke.sh
	bash tests/sleep_states.sh
sanitize:
	$(MAKE) clean
	$(MAKE) CFLAGS='-std=c11 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra -Wpedantic -Wformat=2 -Werror=format-security' LDFLAGS='-fsanitize=address,undefined' test
clean:
	rm -rf build
