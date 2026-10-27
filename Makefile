CC ?= cc
ifeq ($(origin CXX),default)
CXX = c++
endif
CXX ?= c++
PKG_CONFIG ?= pkg-config
CPPFLAGS += -D_GNU_SOURCE
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Wformat=2 -Werror=format-security
JSON_CFLAGS := $(shell $(PKG_CONFIG) --cflags json-c gnutls)
JSON_LIBS := $(shell $(PKG_CONFIG) --libs json-c gnutls)
PAKE_SOURCE ?= build/vendor/boringssl-src
PAKE_LIB := build/vendor/boringssl/libcrypto.a
SEC_OBJ := build/obj/security.o build/obj/pairing.o build/obj/access.o build/obj/pake_bridge.o
TESTS := registry protocol identity security pairing authorization access
TARGET := build/dpdp
.PHONY: all clean test unit-test ssh-test sanitize
all: $(TARGET)
$(PAKE_LIB): scripts/build-pake.sh
	bash scripts/build-pake.sh
build/obj/pake_bridge.o: src/pake_bridge.c src/pake_bridge.h $(PAKE_LIB)
	@mkdir -p build/obj
	$(CC) $(CPPFLAGS) $(CFLAGS) -I$(PAKE_SOURCE)/include -c $< -o $@
build/obj/%.o: src/%.c src/security.h
	@mkdir -p build/obj
	$(CC) $(CPPFLAGS) $(CFLAGS) $(JSON_CFLAGS) -c $< -o $@
$(TARGET): build/obj/dpdp.o $(SEC_OBJ) $(PAKE_LIB)
	$(CXX) -o $@ build/obj/dpdp.o $(SEC_OBJ) $(PAKE_LIB) $(LDFLAGS) $(JSON_LIBS) -pthread
build/%-test: tests/%.c src/dpdp.c src/security.h $(SEC_OBJ) $(PAKE_LIB)
	@mkdir -p build/obj
	$(CC) $(CPPFLAGS) $(CFLAGS) $(JSON_CFLAGS) -c $< -o build/obj/test-$*.o
	$(CXX) -o $@ build/obj/test-$*.o $(SEC_OBJ) $(PAKE_LIB) $(LDFLAGS) $(JSON_LIBS) -pthread
unit-test: $(TARGET) $(TESTS:%=build/%-test)
	@set -e; for name in $(TESTS); do ./build/$$name-test; done
	bash tests/runtime_lock.sh
test: $(TARGET) unit-test build/source_interface-test
	./build/source_interface-test
	bash tests/smoke.sh
	bash tests/sleep_states.sh
ssh-test: build/ssh_transport-test
	python3 tests/ssh_transport.py
sanitize:
	$(MAKE) clean
	$(MAKE) CFLAGS='-std=c11 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra -Wpedantic -Wformat=2 -Werror=format-security' LDFLAGS='-fsanitize=address,undefined' test
clean:
	rm -rf build/obj build/dpdp build/source_interface-test build/ssh_transport-test $(TESTS:%=build/%-test)
