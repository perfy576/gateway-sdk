.DEFAULT_GOAL := all
.DELETE_ON_ERROR:

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
BUILD_DIR ?= $(abspath $(ROOT)/../build)
DEPS_DIR ?= $(abspath $(ROOT)/../.deps)
JWT_CPP_SRC ?= $(DEPS_DIR)/jwt-cpp
JWT_REVISION := e71e0c2d584baff06925bbb3aad683f677e4d498
JWT_READY := $(BUILD_DIR)/deps/jwt-cpp.ready
PREFIX ?= /usr/local
DESTDIR ?=
PKG_CONFIG ?= pkg-config
CXXFLAGS ?= -O3 -DNDEBUG

SDK_CPPFLAGS = $(CPPFLAGS) -I$(ROOT)/include -isystem $(JWT_CPP_SRC)/include $(shell $(PKG_CONFIG) --cflags openssl libcurl)
SDK_CXXFLAGS = $(CXXFLAGS) -std=c++17 -pthread -Wall -Wextra -Wpedantic
SDK_LIBS := $(shell $(PKG_CONFIG) --libs openssl libcurl)
LIBRARY := $(BUILD_DIR)/libgateway_sdk.a
LIB_OBJECTS := $(BUILD_DIR)/obj/src/verifier.o $(BUILD_DIR)/obj/src/client.o
EXAMPLE_OBJECT := $(BUILD_DIR)/obj/examples/verify.o
TEST_OBJECT := $(BUILD_DIR)/obj/tests/verifier.o
OBJECTS := $(LIB_OBJECTS) $(EXAMPLE_OBJECT) $(TEST_OBJECT)

.PHONY: all deps examples test check install clean help
all: $(LIBRARY) $(BUILD_DIR)/gateway-sdk-verify
deps: $(JWT_READY)
examples: $(BUILD_DIR)/gateway-sdk-verify
test check: $(BUILD_DIR)/gateway-sdk-tests
	$(BUILD_DIR)/gateway-sdk-tests

$(JWT_READY): $(ROOT)/tools/fetch-source.sh $(ROOT)/Makefile
	$(SHELL) $(ROOT)/tools/fetch-source.sh https://github.com/Thalhammer/jwt-cpp.git $(JWT_REVISION) $(JWT_CPP_SRC)
	mkdir -p $(@D)
	touch $@

$(BUILD_DIR)/obj/%.o: $(ROOT)/%.cpp $(ROOT)/Makefile $(JWT_READY)
	mkdir -p $(@D)
	$(CXX) $(SDK_CPPFLAGS) $(SDK_CXXFLAGS) -MMD -MP -c $< -o $@

$(LIBRARY): $(LIB_OBJECTS)
	$(AR) rcs $@ $^

$(BUILD_DIR)/gateway-sdk-verify: $(EXAMPLE_OBJECT) $(LIBRARY)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(SDK_LIBS) -pthread $(LDLIBS)

$(BUILD_DIR)/gateway-sdk-tests: $(TEST_OBJECT) $(LIBRARY)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(SDK_LIBS) -pthread $(LDLIBS)

install: all
	install -d $(DESTDIR)$(PREFIX)/include/gateway_sdk $(DESTDIR)$(PREFIX)/lib $(DESTDIR)$(PREFIX)/lib/pkgconfig
	install -m 0644 $(ROOT)/include/gateway_sdk/*.hpp $(DESTDIR)$(PREFIX)/include/gateway_sdk/
	install -m 0644 $(LIBRARY) $(DESTDIR)$(PREFIX)/lib/
	sed 's|@PREFIX@|$(PREFIX)|g' $(ROOT)/gateway-sdk.pc.in > $(DESTDIR)$(PREFIX)/lib/pkgconfig/gateway-sdk.pc

clean:
	$(RM) $(OBJECTS) $(OBJECTS:.o=.d) $(LIBRARY) $(BUILD_DIR)/gateway-sdk-verify $(BUILD_DIR)/gateway-sdk-tests $(JWT_READY)

help:
	@printf '%s\n' 'make -j2       Build the static SDK and verifier example' 'make test      Build and run SDK security tests' 'make install   Install headers, archive and pkg-config metadata' 'make clean     Remove build products; retain downloaded sources' 'Overrides: BUILD_DIR DEPS_DIR JWT_CPP_SRC CXX CPPFLAGS CXXFLAGS LDFLAGS LDLIBS PREFIX DESTDIR'

-include $(OBJECTS:.o=.d)
