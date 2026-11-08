CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 \
            -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE
# Standalone static executable (course requirement): libcrypto and libc are
# linked in, as static-PIE so ASLR and full RELRO still apply. The linker's
# "dlopen/getaddrinfo in statically linked applications" warnings come from
# OpenSSL's engine/socket code, which this program never calls.
LDFLAGS  ?= -static-pie -Wl,-z,relro,-z,now
# Include OpenSSL's private dependencies when linking statically (Ubuntu 26.04).
CPPFLAGS += -isystem third_party   # vendored nlohmann/json 3.11.3 (header-only, MIT)
LDLIBS   := $(shell pkg-config --static --libs libcrypto 2>/dev/null || echo -lcrypto)

SRCS := src/main.cpp src/shell.cpp src/storage.cpp src/jsonio.cpp src/crypto.cpp src/util.cpp
OBJS := $(SRCS:.cpp=.o)

fileserver: $(OBJS)
	@$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS) 2> $@.ldlog || { cat $@.ldlog; rm -f $@.ldlog; exit 1; }
	@grep -v -e 'statically linked applications requires at runtime' -e ': in function' $@.ldlog || true
	@rm -f $@.ldlog
	@echo "linked $@ (static-pie)"

src/%.o: src/%.cpp src/*.h
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c -o $@ $<

test: fileserver
	./tests/run_tests.sh

# --- Sanitizer build (development only) ---------------------------------------
# AddressSanitizer + UndefinedBehaviorSanitizer cannot be linked statically, so
# this is a separate, dynamically linked binary with its own object directory;
# the static ./fileserver is left untouched. Any finding aborts the process.
SAN_DIR   := build-asan
SAN_OBJS  := $(SRCS:src/%.cpp=$(SAN_DIR)/%.o)
SAN_FLAGS := -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
SAN_CXXFLAGS := -std=c++17 -O1 -g -Wall -Wextra $(SAN_FLAGS)

fileserver-asan: $(SAN_OBJS)
	$(CXX) $(SAN_FLAGS) -o $@ $(SAN_OBJS) $(LDLIBS)

$(SAN_DIR)/%.o: src/%.cpp src/*.h | $(SAN_DIR)
	$(CXX) $(CPPFLAGS) $(SAN_CXXFLAGS) -c -o $@ $<

$(SAN_DIR):
	mkdir -p $@

# Runs the full suite against the sanitized binary. Reports go to san-logs/
# (so a leak report at exit cannot go unnoticed); any report fails the target.
test-asan: fileserver-asan
	@rm -rf san-logs && mkdir san-logs
	@status=0; \
	BIN=$(CURDIR)/fileserver-asan \
	ASAN_OPTIONS=log_path=$(CURDIR)/san-logs/asan:detect_leaks=1:abort_on_error=1 \
	UBSAN_OPTIONS=log_path=$(CURDIR)/san-logs/ubsan:print_stacktrace=1 \
	./tests/run_tests.sh || status=1; \
	if ls san-logs/* > /dev/null 2>&1; then \
	    echo "sanitizer reports (full traces in san-logs/):"; \
	    grep -h '^SUMMARY' san-logs/* | sort | uniq -c; status=1; \
	else echo "sanitizers: no reports"; fi; \
	exit $$status

clean:
	rm -rf fileserver $(OBJS) fileserver-asan $(SAN_DIR) san-logs

.PHONY: test test-asan clean
