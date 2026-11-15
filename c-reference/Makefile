# HPSP reference implementation (host build)
CC      ?= cc
CFLAGS  ?= -std=c99 -O1 -g -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion
SAN     ?= -fsanitize=address,undefined -fno-omit-frame-pointer
CORE    = src/hpsp_cbor.c src/hpsp_sha256.c src/hpsp_grant.c src/hpsp_device.c build_p256.o

all: test device

build_p256.o: third_party/p256-m/p256-m.c
	$(CC) -std=c99 -O1 -g $(SAN) -c -o $@ $<

build_p256_nosan.o: third_party/p256-m/p256-m.c
	$(CC) -std=c99 -O2 -c -o $@ $<

tests/spec_data.h: vectors/spec_vectors.json vectors/spec_examples.json tools/make_test_data.py
	python3 tools/make_test_data.py

test: tests/spec_data.h $(CORE) tests/test_main.c
	$(CC) $(CFLAGS) $(SAN) -o build_test tests/test_main.c $(CORE)
	./build_test

DEVSRC  = src/hpsp_cbor.c src/hpsp_sha256.c src/hpsp_grant.c src/hpsp_device.c
device: $(DEVSRC) build_p256_nosan.o posix/device_main.c
	$(CC) $(CFLAGS) -D_DEFAULT_SOURCE -o hpsp_device posix/device_main.c $(DEVSRC) build_p256_nosan.o

sim: device
	python3 tools/sim_controller.py ./hpsp_device

fuzz:
	clang -std=c99 -g -O1 -fsanitize=fuzzer,address,undefined -o build_fuzz tests/fuzz_device.c src/hpsp_cbor.c src/hpsp_sha256.c src/hpsp_grant.c src/hpsp_device.c third_party/p256-m/p256-m.c
	mkdir -p fuzz_corpus && ./build_fuzz -max_total_time=180 -max_len=2048 fuzz_corpus

pake:
	python3 tools/spake2plus.py
	python3 tools/check_pake_vector.py

size:
	$(CC) -std=c99 -Os -c src/hpsp_cbor.c src/hpsp_sha256.c src/hpsp_grant.c src/hpsp_device.c third_party/p256-m/p256-m.c && size *.o && rm -f *.o

clean:
	rm -f build_test build_fuzz hpsp_device *.o device_log.txt fuzz_log.txt

.PHONY: all test device sim fuzz pake size clean
