
all: clean ed25519_dalek_test

CWD = $(shell pwd)
TOP_DIR = $(subst /examples/ffi,,$(CWD))

ed25519_dalek_test:
	-cargo build --features='nightly ffi' --release
	gcc ed25519_dalek_test.c -o ed25519_dalek_test -L${TOP_DIR}/target/release/ -led25519_dalek

clean:
	-rm ed25519_dalek_test
