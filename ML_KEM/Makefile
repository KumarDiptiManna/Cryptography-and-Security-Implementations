# ML-KEM (Kyber) in C - build, test and benchmark
CC      ?= gcc
OPT     ?= -O3
# make NATIVE=1 to add -march=native (faster, but results are machine specific)
ifeq ($(NATIVE),1)
OPT += -march=native
endif
CFLAGS  ?= -std=c99 -Wall -Wextra -Wpedantic -Wshadow $(OPT)
CFLAGS  += -Iinclude -Isrc
BUILDFL := "$(CC) $(CFLAGS)"

SRC := src/mlkem.c src/fips202.c src/randombytes.c
OBJ := $(SRC:.c=.o)

.PHONY: all test bench example clean
all: libmlkem.a

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

libmlkem.a: $(OBJ)
	ar rcs $@ $^

test_mlkem: tests/test_mlkem.c libmlkem.a
	$(CC) $(CFLAGS) $< libmlkem.a -o $@

bench_mlkem: bench/bench.c libmlkem.a
	$(CC) $(CFLAGS) -DBUILD_FLAGS='$(BUILDFL)' $< libmlkem.a -lm -o $@

example: examples/example.c libmlkem.a
	$(CC) $(CFLAGS) $< libmlkem.a -o example_mlkem

test: test_mlkem
	./test_mlkem

bench: bench_mlkem
	./bench_mlkem

clean:
	rm -f $(OBJ) libmlkem.a test_mlkem bench_mlkem example_mlkem
