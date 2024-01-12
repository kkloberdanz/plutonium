CC=cc
STD=-std=c89
OPT=-Ofast -flto=auto -g -D_FORTIFY_SOURCE=3
INC_PATH=$(SSL_HEADERS_PATH)
LIB_PATH=$(SSL_LIB_PATH)
LDFLAGS=$(LIB_PATH)
WARNING=-Wall -Wextra -Wpedantic -Wfloat-equal -Wundef -Wshadow \
	-Wpointer-arith -Wcast-align -Wstrict-prototypes -Wmissing-prototypes \
	-Wstrict-overflow=5 -Wwrite-strings -Waggregate-return -Wcast-qual \
	-Wswitch-enum -Wunreachable-code -Wformat -Wformat-security -Wvla \
	-Werror=implicit-function-declaration -Wno-error=cpp

FLAGS=-fstack-protector-all -fpie -pipe $(ARCH_SPECIFIC)
CFLAGS=$(WARNING) $(STD) $(OPT) $(FLAGS) $(EXTRA) $(INC_PATH)
NONVENDOR=

include config.mk

SRC=plutonium.c

OBJ=plutonium.o

INC=plutonium.h

.PHONY: all
all: plutonium

.PHONY: release
release: all

.PHONY: debug
debug:
	$(MAKE) all OPT='-O0 -ggdb3 -Werror -D_FORTIFY_SOURCE=3'

.PHONY: valgrind
valgrind:
	$(MAKE) all OPT='-O0 -ggdb3 -Werror' FLAGS=''

.PHONY: asan
asan:
	$(MAKE) all OPT='-O0 -ggdb3 $(SANITIZE_OPTS)'

.PHONY: tsan
tsan:
	$(MAKE) all OPT='-O0 -ggdb3 -fsanitize=thread'

.PHONY: ubsan
ubsan:
	$(MAKE) all OPT='-O0 -ggdb3 -fsanitize=undefined'

.PHONY: static-analysis
static-analysis:
	$(MAKE) all NONVENDOR='-fanalyzer'

plutonium: $(OBJ)
	$(CC) -w -o plutonium $(OBJ) $(CFLAGS) $(LDFLAGS)

src/%.o: src/%.c $(INC) Makefile
	$(CC) -c -o $@ $(CFLAGS) $(NONVENDOR) $<

.PHONY: lint
lint:
	clang-tidy $(INC) $(SRC)

.PHONY: fmt
fmt:
	clang-format -i $(INC) $(SRC)

.PHONY: clean
clean:
	rm -f $(OBJ)
	rm -f plutonium
