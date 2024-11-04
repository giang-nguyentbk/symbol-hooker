BIN = ./bin

# RELRO_FLAGS = -Wl,-z,relro,-z,now
# RELRO_FLAGS = -Wl,-z,relro
RELRO_FLAGS = -Wl,-z,norelro
OPTIMIZED_FLAGS = -O0
WARNING_FLAGS = -w
# NO_STRIPPING_SYMBOLS = -Wl,--whole-archive
DEBUG_INFO = -g
# STACK_PROTECTION = -z execstack
STACK_PROTECTION = -z noexecstack

CCFLAGS = $(OPTIMIZED_FLAGS) $(WARNING_FLAGS) $(RELRO_FLAGS) $(NO_STRIPPING_SYMBOLS) $(DEBUG_INFO) $(STACK_PROTECTION)

all: create_bin libfoo main targetexe got_hooker

create_bin:
	@mkdir -p $(BIN)

libfoo: $(BIN)/libfoo.o
	gcc -shared $(CCFLAGS) $^ -o $(BIN)/liblibfoo.so

$(BIN)/libfoo.o: libfoo.c
	gcc libfoo.c -c $(CCFLAGS) -fPIC -o $@

$(BIN)/elf_utils.o:
	gcc -c elf_utils.c $(CCFLAGS) -o $@

$(BIN)/ptrace_wrapper.o:
	gcc -c ptrace_wrapper.c $(CCFLAGS) -o $@

main: main.c $(BIN)/elf_utils.o
	gcc $^ $(CCFLAGS) -L$(BIN) -llibfoo -o $(BIN)/main

targetexe: got_remote_hook/target.c
	gcc $^ $(CCFLAGS) -L$(BIN) -llibfoo -o $(BIN)/target

got_hooker: got_remote_hook/got_hooker.c $(BIN)/elf_utils.o $(BIN)/ptrace_wrapper.o
	gcc $^ $(CCFLAGS) -o $(BIN)/got_hooker

run:
	@echo "Please run this first if not yet: >> export LD_LIBRARY_PATH=./bin:$LD_LIBRARY_PATH"
	@$(BIN)/main

target:
	@$(BIN)/target

got:
	@$(BIN)/got_hooker

# $(BIN)/libfoo_static.o: libfoo.c
# 	gcc libfoo.c -c $(CCFLAGS) -o $@

# libfoo_static: $(BIN)/libfoo_static.o
# 	ar -rcs $(BIN)/liblibfoo_static.a $^

# main_static: libfoo_static $(BIN)/elf_utils.o
# 	gcc main.c $(BIN)/elf_utils.o $(CCFLAGS) -L$(BIN) -llibfoo_static -o $(BIN)/main_static

# runs:
# 	@$(BIN)/main_static

# static: create_bin libfoo_static main_static

clean:
	rm -rf $(BIN)