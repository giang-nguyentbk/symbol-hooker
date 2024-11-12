ROOT_DIR := $(shell git rev-parse --show-toplevel)
SW_DIR := $(ROOT_DIR)/sw
BIN_DIR := $(ROOT_DIR)/bin
SRC_DIR := $(SW_DIR)/src
GOTHOOK_DIR := $(SRC_DIR)/got_remote_hook
UTILS_DIR := $(SW_DIR)/utils
LIBRARIES_DIR := $(SW_DIR)/libraries

# RELRO_FLAGS = -Wl,-z,relro,-z,now
# RELRO_FLAGS = -Wl,-z,relro
RELRO_FLAGS = -Wl,-z,norelro
OPTIMIZED_FLAGS = -O0
WARNING_FLAGS = -w
# NO_STRIPPING_SYMBOLS = -Wl,--whole-archive
# DEBUG_INFO = -g
# STACK_PROTECTION = -z execstack
# STACK_PROTECTION = -z noexecstack

INCLUDE_PATH 	:= \
				-I$(LIBRARIES_DIR) \
				-I$(UTILS_DIR)
CCFLAGS = $(OPTIMIZED_FLAGS) $(WARNING_FLAGS) $(RELRO_FLAGS) $(NO_STRIPPING_SYMBOLS) $(DEBUG_INFO) $(STACK_PROTECTION) $(INCLUDE_PATH)

all: requires create_bin libfoo libfake libsdk main targetexe got_hooker relro_mode

requires:
	@echo "WARNING: Please run this first if not yet: >> export LD_LIBRARY_PATH=./bin:$LD_LIBRARY_PATH"

create_bin:
	@mkdir -p $(BIN_DIR)

libfoo: $(BIN_DIR)/libfoo.o
	@echo "    CC \t $(BIN_DIR)/liblibfoo.so"
	@gcc -shared $(CCFLAGS) $^ -o $(BIN_DIR)/liblibfoo.so

$(BIN_DIR)/libfoo.o: $(LIBRARIES_DIR)/libfoo.c
	@echo "    CC \t $@"
	@gcc $^ -c $(CCFLAGS) -fPIC -o $@

libfake: $(BIN_DIR)/libfake.o
	@echo "    CC \t $(BIN_DIR)/liblibfake.so"
	@gcc -shared $(CCFLAGS) $^ -o $(BIN_DIR)/liblibfake.so

$(BIN_DIR)/libfake.o: $(LIBRARIES_DIR)/libfake.c
	@echo "    CC \t $@"
	@gcc $^ -c $(CCFLAGS) -fPIC -o $@

libsdk: $(BIN_DIR)/libsdk.o
	@echo "    CC \t $(BIN_DIR)/liblibsdk.so"
	@gcc -shared $(CCFLAGS) $^ -L$(BIN_DIR) -llibfoo -o $(BIN_DIR)/liblibsdk.so

$(BIN_DIR)/libsdk.o: $(LIBRARIES_DIR)/libsdk.c
	@echo "    CC \t $@"
	@gcc $^ -c $(CCFLAGS) -fPIC -o $@

$(BIN_DIR)/elf_utils.o: $(UTILS_DIR)/elf_utils.c
	@echo "    CC \t $@"
	@gcc -c $^ $(CCFLAGS) -o $@

$(BIN_DIR)/ptrace_wrapper.o: $(UTILS_DIR)/ptrace_wrapper.c
	@echo "    CC \t $@"
	@gcc -c $^ $(CCFLAGS) -o $@

main: $(SRC_DIR)/main.c $(BIN_DIR)/elf_utils.o
	@echo "    CC \t $(BIN_DIR)/main"
	@gcc $^ $(CCFLAGS) -L$(BIN_DIR) -llibfoo -o $(BIN_DIR)/main

targetexe: $(GOTHOOK_DIR)/target.c $(BIN_DIR)/elf_utils.o
	@echo "    CC \t $(BIN_DIR)/target"
	@gcc $^ $(CCFLAGS) -L$(BIN_DIR) -llibsdk -L$(BIN_DIR) -llibfake -o $(BIN_DIR)/target

got_hooker: $(GOTHOOK_DIR)/got_hooker.c $(BIN_DIR)/elf_utils.o $(BIN_DIR)/ptrace_wrapper.o
	@echo "    CC \t $(BIN_DIR)/got_hooker"
	@gcc $^ $(CCFLAGS) -o $(BIN_DIR)/got_hooker

run:
	@$(BIN_DIR)/main

target:
	@$(BIN_DIR)/target

got:
	@$(BIN_DIR)/got_hooker

relro_mode: $(SRC_DIR)/relro_mode.c $(BIN_DIR)/elf_utils.o
	@echo "    CC \t $(BIN_DIR)/relro_mode"
	@gcc $^ $(CCFLAGS) -o $(BIN_DIR)/relro_mode

rr:
	@$(BIN_DIR)/relro_mode

clean:
	@echo "    RM \t $(BIN_DIR)"
	@rm -rf $(BIN_DIR)