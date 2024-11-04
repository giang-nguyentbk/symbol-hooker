BIN = ./bin

# RELRO_FLAGS = -Wl,-z,relro,-z,now
# RELRO_FLAGS = -Wl,-z,relro
RELRO_FLAGS = -Wl,-z,norelro
OPTIMIZED_FLAGS = -O0
WARNING_FLAGS = -w


all: create_bin library_layer1 library_layer2 main test_elf_utils

create_bin:
	@mkdir -p $(BIN)

library_layer2: $(BIN)/library_layer2.o
	gcc -shared $(OPTIMIZED_FLAGS) $(WARNING_FLAGS) $(RELRO_FLAGS) $^ -L$(BIN) -llibrary_layer1 -o $(BIN)/liblibrary_layer2.so

$(BIN)/library_layer2.o: library_layer2.c
	gcc library_layer2.c -c $(OPTIMIZED_FLAGS) $(WARNING_FLAGS) $(RELRO_FLAGS) -fPIC -o $@

library_layer1: $(BIN)/library_layer1.o
	gcc -shared $(OPTIMIZED_FLAGS) $(WARNING_FLAGS) $(RELRO_FLAGS) $^ -o $(BIN)/liblibrary_layer1.so

$(BIN)/library_layer1.o: library_layer1.c
	gcc library_layer1.c -c $(OPTIMIZED_FLAGS) $(WARNING_FLAGS) $(RELRO_FLAGS) -fPIC -o $@

main: main.c $(BIN)/elf_utils.o
	gcc $^ $(OPTIMIZED_FLAGS) $(WARNING_FLAGS) $(RELRO_FLAGS) -L$(BIN) -llibrary_layer2 -o $(BIN)/main

$(BIN)/elf_utils.o:
	gcc -c elf_utils.c $(WARNING_FLAGS) -o $@

$(BIN)/test_elf_utils.o:
	gcc -c test_elf_utils.c $(WARNING_FLAGS) -o $@

test_elf_utils: $(BIN)/elf_utils.o $(BIN)/test_elf_utils.o
	gcc $(OPTIMIZED_FLAGS) $(WARNING_FLAGS) $^ -o $(BIN)/test_elf_utils

elf:
	@$(BIN)/test_elf_utils

run:
	@echo "Please run this first if not yet: >> export LD_LIBRARY_PATH=./bin:$LD_LIBRARY_PATH"
	@$(BIN)/main

clean:
	rm -rf $(BIN)