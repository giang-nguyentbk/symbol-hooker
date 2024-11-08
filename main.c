#define _GNU_SOURCE
#include "libfoo.h"
#include "elf_utils.h"
#include "benchmark.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>
#include <stdlib.h>



__attribute__((visibility("hidden")))
void call_external_function() {
	printf("Calling exported function \"foo()\" from \"libfoo.so\"...\n");
	void *ptr = &foo;
	foo(1, 2);
	printf("&foo = %p\n", &foo);
}

unsigned long *get_section_address(void *handle, unsigned long elf_base_addr, const char *section) {
	unsigned long *section_addr = elf_base_addr + get_section_memory_offset(handle, section);
	printf("%s: %s range %p -> %p\n", get_elf_name(handle), section, section_addr, section_addr + get_section_size(handle, section));
	return section_addr;
}

void print_section_entries(void *handle, unsigned long *section_addr, const char *section) {
	for(int i = 0; i < get_section_num_of_entries(handle, section); ++i) {
		Dl_info info = {0};
		dladdr((void *)*(section_addr + i), &info);
		if(info.dli_sname != NULL) {
			printf("%s: %s entry %d: (%p) = %p -> %s\n", get_elf_name(handle), section, i, section_addr + i, *(section_addr + i), info.dli_sname);
		} else {
			printf("%s: %s entry %d: (%p) = %p\n", get_elf_name(handle), section, i, section_addr + i, *(section_addr + i));
		}

		if(strcmp(section, ".got.plt") == 0 && i == 1 && *(section_addr + i) != 0) {
			printf("Trying to retrieve ld dynamic linker resolver arguments %p (hint: this is the module base address of liblibfoo.so)\n", *((unsigned long *)(*(section_addr + i))));
		}
	}
}

void printf_symbol(void *handle, unsigned long elf_base_addr, const char *symbol) {
	START_BENCHMARK(start);
	unsigned long symbol_offset = get_symbol_memory_offset(handle, symbol);
	END_BENCHMARK(start, end, duration);
	PRINT_BENCHMARK(duration, "get_symbol_memory_offset");
	
	if(symbol_offset) {
		printf("%s: Symbol \'%s\' has offset = %p, absolute address = %p\n", get_elf_name(handle), symbol, symbol_offset, elf_base_addr + symbol_offset);
	} else {
		printf("%s: Does not have this symbol \'%s\'\n", get_elf_name(handle), symbol);
	}
}

#include <sys/mman.h>

void inspect_elf(const char *elf) {
	void *handle = load_elf_to_memory(elf);
	if(handle == NULL) {
		printf("Failed to load elf file %s\n", elf);
		return;
	}

	unsigned long elf_base_addr = get_load_module_base_address(PID_SELF, elf);
	// printf("%s: ELF has base address = %p\n", get_elf_name(handle), elf_base_addr);

	// get_section_address(handle, elf_base_addr, ".text");
	// get_section_address(handle, elf_base_addr, ".plt");

	// unsigned long got_addr =  get_section_address(handle, elf_base_addr, ".got");
	// print_section_entries(handle, got_addr, ".got");

	// unsigned long got_plt_addr =  get_section_address(handle, elf_base_addr, ".got.plt");
	// print_section_entries(handle, got_plt_addr, ".got.plt");

	// inspect_dynamic_section(handle, elf_base_addr);

	printf_symbol(handle, elf_base_addr, "GLOBAL_SYMBOL_VAR");
	printf("\n========================================\n");
	// printf_symbol(handle, elf_base_addr, "call_weak_fn");
	// printf("\n========================================\n");
	// printf_symbol(handle, elf_base_addr, "load_elf_to_memory");
	// printf("\n========================================\n");

	// unsigned long strcmp_offset = get_symbol_memory_offset(handle, "foo");
	// if(strcmp_offset > 0) {
	// 	unsigned long strcmp_address = elf_base_addr + strcmp_offset;

	// 	size_t page_size = sysconf(_SC_PAGESIZE);
	// 	if (strcmp_address % page_size != 0) {
	// 		strcmp_address -= strcmp_address % page_size;
	// 	}

	// 	printf("Before mprotect...\n");
	// 	if (mprotect((void *)strcmp_address, page_size, PROT_READ) < 0) {
	// 		printf("Failed to mprotect...\n");
	// 	}

	// 	// __builtin___clear_cache((void *)strcmp_address, (void *)(strcmp_address + page_size));
	// 	printf("After mprotect...\n");

	// 	foo(1, 2);
	// }

	unsigned long foo_got_entry_offset = get_got_entry_offset(handle, "foo");
	printf("GOT entry offset of symbol \'%s\' = %p, abs addr = %p\n", "foo", foo_got_entry_offset, elf_base_addr + foo_got_entry_offset);
	unsigned long foo_got_plt_entry_offset = get_got_plt_entry_offset(handle, "foo");
	printf("GOT PLT entry offset of symbol \'%s\' = %p, abs addr = %p\n", "foo", foo_got_plt_entry_offset, elf_base_addr + foo_got_plt_entry_offset);

	unload_elf_from_memory(handle);
}

void perform_got_hook(const char *main_elf, const char *libfoo_elf) {
	void *libfoo_elf_handle = load_elf_to_memory(libfoo_elf);
	if(libfoo_elf_handle == NULL) {
		printf("Failed to load elf file %s\n", libfoo_elf);
		return;
	}
	unsigned long libfoo_elf_base_addr = get_load_module_base_address(PID_SELF, libfoo_elf);
	unsigned long fake_foo_offset = get_symbol_memory_offset(libfoo_elf_handle, "fake_foo");
	unsigned long fake_foo_abs_address = libfoo_elf_base_addr + fake_foo_offset;
	printf("GOT Hook: fake_foo address = %p\n", fake_foo_abs_address);
	unload_elf_from_memory(libfoo_elf_handle);

	void *main_elf_handle = load_elf_to_memory(main_elf);
	if(main_elf_handle == NULL) {
		printf("Failed to load elf file %s\n", main_elf);
		return;
	}
	unsigned long main_elf_base_addr = get_load_module_base_address(PID_SELF, main_elf);
	unsigned long foo_got_plt_entry_offset = get_got_plt_entry_offset(main_elf_handle, "foo");
	unsigned long *foo_got_plt_entry_abs_address = (unsigned long*)(main_elf_base_addr + foo_got_plt_entry_offset);
	*foo_got_plt_entry_abs_address = fake_foo_abs_address;
	printf("GOT Hook: foo GOT PLT entry's absolute address = %p\n", foo_got_plt_entry_abs_address);
	unload_elf_from_memory(main_elf_handle);
}

int callback(struct dl_phdr_info *info, size_t size, void *data) {
	printf("Walking through shared library (NULL means main program): \'%s\'\n", info->dlpi_name);
	return 0;
}

void iterate_phdr() {
	dl_iterate_phdr(callback, NULL);
}

int main() {
	printf("pid = %d\n", getpid());
	// iterate_phdr();

	// printf("\n========================================\n");
	// int x = foo(1, 2);
	// int y = fake_foo(1, 2);
	// printf("Before GOT Hook: x = foo(1, 2) = %d\n", x);
	// printf("Before GOT Hook: y = fake_foo(1, 2) = %d\n", y);
	// printf("\n========================================\n");
	// perform_got_hook("bin/main", "bin/liblibfoo.so");
	// printf("Perform GOT Hook successfully!\n");
	// printf("\n========================================\n");
	// x = foo(1, 2);
	// y = fake_foo(1, 2);
	// printf("After GOT Hook: x = foo(1, 2) = %d\n", x);
	// printf("After GOT Hook: y = fake_foo(1, 2) = %d\n", y);


	getchar();
	printf("\n========================================\n");
	inspect_elf("bin/liblibfoo.so");
	// getchar();
	// printf("\n========================================\n");
	// inspect_elf("bin/main");

	// getchar();
	// printf("\n========================================\n");
	// call_external_function();
	// printf("========================================\n");

	// getchar();
	// inspect_elf("bin/liblibfoo.so");
	// printf("\n========================================\n");
	// inspect_elf("bin/main");

	return 0;
}