#define _GNU_SOURCE
#include "libsdk.h"
#include "libfake.h"
#include "elf_utils.h"
#include "benchmark.h"

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>

#define SYMBOL_GOT_HOOKING_DETECTED -1
#define SYMBOL_GOT_HOOKING_NOT_DETECTED 0
#define PRINT_GOT_PLT_ENTRIES(elf)		printf("\n========================================\n"); \
										print_got_plt_entries(elf); \
										printf("========================================\n\n");

typedef ElfW(Addr) (*DlFixupFuncPtr)(struct link_map *, ElfW(Word));

#ifdef __aarch64__
#define scan_dl_runtime_resolve_text_segment(arg) scan_dl_runtime_resolve_text_segment_aarch64(arg)
#elif defined __x86_64__
#define scan_dl_runtime_resolve_text_segment(arg) scan_dl_runtime_resolve_text_segment_x86_64(arg)
#else
#define scan_dl_runtime_resolve_text_segment(arg) NULL
#endif

/* Symbol hooking detection */
DlFixupFuncPtr scan_dl_runtime_resolve_text_segment_x86_64(unsigned long dl_runtime_resolve_addr) {
	uint8_t *byte_code = (uint8_t *)dl_runtime_resolve_addr;
	for(int i = 0; i < 300; ++i) {
		if(byte_code[i] == (uint8_t)0xE8) {
			int32_t *ptr = (int32_t *)(byte_code + i  + 1);
			if(*ptr < 0) {
				int32_t offset = *ptr;
				void *pc = (void *)(byte_code + i  + 5); // sizeof call _dl_fixup instruction = 5 bytes -> PC = next instruction
				unsigned long dl_fixup_addr = (unsigned long)(pc + offset);
				if(dl_fixup_addr > 0) {
					return (DlFixupFuncPtr)dl_fixup_addr;
				}
			}
		}
	}

	printf("Failed to scan_dl_runtime_resolve_text_segment!\n");
	return NULL;
}

DlFixupFuncPtr scan_dl_runtime_resolve_text_segment_aarch64(unsigned long dl_runtime_resolve_addr) {
	uint32_t *byte_code = (uint32_t *)dl_runtime_resolve_addr;
	for(int i = 0; i < 100; ++i) {
		if((byte_code[i] & (uint32_t)0x97FFF000) == (uint32_t)0x97FFF000) {
			uint32_t *ptr = byte_code + i;
			int32_t instruction_operand = *ptr & 0x03FFFFFF;
			int32_t offset = 0x04000000 - instruction_operand;
			offset = -(offset * 4);
			void *pc = (void *)(ptr);
			unsigned long dl_fixup_addr = (unsigned long)(pc + offset);
			if(dl_fixup_addr > 0) {
				return (DlFixupFuncPtr)dl_fixup_addr;
			}
		}
	}

	printf("Failed to scan_dl_runtime_resolve_text_segment!\n");
	return NULL;
}

DlFixupFuncPtr find_dl_fixup() {
	FILE *f = fopen("/proc/self/maps", "r");
	if(f == NULL) {
		printf("Failed to open /proc/self/maps in find_dl_fixup!\n");
		return NULL;
	}

	char line[512] = {0};
	char prev_path[151] = {0}, path[151] = {0}, perm[5] = {0};
	unsigned long s = 0, e = 0;
	while(fgets(line, sizeof(line), f)) {
		sscanf(line, "%lx-%lx %4s %*x %*x:%*x %*d %150s", &s, &e, perm, path);
		if(strchr(path, '/') != NULL && strcmp(prev_path, path) != 0) {
			void *handle = load_elf_to_memory(path);
			int relro = is_full_relro_enabled(handle);
			if(relro == IS_NO_RELRO) {
				// Try to retrieve _dl_runtime_resolve
				unsigned long gotplt_offset = get_section_memory_offset(handle, ".got.plt");
				if(gotplt_offset > 0) {
					unsigned long module_base_addr = s;
					unsigned long *gotplt = (unsigned long *)(module_base_addr + gotplt_offset);
					unsigned long dl_runtime_resolve_addr = gotplt[2];
					if(dl_runtime_resolve_addr > 0) {
						DlFixupFuncPtr dl_fixup_addr = scan_dl_runtime_resolve_text_segment(dl_runtime_resolve_addr);
						if(dl_fixup_addr > 0) {
							// printf("Found dynamic runtime resolver _dl_fixup = %p in ELF %s\n", dl_fixup_addr, path);
							unload_elf_from_memory(handle);
							fclose(f);
							return dl_fixup_addr;
						}
					}
				}
			}
			unload_elf_from_memory(handle);
			strcpy(prev_path, path);
		}
	}

	printf("Could not find _dl_fixup in /proc/self/maps!\n");
	fclose(f);
	return NULL;
}

struct link_map *find_link_map(const char *target_elf, const char *symbol) {
	FILE *f = fopen("/proc/self/maps", "r");
	if(f == NULL) {
		printf("Failed to open /proc/self/maps in find_link_map!\n");
		return NULL;
	}

	struct link_map *lm;
	char line[512] = {0};
	char prev_path[151] = {0}, path[151] = {0}, perm[5] = {0};
	unsigned long s, e;
	while(fgets(line, sizeof(line), f)) {
		sscanf(line, "%lx-%lx %4s %*x %*x:%*x %*d %150s", &s, &e, perm, path);
		if(strchr(path, '/') != NULL && strcmp(prev_path, path) != 0 && strstr(path, target_elf) != NULL) {
			Dl_info info = {0};
			int ret = dladdr1((void *)s + 100, &info, (void **)&lm, RTLD_DL_LINKMAP);
			if(ret) {
				fclose(f);
				return lm;
			}
			strcpy(prev_path, path);
		}
	}

	printf("Could not find ELF %s in /proc/self/maps!\n", target_elf);
	fclose(f);
	return NULL;
}

ElfW(Sxword) find_reloc_index(const char *target_elf, const char *symbol, unsigned long *current_gotplt_entry_value, unsigned long *gotplt_entry_index) {
	void *handle = load_elf_to_memory(target_elf);
	int relro = is_full_relro_enabled(handle);
	if(relro) {
		printf("This ELF '%s' has FULL RELRO enabled, no .got.plt section available!\n", target_elf);
		unload_elf_from_memory(handle);
		return -1;
	}
	unsigned long gotplt_offset = get_section_memory_offset(handle, ".got.plt");
	if(gotplt_offset == 0) {
		printf("This ELF '%s' does not have .got.plt section!\n", target_elf);
		unload_elf_from_memory(handle);
		return -1;
	}
	unsigned long gotplt_entry_offset = get_got_plt_entry_offset(handle, symbol);
	if(gotplt_entry_offset == 0) {
		printf("This ELF '%s' does not have symbol '%s' in .got.plt section!\n", target_elf, symbol);
		unload_elf_from_memory(handle);
		return -1;
	}
	unsigned long module_base_addr = get_load_module_base_address(PID_SELF, target_elf);
	if(module_base_addr == 0) {
		printf("This ELF '%s' was not loaded into memory yet!\n", target_elf);
		unload_elf_from_memory(handle);
		return -1;
	}
	unsigned long plt_start = module_base_addr + get_section_memory_offset(handle, ".plt");
	unsigned long plt_end = plt_start + get_section_size(handle, ".plt");
	unsigned long *gotplt_entry = (unsigned long *)(module_base_addr + gotplt_entry_offset);
	*current_gotplt_entry_value = *gotplt_entry;
	if(*current_gotplt_entry_value >= plt_start && *current_gotplt_entry_value < plt_end) {
		printf("This symbol '%s' was not resolved yet in ELF %s!\n", symbol, target_elf);
		unload_elf_from_memory(handle);
		return -1;
	}
	
	/* Get .got.plt entry's index of symbol in target_elf -> calculate reloc_arg - the 2nd argument of _dl_fixup */
	*gotplt_entry_index = (gotplt_entry_offset - gotplt_offset) / sizeof(unsigned long);
	ElfW(Sxword) reloc_index = (ElfW(Sxword))((*gotplt_entry_index - 2)*sizeof(unsigned long)*3 / sizeof(ElfW(Rela)) - 1);
#ifdef __aarch64__
	reloc_index *= sizeof(ElfW(Rela)); // aarch64 uses byte indexing instead of ElfW(Rela)-size indexing like x86_64
#endif

	unload_elf_from_memory(handle);
	return reloc_index;
}

int symbol_got_hooking_detection(const char *target_elf, const char *symbol) {
	/* Find _dl_fixup address, run only once if possibly found */
	static DlFixupFuncPtr dl_fixup = NULL;
	if(dl_fixup == NULL) {
		dl_fixup = find_dl_fixup();
	}

	/* Based on target_elf, traverse /proc/pid/maps to retrieve link_map */
	unsigned long current_gotplt_entry_value = 0;
	unsigned long gotplt_entry_index = 0;
	struct link_map *lm = find_link_map(target_elf, symbol);
	ElfW(Sxword) reloc_index = find_reloc_index(target_elf, symbol, &current_gotplt_entry_value, &gotplt_entry_index);

	if(dl_fixup && lm && reloc_index >= 0) {
		ElfW(Addr) resolved_symbol_addr = dl_fixup(lm, (ElfW(Word))reloc_index);
		if(resolved_symbol_addr > 0) {
			if(current_gotplt_entry_value != (unsigned long)resolved_symbol_addr) {
				printf("GOT hook detected on entry %d: ELF = '%s', symbol = '%s', resolved value = %p, hooked value = %p\n", gotplt_entry_index, target_elf, symbol, resolved_symbol_addr, current_gotplt_entry_value);
				return SYMBOL_GOT_HOOKING_DETECTED;
			} else {
				printf("Resolved symbol on entry %d: ELF '%s', symbol = '%s', resolved value = %p, old value = %p\n", gotplt_entry_index, target_elf, symbol, resolved_symbol_addr, current_gotplt_entry_value);
			}
		}
	}

	return SYMBOL_GOT_HOOKING_NOT_DETECTED;
}

/* Helper function */
void print_got_plt_entries(const char *target_elf) {
	void *handle = load_elf_to_memory(target_elf);
	unsigned long module_base_addr = get_load_module_base_address(PID_SELF, target_elf);
	unsigned long gotplt_offset = get_section_memory_offset(handle, ".got.plt");
	unsigned long *gotplt = (unsigned long *)(module_base_addr + gotplt_offset);
	for(unsigned long i = 0; i < get_section_num_of_entries(handle, ".got.plt"); ++i) {
		Dl_info info = {0};
		dladdr((void *)gotplt[i], &info);
		if(info.dli_sname != NULL) {
			printf("%s: .got.plt entry %lu: [%p] = %p -> %s\n", target_elf, i, gotplt + i, gotplt[i], info.dli_sname);
		} else {
			printf("%s: .got.plt entry %lu: [%p] = %p\n", target_elf, i, gotplt + i, gotplt[i]);
		}
	}
	unload_elf_from_memory(handle);
}

unsigned long *get_GLOBAL_SYMBOL_IN_TARGET() {
	static unsigned long GLOBAL_SYMBOL_IN_TARGET = 999;
	return &GLOBAL_SYMBOL_IN_TARGET;
}

/* Simple GOT hooking detection */
int symbol_got_hooking_detection_simple(const char *target_elf_want_to_check,
							const char *library_where_symbol_is_exported, const char *symbol) {
	void *target_handle = load_elf_to_memory(target_elf_want_to_check);
	void *library_handle = load_elf_to_memory(library_where_symbol_is_exported);
	
	unsigned long target_module_base = get_load_module_base_address(PID_SELF, target_elf_want_to_check);
	unsigned long gotplt_entry_offset = get_got_plt_entry_offset(target_handle, symbol);
	if(gotplt_entry_offset == 0) {
		printf("This ELF '%s' does not have symbol '%s' in .got.plt section!\n", target_elf_want_to_check, symbol);
		unload_elf_from_memory(target_handle);
		return SYMBOL_GOT_HOOKING_NOT_DETECTED;
	}
	unsigned long *gotplt = (unsigned long *)(target_module_base + gotplt_entry_offset);
	
	unsigned long library_module_base = get_load_module_base_address(PID_SELF, library_where_symbol_is_exported);
	unsigned long library_text_start = library_module_base + get_section_memory_offset(library_handle, ".text");
	unsigned long library_text_end = library_text_start + get_section_size(library_handle, ".text");

	if(*gotplt < library_text_start || *gotplt >= library_text_end) {
		printf("GOT hook detected: symbol '%s' in '%s' .got.plt should come from library '%s' but it doesn't!!!\n", symbol, target_elf_want_to_check, library_where_symbol_is_exported);
		return SYMBOL_GOT_HOOKING_DETECTED;
	}

	unload_elf_from_memory(target_handle);
	unload_elf_from_memory(library_handle);
	return SYMBOL_GOT_HOOKING_NOT_DETECTED;
}

int main() {
	printf("\n========================================\n");
	int x = use_foo(1, 2);
	int y = fake_foo(1, 2);
	printf("Before GOT Hook: x = foo(1, 2) = %d\n", x);
	printf("Before GOT Hook: y = fake_foo(1, 2) = %d\n", y);
	printf("Before GOT Hook: GLOBAL_SYMBOL_IN_LIBFOO = %lu\n", use_libfoo_global_var());
	// printf("Before GOT Hook: GLOBAL_SYMBOL_IN_TARGET = %lu\n", *get_GLOBAL_SYMBOL_IN_TARGET());
	printf("========================================\n");
	
	PRINT_GOT_PLT_ENTRIES("bin/liblibsdk.so");

	printf("\n========================================\n");
	printf("Waiting for GOT Hook from attacker...\n");
	printf("========================================\n");
	getchar();
	
	printf("\n========================================\n");
	x = use_foo(1, 2);
	y = fake_foo(1, 2);
	printf("After GOT Hook: x = foo(1, 2) = %d\n", x);
	printf("After GOT Hook: y = fake_foo(1, 2) = %d\n", y);
	printf("After GOT Hook: GLOBAL_SYMBOL_IN_LIBFOO = %lu\n", use_libfoo_global_var());
	// printf("After GOT Hook: GLOBAL_SYMBOL_IN_TARGET = %lu\n", *get_GLOBAL_SYMBOL_IN_TARGET());
	printf("========================================\n");

	PRINT_GOT_PLT_ENTRIES("bin/liblibsdk.so");

	printf("\n========================================\n");
	printf("Running GOT Hook detection...\n");
	printf("========================================\n");
	getchar();

	printf("\n========================================\n");
	int is_hooked = SYMBOL_GOT_HOOKING_NOT_DETECTED;
	START_BENCHMARK(start1);
	is_hooked = symbol_got_hooking_detection_simple("bin/liblibsdk.so", "bin/liblibfoo.so", "foo");
	END_BENCHMARK(start1, end1, duration1);
	PRINT_BENCHMARK(duration1, "symbol_got_hooking_detection_simple");
	if(is_hooked == SYMBOL_GOT_HOOKING_DETECTED) {
		printf("symbol_got_hooking_detection_simple: GOT HOOK DETECTED!!!\n");
	}
	printf("========================================\n");
	START_BENCHMARK(start2);
	is_hooked = symbol_got_hooking_detection("bin/liblibsdk.so", "foo");
	END_BENCHMARK(start2, end2, duration2);
	PRINT_BENCHMARK(duration2, "symbol_got_hooking_detection");
	if(is_hooked == SYMBOL_GOT_HOOKING_DETECTED) {
		printf("symbol_got_hooking_detection: GOT HOOK DETECTED!!!\n");
	}
	printf("========================================\n\n");

	return 0;
}