#define _GNU_SOURCE
#include "../libfoo.h"
#include "../elf_utils.h"
#include "../benchmark.h"

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>

#define SYMBOL_GOT_HOOKING_DETECTED -1
#define SYMBOL_GOT_HOOKING_NOT_DETECTED 0
#define PRINT_GOT_PLT_ENTRIES	printf("\n========================================\n"); \
								print_got_plt_entries("bin/target"); \
								printf("========================================\n\n");

typedef ElfW(Addr) (*DlFixupFuncPtr)(struct link_map *, ElfW(Word));

#ifdef __arm64__
#define scan_dl_runtime_resolve_text_segment(arg) scan_dl_runtime_resolve_text_segment_aarch64(arg)
#else
#define scan_dl_runtime_resolve_text_segment(arg) NULL
#endif

/* Symbol hooking detection */
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
						unload_elf_from_memory(handle);
						fclose(f);
						return scan_dl_runtime_resolve_text_segment(dl_runtime_resolve_addr);
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

int symbol_got_hooking_detection(const char *target_elf, const char *symbol) {
	/* Find _dl_fixup address, run only once if possibly found */
	static DlFixupFuncPtr m_dl_fixup = NULL;
	if(m_dl_fixup == NULL) {
		m_dl_fixup = find_dl_fixup();
	}

	/* Based on target_elf, traverse /proc/pid/maps to retrieve link_map */
	struct link_map *m_link_map = find_link_map(target_elf, symbol);
	if(m_link_map == NULL) {
		return SYMBOL_GOT_HOOKING_NOT_DETECTED;
	}

	if(m_dl_fixup) {
		void *handle = load_elf_to_memory(target_elf);
		int relro = is_full_relro_enabled(handle);
		if(relro) {
			printf("This ELF \'%s\' has FULL RELRO enabled, no .got.plt section available!\n", target_elf);
			unload_elf_from_memory(handle);
			return SYMBOL_GOT_HOOKING_NOT_DETECTED;
		}
		unsigned long gotplt_offset = get_section_memory_offset(handle, ".got.plt");
		if(gotplt_offset == 0) {
			printf("This ELF \'%s\' does not have .got.plt section!\n", target_elf);
			unload_elf_from_memory(handle);
			return SYMBOL_GOT_HOOKING_NOT_DETECTED;
		}
		unsigned long gotplt_entry_offset = get_got_plt_entry_offset(handle, symbol);
		if(gotplt_entry_offset == 0) {
			printf("This ELF \'%s\' does not have symbol \'%s\' in .got.plt section!\n", target_elf, symbol);
			unload_elf_from_memory(handle);
			return SYMBOL_GOT_HOOKING_NOT_DETECTED;
		}
		unsigned long module_base_addr = get_load_module_base_address(PID_SELF, target_elf);
		if(module_base_addr == 0) {
			printf("This ELF \'%s\' was not loaded into memory yet!\n", target_elf);
			unload_elf_from_memory(handle);
			return SYMBOL_GOT_HOOKING_NOT_DETECTED;
		}
		unsigned long plt_start = module_base_addr + get_section_memory_offset(handle, ".plt");
		unsigned long plt_end = plt_start + get_section_size(handle, ".plt");
		unsigned long gotplt_entry_index = (gotplt_entry_offset - gotplt_offset) / sizeof(unsigned long);

		/* Get .got.plt entry's index of symbol in target_elf -> calculate reloc_arg - the 2nd argument of _dl_fixup */
		ElfW(Word) m_reloc_arg = (gotplt_entry_index - 2)*sizeof(unsigned long)*3 - sizeof(ElfW(Rela));
		unsigned long *gotplt_entry = (unsigned long *)(module_base_addr + gotplt_entry_offset);
		unsigned long current_value_in_gotplt_entry = *gotplt_entry;
		if(current_value_in_gotplt_entry >= plt_start && current_value_in_gotplt_entry < plt_end) {
			printf("This symbol \'%s\' was not resolved yet in ELF %s!\n", symbol, target_elf);
			unload_elf_from_memory(handle);
			return SYMBOL_GOT_HOOKING_NOT_DETECTED;
		}
		ElfW(Addr) resolved_symbol_addr = m_dl_fixup(m_link_map, m_reloc_arg);
		if(resolved_symbol_addr > 0) {
			if(current_value_in_gotplt_entry != (unsigned long)resolved_symbol_addr) {
				printf("GOT HOOK DETECTED: on entry %d: ELF = \'%s\', symbol = \'%s\', resolved value = %p, hooked value = %p\n", gotplt_entry_index, target_elf, symbol, resolved_symbol_addr, current_value_in_gotplt_entry);
				unload_elf_from_memory(handle);
				return SYMBOL_GOT_HOOKING_DETECTED;
			} else {
				printf("Resolved symbol on entry %d: ELF \'%s\', symbol = \'%s\', resolved value = %p, old value = %p\n", gotplt_entry_index, target_elf, symbol, resolved_symbol_addr, current_value_in_gotplt_entry);
			}
		}

		unload_elf_from_memory(handle);
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



int main() {
    printf("\n========================================\n");
	int x = foo(1, 2);
	int y = fake_foo(1, 2);
	printf("Before GOT Hook: x = foo(1, 2) = %d\n", x);
	printf("Before GOT Hook: y = fake_foo(1, 2) = %d\n", y);
    printf("Before GOT Hook: GLOBAL_SYMBOL_IN_TARGET = %lu\n", *get_GLOBAL_SYMBOL_IN_TARGET());
	printf("========================================\n\n");
	
	// PRINT_GOT_PLT_ENTRIES;

	printf("\n========================================\n");
	printf("Waiting for GOT Hook from attacker...\n");
	printf("========================================\n\n");
    getchar();
	
	printf("\n========================================\n");
	x = foo(1, 2);
	y = fake_foo(1, 2);
	printf("After GOT Hook: x = foo(1, 2) = %d\n", x);
	printf("After GOT Hook: y = fake_foo(1, 2) = %d\n", y);
    printf("After GOT Hook: GLOBAL_SYMBOL_IN_TARGET = %lu\n", *get_GLOBAL_SYMBOL_IN_TARGET());
	printf("========================================\n\n");

	// PRINT_GOT_PLT_ENTRIES;

	printf("\n========================================\n");
	printf("Running GOT Hook detection...\n");
	printf("========================================\n\n");
    getchar();

	printf("\n========================================\n");
	START_BENCHMARK(start);
	symbol_got_hooking_detection("bin/target", "foo");
	END_BENCHMARK(start, end, duration);
	PRINT_BENCHMARK(duration, "symbol_got_hooking_detection");
	printf("========================================\n\n");

    return 0;
}