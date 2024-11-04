#ifndef PLT_ELF_UTILS_H_
#define PLT_ELF_UTILS_H_

#define EXPORT extern
#define PRIVATE static
#define PUBLIC

#define PID_SELF -1

EXPORT void *load_elf_to_memory(const char *path);

EXPORT void unload_elf_from_memory(void *handle);

EXPORT const char *get_elf_name(void *handle);

EXPORT void print_elf_header(void *handle);

EXPORT unsigned long get_elf_base_address_on_memory(int pid, const char *elf_name);

EXPORT unsigned long get_start_of_section_header_offset(void *handle);

EXPORT unsigned long get_section_offset(void *handle, const char *section);

EXPORT unsigned long get_section_num_of_entries(void *handle, const char *section);

EXPORT unsigned long get_section_size(void *handle, const char *section);

EXPORT void inspect_dynamic_section(void *handle, unsigned long elf_base_addr);

EXPORT unsigned long get_symbol_offset(void *handle, const char *symbol);

EXPORT unsigned long get_got_entry_offset(void *handle, const char *symbol);

EXPORT unsigned long get_got_plt_entry_offset(void *handle, const char *symbol);

#endif