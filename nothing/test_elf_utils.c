#include "elf_utils.h"
#include <stdio.h>


int main() {
    void *handle = load_elf_to_memory("./bin/main");
    // Elf_Ehdr *elf_header = get_elf_header(handle);
    // print_elf_header(handle);

    // printf("ELF base address of libc.so: %p\n", get_elf_base_address_on_RAM("libc.so"));

    printf("Section .text starts at: %p\n", get_section_offset(handle, ".text"));
    printf("Section .plt starts at: %p\n", get_section_offset(handle, ".plt"));
    printf("Section .got starts at: %p\n", get_section_offset(handle, ".got"));
    printf("Section .got.plt starts at: %p\n", get_section_offset(handle, ".got.plt"));

    unload_elf_from_memory(handle);
    return 0;
}