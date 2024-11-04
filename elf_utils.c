#include "elf_utils.h"

#include <sys/stat.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <elf.h>
#include <link.h>


#define Elf_Ehdr ElfW(Ehdr)
#define Elf_Shdr ElfW(Shdr)
#define Elf_Addr ElfW(Addr)
#define Elf_Off ElfW(Off)
#define Elf_Dyn ElfW(Dyn)
#define Elf_Xword ElfW(Xword)
#define Elf_Word ElfW(Word)
#define Elf_Half ElfW(Half)
#define Elf_Sym ElfW(Sym)
#define Elf_Rela ElfW(Rela)

#ifdef __LP64__
#define ELF_ST_TYPE ELF64_ST_TYPE
#define ELF_R_TYPE ELF64_R_TYPE
#define ELF_R_SYM ELF64_R_SYM
#else
#define ELF_ST_TYPE ELF32_ST_TYPE
#define ELF_R_TYPE ELF32_R_TYPE
#define ELF_R_SYM ELF32_R_SYM
#endif

// Define platform-specific relocation types
#if defined(__aarch64__)
	#define R_XPLATFORM_GLOB_DAT R_AARCH64_GLOB_DAT
	#define R_XPLATFORM_JUMP_SLOT R_AARCH64_JUMP_SLOT
#elif defined(__x86_64__)
	#define R_XPLATFORM_GLOB_DAT R_X86_64_GLOB_DAT
	#define R_XPLATFORM_JUMP_SLOT R_X86_64_JUMP_SLOT
#elif defined(__arm__)
	#define R_XPLATFORM_GLOB_DAT R_ARM_GLOB_DAT
	#define R_XPLATFORM_JUMP_SLOT R_ARM_JUMP_SLOT
#elif defined(__i386__)
	#define R_XPLATFORM_GLOB_DAT R_386_GLOB_DAT
	#define R_XPLATFORM_JUMP_SLOT R_386_JUMP_SLOT
#elif defined(__sparc__)
	#define R_XPLATFORM_GLOB_DAT R_SPARC_GLOB_DAT
	#define R_XPLATFORM_JUMP_SLOT R_SPARC_JUMP_SLOT
#elif defined(__mips__)
	#define R_XPLATFORM_GLOB_DAT R_MIPS_GLOB_DAT
	#define R_XPLATFORM_JUMP_SLOT R_MIPS_JUMP_SLOT
#elif defined(__powerpc__)
	#define R_XPLATFORM_GLOB_DAT R_PPC_GLOB_DAT
	#define R_XPLATFORM_JUMP_SLOT R_PPC_JUMP_SLOT
#elif defined(__ppc64__)
	#define R_XPLATFORM_GLOB_DAT R_PPC64_GLOB_DAT
	#define R_XPLATFORM_JUMP_SLOT R_PPC64_JUMP_SLOT
#else
	#error "Unsupported architecture"
#endif

typedef struct SymbolInformation {
	char name[256];
	Elf_Off offset;
	unsigned char type; 
} SymbolInformation;

typedef struct ElfInformation {
	char *name;

	// Will be reset right after load_elf_to_memory finishes
	void *mmap_addr;
	long int mmap_size;
	Elf_Ehdr *ehdr;
	Elf_Shdr *shdr;

	Elf_Off text_section_offset_from_memory_base;
	Elf_Off plt_section_offset_from_memory_base;
	Elf_Off got_section_offset_from_memory_base;
	Elf_Off got_plt_section_offset_from_memory_base;
	Elf_Off dynamic_section_offset_from_memory_base;
	Elf_Off dynsym_section_offset_from_memory_base;
	Elf_Off dynstr_section_offset_from_memory_base;
	Elf_Off rela_dyn_section_offset_from_elf_file;
	Elf_Off rela_plt_section_offset_from_elf_file;
	Elf_Off dynsym_section_offset_from_elf_file;
	Elf_Off dynstr_section_offset_from_elf_file;
	Elf_Off symtab_section_offset_from_elf_file;
	Elf_Off strtab_section_offset_from_elf_file;

	Elf_Xword got_section_num_entries;
	Elf_Xword got_plt_section_num_entries;
	Elf_Xword dynamic_section_num_entries;
	Elf_Xword dynsym_section_num_entries;
	Elf_Xword symtab_section_num_entries;
	Elf_Xword rela_dyn_section_num_entries;
	Elf_Xword rela_plt_section_num_entries;

	Elf_Xword text_section_size;
	Elf_Xword plt_section_size;
	Elf_Xword got_section_size;
	Elf_Xword got_plt_section_size;
	Elf_Xword dynamic_section_size;
	Elf_Xword dynsym_section_size;
	Elf_Xword dynstr_section_size;
	Elf_Xword symtab_section_size;
	Elf_Xword strtab_section_size;
	Elf_Xword gnuhash_section_size;
	Elf_Xword rela_dyn_section_size;
	Elf_Xword rela_plt_section_size;

	SymbolInformation *symbol_table;
	int symbol_table_size;

	// uint32_t elf_bucket_size;
	// uint32_t *elf_bucket;
	// uint32_t *elf_chain;

	void *gnuhash_start_addr;
	uint32_t gnu_bucket_count;
	uint32_t gnu_symbol_index;
	uint32_t gnu_bloom_filter_size;
	uint32_t gnu_shift2;
	uintptr_t *gnu_bloom_filter;
	uint32_t *gnu_bucket;
	uint32_t *gnu_chain;
	Elf_Sym *dynsym_start_addr;
	const char *dynstr_start_addr;

	Elf_Rela *rela_dyn_start_addr;
	Elf_Rela *rela_plt_start_addr;

} ElfInformation;

PRIVATE void save_symbol_information_private(ElfInformation *handle) {
	char *strtab_ptr = (char *)(handle->mmap_addr + handle->strtab_section_offset_from_elf_file);
	Elf_Sym *symtab_entries = (Elf_Sym *)(handle->mmap_addr + handle->symtab_section_offset_from_elf_file);

	int symbol_count = 0;
	for(int i = 0; i < handle->symtab_section_num_entries; ++i) {
		Elf_Half symbol_type = ELF_ST_TYPE(symtab_entries[i].st_info);
		if(symtab_entries[i].st_name != 0 && symtab_entries[i].st_value && (symbol_type == STT_FUNC || symbol_type == STT_OBJECT && symtab_entries[i].st_size)) {
			++symbol_count;
		}
	}

	char *dynstr_ptr = (char *)(handle->mmap_addr + handle->dynstr_section_offset_from_elf_file);
	Elf_Sym *dynsym_entries = (Elf_Sym *)(handle->mmap_addr + handle->dynsym_section_offset_from_elf_file);

	for(int i = 0; i < handle->dynsym_section_num_entries; ++i) {
		Elf_Half symbol_type = ELF_ST_TYPE(dynsym_entries[i].st_info);
		if(dynsym_entries[i].st_name != 0 && dynsym_entries[i].st_value && (symbol_type == STT_FUNC || symbol_type == STT_OBJECT && dynsym_entries[i].st_size)) {
			++symbol_count;
		}
	}

	handle->symbol_table = (SymbolInformation *)malloc(symbol_count * sizeof(SymbolInformation));
	memset(handle->symbol_table, 0, symbol_count * sizeof(SymbolInformation));

	for(int i = 0; i < handle->symtab_section_num_entries; ++i) {
		Elf_Half symbol_type = ELF_ST_TYPE(symtab_entries[i].st_info);
		if(symtab_entries[i].st_name != 0 && symtab_entries[i].st_value && (symbol_type == STT_FUNC || symbol_type == STT_OBJECT && symtab_entries[i].st_size)) {
			char *symbol_name = strtab_ptr + symtab_entries[i].st_name;
			// printf("Symbol: .symtab %d: \'%s\'\n", i, symbol_name);
			strcpy(handle->symbol_table[handle->symbol_table_size].name, symbol_name);
			handle->symbol_table[handle->symbol_table_size].offset = symtab_entries[i].st_value;
			handle->symbol_table[handle->symbol_table_size].type = symbol_type;
			++handle->symbol_table_size;
		}
	}

	for(int i = 0; i < handle->dynsym_section_num_entries; ++i) {
		Elf_Half symbol_type = ELF_ST_TYPE(dynsym_entries[i].st_info);
		if(dynsym_entries[i].st_name != 0 && dynsym_entries[i].st_value && (symbol_type == STT_FUNC || symbol_type == STT_OBJECT && dynsym_entries[i].st_size)) {
			char *symbol_name = dynstr_ptr + dynsym_entries[i].st_name;
			// printf("Symbol: .dynsym %d: \'%s\'\n", i, symbol_name);
			strcpy(handle->symbol_table[handle->symbol_table_size].name, symbol_name);
			handle->symbol_table[handle->symbol_table_size].offset = dynsym_entries[i].st_value;
			handle->symbol_table[handle->symbol_table_size].type = symbol_type;
			++handle->symbol_table_size;
		}
	}
}

PRIVATE void save_section_information_private(ElfInformation *handle) {
	handle->shdr = (Elf_Shdr *)(handle->mmap_addr + handle->ehdr->e_shoff);
	Elf_Half shnum = handle->ehdr->e_shnum;

	Elf_Half shstrtab_index = handle->ehdr->e_shstrndx;
	Elf_Shdr *shstrtab = (Elf_Shdr *)(&handle->shdr[shstrtab_index]);
	const char *shstrtab_ptr = (const char *)handle->mmap_addr + shstrtab->sh_offset;

	for(Elf_Half i = 0; i < shnum; ++i) {
		Elf_Addr offset_from_memory_base        = handle->shdr[i].sh_addr;
		Elf_Addr offset_from_elf_file           = handle->shdr[i].sh_offset;
		Elf_Xword section_size                  = handle->shdr[i].sh_size;
		const char *section_name                = shstrtab_ptr + handle->shdr[i].sh_name;
	Elf_Xword section_num_entries   	= 0;
	if(*section_name == '\0') continue;
	if(handle->shdr[i].sh_entsize > 0) {
		section_num_entries  	 	= section_size / handle->shdr[i].sh_entsize;
	}

		if(strcmp(section_name, ".text") == 0) {
			handle->text_section_offset_from_memory_base = offset_from_memory_base;
			handle->text_section_size = section_size;
		} else if(strcmp(section_name, ".plt") == 0) {
			handle->plt_section_offset_from_memory_base = offset_from_memory_base;
			handle->plt_section_size = section_size;
		} else if(strcmp(section_name, ".got") == 0) {
			handle->got_section_offset_from_memory_base = offset_from_memory_base;
			handle->got_section_num_entries = section_num_entries;
			handle->got_section_size = section_size;
		} else if(strcmp(section_name, ".got.plt") == 0) {
			handle->got_plt_section_offset_from_memory_base = offset_from_memory_base;
			handle->got_plt_section_num_entries = section_num_entries;
			handle->got_plt_section_size = section_size;
		} else if(strcmp(section_name, ".dynamic") == 0) {
			handle->dynamic_section_offset_from_memory_base = offset_from_memory_base;
			handle->dynamic_section_num_entries = section_num_entries;
			handle->dynamic_section_size = section_size;
		} else if(strcmp(section_name, ".dynsym") == 0) {
			handle->dynsym_section_offset_from_elf_file = offset_from_elf_file;
			handle->dynsym_section_offset_from_memory_base = offset_from_memory_base;
			handle->dynsym_section_num_entries = section_num_entries;
			handle->dynsym_section_size = section_size;
			handle->dynsym_start_addr = (Elf_Sym *)malloc(section_size);
			memcpy(handle->dynsym_start_addr, handle->mmap_addr + offset_from_elf_file, section_size);
		} else if(strcmp(section_name, ".dynstr") == 0) {
			handle->dynstr_section_offset_from_elf_file = offset_from_elf_file;
			handle->dynstr_section_offset_from_memory_base = offset_from_memory_base;
			handle->dynstr_section_size = section_size;
			handle->dynstr_start_addr = (const char *)malloc(section_size);
			memcpy(handle->dynstr_start_addr, handle->mmap_addr + offset_from_elf_file, section_size);
		} else if(strcmp(section_name, ".symtab") == 0) {
			handle->symtab_section_offset_from_elf_file = offset_from_elf_file;
			handle->symtab_section_num_entries = section_num_entries;
			handle->symtab_section_size = section_size;
		} else if(strcmp(section_name, ".strtab") == 0) {
			handle->strtab_section_offset_from_elf_file = offset_from_elf_file;
			handle->strtab_section_size = section_size;
		} else if(strcmp(section_name, ".gnu.hash") == 0) {
			handle->gnuhash_section_size = section_size;
			handle->gnuhash_start_addr = malloc(section_size);
			Elf_Word *sdata = (Elf_Word *)(handle->mmap_addr + offset_from_elf_file);
			handle->gnu_bucket_count = sdata[0];
			handle->gnu_symbol_index = sdata[1];
			handle->gnu_bloom_filter_size = sdata[2];
			handle->gnu_shift2 = sdata[3];
			memcpy(handle->gnuhash_start_addr, &sdata[4], section_size - 4 * sizeof(Elf_Word));
			handle->gnu_bloom_filter = (uintptr_t *)handle->gnuhash_start_addr;
			handle->gnu_bucket = (uint32_t *)(handle->gnu_bloom_filter + handle->gnu_bloom_filter_size);
			handle->gnu_chain = (uint32_t *)(handle->gnu_bucket + handle->gnu_bucket_count - handle->gnu_symbol_index);
		} else if(strcmp(section_name, ".rela.dyn") == 0) {
			handle->rela_dyn_section_offset_from_elf_file = offset_from_elf_file;
			handle->rela_dyn_section_size = section_size;
			handle->rela_dyn_section_num_entries = section_num_entries;
			handle->rela_dyn_start_addr = (Elf_Rela *)malloc(section_size);
			memcpy(handle->rela_dyn_start_addr, handle->mmap_addr + offset_from_elf_file, section_size);
		} else if(strcmp(section_name, ".rela.plt") == 0) {
			handle->rela_plt_section_offset_from_elf_file = offset_from_elf_file;
			handle->rela_plt_section_size = section_size;
			handle->rela_plt_section_num_entries = section_num_entries;
			handle->rela_plt_start_addr = (Elf_Rela *)malloc(section_size);
			memcpy(handle->rela_plt_start_addr, handle->mmap_addr + offset_from_elf_file, section_size);
		}
	}
}

PRIVATE int save_elf_information_private(ElfInformation *handle) {
	handle->ehdr = (Elf_Ehdr *)handle->mmap_addr;
	if(handle->ehdr->e_type != ET_EXEC && handle->ehdr->e_type != ET_DYN) {
		printf("ELF file not an Executable or Dynamic Shared Object!\n");
		return -1;
	}
	save_section_information_private(handle);
	save_symbol_information_private(handle);
	return 0;
}

PUBLIC void *load_elf_to_memory(const char *path) {
	int fd = -1;
	struct stat status;
	if ((fd = open(path, O_RDONLY)) < 0 || fstat(fd, &status) < 0) {
		printf("No such file or directory %s\n", path);
		return NULL;
	}

	ElfInformation *handle = (ElfInformation *)malloc(sizeof(ElfInformation));
	memset(handle, 0, sizeof(ElfInformation));
	handle->name = malloc(strlen(path) + 1);
	strcpy(handle->name, path);
	handle->mmap_addr = mmap(NULL, status.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (handle->mmap_addr == MAP_FAILED) {
		printf("Failed to mmap %s\n", path);
		close(fd);
		free(handle);
		return NULL;
	}
	handle->mmap_size = status.st_size;
	void *returned_handle = handle;
	int ret = save_elf_information_private(handle);
	if(ret < 0) {
		returned_handle = NULL;
	}

	munmap(handle->mmap_addr, handle->mmap_size);
	handle->mmap_addr = NULL;
	handle->mmap_size = 0;
	close(fd);
	return returned_handle;
}

PUBLIC void unload_elf_from_memory(void *handle) {
	free(((ElfInformation *)handle)->symbol_table);
	free(((ElfInformation *)handle)->gnuhash_start_addr);
	free(((ElfInformation *)handle)->dynsym_start_addr);
	free(((ElfInformation *)handle)->dynstr_start_addr);
	free(((ElfInformation *)handle)->rela_dyn_start_addr);
	free(((ElfInformation *)handle)->rela_plt_start_addr);
	free(((ElfInformation *)handle)->name);
	free(handle);
}

PUBLIC const char *get_elf_name(void *handle) {
	return ((ElfInformation *)handle)->name;
}

PUBLIC void print_elf_header(void *handle) {
	Elf_Ehdr *elf_header = (Elf_Ehdr *)handle;
	printf("ELF Header:\n");
	printf("  Magic:   %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
		elf_header->e_ident[0], elf_header->e_ident[1], elf_header->e_ident[2], elf_header->e_ident[3],
		elf_header->e_ident[4], elf_header->e_ident[5], elf_header->e_ident[6], elf_header->e_ident[7],
		elf_header->e_ident[8], elf_header->e_ident[9], elf_header->e_ident[10], elf_header->e_ident[11],
		elf_header->e_ident[12], elf_header->e_ident[13], elf_header->e_ident[14], elf_header->e_ident[15]);
	printf("  Class:                              %d\n", elf_header->e_ident[EI_CLASS]);
	printf("  Data:                               %d\n", elf_header->e_ident[EI_DATA]);
	printf("  Version:                            %d\n", elf_header->e_ident[EI_VERSION]);
	printf("  OS/ABI:                             %d\n", elf_header->e_ident[EI_OSABI]);
	printf("  ABI Version:                        %d\n", elf_header->e_ident[EI_ABIVERSION]);
	printf("  Type:                               %d\n", elf_header->e_type);
	printf("  Machine:                            %d\n", elf_header->e_machine);
	printf("  Version:                            %d\n", elf_header->e_version);
	printf("  Entry point address:                %lx\n", (Elf_Addr)elf_header->e_entry);
	printf("  Start of program headers:           %lu\n", (Elf_Addr)elf_header->e_phoff);
	printf("  Start of section headers:           %lu\n", (Elf_Addr)elf_header->e_shoff);
	printf("  Flags:                              %d\n", elf_header->e_flags);
	printf("  Size of this header:                %d\n", elf_header->e_ehsize);
	printf("  Size of program headers:            %d\n", elf_header->e_phentsize);
	printf("  Number of program headers:          %d\n", elf_header->e_phnum);
	printf("  Size of section headers:            %d\n", elf_header->e_shentsize);
	printf("  Number of section headers:          %d\n", elf_header->e_shnum);
	printf("  Section header string table index:  %d\n", elf_header->e_shstrndx);
}

PUBLIC unsigned long get_elf_base_address_on_memory(int pid, const char *elf_name) {
	char proc_pid_maps[64] = {0};
	if(pid == PID_SELF) {
		strcpy(proc_pid_maps, "/proc/self/maps");
	} else {
		sprintf(proc_pid_maps, "/proc/%d/maps", pid);
	}

	FILE *f = fopen(proc_pid_maps, "r");
	if(f == NULL) {
		return 0;
	}

	char line[512] = {0};
	while(fgets(line, sizeof(line), f)) {
		if (strlen(line) <= 50) {
			continue;
		}
		char path[151], perm[5];
		Elf_Addr s, e;
		sscanf(line, "%lx-%lx %4s %*x %*x:%*x %*d %150s", &s, &e, perm, path);
		if(strstr(path, elf_name)) {
			fclose(f);
			return s;
		}
	}

	fclose(f);
	return 0;
}

PUBLIC unsigned long get_start_of_section_header_offset(void *handle){
	return ((Elf_Ehdr *)handle)->e_shoff;
}

PUBLIC unsigned long get_section_offset(void *handle, const char *section) {
	ElfInformation *ptr = (ElfInformation *)handle;
	if(strcmp(section, ".text") == 0) {
		return ptr->text_section_offset_from_memory_base;
	} else if(strcmp(section, ".plt") == 0) {
		return ptr->plt_section_offset_from_memory_base;
	} else if(strcmp(section, ".got") == 0) {
		return ptr->got_section_offset_from_memory_base;
	} else if(strcmp(section, ".got.plt") == 0) {
		return ptr->got_plt_section_offset_from_memory_base;
	} else if(strcmp(section, ".dynamic") == 0) {
		return ptr->dynamic_section_offset_from_memory_base;
	} else if(strcmp(section, ".dynstr") == 0) {
		return ptr->dynstr_section_offset_from_memory_base;
	} else if(strcmp(section, ".symtab") == 0) {
		return ptr->symtab_section_offset_from_elf_file;
	} else if(strcmp(section, ".strtab") == 0) {
		return ptr->strtab_section_offset_from_elf_file;
	} else {
		return 0;
	}
}

PUBLIC unsigned long get_section_num_of_entries(void *handle, const char *section) {
	ElfInformation *ptr = (ElfInformation *)handle;
	if(strcmp(section, ".got") == 0) {
		return ptr->got_section_num_entries;
	} else if(strcmp(section, ".got.plt") == 0) {
		return ptr->got_plt_section_num_entries;
	} else if(strcmp(section, ".dynamic") == 0) {
		return ptr->dynamic_section_num_entries;
	} else if(strcmp(section, ".symtab") == 0) {
		return ptr->symtab_section_num_entries;
	} else {
		return 0;
	}
}

PUBLIC unsigned long get_section_size(void *handle, const char *section) {
	ElfInformation *ptr = (ElfInformation *)handle;
	if(strcmp(section, ".text") == 0) {
		return ptr->text_section_size;
	} else if(strcmp(section, ".plt") == 0) {
		return ptr->plt_section_size;
	} else if(strcmp(section, ".got") == 0) {
		return ptr->got_section_size;
	} else if(strcmp(section, ".got.plt") == 0) {
		return ptr->got_plt_section_size;
	} else if(strcmp(section, ".dynamic") == 0) {
		return ptr->dynamic_section_size;
	} else if(strcmp(section, ".dynstr") == 0) {
		return ptr->dynstr_section_size;
	} else if(strcmp(section, ".symtab") == 0) {
		return ptr->symtab_section_size;
	} else if(strcmp(section, ".strtab") == 0) {
		return ptr->strtab_section_size;
	} else {
		return 0;
	}
}

PUBLIC void inspect_dynamic_section(void *handle, unsigned long elf_base_addr) {
	ElfInformation *ptr = (ElfInformation *)handle;
	for (Elf_Dyn *entry = (Elf_Dyn *)(elf_base_addr + ptr->dynamic_section_offset_from_memory_base); entry->d_tag != DT_NULL; entry++) {
		switch (entry->d_tag) {
			case DT_NEEDED:
				printf("Shared library needed (DT_NEEDED): %lu\n", entry->d_un.d_val);
				unsigned long dynstr_offset = get_section_offset(handle, ".dynstr");
				const char *dynstr_addr = (const char *)(elf_base_addr + dynstr_offset);
				printf("Retrieve symbol from .dynstr: %s\n", dynstr_addr + entry->d_un.d_val);
				break;
			case DT_STRTAB:
				printf("String table address (DT_STRTAB): %p\n", (void*)entry->d_un.d_ptr);
				break;
			case DT_SYMTAB:
				printf("Symbol table address (DT_SYMTAB): %p\n", (void*)entry->d_un.d_ptr);
				break;
			case DT_PLTGOT:
				printf("PLT/GOT address (DT_PLTGOT): %p\n", (void*)entry->d_un.d_ptr);
				break;
			case DT_INIT:
				printf("Init function address (DT_INIT): %p\n", (void*)entry->d_un.d_ptr);
				break;
			default:
				printf("Other dynamic entry type: %p\n", entry->d_tag);
				break;
		}
	}
}

PRIVATE unsigned long get_symbol_offset_via_linear_lookup_private(void *handle, const char *symbol) {
	ElfInformation *ptr = (ElfInformation *)handle;
	for(int i = 0; i < ptr->symbol_table_size; ++i) {
		// printf("Symbol: %s = %p\n", ptr->symbol_table[i].name, ptr->symbol_table[i].offset);
		if(strcmp(ptr->symbol_table[i].name, symbol) == 0) {
			return ptr->symbol_table[i].offset;
		}
	}
	return 0;
}

PRIVATE uint32_t gnu_hash(const char *symbol) {
	uint32_t hash = 5381;
	while(*symbol) {
		hash += (hash << 5) + *symbol;
		++symbol;
	}
	return hash;
}

PRIVATE unsigned long get_symbol_offset_via_gnu_hash_lookup_private(void *handle, const char *symbol) {
	ElfInformation *ptr = (ElfInformation *)handle;
	if (ptr->gnu_bucket_count == 0 || ptr->gnu_bloom_filter_size == 0) return 0;

	uint32_t hash = gnu_hash(symbol);
	static Elf_Xword bloom_mask_bits = sizeof(Elf_Addr) * 8;
	Elf_Xword bloom_word = ptr->gnu_bloom_filter[(hash / bloom_mask_bits) % ptr->gnu_bloom_filter_size];
	uintptr_t mask = 0 | (uintptr_t) 1 << (hash % bloom_mask_bits) | (uintptr_t) 1 << ((hash >> ptr->gnu_shift2) % bloom_mask_bits);
	if ((mask & bloom_word) == mask) {
		Elf_Xword symbol_index = ptr->gnu_bucket[hash % ptr->gnu_bucket_count];
		if (symbol_index >= ptr->gnu_symbol_index) {
			char *dynstr_ptr = ptr->dynstr_start_addr;
			do {
				Elf_Sym *dynsym_entries = ptr->dynsym_start_addr;
				// printf("[ETRUGIA] symbol %s: ptr->gnu_chain[symbol_index] = %p\n", symbol, ptr->gnu_chain[symbol_index]);
				// printf("[ETRUGIA] symbol %s: hash = %p\n", symbol, hash);
				// printf("[ETRUGIA] symbol %s: symbol_index = %p\n", symbol, symbol_index);
				if ((ptr->gnu_chain[symbol_index] ^ hash) >> 1 == 0
					&& strcmp(dynstr_ptr + dynsym_entries[symbol_index].st_name, symbol) == 0) {
					return dynsym_entries[symbol_index].st_value;
				}
			} while ((ptr->gnu_chain[symbol_index++] & 1) == 0);
		}
	}
	return 0;
}

PUBLIC unsigned long get_symbol_offset(void *handle, const char *symbol) {
	printf("Trying to find offset of symbol %s\n", symbol);
	unsigned long symbol_offset = 0;

	symbol_offset = get_symbol_offset_via_gnu_hash_lookup_private(handle, symbol);
	if(symbol_offset > 0) {
		printf("Found symbol offset via GNU Hash Lookup: %s = %p\n", symbol, symbol_offset);
		return symbol_offset;
	}

	symbol_offset = get_symbol_offset_via_linear_lookup_private(handle, symbol);
	if(symbol_offset > 0) {
		printf("Found symbol offset via Linear Lookup: %s = %p\n", symbol, symbol_offset);
		return symbol_offset;
	}

	return 0;
}

PUBLIC unsigned long get_got_entry_offset(void *handle, const char *symbol) {
	ElfInformation *ptr = (ElfInformation *)handle;
	Elf_Rela *rela_dyn_entries = ptr->rela_dyn_start_addr;
	for(Elf_Xword i = 0; i < ptr->rela_dyn_section_num_entries; ++i) {
		uint32_t type = ELF_R_TYPE(rela_dyn_entries[i].r_info);
		uint32_t symbol_index = ELF_R_SYM(rela_dyn_entries[i].r_info);
		Elf_Sym *dynsym_entries = &ptr->dynsym_start_addr[symbol_index];
		const char *symbol_name = &ptr->dynstr_start_addr[dynsym_entries->st_name];
		// printf(".rela.dyn: symbol_name = %s\n", symbol_name);
		if(type == R_XPLATFORM_GLOB_DAT && *symbol_name && strcmp(symbol_name, symbol) == 0) {
			Elf_Off got_entry_offset = rela_dyn_entries[i].r_offset + rela_dyn_entries[i].r_addend;
			return got_entry_offset;
		}
	}
	return 0;
}

PUBLIC unsigned long get_got_plt_entry_offset(void *handle, const char *symbol) {
	ElfInformation *ptr = (ElfInformation *)handle;
	Elf_Rela *rela_plt_entries = ptr->rela_plt_start_addr;
	for(Elf_Xword i = 0; i < ptr->rela_plt_section_num_entries; ++i) {
		uint32_t type = ELF_R_TYPE(rela_plt_entries[i].r_info);
		uint32_t symbol_index = ELF_R_SYM(rela_plt_entries[i].r_info);
		Elf_Sym *dynsym_entries = &(ptr->dynsym_start_addr[symbol_index]);
		const char *symbol_name = ptr->dynstr_start_addr + dynsym_entries->st_name;
		// printf(".rela.plt: symbol_name = %p\n", symbol_name);
		if(type == R_XPLATFORM_JUMP_SLOT && *symbol_name && strcmp(symbol_name, symbol) == 0) {
			Elf_Off got_entry_offset = rela_plt_entries[i].r_offset + rela_plt_entries[i].r_addend;
			return got_entry_offset;
		}
	}
	return 0;
}

