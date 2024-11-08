#include "elf_utils.h"

#include <stdio.h>

void print_proc_pid_maps(int pid, const char *path) {
	char proc_pid_maps[64] = {0};
	if(pid == PID_SELF) {
		strcpy(proc_pid_maps, "/proc/self/maps");
	} else {
		sprintf(proc_pid_maps, "/proc/%d/maps", pid);
	}

	FILE *f = fopen(proc_pid_maps, "r");
	if(f == NULL) {
		return;
	}

	char line[512] = {0};
	int i = 0;
	while(fgets(line, sizeof(line), f)) {
		if (strlen(line) <= 50) {
			continue;
		}
		char sopath[151], perm[5];
		unsigned long s, e;
		sscanf(line, "%lx-%lx %4s %*x %*x:%*x %*d %150s", &s, &e, perm, sopath);
		if(strstr(sopath, path)) {
			printf("%s: LOAD SEGMENT %d:\t\t%p - %p\t\t%s\n", path, i, s, e, perm);
			++i;
		}
	}

	fclose(f);
}

int main() {
	const char *elf = "bin/relro_mode";
	print_proc_pid_maps(PID_SELF, elf);
	unsigned long module_base_addr = get_load_module_base_address(PID_SELF, elf);
	void *handle = load_elf_to_memory(elf);

	unsigned long got_addr = module_base_addr + get_section_memory_offset(handle, ".got");
	printf("Section .got start address:\t\t%p\n", got_addr == module_base_addr ? 0 : got_addr);
	unsigned long got_plt_addr = module_base_addr + get_section_memory_offset(handle, ".got.plt");
	printf("Section .got.plt start address:\t\t%p\n", got_plt_addr == module_base_addr ? 0 : got_plt_addr);

	unload_elf_from_memory(handle);
	return 0;
}
