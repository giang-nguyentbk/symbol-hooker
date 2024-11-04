#include "../elf_utils.h"
#include "../ptrace_wrapper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int get_pid_by_name(const char *process_name) {
	// Open a pipe to run "ps -a" and read its output
	FILE *fp = popen("ps -a", "r");
	if (!fp) {
		perror("popen");
		return -1;
	}

	char line[256];
	int pid = -1;

	// Skip the header line
	fgets(line, sizeof(line), fp);

	// Parse each line of output
	while (fgets(line, sizeof(line), fp) != NULL) {
		int current_pid;
		char cmd[256];

		// Parse the line to extract the PID and command name
		if (sscanf(line, "%d %*s %*s %255s", &current_pid, cmd) == 2) {
			// Check if the process_name is a substring of the command name
			if (strstr(cmd, process_name) != NULL) {
				pid = current_pid;
				break;
			}
		}
	}

	pclose(fp);
	return pid;
}

void perform_got_hook(int pid, const char *target_elf, const char *libfoo_elf) {
	void *libfoo_elf_handle = load_elf_to_memory(libfoo_elf);
	if(libfoo_elf_handle == NULL) {
		printf("Failed to load elf file %s\n", libfoo_elf);
		return;
	}
	void *target_elf_handle = load_elf_to_memory(target_elf);
	if(target_elf_handle == NULL) {
		printf("Failed to load elf file %s\n", target_elf);
		return;
	}
	ptrace_wrapper_attach(pid);

	// Address of fake_foo() on memory
	unsigned long libfoo_elf_base_addr = get_elf_base_address_on_memory(pid, libfoo_elf);
	unsigned long fake_foo_offset = get_symbol_offset(libfoo_elf_handle, "fake_foo");
	unsigned long fake_foo_abs_address = libfoo_elf_base_addr + fake_foo_offset;
	// Address of foo's .got.plt entry on memory
	unsigned long target_elf_base_addr = get_elf_base_address_on_memory(pid, target_elf);
	unsigned long foo_got_plt_entry_offset = get_got_plt_entry_offset(target_elf_handle, "foo");
	unsigned long *foo_got_plt_entry_abs_address = (unsigned long*)(target_elf_base_addr + foo_got_plt_entry_offset);
	ptrace_wrapper_write(pid, (uint8_t *)foo_got_plt_entry_abs_address, (uint8_t *)&fake_foo_abs_address, sizeof(fake_foo_abs_address));



	// Address of GLOBAL_SYMBOL_IN_LIBFOO variable on memory
	unsigned long global_val_in_libfoo_offset = get_symbol_offset(libfoo_elf_handle, "GLOBAL_SYMBOL_IN_LIBFOO");
	unsigned long global_val_in_libfoo_abs_address = libfoo_elf_base_addr + global_val_in_libfoo_offset;
	// Address of GLOBAL_SYMBOL_IN_TARGET variable on memory
	unsigned long global_val_in_target_offset = get_symbol_offset(target_elf_handle, "GLOBAL_SYMBOL_IN_TARGET");
	unsigned long global_val_in_target_abs_address = target_elf_base_addr + global_val_in_target_offset;

	unsigned long fake_global_variable = 111;
	ptrace_wrapper_write(pid, (uint8_t *)global_val_in_libfoo_abs_address, (uint8_t *)&fake_global_variable, sizeof(fake_global_variable));
	ptrace_wrapper_write(pid, (uint8_t *)global_val_in_target_abs_address, (uint8_t *)&fake_global_variable, sizeof(fake_global_variable));
	

	ptrace_wrapper_detach(pid);
	unload_elf_from_memory(libfoo_elf_handle);
	unload_elf_from_memory(target_elf_handle);
}

int main() {
	int pid = get_pid_by_name("target");
	if(pid < 0) return -1;

	perform_got_hook(pid, "bin/target", "bin/liblibfoo.so");

	return 0;
}