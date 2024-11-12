#ifndef PTRACE_WRAPPER_H_
#define PTRACE_WRAPPER_H_
#define CPSR_T_MASK (1u << 5)

#include <stdint.h>
#include <stddef.h>

int ptrace_wrapper_attach(int pid);

int ptrace_wrapper_detach(int pid);

int ptrace_wrapper_read(int pid, long *addr, long *buffer, int size);

void ptrace_wrapper_write(int pid, uint8_t* addr, uint8_t* data, size_t size);

#endif // PTRACE_WRAPPER_H_