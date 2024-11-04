#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>

#include "ptrace_wrapper.h"

int ptrace_wrapper_attach(pid_t pid) {
    if (pid == -1) {
        return -1;
    }
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror(NULL);
        return -1;
    }
    waitpid(pid, NULL, WUNTRACED);
    
    printf("Attached to process %d\n", pid);
    return 0;
}

int ptrace_wrapper_detach(pid_t pid) {
    if (pid == -1) {
        return -1;
    }
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
        perror(NULL);
        return -1;
    }
    
    printf("Detached from process %d\n", pid);
    return 0;
}

int ptrace_wrapper_read(pid_t pid, long *addr, long *buffer, int size) {
    const size_t WORD_SIZE = sizeof(long);
    int loop_count = size / WORD_SIZE;
    for(int i = 0; i < loop_count; ++i) {
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + i), NULL);
        buffer[i] = word;
    }
    return 0;

    printf("Read %d bytes to %p process %d\n", size, addr, pid);
}

void ptrace_wrapper_write(pid_t pid, uint8_t* addr, uint8_t* data, size_t size) {
    const size_t WORD_SIZE = sizeof(long);
    int mod = size % WORD_SIZE;
    int loop_count = size / WORD_SIZE;
    uint8_t* tmp_addr = addr;
    uint8_t* tmp_data = data;
    for(int i = 0; i < loop_count; ++i) {
        ptrace(PTRACE_POKEDATA, pid, tmp_addr, *((long*)tmp_data));
        tmp_addr += WORD_SIZE;
        tmp_data += WORD_SIZE;
    }
    if (mod > 0) {
        long val = ptrace(PTRACE_PEEKDATA, pid, tmp_addr, NULL);
        uint8_t* p = (uint8_t*) &val;
        for(int i = 0; i < mod; ++i) {
            *p = *(tmp_data);
            p++;
            tmp_data++;
        }
        ptrace(PTRACE_POKEDATA, pid, tmp_addr, val);
    }
    
    printf("Write %d bytes to %p process %d\n", size, addr, pid);
}
