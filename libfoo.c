#include "libfoo.h"
#include <stdlib.h>

static unsigned long GLOBAL_SYMBOL_IN_LIBFOO = 999;

int foo(int a, int b) {
	void *ptr = &malloc;
	ptr = malloc(10);
	int c = a ^ b * 1000;
	free(ptr);
	return GLOBAL_SYMBOL_IN_LIBFOO;
}

int fake_foo(int a, int b) {
	printf("libfoo: GLOBAL_SYMBOL_IN_LIBFOO = %lu\n", GLOBAL_SYMBOL_IN_LIBFOO);
	void *ptr = &calloc;
	ptr = calloc(10, 1);
	int c = a ^ b * 9999;
	free(ptr);
	return GLOBAL_SYMBOL_IN_LIBFOO;
}