#include "libfoo.h"
#include <stdlib.h>

static unsigned long GLOBAL_SYMBOL_IN_LIBFOO = 999;

int foo(int a, int b) {
	void *ptr = &malloc;
	ptr = malloc(10);
	int c = a ^ b * 1000;
	free(ptr);
	return 999;
}

int get_global_var() {
	return GLOBAL_SYMBOL_IN_LIBFOO;
}
