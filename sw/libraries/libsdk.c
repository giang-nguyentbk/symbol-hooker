#include "libsdk.h"
#include "libfoo.h"

int use_foo(int a, int b) {
	int c = a ^ b * 1000;
	c += a << 2 | b ^ 111;
	return foo(c, b);
}

int use_libfoo_global_var() {
	return get_global_var();
}
