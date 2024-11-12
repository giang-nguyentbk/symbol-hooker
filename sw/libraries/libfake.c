#include "libfake.h"
#include <stdlib.h>

int fake_foo(int a, int b) {
	int c = a ^ b * 9999;
	return 111;
}