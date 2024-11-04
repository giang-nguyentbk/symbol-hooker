#include "library_layer1.h"
#include <unistd.h>


int library_layer_1_function(int a, int b) {
	void *ptr = &sleep;
	sleep(1);
	(void)ptr;
	int c = a | b;
	return c ^ (a | b) & c;
}