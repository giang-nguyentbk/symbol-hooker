#include "library_layer2.h"
#include <stdlib.h>
#include "library_layer1.h"


int library_layer_2_function(int a, int b) {
	void *ptr = &malloc;
	(void)ptr;
	ptr = &library_layer_1_function;
	// int c = a ^ b * 1000;
	int c = a ^ b * library_layer_1_function(a, b);
	return c ^ (a & b) & c;
}