#include "../libfoo.h"

#include <stdio.h>
#include <unistd.h>


static unsigned long GLOBAL_SYMBOL_IN_TARGET = 888;

int main() {
	int x = foo(1, 2);
	int y = fake_foo(1, 2);
	printf("Before GOT Hook: x = foo(1, 2) = %d\n", x);
	printf("Before GOT Hook: y = fake_foo(1, 2) = %d\n", y);
	printf("Before GOT Hook: GLOBAL_SYMBOL_IN_TARGET = %lu\n", GLOBAL_SYMBOL_IN_TARGET);

	printf("\n========================================\n");
	printf("Waiting for GOT Hook from attacker...");
	getchar();
	printf("\n========================================\n");
	
	x = foo(1, 2);
	y = fake_foo(1, 2);
	printf("After GOT Hook: x = foo(1, 2) = %d\n", x);
	printf("After GOT Hook: y = fake_foo(1, 2) = %d\n", y);
	printf("After GOT Hook: GLOBAL_SYMBOL_IN_TARGET = %lu\n", GLOBAL_SYMBOL_IN_TARGET);

    return 0;
}