#include "stdio.h"
#include <string.h>

void unsafe_func(char* strings)
{
	char buf[8] = {0};
	strcpy(buf, strings);
	// __asm__ __volatile__("xchg %bx, %bx");
	// printf("buf's 0x%8x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x\n", &buf);
	// __asm__ __volatile__("xchg %bx, %bx");
	return;
}

void hacked()
{
	printf("\nthe dest is hacked!!\n");
}

int main(int argc, char* argv[])
{
	printf("now in dest\n");
	__asm__ __volatile__("xchg %bx, %bx");
	unsafe_func(argv[1]);
	// __asm__ __volatile__("xchg %bx, %bx");
	return 0;
}
