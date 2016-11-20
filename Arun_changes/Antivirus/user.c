#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>

#ifndef __NR_trapper
#error trapper system call not defined
#endif

int main(int argc, const char *argv[])
{
	int rc;

	//void *dummy = (void *)NULL;
	//void *dummy = (void *) argv[1];
	
	rc = syscall(__NR_trapper);
	if (rc == 0)
		printf("syscall returned %d\n", rc);
	else
		printf("syscall returned %d (errno=%d)\n", rc, errno);

	exit(rc);
}

