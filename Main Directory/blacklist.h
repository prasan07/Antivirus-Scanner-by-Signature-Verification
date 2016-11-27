#ifndef _BLACKLIST_H_
#define _BLACKLIST_H_


#include<string.h>
#include<stdio.h>
#include<stdlib.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<unistd.h>
#include <errno.h>
#include <sys/types.h>

int blacklist_scan(char* filename);



#endif



