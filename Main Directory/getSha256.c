#include <stdio.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <sys/types.h>
#include "dbutility.h"

int generate_sha256(char* file_path, unsigned char* hashed_string)
{
        FILE* file = fopen(file_path, "r");
        SHA256_CTX sha;
        char* file_buffer = (char *)malloc(PAGE_SIZE);
        int bytesRead = 0;
        if(!file){
                printf("Unable to retrieve file\n");
                return -1;
        }
        if(!file_buffer){
                printf("unable to allocate memory\n");
                return -1;
        }
     	SHA256_Init(&sha);
        while((bytesRead = fread(file_buffer, 1, PAGE_SIZE, file)))
        {
                SHA256_Update(&sha, file_buffer, bytesRead);
        }
        SHA256_Final(hashed_string, &sha);
        fclose(file);
        free(file_buffer);
        return 0;
}

char* getsha256(char * file_path)
{
	char* output_buffer= (char *)malloc(SHA256_DIGEST_LENGTH*2);
	unsigned char hashed_string[SHA256_DIGEST_LENGTH];
	int i = 0;
	if(generate_sha256(file_path, hashed_string)==-1){
		return NULL;
	}
        for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
        {
                sprintf(output_buffer + (i * 2), "%02x", hashed_string[i]);
        }
	return output_buffer;
}
