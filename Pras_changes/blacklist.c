#include "blacklist.h"
#include <fcntl.h>
#include <sys/types.h>
#include "dbutility.h"

/* 
This function checks if the given file is a virus 
by scanning for blacklist signatures 
param 	- A file path
return	- 1 if virus
	  0 if not virus
	 -1 if scan error
*/
int blacklist_scan(char* file_path){

	int ret = 0;
	blacklist_from_db* blacklist = NULL;
	char* signature = NULL;
	int next_pos = 0;
	unsigned char* file_bytes = NULL;
	int i;
	int f = -1;
        struct stat st;
        size_t fsize = 0;

	/* Perform whitelist validation, call made to DB API " */
	ret = isWhitelisted(file_path);
	if( ret < 0){
#ifdef ERR
		fprintf(stderr, "Error during whitelist validation");
#endif
		goto exit_fn;
	}
	else if( ret == 1){
#ifdef DEBUG
		fprintf(stdout, "File %s is in whitelist ",filepath);
#endif
		ret = 0;
		goto exit_fn;
        } else {
                printf("%s -- \n", file_path);
                f = open(file_path, O_RDONLY, 0);
                if(f < 0){
#ifdef ERR
                        perror("");
#endif
                        printf("Sdsdsd\n");
                        ret = -1;
                        goto exit_fn;
                }
                if(stat(file_path,&st) < 0){
#ifdef ERR
                        perror(f);
#endif
                        printf("Sdsdsd -- 1\n");
                        ret = -1;
                        goto exit_fn;
                }
                if((st.st_mode & S_IEXEC) == 0){
#ifdef DEBUG
                        fprintf(stdout, "%s is not an executable file ",file_path);
#endif
                        printf("Sdsdsd -- 2\n");
                        ret = 0;
                        goto exit_fn;
                }
                /* Call made to DB API to get the complete up-to date blacklist */
                blacklist = getstructures();
                fsize = st.st_size;
                file_bytes = malloc(fsize+1);
                // Malloc fail add here

                i = read(f, file_bytes, fsize);
                *(file_bytes + fsize) = '\0';
                printf("=====> file size = %ld %d\n", fsize, i);

                if(i < 0){
#ifdef ERR	
                        fprintf(stderr,"File read error");
#endif
                        close(f);
                        goto exit_fn;
                }
                else if(i < fsize){
#ifdef DEBUG
                        fprintf(stdout, "Only partial file read of %s ",file_path);
#endif
                        ret = -1;
                        close(f);
                        goto exit_fn;
                }
                else{		
                        /* unsigned char* hex_str = malloc(2*fsize + 1);
                         *(hex_str + 2*fsize) = '\0';
                         unsigned char* copy_prt = hex_str;
                         for (i = 0; i < size; i++)
                         {
                         copy_ptr += sprintf(copyfb_ptr, "%02X", *(buf+i));
                         }*/

                        for(i = 1; i <= blacklist->sig_count; i++){
                                int j = 0;
                                signature = blacklist->signatures + next_pos;
                                #if 0
                                printf("%s %ld ---- %s\n", file_bytes, strlen(file_bytes), signature);
                                if(strstr(file_bytes, signature) != NULL){
                                        ret = 1;
#ifdef DEBUG
                                        fprintf(stdout, "%s is a virus ",file_path);
#endif
                                        goto exit_fn;
                                }
                                #endif
                                for (j = 0; j < (fsize - strlen(signature - 1)); j++) {
                                        #if 0
                                        char *temp = malloc(strlen(signature) + 1);
                                        memcpy(temp, file_bytes + j, strlen(signature));
                                        temp[strlen(signature)] = '\0';
                                        
                                        printf("===> Read string %s\n", temp);
                                        #endif
                                        if (memcmp(file_bytes + j, signature, strlen(signature)) == 0) {
                                                printf("===> detected\n");
                                                ret = 1;
                                                goto exit_fn;
                                        }
                                }

                                next_pos += 1 + strlen(signature);

                        }
                }



        }
#ifdef DEBUF
	fprintf(stdout, "%s is not a virus ",file_path);
#endif
	close(f);
	exit_fn:
		return ret;
}

