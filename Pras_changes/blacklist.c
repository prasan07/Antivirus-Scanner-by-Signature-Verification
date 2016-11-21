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
#ifdef DEBUG
		fprintf(stderr, "Error during whitelist validation");
#endif
		goto exit_fn;
	}
	else if( ret == 1){
#ifdef DEBUG
		fprintf(stdout, "File %s is in whitelist ",file_path);
#endif
		ret = 0;
		goto exit_fn;
        } else {
                f = open(file_path, O_RDONLY, 0);
                if(f < 0){
#ifdef DEBUG
                        perror(file_path);
#endif
                        ret = -1;
                        goto exit_fn;
                }
                if(stat(file_path,&st) < 0){
#ifdef DEBUG
                        perror(file_path);
#endif
                        ret = -1;
                        goto exit_fn;
                }
                if((st.st_mode & S_IEXEC) == 0){
#ifdef DEBUG
                        fprintf(stdout, "%s is not an executable file ",file_path);
#endif
                        ret = 0;
                        goto exit_fn;
                }
                /* Call made to DB API to get the complete up-to date blacklist */
                blacklist = getstructures();
                fsize = st.st_size;
                file_bytes = malloc(fsize+1);
                if(!file_bytes){
#ifdef DEBUG
			fprintf(stderr, "Memory allocation error ");		
#endif
			ret = -1;
			goto exit_fn;
		}

                i = read(f, file_bytes, fsize);
                *(file_bytes + fsize) = '\0';

                if(i < 0){
#ifdef ERR	
                        fprintf(stderr,"File read error");
#endif
                        ret = -1;
                        goto exit_fn;
                }
                else if(i < fsize){
#ifdef DEBUG
                        fprintf(stdout, "Only partial file read of %s ",file_path);
#endif
                        ret = -1;
                        goto exit_fn;
                }
                else{		

                        for(i = 1; i <= blacklist->sig_count; i++){
                                int j = 0;
                                signature = blacklist->signatures + next_pos;
                                for (j = 0; j <= (fsize - strlen(signature)); j++) {
                                        if (memcmp(file_bytes + j, signature, strlen(signature)) == 0) {
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
exit_fn:
	if(f>=0){
		close(f);
	}
	return ret;
}

