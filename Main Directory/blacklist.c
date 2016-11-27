#include "blacklist.h"
#include "dbutility.h"

/* 
This function checks if the given file is a virus 
by scanning for blacklist hex_signatures 
param 	- A file path
return	- 1 if virus
	  0 if not virus
	 -1 if scan error
*/
int blacklist_scan(char* file_path){

	int ret = 0, j=0;
	blacklist_from_db* blacklist = NULL;
	char* hex_signature = NULL;
	char* byte_signature = NULL;
	char* pos = NULL;
	char* hex_pos = NULL;
	int next_pos = 0;
	unsigned char* file_bytes = NULL;
	int i;
	int f = -1;
        struct stat st;
        size_t fsize = 0;

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

                /* Call made to DB API to get the complete up-to date blacklist */
                blacklist = getstructures();
                fsize = st.st_size;
                file_bytes = malloc(fsize+1);
                if(!file_bytes){
#ifdef DEBUG
			fprintf(stderr, "Memory allocation error ");		
#endif
			ret = -ENOMEM;
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
				/* Get the hex signature string from DB */
                                hex_signature = blacklist->signatures + next_pos;
				hex_pos = hex_signature;	
				byte_signature = malloc(strlen(hex_signature)/2 + 1);
				if(!byte_signature){
#ifdef DEBUG
					fprintf(stderr, "Memory allocation error ");		
#endif
					ret = -ENOMEM;
					goto exit_fn;
				}
				pos = byte_signature;
				/* Convert the hex_signature string to byte array */
				for(j = 0; j < strlen(hex_signature)/2; j++){
					sscanf(hex_pos,"%2hhx",pos);				
					hex_pos += 2;
					pos += 1;
				}	
				pos = '\0';
#ifdef TEST
				printf("\n%s byte sig", byte_signature);
				printf("\n%s hex sig", hex_signature); 
       				printf("\n%ld",strlen(byte_signature));                         
#endif
				for (j = 0; j <= (fsize - strlen(byte_signature)); j++) {
                                        if (memcmp(file_bytes + j, byte_signature, strlen(byte_signature)) == 0) {
                                                ret = 1;
                                                goto exit_fn;
                                        }
                                }

                                next_pos += 1 + strlen(hex_signature);
				free(byte_signature);
                        }
                }



        }
#ifdef DEBUG
	fprintf(stdout, "%s is not a virus ",file_path);
#endif
exit_fn:
	if(f>=0){
		close(f);
	}
        free(blacklist);
	return ret;
}

