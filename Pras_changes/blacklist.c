#include "blacklist.h"
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
	FILE *f = NULL;
	struct stat st;

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
                f = fopen(file_path, "rb");
                if(!f){
#ifdef ERR
                        perror(f);
#endif
                        ret = -1;
                        goto exit_fn;
                }
                if(stat(file_path,&st) < 0){
#ifdef ERR
                        perror(f);
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
                fseek(f, 0, SEEK_END);
                long fsize = ftell(f);
                fseek(f, 0, SEEK_SET);

                file_bytes = malloc(fsize+1);
                // Malloc fail add here

                i = fread(file_bytes, 1, fsize, f);
                *(file_bytes + fsize) = '\0';

                if(i < 0){
#ifdef ERR	
                        fprintf(stderr,"File read error");
#endif
                        fclose(f);
                        goto exit_fn;
                }
                else if(i < fsize){
#ifdef DEBUG
                        fprintf(stdout, "Only partial file read of %s ",file_path);
#endif
                        ret = -1;
                        fclose(f);
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
                                signature = blacklist->signatures + next_pos;
                                if(strstr(file_bytes, signature) != NULL){
                                        ret = 1;
#ifdef DEBUG
                                        fprintf(stdout, "%s is a virus ",file_path);
#endif
                                        fclose(f);
                                        goto exit_fn;
                                }
                                next_pos += 1 + strlen(signature);

                        }
                }



        }
#ifdef DEBUF
	fprintf(stdout, "%s is not a virus ",file_path);
#endif
	fclose(f);
	exit_fn:
		return ret;
}

