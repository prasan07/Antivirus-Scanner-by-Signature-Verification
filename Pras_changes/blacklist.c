#include "blacklist.h"
#include "dbutility.h"

int blacklist_scan(char* file_path){

	int ret = 0;
	blacklist_from_db* blacklist = NULL;
	char* signature = NULL;
	int next_pos = 0;
	unsigned char* file_bytes = NULL;
	int i;
	FILE *f = NULL;

	/* Perform whitelist validation, call made to DB API " */
	ret = isWhitelisted(file_path);
	if( ret < 1){
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
	}
	else{

		blacklist = getstructures();
		
		f = fopen(file_path, "rb");
		if(!f){
#ifdef ERR
		perror(f);
#endif
		}
		fseek(f, 0, SEEK_END);
		long fsize = ftell(f);
		fseek(f, 0, SEEK_SET);

		file_bytes = malloc(fsize+1);
		*(file_bytes + fsize) = '\0';

		i = fread(file_bytes,fsize, 1, f);
		if(i < 0){
#ifdef ERR	
			fprintf(stderr,"File read error");i
#endif
			fclose(f);
			goto exit_fn;
		}
		else if(i < fsize){
#ifdef DEBUG
			fprintf(stdout, "Only partial file read of %s ",file_path);
#endif
			ret = 0;
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
		
			for(i = 0; i < blacklist->sig_count; i++){
				signature = blacklist->signatures + next_pos;
				if(strstr(file_bytes, signature) != NULL){
					ret = 1;
#ifdef DEBUG
					fprintf(stdout, "%s is a virus ",file_path);
#endif
					fclose(f);
					goto exit_fn;
				}
				next_pos += next_pos + strlen(signature);

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

