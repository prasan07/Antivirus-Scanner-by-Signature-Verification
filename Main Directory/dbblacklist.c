#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include "dbutility.h"
#include <mysql.h>
#include <fcntl.h>
#include <string.h>

/* This program updates the blacklist database from a local file text file 
which contains the newly found blaclist signatures */

int insertBlackList(MYSQL *conn, char * file_path){
	FILE *fp;
	char query[65100];
	char* buf;
	int result = 0;
	//start Transaction
	if(mysql_query(conn, "START TRANSACTION")){
                fprintf(stderr, "%s\n", mysql_error(conn));
                result = -1;
                goto out;
        }
	if ((fp=(fopen(file_path,"r"))) != NULL){
                while (!feof(fp)){
			buf = malloc(65000);
			if(fgets(buf,65000,fp) != NULL){
				if(buf[0] == '\n' || buf[0] == '\r' || buf[0] == '\0'){
					free(buf);
					continue;
				}
				sprintf(query, "insert into blacklist (signature) values ('%s')", buf);
				if (buf[strlen(buf) - 1] == '\n')
					buf[strlen(buf) - 1] = '\0';
				if (mysql_query(conn, query)) {
					fprintf(stderr, "%s\n", mysql_error(conn));
					result = -1;
					fclose(fp);
					free(buf);
					goto out;
				}
			}
			free(buf);	
                }
               	fclose(fp);
        }
	if(mysql_query(conn, "COMMIT")){
                fprintf(stderr, "%s\n", mysql_error(conn));
                result = -1;
        }
        //perform clean up and exit
out:
        if(result == -1){
                mysql_query(conn, "ROLLBACK");
                printf("Rolling back DB changes\n");
        }
	return result;
}

int main(){
	MYSQL * conn;
	conn = mysql_init(NULL);
	char blacklist_file[PAGE_SIZE];
	printf("Enter blacklist file path:\n");
	scanf("%s", blacklist_file); 
	// Connect to local database 
	if (!mysql_real_connect(conn, SERVER_LOC,
				USER, PASS, DATABASE, 0, NULL, 0)) {
		fprintf(stderr, "%s\n", mysql_error(conn));
		return -1;
	}
	//verify tables exist
	if(verify_tables(conn)!=0){
		fprintf(stderr, "%s\n", mysql_error(conn));
		return -1;
	}
	insertBlackList(conn, blacklist_file);
	if(conn!=NULL)
		mysql_close(conn);
	return 0;
}
