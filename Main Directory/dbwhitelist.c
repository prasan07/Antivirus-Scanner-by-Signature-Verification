#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include "dbutility.h"
#include <mysql.h>

int insertWhiteList(char * file_path){
	char* hash_val = NULL;
	DIR *dir;
        struct dirent *ent;
	char query[300];
	char filename[256];
	int result = 0;
	MYSQL * conn;

	conn = mysql_init(NULL);
	printf("Connection\n");
        // Connect to local database 
        if (!mysql_real_connect(conn, SERVER_LOC,
                                USER, PASS, DATABASE, 0, NULL, 0)) {
                fprintf(stderr, "%s\n", mysql_error(conn));
                return -1;
        }
	printf("Connection1\n");
	//verify tables exist
	if(verify_tables(conn)!=0){
		fprintf(stderr, "%s\n", mysql_error(conn));
                return -1;
	}
	printf("Connection2\n");
	//start Transaction
	if(mysql_query(conn, "START TRANSACTION")){
                fprintf(stderr, "%s\n", mysql_error(conn));
                result = -1;
                goto out;
        }
	printf("Connection3\n");
	if ((dir = opendir (file_path)) != NULL) {
                while ((ent = readdir (dir)) != NULL) {
                        sprintf (filename, "%s/%s", file_path, ent->d_name);
                        printf("%s \n", filename);
                        //retrieve hash of the given file
        		hash_val = getsha256(filename);
        		sprintf(query, "insert into whitelist (hash) values ('%s')", hash_val);
        		if (mysql_query(conn, query)) {
                		fprintf(stderr, "%s\n", mysql_error(conn));
                		result = -1;
                		goto out;
        		}
                }
                closedir (dir);
        }
	printf("Connection4\n");
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
	if(conn!=NULL)
		mysql_close(conn);
	return result;
}

int main(){
	DIR *dir;
	int i=0;
	char* whitelistDirs[6] = {"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"};
	while ((dir = opendir (whitelistDirs[i])) != NULL) {
		insertWhiteList(whitelistDirs[i]);
		i++;
	}
}
