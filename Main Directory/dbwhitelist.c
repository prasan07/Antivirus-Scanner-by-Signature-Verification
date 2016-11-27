#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include "dbutility.h"
#include <mysql.h>

/*
function        : method to populate the database with whitelist values from known executables
return value    : returns 0 on success, -1 on failure to create tables
parameters      : MYSQL connection object and directory path
*/

int insertWhiteList(MYSQL *conn, char * file_path){
	char* hash_val = NULL;
	DIR *dir;
        struct dirent *ent;
	char query[300];
	char filename[256];
	int result = 0;
	
	//start Transaction
	if(mysql_query(conn, "START TRANSACTION")){
#ifdef DEBUG
                fprintf(stderr, "%s\n", mysql_error(conn));
#endif
                result = -1;
                goto out;
        }
	if ((dir = opendir (file_path)) != NULL) {
                while ((ent = readdir (dir)) != NULL) {
                        sprintf (filename, "%s/%s", file_path, ent->d_name);
#ifdef DEBUG
                        printf("%s \n", filename);
#endif
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
	if(mysql_query(conn, "COMMIT")){
#ifdef DEBUG
                fprintf(stderr, "%s\n", mysql_error(conn));
#endif
                result = -1;
        }
        //perform clean up and exit
out:
        if(result == -1){
                mysql_query(conn, "ROLLBACK");
#ifdef DEBUG
                printf("Rolling back DB changes\n");
#endif
        }
	return result;
}

int main(){
	DIR *dir;
	int i=0;
	char* whitelistDirs[7] = {"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/lib/x86_64-linux-gnu"};
	MYSQL *conn;

        conn = mysql_init(NULL);
        //Connect to local database 
        if(!mysql_real_connect(conn, SERVER_LOC,
                                USER, PASS, DATABASE, 0, NULL, 0)) {
#ifdef DEBUG
                fprintf(stderr, "%s\n", mysql_error(conn));
#endif
                return -1;
        }
        //verify tables exist
        if(verify_tables(conn)!=0){
#ifdef DEBUG
                fprintf(stderr, "%s\n", mysql_error(conn));
#endif
                return -1;
        }
        
        while ((i < 7) && (dir = opendir (whitelistDirs[i])) != NULL) {
		insertWhiteList(conn, whitelistDirs[i]);
		i++;
	}
        if(conn!=NULL)
        mysql_close(conn);

        return 0;
}
