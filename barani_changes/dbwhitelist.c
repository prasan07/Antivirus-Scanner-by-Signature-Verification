#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include "dbutility.h"
#include <mysql.h>

//MYSQL * conn;
/*int db_init(){
	conn = mysql_init(NULL);
        if (!mysql_real_connect(conn, SERVER_LOC,
                                USER, PASS, DATABASE, 0, NULL, 0)) {
                fprintf(stderr, "%s\n", mysql_error(conn));
                return -1;
        }
	return 0;
}*/

int insertWhiteList(char * file_path){
	char* hash_val = NULL;
	char query[300];
	int result = 0;
	MYSQL * conn;

	conn = mysql_init(NULL);
        /* Connect to local database */
        if (!mysql_real_connect(conn, SERVER_LOC,
                                USER, PASS, DATABASE, 0, NULL, 0)) {
                fprintf(stderr, "%s\n", mysql_error(conn));
                return -1;
        }
	/*if(conn==NULL){
		if(db_init()==-1){
			result = -1;
			goto out;
		}		
	}*/

	/*retrieve hash of the given file*/
	hash_val = getsha256(file_path);
	sprintf(query, "insert into whitelist (hash) values ('%s')", hash_val);
	if (mysql_query(conn, query)) {
		fprintf(stderr, "%s\n", mysql_error(conn));
		result = -1;
		goto out;
	}
out:
	if(conn!=NULL)
		mysql_close(conn);
	return result;
}

int main(){

	DIR *dir;
	struct dirent *ent;
	char filename[256];
	if ((dir = opendir ("/bin/")) != NULL) {
		while ((ent = readdir (dir)) != NULL) {
			sprintf (filename, "/bin/%s", ent->d_name);
			printf("%s \n", filename);
			insertWhiteList(filename);
		}
		closedir (dir);
	}
}
