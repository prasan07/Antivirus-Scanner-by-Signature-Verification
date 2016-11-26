#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include "dbutility.h"

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

int insertWhiteList(MYSQL *conn, char * file_path){
	char* hash_val = NULL;
	char query[300];
	int result = 0;
        int transaction_start = 1;
	/*if(conn==NULL){
		if(db_init()==-1){
			result = -1;
			goto out;
		}		
	}*/
        if(mysql_query(conn, "START TRANSACTION")){
                fprintf(stderr, "%s\n", mysql_error(conn));
                result = -1;
                goto out;
        }
	/*retrieve hash of the given file*/
	hash_val = getsha256(file_path);
	sprintf(query, "insert into whitelist (hash) values ('%s')", hash_val);
	if (mysql_query(conn, query)) {
		fprintf(stderr, "%s\n", mysql_error(conn));
		result = -1;
		goto out;
	}
        if(mysql_query(conn, "COMMIT")){
                fprintf(stderr, "%s\n", mysql_error(conn));
                result = -1;
        }
        printf("Commited the changes\n");
        //perform clean up and exit
out:
        if(transaction_start && result == -1){
                mysql_query(conn, "ROLLBACK");
                printf("Rolling back DB changes\n");
        }
	return result;
}

int main(){

	DIR *dir;
	struct dirent *ent;
	char filename[256];
        MYSQL * conn;

        conn = mysql_init(NULL);

        if (conn == NULL){
                fprintf(stderr, "MySQL connection init error\n");
                goto whitelist_out;
        }
        /* Connect to local database */
        if (!mysql_real_connect(conn, SERVER_LOC,
                                USER, PASS, DATABASE, 0, NULL, 0)) {
                fprintf(stderr, "%s\n", mysql_error(conn));
                goto whitelist_out;
        }
        if (!verify_tables(conn))
                goto whitelist_out;
        
        if ((dir = opendir ("/bin/")) != NULL) {
		while ((ent = readdir (dir)) != NULL) {
			sprintf (filename, "/bin/%s", ent->d_name);
			printf("%s \n", filename);
			insertWhiteList(conn, filename);
		}
		closedir (dir);
	}
whitelist_out:
        if(conn!=NULL)
                mysql_close(conn);
        return 0;
}
