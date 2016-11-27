/*
  program to connect to mysql and access blacklist and whitelist tables
  and also updating the current database from remote server. 
  The methods create their connection and destroy them before returning to
  the calling function, this is a preferred design choice for programs that does not
  use the db often. This prevents having an open db connection all the time.
*/
#include <stdio.h>
#include "dbutility.h"
#include <stdlib.h>
#include <string.h>

/*
function        : method to check if the tables are present or create them
return value    : returns 0 on success, -1 on failure to create tables
parameters      : MYSQL connection object
*/
int verify_tables(MYSQL *conn){
	char query[4096];
	MYSQL_RES *res;
        int result = 0;

        if(mysql_query(conn, "START TRANSACTION")){
#ifdef DEBUG
                fprintf(stderr, "%s\n", mysql_error(conn));
#endif
                result = -1;
                goto out;
        }
        sprintf(query,"SELECT * FROM information_schema.tables WHERE table_schema = '%s' AND table_name = 'whitelist' LIMIT 1", DATABASE);
        if (mysql_query(conn, query)) {
#ifdef DEBUG
               fprintf(stderr, "%s\n", mysql_error(conn));
#endif
                result = -1;
                goto out;
        }
        res = mysql_store_result(conn);
        if(mysql_num_rows(res)==0){
                if (mysql_query(conn, "create table whitelist(hash_id int auto_increment primary key, hash varchar(65))")) {
#ifdef DEBUG
                        fprintf(stderr, "%s\n", mysql_error(conn));
#endif
                	return -1;
		}
        }
        sprintf(query,"SELECT * FROM information_schema.tables WHERE table_schema = '%s' AND table_name = 'blacklist' LIMIT 1", DATABASE);
        if (mysql_query(conn, query)) {
#ifdef DEBUG
                fprintf(stderr, "%s\n", mysql_error(conn));
#endif
                return -1;
        }
        res = mysql_store_result(conn);
        if(mysql_num_rows(res)==0){
                if (mysql_query(conn, "create table blacklist(signature_id int auto_increment primary key, signature varchar(65000))")) {
#ifdef DEBUG
                        fprintf(stderr, "%s\n", mysql_error(conn));
#endif
                        return -1;
                }
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
	return 0;
}

/*
function 	: method to retrieve the list of virus signatures
return value 	: returns a struct signatures list which contains all the blacklisted signatures in the db.
parameters 	: none
*/
struct signatures *getstructures(){
	int row_count = 0;
	int total_length = 0;
	int current_loc = 0;
	struct signatures* result = (struct signatures *) malloc(sizeof(struct signatures));	
	MYSQL *conn= NULL;
	MYSQL_RES *res =NULL;
	MYSQL_ROW row;
	if(result == NULL){
#ifdef DEBUG
		printf("Unable to allocate memory\n");
#endif
		goto out;
	}
	conn = mysql_init(NULL);
        // Connect to the local database
        if (!mysql_real_connect(conn, SERVER_LOC,
                                USER, PASS, DATABASE, 0, NULL, 0)) {
#ifdef DEBUG
                fprintf(stderr, "%s\n", mysql_error(conn));
#endif
		free(result);
                result = NULL;
		goto out;
        }
	//verify that the tables are present else create them
        if(verify_tables(conn)!=0){
		free(result);
                result = NULL;
		goto out;
        }
	// execute SQL query 
        if (mysql_query(conn, "select * from blacklist")) {
#ifdef DEBUG
                fprintf(stderr, "%s\n", mysql_error(conn));
#endif
		free(result);
                result = NULL;
		goto out;
	}
	res = mysql_store_result(conn);
	if (res == NULL)
	{	
		free(result);
		result = NULL;
		goto out;
	}
	// find the total size of the strings in the table
	while ((row = mysql_fetch_row(res)))
	{
		total_length+=strlen(row[1])+1;
                row_count++;
	}
	result->signatures = (char *) malloc(total_length);
	if(result->signatures ==NULL){
#ifdef DEBUG
		printf("Unable to allocate memory\n");
#endif
		goto out;
	}
	result->sig_count = row_count;
	mysql_data_seek(res, 0);
	//copy the strings in the structure one by one
	while ((row = mysql_fetch_row(res)))
	{
		memcpy(result->signatures + current_loc, row[1], strlen(row[1]));  
                current_loc += strlen(row[1]);
                result->signatures[current_loc] = '\0';
                current_loc++;
	}
out:
	//perform clean up and exit
	if(res!=NULL)
		mysql_free_result(res);
	if(conn!=NULL)
		mysql_close(conn);
	return result;
}

/*
function 	: method to update the virus signatures from remote DB server
return value 	: 1 on success, -1 on failure
parameters 	: flag to signify which tables to updates 0-both, 1- whitelist 2-blacklist
*/
int update_structures(unsigned int flag){
	char insert_query[65100];
        MYSQL_RES *res = NULL;
        MYSQL_ROW row;
	MYSQL *conn = NULL;
        MYSQL *remote_conn;
	int retval = 0;

        conn = mysql_init(NULL);
        // Connect to local database 
        if (!mysql_real_connect(conn, SERVER_LOC,
                                USER, PASS, DATABASE, 0, NULL, 0)) {
#ifdef DEBUG
                fprintf(stderr, "%s\n", mysql_error(conn));
#endif
                retval = -1;
		goto out;
        }
	//verify that the tables are present else create them
	if(verify_tables(conn)!=0){
		retval = -1;
		goto out;	
	}
	if(mysql_query(conn, "START TRANSACTION")){
#ifdef DEBUG
		fprintf(stderr, "%s\n", mysql_error(conn));
#endif
                retval = -1;
                goto out;
	}
	// Connect to remote database 
        remote_conn = mysql_init(NULL);
        if (!mysql_real_connect(remote_conn, REMOTE_LOC,
                                REMOTE_USER, PASS, DATABASE, 3306, NULL, 0)) {
#ifdef DEBUG
                fprintf(stderr, "%s\n", mysql_error(conn));
                printf("connection failed!!!");
#endif
                retval = -1;
                goto out;
	}
	if(flag == UPDATE_ALL || flag == UPDATE_WHITELIST){
		//remove local whitelist table
		if(mysql_query(conn, "delete from whitelist")){
#ifdef DEBUG
			fprintf(stderr, "%s\n", mysql_error(conn));
#endif
			retval = -1;
			goto out;
		}
		//retrieve update data for whitelist
		if (mysql_query(remote_conn, "select * from whitelist")) {
#ifdef DEBUG
			fprintf(stderr, "%s\n", mysql_error(conn));		
#endif
			retval = -1;
			goto out;
		}
		res = mysql_store_result(remote_conn);
		// insert new data into whitelist
		while((row = mysql_fetch_row(res)) != NULL){
			sprintf(insert_query, "insert into whitelist (hash) values ('%s')", row[1]);
			if (mysql_query(conn, insert_query)) {
#ifdef DEBUG
				fprintf(stderr, "%s\n", mysql_error(conn));
#endif
				retval = -1;
				goto out;
			}
		}
		mysql_free_result(res);
		res = NULL;
	}
	if(flag == UPDATE_ALL || flag == UPDATE_BLACKLIST){
		//remove local blacklist table
		if(mysql_query(conn, "delete from blacklist")){
#ifdef DEBUG
			fprintf(stderr, "%s\n", mysql_error(conn));
#endif
			retval = -1;
			goto out;
		}
		//retrieve update data for blacklist
		if (mysql_query(remote_conn, "select * from blacklist")) {
#ifdef DEBUG
			fprintf(stderr, "%s\n", mysql_error(conn));
#endif
			retval = -1;
			goto out;
		}
		res = mysql_use_result(remote_conn);
		// insert new data into blacklist
		while((row = mysql_fetch_row(res)) != NULL){
			sprintf(insert_query, "insert into blacklist (signature) values ('%s')", row[1]);
			if (mysql_query(conn, insert_query)) {
#ifdef DEBUG
				fprintf(stderr, "%s\n", mysql_error(conn));
#endif
				retval = -1;
				goto out;
			}
		}
	}
	if(mysql_query(conn, "COMMIT")){
#ifdef DEBUG
        	fprintf(stderr, "%s\n", mysql_error(conn));
#endif
                retval = -1;
	}
out:
	//perform clean up and exit
	if(retval == -1){
		mysql_query(conn, "ROLLBACK");
#ifdef DEBUG
		printf("Rolling back DB changes\n");
#endif
	}
	if(res!=NULL)
        	mysql_free_result(res);
	if(conn!=NULL)
        	mysql_close(conn);
	return retval;	
}

/*
function	: method to compare the whitelist hashes
return value 	: 1 on success (hash is present)
		  0 on success (hash is not present)
		 -1 on error
parameters	: path of the file whose hash is to be compared
*/
int isWhitelisted(char * file_path){
	char* hash_val = NULL;
	char query[4096];
	char insert_query[4096];
	int result = 0;
	MYSQL_RES *res= NULL;
        MYSQL_ROW row;
	MYSQL *conn = NULL;

        conn = mysql_init(NULL);
        // Connect to local database
        if (!mysql_real_connect(conn, SERVER_LOC,
                                USER, PASS, DATABASE, 0, NULL, 0)) {
#ifdef DEBUG
                fprintf(stderr, "%s\n", mysql_error(conn));
#endif
                result = -1;
		goto out;
        }
	//verify that the tables are present else create them
        if(verify_tables(conn)!=0){
#ifdef DEBUG
		printf("Unable to verify tables\n");
#endif
                result = -1;
		goto out;
        }
	//retrieve hash of the given file
	sprintf(insert_query, "insert into whitelist (hash) values ('%s')", file_path);
                        if (mysql_query(conn, insert_query)) {
#ifdef DEBUG
                                fprintf(stderr, "%s\n", mysql_error(conn));
#endif
                                result = -1;
                                goto out;
                        }

	hash_val = getsha256(file_path);
        sprintf(query, "select * from whitelist where hash = '%s'", hash_val);
	//check for the hash in the whitelist table
	if (mysql_query(conn, query)) {
#ifdef DEBUG
                fprintf(stderr, "%s\n", mysql_error(conn));
#endif
                result = -1;
		goto out;
        }
        res = mysql_use_result(conn);
	if((row = mysql_fetch_row(res)) != NULL){
                result = 1;
#ifdef DEBUG
		printf("Hash found, not a virus\n");
#endif
        }else{
		result = 0;
#ifdef DEBUG
		printf("Hash not found, proceding to check virus signature\n");
#endif
	}
	        sprintf(insert_query, "insert into whitelist (hash) values ('%d')", (result));
                        if (mysql_query(conn, insert_query)) {
#ifdef DEBUG
                                fprintf(stderr, "%s\n", mysql_error(conn));
#endif
                                result = -1;
                                goto out;
                        }

out:
	//perform clean up and exit
	if(res!=NULL)
		mysql_free_result(res);
	if(conn!=NULL)
   		mysql_close(conn);
	return result;
}
