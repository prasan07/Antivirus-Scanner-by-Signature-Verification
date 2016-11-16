#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#if 0
void recursive_scan(char *path)
{
        DIR *dir;
        nclude <sys/types.h>
        #include <sys/stat.h>
        struct dirent *entry;

        //if ()
}
#endif

void print_help(char *argv)
{
        printf("\nAntivirus program help\n");
        printf("\nUsage: %s (-u|path to file/directory)\n", argv);
        printf("\nDescription of arguments:\n");
        printf("-u\t\t\t- Update database definitions\n");
        printf("path to file/directory\t- Path of file/directory to scan\n");
}

int main(int argc, char *argv[])
{
        int rc = 0;

        if (argc != 2) {
                rc = -EINVAL;
                goto exit_antivirus;
        }
        
        if (strcmp(argv[1], "-u") == 0) {
                /* Call update */
                printf("Update defs\n");
        } else if (strcmp(argv[1], "?") == 0) {
                print_help(argv[0]);
        } else if (access(argv[1], F_OK) != 0) {
                rc = -errno;
                printf("No such file/directory %d\n", rc);
                goto exit_antivirus;
        } else {
                /* All Good - Scan the provided args */
                struct stat stat_buf;
                char *new_name = NULL;
                //int file_type;
                char *xmessage = NULL;
                char *command = "xmessage -center \"The following files have been quarantined by the antivirus:\n";

                if (stat(argv[1], &stat_buf) != 0) {
                        rc = -errno;
                        printf("Stat failed %d\n", rc);
                        goto exit_antivirus;
                }

                //file_type = (stat_buf.st_mode & S_IFMT);

                new_name = (char *)malloc(strlen(argv[1]) + 6);

                if (!new_name) {
                        printf("Memory alloc failed\n");
                        rc = ENOMEM;
                        goto exit_antivirus;
                }

                xmessage = (char *)malloc(strlen(argv[1]) + strlen(command));

                if (!xmessage) {
                        printf("Memory alloc failed\n");
                        rc = ENOMEM;
                        goto exit_antivirus;
                }

                if (chmod(argv[1], 0) != 0) {
                        printf("Chmod failed\n");
                        rc = -errno;
                        goto exit_antivirus;
                }

                strcpy(new_name, argv[1]);

                strcat(new_name, ".virus");

                if (rename(argv[1], new_name) != 0) {
                        rc = -errno;
                        printf("Rename failed\n");
                        goto exit_antivirus;
                }

                strcpy(xmessage, command);

                strcat(xmessage, argv[1]);

                strcat(xmessage, "\na\"");

                system(xmessage);

                free(xmessage);
                free(new_name);
        }
exit_antivirus:
        return rc;
}
