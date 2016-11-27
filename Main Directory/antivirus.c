#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "blacklist.h"
#include "dbutility.h"

/* Stack used in recursive directory scans
 * to save the index in the file path from where
 * next scan file/dir name needs to be appended
 */
struct idx_stack
{
        struct idx_stack *next;
        int idx;
};

struct idx_stack *top = NULL;

struct idx_stack *insStack(int idx)
{
        struct idx_stack *StackEntry = (struct idx_stack *)malloc(
                sizeof(struct idx_stack));

        if (!StackEntry) {
#ifdef DEBUG
                fprintf(stderr, "Stack Entry Malloc failed\n");
#endif
                return NULL;
        }

        StackEntry->next = NULL;
        StackEntry->idx = idx;
        return StackEntry;
}

int push(int idx)
{
        int ret = 1;

        if (!top) {
                top = insStack(idx);
                ret = (top == NULL);
        } else {
                struct idx_stack *cur_top = top;
                top = insStack(idx);

                if (!top) {
                        top = cur_top;
                        ret = 1;
                } else {
                        top->next = cur_top;
                        ret = 0;
                }
        }
        return ret;
}

int pop(void)
{
        int ret = 0;
        if (top) {
                struct idx_stack *cur_top = top;
                ret = top->idx;
                top = top->next;
                free(cur_top);
        }
        return ret;
}

void clearStack(void)
{
        while (top)
                pop();
}

/* List of files quarantined by the antivirus */
struct quarantine_list
{
        struct quarantine_list *next;
        char file_name[1];
};

struct quarantine_list *head = NULL;
struct quarantine_list *tail = NULL;

struct quarantine_list *newItem(char *file_name, int name_size)
{
        struct quarantine_list *item = (struct quarantine_list *)malloc(
                sizeof(struct quarantine_list) + name_size);

        if (!item) {
#ifdef DEBUG
                fprintf(stderr, "List Item Malloc failed\n");
#endif
                return NULL;
        }

        item->next = NULL;
        strncpy(item->file_name, file_name, name_size);
        item->file_name[name_size] = '\0';
        return item;
}

int insItem(char *file_name, int name_size)
{
        int ret = 1;
        
        if (!tail) {
                head = newItem(file_name, name_size);
                tail = head;
                ret = (head == NULL);
        } else {
                tail->next = newItem(file_name, name_size);
                if (tail->next) {
                        tail = tail->next;
                        ret = 0;
                }
        }
        return ret;
}

void delItem(void)
{
        if (head) {
                struct quarantine_list *t = head;
                head = head->next;
                free(t);
        }
}

void delList(void)
{
        while (head)
                delItem();

        head = NULL;
        tail = NULL;
}

void printQList(void)
{
        struct quarantine_list *iter = head;

        printf("\nQuarantine List: \n");
        while (iter) {
                printf("%s\n", iter->file_name);
                iter = iter->next;
        }

}

void print_help(char *argv)
{
        printf("\nAntivirus program help\n");
        printf("\nUsage: %s (-ua|-ub|-uw|path to file/directory)\n", argv);
        printf("\nDescription of arguments:\n");
        printf("-ua\t\t\t- Update all database definitions\n"); 
        printf("-ub\t\t\t- Update blacklist definitions\n");
        printf("-uw\t\t\t- Update whitelist definitions\n");
        printf("path to file/directory\t- Path of file/directory to scan\n");
}

/* Function printmsgBox 
 * 
 * displays the quarantined file names as an alert box to the user
 */
int printMsgBox(void)
{
        int ret = 0;
        struct quarantine_list *iter = head;
        char *xmessage = NULL;
        char *command = "xmessage -center \"The following files have been quarantined by the antivirus:\n";
        char *newline = "\n";
        int size = strlen(command);

        while (iter) {
                size += strlen(iter->file_name) + 1;
                iter = iter->next;
        }

        xmessage = (char *)malloc(size + 2);

        if (!xmessage) {
#ifdef DEBUG
                fprintf(stderr, "Message Box allocation error\n");
#endif
                ret = -ENOMEM;
                goto exit_printMsgBox;
        }

        strcpy(xmessage, command);
        iter = head;

        while (iter) {
                strcat(xmessage, iter->file_name);
                strcat(xmessage, newline);
                iter = iter->next;
        }
        xmessage[size] = '\"';
        xmessage[size + 1] = '\0';
        system(xmessage);
exit_printMsgBox:
        free(xmessage);
        return ret;
}

/* Function file_scan
 * 
 * takes a file argument, scans it with the virus definitions and if it is
 * flagged to contain a virus, removes all file permissions and appends a
 * ".virus" to the filename
 */
int file_scan(char *arg)
{
        int ret = 1, qlist_ret = 0;
        char *new_name = NULL;

        ret = blacklist_scan(arg);

#ifdef DEBUG
        printf("Scanning file %s\n", arg);
#endif

        if (ret <= 0)
                goto exit_file_scan;

        /* Scanned file matches a known virus pattern */
        new_name = (char *)malloc(strlen(arg) + 6);

        if (!new_name) {
#ifdef DEBUG
                fprintf(stderr, "Memory alloc failed\n");
#endif
                ret = -ENOMEM;
                goto exit_file_scan;
        }

        if (chmod(arg, 0) != 0) {
#ifdef DEBUG
                fprintf(stderr, "Chmod failed\n");
#endif
                ret = -errno;
                goto exit_file_scan;
        }

        strcpy(new_name, arg);

        strcat(new_name, ".virus");

        if (rename(arg, new_name) != 0) {
                ret = -errno;
#ifdef DEBUG
                fprintf(stderr, "Renaming of %s failed\n", arg);
#endif
                goto exit_file_scan;
        }

        qlist_ret = insItem(arg, strlen(arg));

        if (qlist_ret) {
#ifdef DEBUG
                fprintf(stderr, "Insertion into qlist error\n");
#endif
                ret = -ENOMEM;
        }
exit_file_scan:
        free(new_name);
        return ret;
}

/* Function dir_scan
 * 
 * takes a directory argument and recursively scans its contents for
 * possible virus definition matches
 */
int dir_scan(char *arg)
{
        int ret = 0, scan_ret = 0;
        DIR *dir;
        struct dirent *entry;
        char *dir_path = NULL;
        int prev_size = 0; 

        if (!(dir = opendir(arg))) {
                printf("opendir error %s\n", arg);
                ret = -errno;
                goto exit_dir_scan;
        }

        /* Create path to current file/dir */
        dir_path = (char *)malloc(strlen(arg) + 1);

        if (!dir_path) {
                printf("Mem alloc error\n");
                ret = -ENOMEM;
                goto exit_dir_scan;
        }

        strcpy(dir_path, arg);
        dir_path[strlen(arg)] = '\0';
        prev_size = strlen(dir_path);

        /* Iterate through directory contents and add to
         * or remove from the created directory path as
         * needed. A stack is used to keep track of depth
         * as recursive scans proceed
         */
        while ((entry = readdir(dir))) {
                if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                        continue;

                if (dir_path && push(prev_size)) {
                        ret = -ENOMEM;
                        goto exit_dir_scan;
                }

                dir_path = (char *)realloc(dir_path, prev_size + 2 + strlen(entry->d_name));

                if (!dir_path) {
                        ret = -ENOMEM;
#ifdef DEBUG
                        fprintf(stderr, "Directory name memalloc failed\n");
#endif
                }

                dir_path[prev_size] = '/';
                dir_path[prev_size + 1] = '\0';
                strcat(dir_path, entry->d_name);

                if (entry->d_type == DT_DIR)
                        scan_ret = dir_scan(dir_path);
                else
                        scan_ret = file_scan(dir_path);

                if (scan_ret != 0)
                        ret = scan_ret;

                if (ret < 0)
                        break;

                prev_size = pop();
        }
exit_dir_scan:
        free(dir_path);
        return ret;
}

/* Function antivirus_scan
 *
 * Scans the input file/directory argument. Can be called on demand / on access
 */
int antivirus_scan(char *arg)
{
        struct stat stat_buf;
        int file_type;
        int ret = 0, msg_ret = 0;

        /* Validate input argument */
        if (stat(arg, &stat_buf) != 0) {
                ret = -errno;
                fprintf(stderr, "Stat failed\n");
                goto exit_antivirus;
        }

        file_type = (stat_buf.st_mode & S_IFMT);

        if (file_type == S_IFDIR)
                ret = dir_scan(arg);
        else
                ret = file_scan(arg);

        if (ret <= 0)
                goto exit_antivirus;

        msg_ret = printMsgBox();

        if (msg_ret < 0)
                ret = msg_ret;

exit_antivirus:
        clearStack();
        delList();
        return ret;
}

int main(int argc, char *argv[])
{
        int ret = 0;

        if (argc != 2) {
                ret = -EINVAL;
                goto exit_antivirus;
        }
        
        if ((strcmp(argv[1], "-ua") == 0) || (strcmp(argv[1], "-ub") == 0) ||
                (strcmp(argv[1], "-uw") == 0)) {
                int flags = UPDATE_ALL;

                if (strcmp(argv[1], "-ub") == 0)
                        flags = UPDATE_BLACKLIST;
                else if (strcmp(argv[1], "-uw") == 0)
                        flags = UPDATE_WHITELIST;

                ret = update_structures(flags);
#ifdef DEBUG
                printf("Update antivirus definitions\n");

                if (ret == -1)
                        fprintf(stderr, "Antivirus update failed\n");
                else
                        printf("Update success\n");
#endif
        } else if (strcmp(argv[1], "?") == 0) {
                print_help(argv[0]);
        } else if (access(argv[1], F_OK) != 0) {
                ret = -errno;
#ifdef DEBUG
                fprintf(stderr, "No such file/directory\n");
#endif
                goto exit_antivirus;
        } else {
                /* Scan the provided args */
                ret = antivirus_scan(argv[1]);    
        }
exit_antivirus:
        return ret;
}
