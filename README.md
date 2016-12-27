This Report describes the Antivirus Course Project of the Fall 2016 CSE509 Systems Security course
at Stony Brook University.

Contributors: 

Arun Ramachandran (aruramachand@cs.stonybrook.edu, <110852807>)
Gangabarani Balakrishnan (gbalakrishna@cs.stonybrook.edu, <110975065>)
Prasanth Sridhar (prsridhar@cs.stonybrook.edu, <110899181>)
Shyam Sundar Chandrasekaran (shychandrase@cs.stonybrook.edu, <110815338>)
---------------------------------------------------------------------------------------------------

DESCRIPTION:

A "simple" antivirus scanner that supports updates over the Internet. 

The antivirus contains a list of known harmless programs - a whitelist - and a known malware
signature list - a blacklist - and detects malware based on signatures of malicious programs. 

Any detected malicious program is quarantined by removing its permissions and appending a ".virus"
suffix to the name. User is appropriately notified of this via an alert message box.

The antivirus runs in two scanning modes:

        i) On Demand Scanning:
           In On Demand scanning, the user can run a program to scan a file, or a directory
           containing files, e.g. ./antivirus /home/jack/Downloads.

        ii) On Access Scanning:
           In On Access scanning, a kernel driver must hook to appropriate system calls
           (e.g. open, execve, and execveat) and must scan the file before it is opened.
           If the file is infected, then the file must not be opened.
           Additionally, a message could be printed to the kernel log to indicate that the file
           is infected. However, this did not work as part of our project.

Details of usage can be found in the "INSTRUCTIONS" section.
----------------------------------------------------------------------------------------------------

DESIGN DECISIONS:

In this section, we describe the various design decisions that we undertook for the project.

Database APIs and Tables:

The application uses a mysql DB to store the values of the whitelisted hashes and the blacklisted 
virus signatures. There are two separate tables, one table (whitelist) used for storing the hashes 
of whitelisted applications, One table(blacklist) used for storing the blacklist signatures. 

whitelist table:
1. hash_id 	- integer primary key.
2. hash 	- varchar 65 characters long string.

blacklist table:
1. signature_id	- integer primary key.
2. signature	- variable length signature having max 65535 characters.

The DB modules consists of three API calls, one API call for checking whether a hash value exists 
in the database, one for retrieving a list of all the blacklist signatures, and the last one for
getting updates from the remote server. 

API Calls:

1. struct signatures* getstructures()
	This call returns a concatenated string of all the blacklisted virus signatures delimited 
	by a '\0' along with the number of such strings. This method returns a NULL on error and 
	a valid struct object on success.

2. int update_structures(int flag)
	This call removes existing values in both the tables, connects to a remote database, gets 
	the new values and inserts them into the local database. The entire operation is performed
	as a single transaction. In case of failure, the database will still be in a stable state.
	This method returns -1 on error, and 0 on success.
	0 - update both tables
	1 - update whitelist table only
	2 - update blacklist table only

3. int isWhitelisted(char * file_path)
	This method gets the file location as input, calculates the sha256 hash value of the file,
	checks to see if the value already exists in the database and returns 1 if the hash exists, 
	0 if the hash doesn't exist and -1 on error.

The remote server is a mysql DB server, which allows remote connection to a user based on the 
permissions granted to the user. The entire operation of update is performed as a single 
transaction. In case anything breaks in between, the entire transaction is rolled back and the
database always remains in a stable state.

The hash function used in our application is SHA256, which gives a 32 byte hash value for each
hashed file.  

Kernel Driver:

We used a driver as a module to intercept the open and exec family of system calls.

First, we added a new entry to the syscall_64.tbl table, to facilitate the insertion and removal
 of a module.
Next, the corresponding initialization and exit functions of the module were used by custom
 functions to hook to open, execve and execveat syscalls.
The custom functions of the corresponding system calls, invoked the user space application, to
 determine if the file was infected. If it were infected, then the corresponding open or exec
 operation did not proceed, but a value of 1 was returned to the user (1 was to distinguish it
 from standard errors which had negative values, and SUCCESS which returned 0). The intercepted
 functions also logged a message in the kernel's dmesg log to indicate that the file was
 infected. If the file was not detected, the standard sys_open() was invoked.

The first major design choice was regarding the accessing of the syscall_table, which is an
 array of pointers to corresponding system-call functions (like sys_open()). We decided to export
 the table, and directly reference it.
The next design choice was with respect to accessing the syscall_table, which was write-protected.
 We used 2 techniques in combination, for this : 
	a) To obtain the address of the page corresponding to the syscall_table and make it
 	   read-write for the period of time when the module was inserted, and restore to
	   read-only later.
	b) To disable the architecture-level write-protection bit in the control register of the
	   CPU, for this period of time, and enable later.
Once the above two were done, we were able to hook to the open syscall. Upon inserting the module,
 we just saved the function pointer of the entry in the syscall_table array corresponding to
 sys_open(), pointed that entry to our custom function, and restored the old pointer upon exiting
 the module. The custom function invoked the virus-detection logic in user space, and either
 disallow an open upon detecting an infected file or allow the standard sys_open() to proceed.
 This was possible because we used the stored pointer of the entry corresponding to sys_open().

Hooking to the exec family of system calls was quite more difficult, because exec was a part of a
 set of operations for which assembly stubs were being added to the syscall. We tried the
 following techniques, which all failed :

    Directly save the pointer of
    table[__NR_execve] and reference it	 	:   Process got killed

    Directly invoke do_execve(), the function 
        invoked by sys_execve()			:   Process got killed

    Use the udis86 disassembler(open source
    library), and determine the exact location
    of the sys_execve() within the stub code	:   Able to hook correctly, but the provided input
                                                    parameter in the form of a userspace address was
                                                    seen as a bad address(-EFAULT), due to which the
                                                    userspace logic could not correctly function

    Exploit SYSCALL_OPEN() directly             :   This was what we finally resorted to. It is not
                                                    the same as hooking in the form of a module.
                                                    The interception is permanent. However, though this
                                                    could invoke the userspace logic, the userspace could 						     not obtain the parameters passed by the kernel in a
                                                    proper format
Blacklist signature verification:

On each file, signature verification is performed to scan and check for any blacklists.
During each file scan, the following operations are performed:

	1. Perform file stat mode validation and skip the scan process if it is an executable file.

	2. Validate if the file is a whitelist using the isWhitelist() API call. If so, skip the scanning 
process.

	3. If the file is a non-whitelist execuatable, retrieve the blacklist info from the database using
the getStructures() API call and pack them inside a user defined structure.

	4. The blacklist signature retrieved from the database is in hexstring format.
These hex signatures are formatted to a byte array signatures.

	5. The formatted bytearray is memcompared with a file binary to look for the pattern. If there is
memcompare match, then the file is flagged as a blacklist and intimated to the controller program.


Antivirus Userspace executable:

For the antivirus userspace application, we store the list of files that have been flagged as mali-
cious programs within a linked list where each list entry contains path to the malicious file.

This list is used to show to the user the files that have been quarantined - displayed via xmessage
that displays it in a message box.

we decided to add recursive traversal of subdirectories and files so as to scan all the contents
within a directory.
So, to keep track of the current directory namespace, we maintain a stack that stores the index,
within the namespace, the location within the namespace where the next directory
name/file names needs to be added to

The antivirus also supports scanning on softlinks - if a linked file is detected as a virus, its
permissions are removed but the softlink to it is renamed with a ".virus" added at the end of the link
name.

For updating the virus database definitions, the antivirus makes use of the updateStructures()
described above.
----------------------------------------------------------------------------------------------------

INSTRUCTIONS:

Our antivirus works with *nix machines.

We have provided a script, compile.sh, that can be used to build our antivirus as follows:

        i) Download the source from 

        ii) Build the source files using the following commands:
                
                sh compile.sh

The antivirus can currently support only On Demand scanning mode. 
For On Demand scanning of files or to update the antivirus definitions from remote repo:

                ./antivirus (-u(a|b|w)|path to file/directory)

                Description of arguments:
                -ua                     - Update all database definitions
                -ub                     - Update blacklist definitions
                -uw                     - Update whitelist definitions
                path to file/directory  - Path of file/directory to scan

        ii) For On Access scanning,
		To insert the module
			insmod hook.ko
		To unload the module
			rmmod hook.ko
                <Fill in the details>

The antivirus uses a MySQL DB backend to store virus definitions that are used in scans. So, MySQL
should be installed on the user machine for the antivirus software to be fully effective.

MySQL installation guide can be found at:
https://www.digitalocean.com/community/tutorials/how-to-install-mysql-on-ubuntu-14-04

In order to update virus definitions, we had to add firewall whitelisting and grant privileges on
the remote MySQL DB as follows:

/sbin/iptables -A INPUT -i <interface> -p tcp --destination-port 3306 -j ACCEPT

grant all privileges on "database.tables" to 'username'@'%' identified by 'passphrase'

edit /etc/mysql/my.cnf
change line with bind-address to "bind-address = *"

populating the DB:
1. whitelist - for adding entries to whitelist table- run "./dbwhitelist" command after compilation using "sh compile.sh"

2. blacklist - for adding entries to blacklist table- run "./dbblacklist" command after compilation using "sh compile.sh"

	       The prompt will ask for a blacklist file location, enter "blacklist.txt" loc.
----------------------------------------------------------------------------------------------------

MAIN FILES:

The details of the main antivirus source files are as follows:

REPORT            -     Project Report      
antivirus.c       -     Code for the antivirus userspace executable
trapper.c	  - 	Module to intercept open and exec-related system calls, and invoke the userspace
			virus-detection logic
dboperations.c    -     This file contains all the main db operation APIs. The definitions of the following files are
                        present.

                        1. verify_tables(MYSQL* conn)   - tests whether the given function has all 
                                                          the required db tables(whitelist, blacklist)
                        2. isWhitelisted(char* filepath)- generates the sha256 of the given file and  
                                                           checks if the generated hash is present in the whitelist.
                        3. getStructures()              - retrieves all the blacklist signatures from DB,
                                                          formats it to a structure and returns to the caller.
                        4. updateStructures(int flag)   - retrieve the data from the remote db server, and update
                                                          the local db with that value.
getsha256.c       -     Generates the sha256 hash of the filepath passed to it and returns it in 64 char long string.
dbutility.h       -     The Main db header file contains all the API calls.
dbwhitelist.h     -     This program populates the hash value into the db whitelist table for known files.
test_programs     -     Directory containing sample c and c++ programs that we used for testing
test_script.sh    -     Shell script to compile and sanitize programs in test_programs directory

The following set of files were used from a reference code in github, for the purpose of hooking into
sys_execve and sys_execveat. Unlike the sys_open system call, for which the syscall_table's entry
corresponding to sys_open could be made to point to a custom-defined function, the sys_execve system call
needed to be handled differently because assembly stubs were being added to the system call :

mem.h and mem.c	  -	Helper functions to determine the actual pointer to the system call within the stub,
			 and hook to that	

The following files were used from the udis86 open source library for x86 architecture, which performed
disassembling :

udis86.h and libudis86/* 
		  -	Functions of the disassembler engine(to
                        inspect the input stream of machine code bytes)
Makefile	  -	To compile and build the modules
blacklist.h	  -	Exposes blacklist_scan function as an interface to the controller program and
			contains the header files required for dbblacklist.c and blacklist.c
blacklist.c	  - 	blacklist_scan implementation that performs byte-wise comparison between file binary
			and blacklist signatures.
dbblacklist.c	  -	A user program that updates newly discovered blacklists to the database.
blacklist.txt     - 	file containing list all the blacklisted signatures, to be used when populating db
			using "./dbblacklist" command.
----------------------------------------------------------------------------------------------------

TESTING:

a) On-Demand scanning:
        For testing, we created a set of C and C++ programs and stored in inside test_programs directory

        Using test_script.sh shell script, we compile and sanitize the programs inside test_programs

        We added signatures from some of the c and c++ programs into a text file, blacklist.txt.
        Using the program, dbblacklist.c, We fed the signatures to the (remote/local) database
        and ran on demand scans against the contents of test_programs

        For whitelist, using the dbwhitelist utility, we create and populate SHA's of Linux Utilities and
        Libraries that can be considered definitively as "Non-Viruses". We then tested on demand scanning of
        these linux executables against this whitelist.

        We verified virus definition updates by adding privileges for the local db user in the remote db,
        adding appropriate firewall exceptions and modifying the remote db address in our code.
        After re-compilation, we tested updates via "./antivirus -u(a|b|w)"

b) On-access scanning:
	Upon insertion of the module, using "insmod trapper.ko", the open and exec related system calls will be
	intercepted.
	Upon execution of a file containing a virus, it will remove the permissions of the file, append ".virus"
	to the file and disallow execution of the file.
	The dmesg log in the kernel must be checked to notice a message that the file is infected.
	The standard linux utilities will be continuously opened and executed, without being affected in any way.
	This could be verified by checking the dmesg logs to see that no such standard utility is reported as
        infected. Moreover, if such a thing happens, the user-detection logic would append the utility
	with a .virus, which would be noticed due to its impact on the system.
----------------------------------------------------------------------------------------------------

LIMITATIONS:

On-access does not work for both open and exec family of system calls.
In both the cases, the original system calls could be intercepted by functions facilitated by a kernel module.
But, the kernel had to invoke a user space application to perform the virus-detection, and
the kernel could not pass the parameters in a correct manner that the user process could understand.

We tried to implement secure communication for updating the database through SSL, the server side
SSL requirement was completed, but the client side SSL requirement failed over differing db versions
the SCRIPT present in the CREATE_SSL.SH contains the server side SSL script.

-------------------------------------------------------------------------------------------------------
REFERENCES:

stackoverflow.com and linux man pages have been invaluable references.

Conversion of hex string to bytes(unsigned char):
http://stackoverflow.com/questions/18267803/how-to-correctly-convert-a-hex-string-to-byte-array-in-c

Kernel-Driver:
1.  Patch code of Prof Erez Zadok(that had been in used in one of the OS assignments) to add a new system call

2.  Hooking into open syscall :
    http://www.gilgalab.com.br/hacking/programming/linux/2013/01/11/Hooking-Linux-3-syscalls/
    https://ruinedsec.wordpress.com/2013/04/04/modifying-system-calls-dispatching-linux/
    https://memset.wordpress.com/2010/12/03/syscall-hijacking-kernel-2-6-systems/

3.  Invoking userspace application from within the kernel :
    https://www.kernel.org/doc/htmldocs/kernel-api/API-call-usermodehelper-setup.html
    https://www.ibm.com/developerworks/library/l-user-space-apps/
    https://e2e.ti.com/support/embedded/linux/f/354/p/308901/1081956
    http://www.tsri.com/jeneral/kernel/kernel/kmod.c/pm/PM-CALL_USERMODEHELPER.html

4.  Hooking into exec family of syscalls :
    https://github.com/kfiros/execmon : Referred a major part of the code for intercepting the execve syscall
    http://www.gossamer-threads.com/lists/linux/kernel/159382
    https://gist.github.com/mike820324/ba7b8c934f858fadc28b/
    https://www.kernel.org/pub/linux/kernel/people/marcelo/linux-2.4/arch/mips/kernel/syscall.c
    http://s.eresi-project.org/inc/articles/elf-rtld.txt

5.  Consulted a partner team (Ravikumar Rajendran, Malini, and Parkavi) to know that the execve system call using
    the udis86 library, will work only on certain distributions.

We also used the following references to use mysql apis with C programs and invoking user space
applications from the kernel:

Remote DB connection:
1. https://www.cyberciti.biz/tips/how-do-i-enable-remote-access-to-mysql-database-server.html
2. https://stackoverflow.com/questions/15872543/access-remote-database-from-command-line

MYSQL:
1. http://dev.mysql.com/doc/refman/5.7/en/c-api-function-overview.html
2. http://zetcode.com/db/mysqlc/
3. http://stackoverflow.com/questions/11526369/c-sample-transaction-for-mysql

SHA256:
1. http://bradconte.com/sha256_c
2. http://stackoverflow.com/questions/7853156/calculate-sha256-of-a-file-using-openssl-libcrypto-in-c
3. http://stackoverflow.com/questions/22880627/sha256-implementation-in-c

Recursive Directory Scanning:
1. https://stackoverflow.com/questions/8436841/how-to-recursively-list-directories-in-c-on-linux

Using Xmessage Box:
1: https//www.daniweb.com/programming/software-development/threads/42340/message-box-in-c 
-----------------------------------------------------------------------------------------------