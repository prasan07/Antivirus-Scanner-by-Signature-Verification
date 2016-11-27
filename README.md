README of Criminal Minds
------------------------


=========To be removed==========>

Current blacklist hex-strings where more will be added in course of time  (can be tested on hello program for now)
+--------------+----------------------------------+
| signature_id | signature                        |
+--------------+----------------------------------+
|            1 | 2f6c69623634                     |
|            2 | 642d6c696e75782d7838362d36342e73 |
|            3 | ea069d15fb8d5d4701000000         |
+--------------+----------------------------------+

=================================>



In case you guys have a problem with checking out using https - Checkout repo via ssh

https://confluence.atlassian.com/bitbucket/add-an-ssh-key-to-an-account-302811853.html

DESCRIPTION OF WORK TO BE DONE:
-------------------------------

1) Blacklist comparison :
   memcmp of virus signatures with the binary of the file.
   To be done in the user space.
   Remote SQL server must have the dbase of the virus signatures, from which we must periodically 
   retrieve. The dbase must be updatable.

2) Whitelist comparison :
   SHA-256 hash of the file is compared with the SHA-256 hash of standard linux utility binaries.
   To be done in the user space.
   Remote SQL server must have the dbase of the SHA-256 hash of std linux utilities, from which we    must periodically retrieve. The dbase must be updatable.

3) Interception of standard system calls like open, exec, execv, to run custom functions(where the    the user-space application with the logic to detect virus, is invoked from the kernel).

4) User space application for the antivirus logic :
   Making use of the blacklist and whitelist comparison, this will recursively scan the set of 
   files, directories and symlinks. Accordingly, it would add the .virus suffix to vulnerable 
   objects and chmod them.
   On-access scan from the kernel space must invoke this user space function, providing the 
   pathname as input. --------------> DONE - Need to plugin in comparison and DB update APIs.


Using MYSQL with C - some helpful guides:

http://www.cs.wichita.edu/~chang/lecture/cs742/program/how-mysql-c-api.html

https://stackoverflow.com/questions/6413855/update-database-table-from-one-sql-server-database-table-to-another

Added a file - script.sh in Shyam's Changes folder - This script will create a test_dir with sample
files - Can be used during tests if needed

COMPLETED WORK
--------------

User space application
The DB-update API must be plugged into the space provided in the main() function.

The blacklist and whitelist logic must be plugged into the space provided in the 
file_scan() function.

PENDING WORK
------------

Kernel interception for open syscall has been coded. Will test today to see if it works.
Will also test invocation of user space application.
Will then check for other syscalls like exec, execv, execlv etc.

***Testing and input data for the black/white lists***

**initializing remote db with whitelist and blacklist script**

Error reporting from user space app must be checked to see as to what happens if the kernel invokes it.

-------------------------------------------------------------------------------

https://www.cyberciti.biz/tips/how-do-i-enable-remote-access-to-mysql-database-server.html

https://stackoverflow.com/questions/15872543/access-remote-database-from-command-line

TO connect to a remote mysql server, 

1. comment out the bind address in the /etc/mysql/my.cnf
2. use the "/sbin/iptables -A INPUT -i eth0 -p tcp --destination-port 3306 -j ACCEPT" to suppress firewall. instead of 'eth0' use your interface.
3. grant all the permission using the following 
grant all privileges on cse509.* to 'username'@'%' identified by 'passphrase' REQUIRE SSL;
4. Make sure that the previleges are set for the tables as well.

gcc command to compile with the libraries:
gcc -o operations dboperations.c getSha256.c `mysql_config --cflags --libs` -lssl -lcrypto

Added the table checking and creating logic for three calls. 

Creating MYSQL SSL Files using openssl:
--------------------------------------
https://dev.mysql.com/doc/refman/5.5/en/creating-ssl-files-using-openssl.html

Setting up MYSQL SSL:
---------------------
https://lowendbox.com/blog/getting-started-with-mysql-over-ssl/

generate the CA certificate and private key. On the server, go to /etc/mysql and type the following command:

openssl genrsa 2048 > ca-key.pem

generate the certificate using that key:

openssl req -sha1 -new -x509 -nodes -days 3650 -key ca-key.pem > ca-cert.pem

create a private key for the server and a signing request to go with that:

openssl req -sha1 -newkey rsa:2048 -days 730 -nodes -keyout server-key.pem > server-req.pem

export the private key into an RSA private key:

openssl rsa -in server-key.pem -out server-key.pem

create a certificate using the CA certificate:

openssl x509 -sha1 -req -in server-req.pem -days 730  -CA ca-cert.pem -CAkey ca-key.pem -set_serial 01 > server-cert.pem

Configure MySQL to use them. Open up /etc/mysql/my.cnf and put the following lines in the [mysqld] section:

ssl-ca=/etc/mysql/ca-cert.pem
ssl-cert=/etc/mysql/server-cert.pem
ssl-key=/etc/mysql/server-key.pem

To apply these changes, restart MySQL:

sudo service mysql restart

**Setting up the client:**

we start with a private key and a certificate signing request:

openssl req -sha1 -newkey rsa:2048 -days 730 -nodes -keyout client-key.pem > client-req.pem

export the private key to an RSA private key:

openssl rsa -in client-key.pem -out client-key.pem

create a certificate using the CA private key and certificate:

openssl x509 -sha1 -req -in client-req.pem -days 730 -CA ca-cert.pem -CAkey ca-key.pem -set_serial 01 > client-cert.pem

copy the following three files to the client:

ca-cert.pem
client-key.pem
client-cert.pem

open up /etc/mysql/my.cnf and add the following lines under the [client] section:

ssl-cert=/etc/mysql/server-cert.pem
ssl-key=/etc/mysql/server-key.pem

Whitelist population utilities:
-------------------------------
https://askubuntu.com/questions/308045/differences-between-bin-sbin-usr-bin-usr-sbin-usr-local-bin-usr-local

SSH IPTABLES:
-------------
sudo iptables -A INPUT -p tcp --dport ssh -j ACCEPT
Edit /etc/ssh/ssh_config as sudo change port from 22 to xxxx

https://www.scribd.com/document/320972085/Install-MySql-5-5-Ubuntu16-04-Xenial-Xerus