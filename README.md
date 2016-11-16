README of Criminal Minds


In case you guys have a problem with checking out using https - Checkout repo via ssh

https://confluence.atlassian.com/bitbucket/add-an-ssh-key-to-an-account-302811853.html

DESCRIPTION OF WORK TO BE DONE:

1) Blacklist comparison :
   strcmp of virus signatures with the binary of the file.
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
   pathname as input.


